package cluster

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"maps"
	"slices"
	"sync"
	"time"
)

const (
	// lookupProtocolVersion is what a primary advertises when it takes a
	// replica's lookups in the heartbeat. A replica sends none to a primary
	// that does not advertise it, since an older primary refuses a heartbeat
	// with a field it does not know.
	lookupProtocolVersion = 1
	// lookupReportInterval is how often a replica reads which client
	// addresses asked it something, and how often it repeats an unchanged
	// report so a primary that restarted hears it again. A replica that has
	// no report yet, such as one that just joined, tries every
	// lookupGatherTick instead, since the lead holds findings back until it
	// hears from every replica.
	lookupReportInterval = 5 * time.Minute
	lookupGatherTick     = time.Minute
	// lookupReportLookback is how far back a report reaches: the longest a
	// device may be watched for, and a day to spare.
	lookupReportLookback = 8 * 24 * time.Hour
	// lookupGatherTimeout bounds one read of the store.
	lookupGatherTimeout = 30 * time.Second
	// maximumLookupReportBytes keeps a report well inside what the primary
	// accepts for a whole heartbeat. The addresses that asked longest ago are
	// the ones left out of a report that would not fit.
	maximumLookupReportBytes = 768 << 10
	// MaximumHeartbeatBytes is the most a primary reads of one heartbeat.
	MaximumHeartbeatBytes = 1 << 20
)

// LocalLookups reads, for each client address that asked this node anything
// since a moment, when it last did.
type LocalLookups func(context.Context, time.Time) (map[string]time.Time, error)

// NodeLookups is what one replica last said about which client addresses
// asked it something. Reported is when the lead heard it, and is zero for a
// replica that has not reported since this node started leading.
type NodeLookups struct {
	NodeID   string
	Name     string
	Reported time.Time
	Last     map[string]time.Time
}

// reportedLookups is a replica's latest report as the primary keeps it.
type reportedLookups struct {
	last     map[string]time.Time
	received time.Time
}

// lookupReporter is what a replica gathered about the addresses that asked
// it something, and what it last told the primary.
type lookupReporter struct {
	mu           sync.Mutex
	gatheredAt   time.Time
	encoded      json.RawMessage
	revision     uint64
	sentTo       string
	sentAt       time.Time
	sentRevision uint64
}

// SetLocalLookups has this node, whenever it is a replica, tell the lead
// which client addresses asked it something, so the lead can tell a device
// that only uses this node from one that uses no node at all.
func (service *Service) SetLocalLookups(local LocalLookups) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.localLookups = local
}

// ReplicaLookups returns what each replica last said about which client
// addresses asked it something, one entry for every replica whether or not
// it has reported. Leads is false on a node that does not lead a cluster,
// which has nothing to return.
func (service *Service) ReplicaLookups() (lookups []NodeLookups, leads bool) {
	service.mu.RLock()
	defer service.mu.RUnlock()
	if service.manifest == nil || service.manifest.PrimaryID != service.nodeID {
		return nil, false
	}
	for _, node := range service.manifest.Nodes {
		if node.ID == service.nodeID {
			continue
		}
		entry := NodeLookups{NodeID: node.ID, Name: node.Name}
		if report, reported := service.reportedLookups[node.ID]; reported {
			entry.Reported, entry.Last = report.received, maps.Clone(report.last)
		}
		lookups = append(lookups, entry)
	}
	return lookups, true
}

// recordReportedLookups keeps what a replica said. It is called with
// service.mu held. A report that cannot be read tells nothing, and the last
// one stands.
func (service *Service) recordReportedLookups(nodeID string, encoded json.RawMessage, now time.Time) {
	var seconds map[string]int64
	if err := json.Unmarshal(encoded, &seconds); err != nil {
		if service.logger != nil {
			service.logger.Warn("read cluster member lookups", "node_id", nodeID, "error", err)
		}
		return
	}
	last := make(map[string]time.Time, len(seconds))
	for address, moment := range seconds {
		if address != "" && moment > 0 {
			last[address] = time.Unix(moment, 0).UTC()
		}
	}
	service.reportedLookups[nodeID] = reportedLookups{last: last, received: now}
}

// gatherLocalLookups reads this node's lookups every few minutes while it is
// a replica. It runs apart from the heartbeat so a slow read never delays one.
func (service *Service) gatherLocalLookups(ctx context.Context) {
	ticker := time.NewTicker(lookupGatherTick)
	defer ticker.Stop()
	for {
		service.gatherLocalLookupsOnce(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (service *Service) gatherLocalLookupsOnce(ctx context.Context, now time.Time) {
	service.mu.RLock()
	local := service.localLookups
	replica := service.manifest != nil && service.manifest.PrimaryID != service.nodeID
	service.mu.RUnlock()
	if local == nil || !replica {
		service.lookupReport.reset()
		return
	}
	if !service.lookupReport.due(now) {
		return
	}
	gatherContext, cancel := context.WithTimeout(ctx, lookupGatherTimeout)
	found, err := local(gatherContext, now.Add(-lookupReportLookback))
	cancel()
	if err != nil {
		if ctx.Err() == nil && service.logger != nil {
			service.logger.Warn("read lookups for the cluster lead", "error", err)
		}
		return
	}
	encoded, left := encodeLookupReport(found)
	if left > 0 && service.logger != nil {
		service.logger.Warn("cluster lookup report is too large to carry whole", "left_out", left)
	}
	service.lookupReport.record(encoded, now)
}

// due reports whether it is time to read the lookups again.
func (reporter *lookupReporter) due(now time.Time) bool {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	return reporter.gatheredAt.IsZero() || now.Sub(reporter.gatheredAt) >= lookupReportInterval
}

// record keeps a newly gathered report.
func (reporter *lookupReporter) record(encoded json.RawMessage, now time.Time) {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	reporter.gatheredAt = now
	if reporter.encoded != nil && bytes.Equal(encoded, reporter.encoded) {
		return
	}
	reporter.encoded = encoded
	reporter.revision++
}

// pending returns the report for the next heartbeat to a primary, when one is
// due: the report changed, the primary changed, or it has not heard the
// report for a while.
func (reporter *lookupReporter) pending(primaryID string, now time.Time) (json.RawMessage, uint64) {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if reporter.encoded == nil {
		return nil, 0
	}
	if reporter.sentTo == primaryID && reporter.sentRevision == reporter.revision && now.Sub(reporter.sentAt) < lookupReportInterval {
		return nil, 0
	}
	return slices.Clone(reporter.encoded), reporter.revision
}

// delivered notes that a primary accepted a heartbeat carrying a report.
func (reporter *lookupReporter) delivered(primaryID string, revision uint64, at time.Time) {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	reporter.sentTo, reporter.sentRevision, reporter.sentAt = primaryID, revision, at
}

// reset forgets what was gathered and sent, for a node that now leads.
func (reporter *lookupReporter) reset() {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	reporter.encoded, reporter.gatheredAt, reporter.sentTo, reporter.sentAt = nil, time.Time{}, "", time.Time{}
}

// encodeLookupReport encodes each address's last lookup in Unix seconds,
// keeping the most recent ones that fit in maximumLookupReportBytes. It
// returns the encoding and how many addresses it left out.
func encodeLookupReport(found map[string]time.Time) (json.RawMessage, int) {
	addresses := slices.Collect(maps.Keys(found))
	slices.SortFunc(addresses, func(left, right string) int {
		return cmp.Or(found[right].Compare(found[left]), cmp.Compare(left, right))
	})
	kept := make(map[string]int64, len(addresses))
	size, left := len("{}"), 0
	for _, address := range addresses {
		// "address":1790000000, is the address, its quotes, a colon, ten
		// digits, and a comma.
		entry := len(address) + 14
		if size+entry > maximumLookupReportBytes {
			left++
			continue
		}
		size += entry
		kept[address] = found[address].Unix()
	}
	encoded, err := json.Marshal(kept)
	if err != nil {
		return json.RawMessage("{}"), len(found)
	}
	return encoded, left
}
