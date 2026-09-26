package cluster

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/drudge/sable/internal/alerts"
)

const (
	// alertProtocolVersion is what a primary advertises when it takes a
	// replica's own alerts in the heartbeat. A replica sends none to a primary
	// that does not advertise it: an older primary refuses a heartbeat with a
	// field it does not know, and the replica would look unreachable to it.
	alertProtocolVersion = 1
	// alertReportInterval is how often a replica gathers its own alerts, and
	// how often it repeats an unchanged list so the primary can tell a replica
	// with nothing to say from one that stopped saying anything. The
	// dispatcher sends once a minute, so gathering faster would not alert any
	// sooner.
	alertReportInterval = time.Minute
	// alertReportFreshness is how long a list is trusted: on the primary from
	// when it arrived, and on the replica from when it was gathered. A replica
	// repeats its list every minute, so an older one belongs to a replica that
	// stopped reporting, and what it said may no longer be news.
	alertReportFreshness = 3 * time.Minute
	// alertGatherTimeout bounds one gathering, so a stuck source cannot hold
	// the whole list back.
	alertGatherTimeout = 30 * time.Second
	// maximumAlertReportBytes keeps a list well inside the 64 KiB the primary
	// accepts for a whole heartbeat.
	maximumAlertReportBytes = 32 << 10
)

// LocalAlerts gathers what the alert sources placed on each node see in this
// node. It is the alert dispatcher's Local, handed in so this package does not
// need to know how alerts are gathered.
type LocalAlerts func(context.Context, time.Time) ([]alerts.Alert, error)

// reportedAlerts is a replica's latest list as the primary keeps it.
type reportedAlerts struct {
	list     []alerts.Alert
	received time.Time
}

// alertReporter is what a replica gathered about itself, and what it last told
// the primary.
type alertReporter struct {
	mu           sync.Mutex
	gathered     []alerts.Alert
	encoded      json.RawMessage
	gatheredAt   time.Time
	revision     uint64
	sentTo       string
	sentAt       time.Time
	sentRevision uint64
}

// SetLocalAlerts has this node, whenever it is a replica, gather its own
// alerts and hand them to the lead in its heartbeat, since only the lead sends.
func (service *Service) SetLocalAlerts(local LocalAlerts) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.localAlerts = local
}

// ReportedAlerts returns the alerts each replica last reported about itself,
// for the lead to send. A node that does not lead has none to return. The
// lead's own are never among them: its dispatcher gathers those itself.
func (service *Service) ReportedAlerts(now time.Time) []alerts.Alert {
	service.mu.RLock()
	defer service.mu.RUnlock()
	found := make([]alerts.Alert, 0)
	if service.manifest == nil || service.manifest.PrimaryID != service.nodeID {
		return found
	}
	for _, node := range service.manifest.Nodes {
		report, reported := service.reportedAlerts[node.ID]
		if node.ID == service.nodeID || !reported || now.Sub(report.received) >= alertReportFreshness {
			continue
		}
		for _, alert := range report.list {
			found = append(found, cloneAlert(alert))
		}
	}
	return found
}

// recordReportedAlerts keeps what a replica said about itself. It is called
// with service.mu held. The list is read leniently, so fields a later release
// added are passed over rather than refused. A list that cannot be read at
// all tells nothing, and the last one stands until it goes stale.
func (service *Service) recordReportedAlerts(nodeID string, encoded json.RawMessage, now time.Time) {
	var list []alerts.Alert
	if err := json.Unmarshal(encoded, &list); err != nil {
		if service.logger != nil {
			service.logger.Warn("read cluster member alerts", "node_id", nodeID, "error", err)
		}
		return
	}
	list = slices.DeleteFunc(list, func(alert alerts.Alert) bool { return alert.ID == "" })
	service.reportedAlerts[nodeID] = reportedAlerts{list: list, received: now}
}

// gatherLocalAlerts gathers this node's own alerts every minute while it is a
// replica. It runs apart from the heartbeat so a slow source never delays one,
// since a late heartbeat makes a node look unreachable.
func (service *Service) gatherLocalAlerts(ctx context.Context) {
	ticker := time.NewTicker(alertReportInterval)
	defer ticker.Stop()
	for {
		service.gatherLocalAlertsOnce(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (service *Service) gatherLocalAlertsOnce(ctx context.Context, now time.Time) {
	service.mu.RLock()
	local := service.localAlerts
	replica := service.manifest != nil && service.manifest.PrimaryID != service.nodeID
	service.mu.RUnlock()
	if local == nil || !replica {
		// A node that leads sends its own alerts. What it gathered as a replica
		// is dropped, so it never hands over old news after stepping down.
		service.alertReport.reset()
		return
	}
	gatherContext, cancel := context.WithTimeout(ctx, alertGatherTimeout)
	found, err := local(gatherContext, now)
	cancel()
	if ctx.Err() != nil {
		return
	}
	// The dispatcher has already logged whichever source failed.
	if left := service.alertReport.record(found, err != nil, now); left > 0 && service.logger != nil {
		service.logger.Warn("cluster alert report is too large to carry whole", "left_out", left)
	}
}

// record keeps a newly gathered list, and returns how many alerts it left out
// of a changed list to keep it small enough to carry. A list gathered while a
// source failed also keeps what the last list said, as the dispatcher does:
// the failing source may still have news, and the lead would forget whatever
// a shorter list left out.
func (reporter *alertReporter) record(found []alerts.Alert, partial bool, now time.Time) int {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if partial {
		found = mergeAlerts(found, reporter.gathered)
	}
	encoded, kept, left := encodeAlertReport(found)
	reporter.gatheredAt = now
	if reporter.encoded != nil && bytes.Equal(encoded, reporter.encoded) {
		return 0
	}
	reporter.gathered, reporter.encoded = kept, encoded
	reporter.revision++
	return left
}

// pending returns the list for the next heartbeat to a primary, when one is
// due: the list changed, the primary changed, or a minute passed since the
// primary last heard it. A list not gathered lately is never carried, since
// it may be stale.
func (reporter *alertReporter) pending(primaryID string, now time.Time) (json.RawMessage, uint64) {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if reporter.encoded == nil || now.Sub(reporter.gatheredAt) >= alertReportFreshness {
		return nil, 0
	}
	if reporter.sentTo == primaryID && reporter.sentRevision == reporter.revision && now.Sub(reporter.sentAt) < alertReportInterval {
		return nil, 0
	}
	return slices.Clone(reporter.encoded), reporter.revision
}

// delivered notes that a primary accepted a heartbeat carrying a list.
func (reporter *alertReporter) delivered(primaryID string, revision uint64, at time.Time) {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	reporter.sentTo, reporter.sentRevision, reporter.sentAt = primaryID, revision, at
}

// reset forgets what was gathered and sent. The revision keeps counting, so a
// list gathered later never passes for one already sent.
func (reporter *alertReporter) reset() {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	reporter.gathered, reporter.encoded, reporter.gatheredAt = nil, nil, time.Time{}
	reporter.sentTo, reporter.sentAt = "", time.Time{}
}

// encodeAlertReport encodes as many alerts as fit in maximumAlertReportBytes,
// in the dispatcher's order. It returns the encoding, the alerts it kept, and
// how many it left out.
func encodeAlertReport(found []alerts.Alert) (json.RawMessage, []alerts.Alert, int) {
	kept := make([]alerts.Alert, 0, len(found))
	size, left := len("[]"), 0
	for _, alert := range found {
		encoded, err := json.Marshal(alert)
		if err != nil || size+len(encoded)+len(",") > maximumAlertReportBytes {
			left++
			continue
		}
		size += len(encoded) + len(",")
		kept = append(kept, cloneAlert(alert))
	}
	encoded, err := json.Marshal(kept)
	if err != nil {
		return json.RawMessage("[]"), nil, len(found)
	}
	return encoded, kept, left
}

// mergeAlerts adds to a list whatever an earlier one had that it does not,
// oldest first as the dispatcher orders them.
func mergeAlerts(found, earlier []alerts.Alert) []alerts.Alert {
	merged := slices.Clone(found)
	for _, alert := range earlier {
		if !slices.ContainsFunc(merged, func(kept alerts.Alert) bool { return kept.ID == alert.ID }) {
			merged = append(merged, alert)
		}
	}
	slices.SortStableFunc(merged, func(left, right alerts.Alert) int {
		return cmp.Or(left.ObservedAt.Compare(right.ObservedAt), cmp.Compare(left.ID, right.ID))
	})
	return merged
}

func cloneAlert(alert alerts.Alert) alerts.Alert {
	alert.Reasons = slices.Clone(alert.Reasons)
	return alert
}
