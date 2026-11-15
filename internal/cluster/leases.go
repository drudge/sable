package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"math"
	"slices"
	"time"
)

const (
	// leaseProtocolVersion is what a primary advertises when it mirrors DHCP
	// leases through heartbeats and sync responses.
	leaseProtocolVersion = 1
	// leaseBatchLimit caps the leases one heartbeat or sync response
	// carries; the rest follow on the next beats (docs/design/dhcp.md §3).
	leaseBatchLimit = 500
	// leaseBatchBytes caps the same batch by its encoded size, well inside
	// MaximumHeartbeatBytes: a row keeps what the client sent, and 500 rows
	// at the wire's maximum are over two megabytes.
	leaseBatchBytes = 256 << 10
)

// fitLeaseBatch cuts rows to leaseBatchBytes of JSON, keeping at least one
// so the mirror always moves on.
func fitLeaseBatch(rows []SharedLease) []SharedLease {
	size := 0
	for index, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			return rows[:index]
		}
		if size += len(encoded) + 1; size > leaseBatchBytes && index > 0 {
			return rows[:index]
		}
	}
	return rows
}

// SharedLease is a DHCP lease as it crosses between nodes. Seq is the
// owner's sequence number, which every mirror keeps.
type SharedLease struct {
	NodeID      string    `json:"node_id"`
	Address     string    `json:"address"`
	ScopeID     string    `json:"scope_id"`
	ClientKey   string    `json:"client_key"`
	MAC         string    `json:"mac,omitempty"`
	ClientID    string    `json:"client_id,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`
	Label       string    `json:"label,omitempty"`
	State       string    `json:"state"`
	BoundAt     time.Time `json:"bound_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Seq         int64     `json:"seq"`
	Relay       string    `json:"relay,omitempty"`
	VendorClass string    `json:"vendor_class,omitempty"`
}

// LeaseReport travels both ways. Held is the highest sequence number the
// sender holds of each node's leases, and Rows are leases the receiver lacks:
// a replica's own on a heartbeat, every other node's on a sync response.
// Recovered, set only by a replica part way through taking its own leases
// back after a wipe, is the highest number it has taken back so far. Wanted,
// set only by a primary taking its own leases back the same way, is the
// number after which it wants the replica's mirror of them on the next beat.
type LeaseReport struct {
	Held      map[string]int64 `json:"held"`
	Rows      []SharedLease    `json:"rows,omitempty"`
	Recovered *int64           `json:"recovered,omitempty"`
	Wanted    *int64           `json:"wanted,omitempty"`
}

// LeaseMirror reads and writes this node's lease table for the mirror.
// Mirror writes rows another node owns, keeping their sequence numbers and
// passing over any not newer than what it holds. Raise lifts a node's counter
// to a number and renumbers its rows above it, reporting whether it did.
// Recover, when set, writes this node's own rows back from the primary's
// mirror after a wipe, keeping their numbers and passing over any address it
// already holds. Recovery, when set, reports whether the node's counter
// started over and how far it has taken its rows back since, which its count
// can't show once it has leased as many since as it held before; Recovered
// moves that on, or ends it when done. Changed, when set, is called after a
// mirror writes something.
type LeaseMirror struct {
	Held      func(context.Context) (map[string]int64, error)
	Since     func(ctx context.Context, nodeID string, seq int64, limit int) ([]SharedLease, error)
	Mirror    func(context.Context, []SharedLease) (int, error)
	Raise     func(ctx context.Context, nodeID string, seq int64) (bool, error)
	Recover   func(context.Context, []SharedLease) (int, error)
	Recovery  func(ctx context.Context, nodeID string) (seq int64, open bool, err error)
	Recovered func(ctx context.Context, nodeID string, seq int64, done bool) error
	Changed   func()
}

func (mirror LeaseMirror) enabled() bool {
	return mirror.Held != nil && mirror.Since != nil && mirror.Mirror != nil && mirror.Raise != nil
}

// SetLeaseMirror lets the service mirror DHCP leases with the other members.
func (service *Service) SetLeaseMirror(mirror LeaseMirror) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.leaseMirror = mirror
}

// leaseReportForPrimary builds what this replica tells the primary that
// advertised the mirror: what it holds of every node, and its own leases
// written since the primary last said it held them. It reads the store
// before the heartbeat takes the service lock, and returns the primary it is
// meant for.
func (service *Service) leaseReportForPrimary(ctx context.Context) (*LeaseReport, string) {
	service.mu.Lock()
	mirror, primaryID, acknowledged, wanted := service.leaseMirror, service.leasePrimaryID, service.leaseAcknowledged, service.leaseWanted
	service.mu.Unlock()
	if primaryID == "" || !mirror.enabled() {
		return nil, ""
	}
	held, err := mirror.Held(ctx)
	if err != nil {
		service.warnLeaseMirror("read held DHCP leases", err)
		return nil, ""
	}
	rows, err := mirror.Since(ctx, service.nodeID, acknowledged, leaseBatchLimit)
	if err != nil {
		service.warnLeaseMirror("read DHCP leases to mirror", err)
		return nil, ""
	}
	report := &LeaseReport{Held: held, Rows: service.withPrimaryLeases(ctx, mirror, primaryID, wanted, fitLeaseBatch(rows))}
	stored, open := service.storedLeaseRecovery(ctx, mirror)
	service.mu.Lock()
	if recovered := max(service.leaseRecovered, stored); open || recovered > 0 {
		report.Recovered = &recovered
	}
	service.mu.Unlock()
	return report, primaryID
}

// withPrimaryLeases adds to a replica's own rows the primary's, from the
// replica's mirror after the number the primary wants them from, as far as
// the batch has room. A batch cut short ends on a whole number, as a
// replica's recovery does (wholeLeaseNumbers).
func (service *Service) withPrimaryLeases(ctx context.Context, mirror LeaseMirror, primaryID string, wanted *int64, own []SharedLease) []SharedLease {
	room := leaseBatchLimit - len(own)
	if wanted == nil || room <= 0 {
		return own
	}
	theirs, err := mirror.Since(ctx, primaryID, *wanted, room)
	if err != nil {
		service.warnLeaseMirror("read the primary's DHCP leases to send back", err)
		return own
	}
	rows := fitLeaseBatch(append(slices.Clone(own), theirs...))
	if len(rows) <= len(own) {
		return own
	}
	if cut := rows[len(own):]; len(cut) < len(theirs) || len(theirs) == room {
		rows = append(rows[:len(own):len(own)], wholeLeaseNumbers(cut)...)
	}
	return rows
}

// exchangeLeases is the primary's side: it mirrors the sender's own leases,
// then answers with what it holds and the leases the sender lacks: every
// other node's, and first its own when the primary holds more of them than
// the sender does, as after a wipe (receiveLeases). A row naming any node
// but the sender is dropped, so no member writes another's leases. Without a
// report from the sender, which has yet to learn the primary mirrors, the
// answer carries only what the primary holds.
func (service *Service) exchangeLeases(ctx context.Context, mirror LeaseMirror, from string, report *LeaseReport) *LeaseReport {
	recovering := report != nil && report.Recovered != nil && service.holdsLeasesOf(ctx, mirror, from)
	if report != nil {
		own := slices.DeleteFunc(slices.Clone(report.Rows), func(row SharedLease) bool { return row.NodeID != from })
		service.mirrorLeases(ctx, mirror, own)
	}
	var wanted *int64
	if report != nil {
		// A primary rebuilt from a backup counts again from below what the
		// replicas hold of it, as a wiped replica does (receiveLeases), and
		// takes its own rows back from the sender's mirror.
		if _, err := mirror.Raise(ctx, service.nodeID, report.Held[service.nodeID]); err != nil {
			service.warnLeaseMirror("raise the DHCP lease counter", err)
		}
		wanted = service.recoverOwnLeases(ctx, mirror, from, report)
	}
	held, err := mirror.Held(ctx)
	if err != nil {
		service.warnLeaseMirror("read held DHCP leases", err)
		return nil
	}
	answer := &LeaseReport{Held: held, Wanted: wanted}
	if report == nil {
		return answer
	}
	nodes := slices.DeleteFunc(slices.Sorted(maps.Keys(held)), func(node string) bool { return node == from })
	for _, node := range append([]string{from}, nodes...) {
		room := leaseBatchLimit - len(answer.Rows)
		takeBack := node == from && recovering
		if room <= 0 || (held[node] <= report.Held[node] && !takeBack) {
			continue
		}
		rows, err := mirror.Since(ctx, node, leaseCursor(node, from, report), room)
		if err != nil {
			service.warnLeaseMirror("read DHCP leases to mirror", err)
			break
		}
		if fitted := fitLeaseBatch(rows); takeBack && (len(rows) == room || len(fitted) < len(rows)) {
			rows = wholeLeaseNumbers(fitted)
		}
		answer.Rows = append(answer.Rows, rows...)
	}
	answer.Rows = fitLeaseBatch(answer.Rows)
	return answer
}

// recoverOwnLeases is a primary taking its own leases back from a replica's
// mirror while its stored recovery is open, as after a wipe or a restore
// from an older backup. It writes back the primary's rows the replica sent,
// then returns the number after which it wants the next batch, or nil once
// the replica holds none past it. Each replica mirrors on its own, so one
// that holds none says nothing of the rest: only once every replica has said
// so does it end the recovery and, when it took rows back, raise its counter
// past them all and renumber its rows, so
// rows granted since that share a number with the replica's reach it again
// (raiseLeaseCounter). Rows naming the primary are taken only while its
// recovery is open, so a replica can't add to a primary that never lost any.
func (service *Service) recoverOwnLeases(ctx context.Context, mirror LeaseMirror, from string, report *LeaseReport) *int64 {
	cursor, open := service.storedLeaseRecovery(ctx, mirror)
	if !open || mirror.Recover == nil {
		return nil
	}
	if own := slices.DeleteFunc(slices.Clone(report.Rows), func(row SharedLease) bool { return row.NodeID != service.nodeID }); len(own) > 0 {
		written, err := mirror.Recover(ctx, own)
		if err != nil {
			service.warnLeaseMirror("recover DHCP leases from a replica", err)
			return nil
		}
		if written > 0 && mirror.Changed != nil {
			mirror.Changed()
		}
		for _, row := range own {
			cursor = max(cursor, row.Seq)
		}
		if err := mirror.Recovered(ctx, service.nodeID, cursor, false); err != nil {
			service.warnLeaseMirror("note the DHCP lease recovery", err)
		}
	}
	if report.Held[service.nodeID] > cursor {
		return &cursor
	}
	if !service.allReplicasRecovered(from) {
		return nil
	}
	held, err := mirror.Held(ctx)
	if err != nil {
		service.warnLeaseMirror("read held DHCP leases", err)
		return &cursor
	}
	if !service.raiseLeaseCounter(ctx, mirror, report.Held[service.nodeID], held[service.nodeID], true, cursor > 0) {
		return &cursor
	}
	service.mu.Lock()
	service.leaseSourcesDone = nil
	service.mu.Unlock()
	return nil
}

// allReplicasRecovered notes that from holds none of this primary's leases
// past its recovery's cursor, and reports whether every replica in the
// manifest has now said so. The cursor only grows, so a replica that said so
// once stays done. The notes live in memory: after a restart the primary
// asks every replica again, which costs a beat and loses nothing.
func (service *Service) allReplicasRecovered(from string) bool {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.leaseSourcesDone == nil {
		service.leaseSourcesDone = map[string]bool{}
	}
	service.leaseSourcesDone[from] = true
	if service.manifest == nil {
		return false
	}
	for _, node := range service.manifest.Nodes {
		if node.ID != service.nodeID && !service.leaseSourcesDone[node.ID] {
			return false
		}
	}
	return true
}

// holdsLeasesOf reports whether this node held any of a node's leases
// before its report: a node in recovery whose leases the primary has never
// held has none to take back.
func (service *Service) holdsLeasesOf(ctx context.Context, mirror LeaseMirror, node string) bool {
	held, err := mirror.Held(ctx)
	if err != nil {
		service.warnLeaseMirror("read held DHCP leases", err)
		return false
	}
	return held[node] > 0
}

// wholeLeaseNumbers drops the rows at the end of a cut batch that share the
// last row's number. After a wipe two of a node's rows can share a number,
// one from before and one since, and a recovery that takes the batch through
// that number must not skip the one left out. A batch of one number keeps
// it, so the recovery still moves.
func wholeLeaseNumbers(rows []SharedLease) []SharedLease {
	for end := len(rows) - 1; end > 0; end-- {
		if rows[end-1].Seq != rows[len(rows)-1].Seq {
			return rows[:end]
		}
	}
	return rows
}

// leaseCursor is the number after which the primary sends node's leases to
// the sender. Of other nodes' leases that's what the sender holds. Of the
// sender's own, which the primary holds more of than the sender only after a
// wipe, it's how far the sender has taken them back, from the first: the
// sender's own count can include leases it granted since the wipe, and
// starting there would skip as many of its oldest.
func leaseCursor(node, from string, report *LeaseReport) int64 {
	switch {
	case node != from:
		return report.Held[node]
	case report.Recovered != nil:
		return *report.Recovered
	default:
		return 0
	}
}

// receiveLeases is the replica's side: it mirrors the other nodes' leases the
// primary sent and learns how far the primary holds its own. When the primary
// holds more of this node than its counter has reached, the database was
// wiped or restored: the node first takes its own rows back from the mirror,
// a batch a beat, and then raises the counter past them and sends every row
// again under a new number. Sent is the report this node's heartbeat carried:
// without one the primary couldn't send this node's rows, so a recovery
// waits for the next beat rather than end before it starts.
func (service *Service) receiveLeases(ctx context.Context, sent, report *LeaseReport) {
	service.mu.Lock()
	mirror := service.leaseMirror
	service.mu.Unlock()
	if report == nil || !mirror.enabled() {
		return
	}
	others := slices.DeleteFunc(slices.Clone(report.Rows), func(row SharedLease) bool { return row.NodeID == service.nodeID })
	service.mirrorLeases(ctx, mirror, others)
	service.mu.Lock()
	service.leaseWanted = report.Wanted
	service.mu.Unlock()
	acknowledged := report.Held[service.nodeID]
	stored, open := service.storedLeaseRecovery(ctx, mirror)
	held, err := mirror.Held(ctx)
	if err != nil {
		service.warnLeaseMirror("read held DHCP leases", err)
		return
	}
	if sent == nil {
		if open || held[service.nodeID] < acknowledged {
			return
		}
	} else if service.recoverLeases(ctx, mirror, report.Rows) < acknowledged {
		return
	}
	service.mu.Lock()
	renumber := open && max(stored, service.leaseRecovered) > 0
	service.mu.Unlock()
	if !service.raiseLeaseCounter(ctx, mirror, acknowledged, held[service.nodeID], open, renumber) {
		return
	}
	service.mu.Lock()
	service.leaseAcknowledged, service.leaseRecovered = acknowledged, 0
	service.mu.Unlock()
}

// raiseLeaseCounter ends a recovery: it lifts this node's counter past what
// the primary holds of it and renumbers its rows above, so each reaches the
// primary again. After a counter that started over, when the primary held
// rows of this node from before, rows granted since may share numbers or
// addresses with them, so it lifts the counter past its own rows too, which
// renumbers every one of them. Open ends the stored recovery.
func (service *Service) raiseLeaseCounter(ctx context.Context, mirror LeaseMirror, acknowledged, own int64, open, renumber bool) bool {
	target := acknowledged
	if renumber {
		target = max(acknowledged, own) + 1
	}
	if _, err := mirror.Raise(ctx, service.nodeID, target); err != nil {
		service.warnLeaseMirror("raise the DHCP lease counter", err)
		return false
	}
	if open {
		if err := mirror.Recovered(ctx, service.nodeID, 0, true); err != nil {
			service.warnLeaseMirror("end the DHCP lease recovery", err)
			return false
		}
	}
	return true
}

// storedLeaseRecovery reports whether this node's counter started over and
// it has yet to take its own leases back, and how far it has so far.
func (service *Service) storedLeaseRecovery(ctx context.Context, mirror LeaseMirror) (int64, bool) {
	if mirror.Recovery == nil || mirror.Recovered == nil {
		return 0, false
	}
	seq, open, err := mirror.Recovery(ctx, service.nodeID)
	if err != nil {
		service.warnLeaseMirror("read the DHCP lease recovery", err)
		return 0, false
	}
	return seq, open
}

// recoverLeases writes back this node's own rows the primary sent and
// returns the highest number it has taken back so far, which the next
// heartbeat reports so the primary sends the batch after it. Without rows to
// recover, or when writing them fails, it returns the most a number can be,
// so the caller raises the counter rather than wait on a recovery.
func (service *Service) recoverLeases(ctx context.Context, mirror LeaseMirror, rows []SharedLease) int64 {
	own := slices.DeleteFunc(slices.Clone(rows), func(row SharedLease) bool { return row.NodeID != service.nodeID })
	if len(own) == 0 || mirror.Recover == nil {
		return math.MaxInt64
	}
	written, err := mirror.Recover(ctx, own)
	if err != nil {
		service.warnLeaseMirror("recover DHCP leases from the mirror", err)
		return math.MaxInt64
	}
	if written > 0 && mirror.Changed != nil {
		mirror.Changed()
	}
	recovered := own[0].Seq
	for _, row := range own {
		recovered = max(recovered, row.Seq)
	}
	service.mu.Lock()
	service.leaseRecovered = max(service.leaseRecovered, recovered)
	recovered = service.leaseRecovered
	service.mu.Unlock()
	if mirror.Recovered != nil {
		if err := mirror.Recovered(ctx, service.nodeID, recovered, false); err != nil {
			service.warnLeaseMirror("note the DHCP lease recovery", err)
		}
	}
	return recovered
}

func (service *Service) mirrorLeases(ctx context.Context, mirror LeaseMirror, rows []SharedLease) {
	if len(rows) == 0 {
		return
	}
	written, err := mirror.Mirror(ctx, rows)
	if err != nil {
		service.warnLeaseMirror("mirror DHCP leases", err)
		return
	}
	if written > 0 && mirror.Changed != nil {
		mirror.Changed()
	}
}

func (service *Service) warnLeaseMirror(action string, err error) {
	if service.logger != nil && !errors.Is(err, context.Canceled) {
		service.logger.Warn(action, "error", err)
	}
}
