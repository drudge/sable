package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
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
type LeaseReport struct {
	Held map[string]int64 `json:"held"`
	Rows []SharedLease    `json:"rows,omitempty"`
}

// LeaseMirror reads and writes this node's lease table for the mirror.
// Mirror writes rows another node owns, keeping their sequence numbers and
// passing over any not newer than what it holds. Raise lifts a node's counter
// to a number and renumbers its rows above it, reporting whether it did.
// Changed, when set, is called after a mirror writes something.
type LeaseMirror struct {
	Held    func(context.Context) (map[string]int64, error)
	Since   func(ctx context.Context, nodeID string, seq int64, limit int) ([]SharedLease, error)
	Mirror  func(context.Context, []SharedLease) (int, error)
	Raise   func(ctx context.Context, nodeID string, seq int64) (bool, error)
	Changed func()
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
	mirror, primaryID, acknowledged := service.leaseMirror, service.leasePrimaryID, service.leaseAcknowledged
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
	return &LeaseReport{Held: held, Rows: fitLeaseBatch(rows)}, primaryID
}

// exchangeLeases is the primary's side: it mirrors the sender's own leases,
// then answers with what it holds and the other nodes' leases the sender
// lacks. A row naming any node but the sender is dropped, so no member writes
// another's leases. Without a report from the sender, which has yet to learn
// the primary mirrors, the answer carries only what the primary holds.
func (service *Service) exchangeLeases(ctx context.Context, mirror LeaseMirror, from string, report *LeaseReport) *LeaseReport {
	if report != nil {
		own := slices.DeleteFunc(slices.Clone(report.Rows), func(row SharedLease) bool { return row.NodeID != from })
		service.mirrorLeases(ctx, mirror, own)
	}
	if report != nil {
		// A primary rebuilt from a backup counts again from below what the
		// replicas hold of it, as a wiped replica does (receiveLeases).
		if _, err := mirror.Raise(ctx, service.nodeID, report.Held[service.nodeID]); err != nil {
			service.warnLeaseMirror("raise the DHCP lease counter", err)
		}
	}
	held, err := mirror.Held(ctx)
	if err != nil {
		service.warnLeaseMirror("read held DHCP leases", err)
		return nil
	}
	answer := &LeaseReport{Held: held}
	if report == nil {
		return answer
	}
	for _, node := range slices.Sorted(maps.Keys(held)) {
		room := leaseBatchLimit - len(answer.Rows)
		if node == from || room <= 0 || held[node] <= report.Held[node] {
			continue
		}
		rows, err := mirror.Since(ctx, node, report.Held[node], room)
		if err != nil {
			service.warnLeaseMirror("read DHCP leases to mirror", err)
			break
		}
		answer.Rows = append(answer.Rows, rows...)
	}
	answer.Rows = fitLeaseBatch(answer.Rows)
	return answer
}

// receiveLeases is the replica's side: it mirrors the other nodes' leases the
// primary sent and learns how far the primary holds its own. When the primary
// holds more of this node than its counter has reached, the database was
// wiped or restored, so the counter is raised past it and every row is sent
// again under a new number.
func (service *Service) receiveLeases(ctx context.Context, report *LeaseReport) {
	service.mu.Lock()
	mirror := service.leaseMirror
	service.mu.Unlock()
	if report == nil || !mirror.enabled() {
		return
	}
	others := slices.DeleteFunc(slices.Clone(report.Rows), func(row SharedLease) bool { return row.NodeID == service.nodeID })
	service.mirrorLeases(ctx, mirror, others)
	acknowledged := report.Held[service.nodeID]
	if _, err := mirror.Raise(ctx, service.nodeID, acknowledged); err != nil {
		service.warnLeaseMirror("raise the DHCP lease counter", err)
		return
	}
	service.mu.Lock()
	service.leaseAcknowledged = acknowledged
	service.mu.Unlock()
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
