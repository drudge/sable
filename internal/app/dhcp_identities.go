package app

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/store"
)

const (
	// dhcpIdentitySource labels identities read from this server's DHCP
	// leases.
	dhcpIdentitySource = "dhcp"
	// dhcpIdentityInterval is how often the active leases are recorded
	// besides after each lease change, so a long lease stays current in
	// Insights the way the neighbor table's sightings do.
	dhcpIdentityInterval = time.Minute
)

// dhcpIdentities records this node's active DHCP leases as Insights identity
// sightings: after a lease changes and once a minute. Like the neighbor
// sampler it stays off the DNS path and records nothing while Insights is off.
type dhcpIdentities struct {
	enabled func() bool
	leases  func(context.Context) ([]store.DHCPLease, error)
	nodeID  func() string
	record  func(context.Context, []querylog.ClientIdentity) error
	logger  *slog.Logger
	wake    chan struct{}
}

func newDHCPIdentities(enabled func() bool, leases func(context.Context) ([]store.DHCPLease, error), nodeID func() string, record func(context.Context, []querylog.ClientIdentity) error, logger *slog.Logger) *dhcpIdentities {
	return &dhcpIdentities{enabled: enabled, leases: leases, nodeID: nodeID, record: record,
		logger: logger.With("component", "dhcp-identities"), wake: make(chan struct{}, 1)}
}

// Changed asks for a recording now: a lease changed.
func (identities *dhcpIdentities) Changed() {
	select {
	case identities.wake <- struct{}{}:
	default:
	}
}

// Run records after each change and each interval until ctx ends.
func (identities *dhcpIdentities) Run(ctx context.Context) {
	ticker := time.NewTicker(dhcpIdentityInterval)
	defer ticker.Stop()
	reported := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-identities.wake:
		}
		err := recordDHCPIdentities(ctx, identities.enabled, identities.leases, identities.nodeID, identities.record, time.Now())
		// A store that can't be read fails the same way every minute.
		if err != nil && !reported && ctx.Err() == nil {
			identities.logger.Warn("record DHCP leases for Insights", "error", err)
			reported = true
		}
	}
}

// recordDHCPIdentities records one sighting per lease this node holds that is
// active and unexpired, named with the label the lease registered in DNS, or
// the client's host name (RFC 2132 §3.14) when it registered none. Another
// node's leases are that node's to record.
func recordDHCPIdentities(
	ctx context.Context,
	enabled func() bool,
	read func(context.Context) ([]store.DHCPLease, error),
	nodeID func() string,
	record func(context.Context, []querylog.ClientIdentity) error,
	now time.Time,
) error {
	if !enabled() {
		return nil
	}
	leases, err := read(ctx)
	if err != nil {
		return err
	}
	node := nodeID()
	sightings := make([]querylog.ClientIdentity, 0, len(leases))
	for _, lease := range leases {
		if lease.NodeID != node || lease.State != store.DHCPLeaseActive || !lease.ExpiresAt.After(now) || lease.MAC == "" {
			continue
		}
		name := lease.Label
		if name == "" {
			name = lease.Hostname
		}
		sightings = append(sightings, querylog.ClientIdentity{
			Address: lease.Address.String(), MAC: strings.ToLower(lease.MAC),
			Source: dhcpIdentitySource, Hostname: name, SeenAt: now,
		})
	}
	if len(sightings) == 0 {
		return nil
	}
	return record(ctx, sightings)
}
