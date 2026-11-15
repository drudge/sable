package app

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
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
	enabled  func() bool
	leases   func(context.Context) ([]store.DHCPLease, error)
	nodeID   func() string
	settings func() config.DHCP
	record   func(context.Context, []querylog.ClientIdentity) error
	logger   *slog.Logger
	wake     chan struct{}
}

func newDHCPIdentities(enabled func() bool, leases func(context.Context) ([]store.DHCPLease, error), nodeID func() string, settings func() config.DHCP, record func(context.Context, []querylog.ClientIdentity) error, logger *slog.Logger) *dhcpIdentities {
	return &dhcpIdentities{enabled: enabled, leases: leases, nodeID: nodeID, settings: settings, record: record,
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
		err := recordDHCPIdentities(ctx, identities.enabled, identities.leases, identities.nodeID, identities.settings, identities.record, time.Now())
		// A store that can't be read fails the same way every minute.
		if err != nil && !reported && ctx.Err() == nil {
			identities.logger.Warn("record DHCP leases for Insights", "error", err)
			reported = true
		}
	}
}

// recordDHCPIdentities records one sighting per lease this node holds that is
// active and unexpired, named by dhcpIdentityName. Another node's leases are
// that node's to record.
func recordDHCPIdentities(
	ctx context.Context,
	enabled func() bool,
	read func(context.Context) ([]store.DHCPLease, error),
	nodeID func() string,
	settings func() config.DHCP,
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
	node, reserved := nodeID(), dhcpReservedLabels(settings())
	sightings := make([]querylog.ClientIdentity, 0, len(leases))
	for _, lease := range leases {
		if lease.NodeID != node || lease.State != store.DHCPLeaseActive || !lease.ExpiresAt.After(now) || lease.MAC == "" {
			continue
		}
		sightings = append(sightings, querylog.ClientIdentity{
			Address: lease.Address.String(), MAC: strings.ToLower(lease.MAC),
			Source: dhcpIdentitySource, Hostname: dhcpIdentityName(lease, reserved), SeenAt: now,
		})
	}
	if len(sightings) == 0 {
		return nil
	}
	return record(ctx, sightings)
}

// dhcpReservedLabels maps a scope's ID and a hardware address to the label
// of that client's named reservation.
func dhcpReservedLabels(settings config.DHCP) map[[2]string]string {
	labels := make(map[[2]string]string)
	for _, scope := range settings.Scopes {
		for _, reservation := range scope.Reservations {
			if label := dhcpLabel(reservation.Name, true); label != "" {
				labels[[2]string{scope.ID, strings.ToLower(reservation.MAC)}] = label
			}
		}
	}
	return labels
}

// dhcpIdentityName names a lease's device the way DNS does: the name of the
// client's reservation, which the operator chose and dhcpScopeNames
// publishes instead of the client's own, then the label the lease registered,
// then the host name the client sent (RFC 2132 §3.14) when it took no label.
func dhcpIdentityName(lease store.DHCPLease, reserved map[[2]string]string) string {
	if name := reserved[[2]string{lease.ScopeID, strings.ToLower(lease.MAC)}]; name != "" {
		return name
	}
	if lease.Label != "" {
		return lease.Label
	}
	return lease.Hostname
}
