package app

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/drudge/sable/internal/dhcp"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/web"
)

var (
	errDHCPLeasesUnavailable = errors.New("the lease store isn't answering; try again")
	errDHCPRestarting        = errors.New("the DHCP server is restarting; try again in a moment")
)

// Status is what the console and the API show about the server.
func (service *dhcpService) Status() web.DHCPStatus {
	service.mutex.Lock()
	enabled, running := service.active.Enabled, service.running != nil
	service.mutex.Unlock()
	status := web.DHCPStatus{
		Enabled: enabled, Serving: running && service.current.Load().accepting(),
		Clustered: enabled && service.role() != "",
		Received:  service.stats.Received.Load(), Replied: service.stats.Replied.Load(),
		Dropped: service.stats.Dropped.Load(), Conflicts: service.stats.Conflicts.Load(),
		StoreFailed: service.stats.StoreFailed.Load(),
	}
	return status
}

// Leases returns every stored lease row, this node's and mirrored ones.
func (service *dhcpService) Leases(ctx context.Context) ([]store.DHCPLease, error) {
	return service.leases.DHCPLeases(ctx)
}

// ReloadLeases has a running server read its leases from the store again, in
// its serve goroutine, after this node's own rows came back from a mirror. A
// stopped server reads them when it starts.
func (service *dhcpService) ReloadLeases(ctx context.Context) {
	if server := service.current.Load(); server != nil {
		server.submit(ctx, dhcpRequest{reload: true})
	}
}

// RemoveLease ends this node's lease on address and reports whether there
// was one. A running server removes it in its serve goroutine; a stopped one
// has no engine to disagree with, so the store row is written directly.
func (service *dhcpService) RemoveLease(ctx context.Context, address netip.Addr) (bool, error) {
	service.mutex.Lock()
	running := service.running != nil
	service.mutex.Unlock()
	if !running {
		return service.removeStored(ctx, address)
	}
	server := service.current.Load()
	removal := &dhcpRemoval{address: address, done: make(chan dhcpRemoved, 1)}
	if server == nil || !server.submit(ctx, dhcpRequest{remove: removal}) {
		return false, errDHCPRestarting
	}
	select {
	case removed := <-removal.done:
		return removed.lease != nil, removed.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// removeStored releases this node's row for address in the store while no
// server runs, so a server started later doesn't keep the lease alive.
func (service *dhcpService) removeStored(ctx context.Context, address netip.Addr) (bool, error) {
	rows, err := service.leases.DHCPLeases(ctx)
	if err != nil {
		return false, errDHCPLeasesUnavailable
	}
	now, node := time.Now(), service.node()
	for _, row := range rows {
		lease := dhcpLeaseFromStore(row)
		if lease.NodeID != node || lease.Address != address || !dhcpLeaseHeld(lease, now) {
			continue
		}
		lease.State, lease.ExpiresAt = dhcp.LeaseReleased, now
		if err := service.save(ctx, []dhcp.Lease{lease}); err != nil {
			return false, errDHCPLeasesUnavailable
		}
		return true, nil
	}
	return false, nil
}

// dhcpLeaseHeld matches the engine's rule: active and declined leases hold
// their address until they expire.
func dhcpLeaseHeld(lease dhcp.Lease, now time.Time) bool {
	return (lease.State == dhcp.LeaseActive || lease.State == dhcp.LeaseDeclined) && now.Before(lease.ExpiresAt)
}
