package app

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/store"
)

// dhcpMirrorStore is the part of the store the cluster's lease mirror uses.
type dhcpMirrorStore interface {
	DHCPLeaseHeld(context.Context) (map[string]int64, error)
	DHCPLeasesSince(ctx context.Context, nodeID string, seq int64, limit int) ([]store.DHCPLease, error)
	MirrorDHCPLeases(context.Context, []store.DHCPLease) (int, error)
	RaiseDHCPLeaseSeq(ctx context.Context, nodeID string, seq int64) (bool, error)
}

// dhcpLeaseMirror lets the cluster mirror every node's leases into this
// node's store (docs/design/dhcp.md §3), telling changed when a mirror
// writes something.
func dhcpLeaseMirror(leases dhcpMirrorStore, changed func()) cluster.LeaseMirror {
	return cluster.LeaseMirror{
		Held: leases.DHCPLeaseHeld,
		Since: func(ctx context.Context, nodeID string, seq int64, limit int) ([]cluster.SharedLease, error) {
			rows, err := leases.DHCPLeasesSince(ctx, nodeID, seq, limit)
			shared := make([]cluster.SharedLease, 0, len(rows))
			for _, row := range rows {
				shared = append(shared, sharedDHCPLease(row))
			}
			return shared, err
		},
		Mirror: func(ctx context.Context, shared []cluster.SharedLease) (int, error) {
			rows := make([]store.DHCPLease, 0, len(shared))
			for _, lease := range shared {
				row, err := storedDHCPLease(lease)
				if err != nil {
					return 0, err
				}
				rows = append(rows, row)
			}
			return leases.MirrorDHCPLeases(ctx, rows)
		},
		Raise:   leases.RaiseDHCPLeaseSeq,
		Changed: changed,
	}
}

func sharedDHCPLease(row store.DHCPLease) cluster.SharedLease {
	return cluster.SharedLease{
		NodeID: row.NodeID, Address: row.Address.String(), ScopeID: row.ScopeID, ClientKey: row.ClientKey,
		MAC: row.MAC, ClientID: row.ClientID, Hostname: row.Hostname, Label: row.Label, State: string(row.State),
		BoundAt: row.BoundAt, ExpiresAt: row.ExpiresAt, Seq: row.Seq, Relay: row.Relay, VendorClass: row.VendorClass,
	}
}

func storedDHCPLease(lease cluster.SharedLease) (store.DHCPLease, error) {
	address, err := netip.ParseAddr(lease.Address)
	if err != nil {
		return store.DHCPLease{}, fmt.Errorf("mirrored DHCP lease address %q: %w", lease.Address, err)
	}
	return store.DHCPLease{
		NodeID: lease.NodeID, Address: address, ScopeID: lease.ScopeID, ClientKey: lease.ClientKey,
		MAC: lease.MAC, ClientID: lease.ClientID, Hostname: lease.Hostname, Label: lease.Label,
		State: store.DHCPLeaseState(lease.State), BoundAt: lease.BoundAt, ExpiresAt: lease.ExpiresAt,
		Seq: lease.Seq, Relay: lease.Relay, VendorClass: lease.VendorClass,
	}, nil
}
