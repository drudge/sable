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
	RecoverDHCPLeases(context.Context, []store.DHCPLease) (int, error)
	OpenDHCPLeaseRecoveryBelow(ctx context.Context, nodeID string, seq int64) (bool, error)
	DHCPLeaseRecovery(ctx context.Context, nodeID string) (int64, bool, error)
	AdvanceDHCPLeaseRecovery(ctx context.Context, nodeID string, seq int64, done bool) error
}

// dhcpLeaseMirror lets the cluster mirror every node's leases into this
// node's store (docs/design/dhcp.md §3), telling changed when a mirror
// writes something. When a wiped node takes its own leases back from the
// primary's mirror, recovered reloads them into the running server, so it
// keeps each client on the address it was told it holds (RFC 2131 §4.3.1).
func dhcpLeaseMirror(leases dhcpMirrorStore, changed func(), recovered func(context.Context)) cluster.LeaseMirror {
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
			rows, err := storedDHCPLeases(shared)
			if err != nil {
				return 0, err
			}
			return leases.MirrorDHCPLeases(ctx, rows)
		},
		Raise: leases.RaiseDHCPLeaseSeq,
		Recover: func(ctx context.Context, shared []cluster.SharedLease) (int, error) {
			rows, err := storedDHCPLeases(shared)
			if err != nil {
				return 0, err
			}
			written, err := leases.RecoverDHCPLeases(ctx, rows)
			if written > 0 && recovered != nil {
				recovered(ctx)
			}
			return written, err
		},
		Behind:    leases.OpenDHCPLeaseRecoveryBelow,
		Recovery:  leases.DHCPLeaseRecovery,
		Recovered: leases.AdvanceDHCPLeaseRecovery,
		Changed:   changed,
	}
}

func storedDHCPLeases(shared []cluster.SharedLease) ([]store.DHCPLease, error) {
	rows := make([]store.DHCPLease, 0, len(shared))
	for _, lease := range shared {
		row, err := storedDHCPLease(lease)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
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
