package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// DHCPLeaseState is where a lease stands. Only active leases hold their
// address; the others are kept so a returning client gets its old one.
type DHCPLeaseState string

const (
	DHCPLeaseActive   DHCPLeaseState = "active"
	DHCPLeaseReleased DHCPLeaseState = "released"
	DHCPLeaseExpired  DHCPLeaseState = "expired"
	DHCPLeaseDeclined DHCPLeaseState = "declined"
)

// DHCPLease is one address a node has bound to a client. The node that wrote
// it owns the row; the other nodes hold a mirror of it.
type DHCPLease struct {
	NodeID  string
	Address netip.Addr
	ScopeID string
	// ClientKey is the client identifier when the client sent one, otherwise
	// the hardware type and address (RFC 2131 §4.2).
	ClientKey string
	MAC       string
	ClientID  string
	// Hostname is the name as the client sent it; Label is the one that was
	// registered in DNS.
	Hostname    string
	Label       string
	State       DHCPLeaseState
	BoundAt     time.Time
	ExpiresAt   time.Time
	Seq         int64
	Relay       string
	VendorClass string
}

// dhcpLeaseRetention is how long a lease that no longer holds its address is
// kept, so a client that comes back within it is offered the same address.
const dhcpLeaseRetention = 30 * 24 * time.Hour

const dhcpLeaseColumns = "node_id, address, scope_id, client_key, mac, client_id, hostname, label, state, " +
	"bound_at_ns, expires_at_ns, seq, relay, vendor_class"

func dhcpLeaseTables() []string {
	return []string{`
CREATE TABLE IF NOT EXISTS sable_dhcp_leases (
    node_id TEXT NOT NULL,
    address TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    client_key TEXT NOT NULL,
    mac TEXT NOT NULL DEFAULT '',
    client_id TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL,
    bound_at_ns BIGINT NOT NULL,
    expires_at_ns BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    relay TEXT NOT NULL DEFAULT '',
    vendor_class TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (node_id, address)
)`,
		"CREATE INDEX IF NOT EXISTS sable_dhcp_leases_client_idx ON sable_dhcp_leases (scope_id, client_key)",
		"CREATE INDEX IF NOT EXISTS sable_dhcp_leases_seq_idx ON sable_dhcp_leases (node_id, seq)",
	}
}

// migrateDHCPLeases is schema step 2: the table the DHCP server keeps its
// leases in.
func (store *Store) migrateDHCPLeases(ctx context.Context) error {
	for _, statement := range dhcpLeaseTables() {
		if _, err := store.database.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

// SaveDHCPLease writes a lease this node owns, in place of the one it held
// for that address, and returns it with the node's next sequence number. The
// server calls it before it sends the ACK, so a lease a client was told it
// holds is never lost.
func (store *Store) SaveDHCPLease(ctx context.Context, lease DHCPLease) (DHCPLease, error) {
	if err := validDHCPLease(lease); err != nil {
		return lease, err
	}
	err := store.withTx(ctx, "DHCP lease", func(transaction *sql.Tx) error {
		if err := transaction.QueryRowContext(ctx,
			"SELECT COALESCE(MAX(seq), 0) + 1 FROM sable_dhcp_leases WHERE node_id = "+store.placeholder(1),
			lease.NodeID).Scan(&lease.Seq); err != nil {
			return fmt.Errorf("next DHCP lease sequence: %w", err)
		}
		return store.upsertDHCPLease(ctx, transaction, lease)
	})
	return lease, err
}

func validDHCPLease(lease DHCPLease) error {
	switch {
	case lease.NodeID == "":
		return errors.New("DHCP lease has no node")
	case !lease.Address.Is4():
		return fmt.Errorf("DHCP lease address %v is not IPv4", lease.Address)
	case lease.ScopeID == "" || lease.ClientKey == "":
		return errors.New("DHCP lease has no scope or client")
	}
	switch lease.State {
	case DHCPLeaseActive, DHCPLeaseReleased, DHCPLeaseExpired, DHCPLeaseDeclined:
		return nil
	}
	return fmt.Errorf("DHCP lease state %q is not known", lease.State)
}

func (store *Store) upsertDHCPLease(ctx context.Context, transaction *sql.Tx, lease DHCPLease) error {
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_dhcp_leases (`+dhcpLeaseColumns+`)
VALUES (`+store.placeholders(14)+`)
ON CONFLICT (node_id, address) DO UPDATE SET
    scope_id = excluded.scope_id, client_key = excluded.client_key, mac = excluded.mac,
    client_id = excluded.client_id, hostname = excluded.hostname, label = excluded.label,
    state = excluded.state, bound_at_ns = excluded.bound_at_ns, expires_at_ns = excluded.expires_at_ns,
    seq = excluded.seq, relay = excluded.relay, vendor_class = excluded.vendor_class`,
		lease.NodeID, lease.Address.String(), lease.ScopeID, lease.ClientKey, lease.MAC, lease.ClientID,
		lease.Hostname, lease.Label, string(lease.State), unixNanos(lease.BoundAt), unixNanos(lease.ExpiresAt),
		lease.Seq, lease.Relay, lease.VendorClass); err != nil {
		return fmt.Errorf("save DHCP lease %s: %w", lease.Address, err)
	}
	return nil
}

// DHCPLeases returns every lease the database holds, this node's and the
// mirrors of other nodes', in node and sequence order. The server loads them
// into its in-memory table at start.
func (store *Store) DHCPLeases(ctx context.Context) ([]DHCPLease, error) {
	return store.queryDHCPLeases(ctx, "SELECT "+dhcpLeaseColumns+" FROM sable_dhcp_leases ORDER BY node_id, seq")
}

// DHCPLeasesSince returns at most limit of a node's leases written after a
// sequence number, oldest first: what a replica sends the primary on a
// heartbeat.
func (store *Store) DHCPLeasesSince(ctx context.Context, nodeID string, seq int64, limit int) ([]DHCPLease, error) {
	return store.queryDHCPLeases(ctx, "SELECT "+dhcpLeaseColumns+" FROM sable_dhcp_leases WHERE node_id = "+
		store.placeholder(1)+" AND seq > "+store.placeholder(2)+" ORDER BY seq LIMIT "+store.placeholder(3),
		nodeID, seq, limit)
}

func (store *Store) queryDHCPLeases(ctx context.Context, query string, args ...any) ([]DHCPLease, error) {
	rows, err := store.database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("read DHCP leases: %w", err)
	}
	defer rows.Close()
	var leases []DHCPLease
	for rows.Next() {
		lease, err := scanDHCPLease(rows)
		if err != nil {
			return nil, err
		}
		leases = append(leases, lease)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read DHCP leases: %w", err)
	}
	return leases, nil
}

func scanDHCPLease(rows *sql.Rows) (DHCPLease, error) {
	var lease DHCPLease
	var address, state string
	var boundAt, expiresAt int64
	if err := rows.Scan(&lease.NodeID, &address, &lease.ScopeID, &lease.ClientKey, &lease.MAC, &lease.ClientID,
		&lease.Hostname, &lease.Label, &state, &boundAt, &expiresAt, &lease.Seq, &lease.Relay, &lease.VendorClass); err != nil {
		return lease, fmt.Errorf("read DHCP lease: %w", err)
	}
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		return lease, fmt.Errorf("read DHCP lease address %q: %w", address, err)
	}
	lease.Address, lease.State = parsed, DHCPLeaseState(state)
	lease.BoundAt, lease.ExpiresAt = fromUnixNanos(boundAt), fromUnixNanos(expiresAt)
	return lease, nil
}

// PruneDHCPLeases forgets leases that stopped holding their address more than
// the retention ago. Active leases are kept whatever their expiry: the server
// marks them expired first, and only the owner may.
func (store *Store) PruneDHCPLeases(ctx context.Context, now time.Time) (int64, error) {
	result, err := store.database.ExecContext(ctx, "DELETE FROM sable_dhcp_leases WHERE state <> "+
		store.placeholder(1)+" AND expires_at_ns < "+store.placeholder(2),
		string(DHCPLeaseActive), unixNanos(now.Add(-dhcpLeaseRetention)))
	if err != nil {
		return 0, fmt.Errorf("prune DHCP leases: %w", err)
	}
	return result.RowsAffected()
}

func unixNanos(moment time.Time) int64 {
	if moment.IsZero() {
		return 0
	}
	return moment.UnixNano()
}

func fromUnixNanos(nanos int64) time.Time {
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos).UTC()
}
