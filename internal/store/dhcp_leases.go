package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
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
		"CREATE INDEX IF NOT EXISTS sable_dhcp_leases_expires_idx ON sable_dhcp_leases (expires_at_ns)",
		// Each node's last sequence number, kept apart from the leases so a
		// prune that deletes the newest row never hands its number out again.
		`
CREATE TABLE IF NOT EXISTS sable_dhcp_lease_seqs (
    node_id TEXT PRIMARY KEY,
    seq BIGINT NOT NULL
)`,
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
// for that address, and returns it with the node's next sequence number.
func (store *Store) SaveDHCPLease(ctx context.Context, lease DHCPLease) (DHCPLease, error) {
	saved, err := store.SaveDHCPLeases(ctx, []DHCPLease{lease})
	if err != nil {
		return lease, err
	}
	return saved[0], nil
}

// SaveDHCPLeases writes leases in order in one transaction, each with the
// node's next sequence number. The server calls it before it sends the ACK,
// so a lease a client was told it holds is never lost, and a client that
// moves never leaves its old lease active beside the new one.
func (store *Store) SaveDHCPLeases(ctx context.Context, leases []DHCPLease) ([]DHCPLease, error) {
	for _, lease := range leases {
		if err := validDHCPLease(lease); err != nil {
			return nil, err
		}
	}
	saved := slices.Clone(leases)
	err := store.withTx(ctx, "DHCP leases", func(transaction *sql.Tx) error {
		for index := range saved {
			seq, err := store.nextDHCPLeaseSeq(ctx, transaction, saved[index].NodeID)
			if err != nil {
				return err
			}
			saved[index].Seq = seq
			if seq == 1 {
				if err := store.openDHCPLeaseRecovery(ctx, transaction, saved[index].NodeID); err != nil {
					return err
				}
			}
			if _, err := store.upsertDHCPLease(ctx, transaction, saved[index], dhcpLeaseReplace); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return saved, nil
}

// nextDHCPLeaseSeq takes the node's next sequence number. The counter only
// climbs, whatever PruneDHCPLeases deletes, so a replica that has seen a
// number never misses a later write; on Postgres the upsert's row lock also
// keeps two writers on one node from taking the same number.
func (store *Store) nextDHCPLeaseSeq(ctx context.Context, transaction *sql.Tx, nodeID string) (int64, error) {
	var seq int64
	if err := transaction.QueryRowContext(ctx, `
INSERT INTO sable_dhcp_lease_seqs (node_id, seq) VALUES (`+store.placeholders(2)+`)
ON CONFLICT (node_id) DO UPDATE SET seq = sable_dhcp_lease_seqs.seq + 1
RETURNING seq`, nodeID, 1).Scan(&seq); err != nil {
		return 0, fmt.Errorf("next DHCP lease sequence: %w", err)
	}
	return seq, nil
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

// dhcpLeaseWrite is what a write does to a stored row for the same address.
type dhcpLeaseWrite int

const (
	// dhcpLeaseReplace always replaces it: this node's own new write.
	dhcpLeaseReplace dhcpLeaseWrite = iota
	// dhcpLeaseIfNewer replaces it only when its seq is lower: a mirror.
	dhcpLeaseIfNewer
	// dhcpLeaseIfBoundLater replaces it only when the row was bound later,
	// or bound at the same moment and ends sooner: this node's rows
	// recovered from a mirror. What it wrote since a wipe was bound after
	// anything the mirror holds and stays; a row put back from an older copy
	// was bound before what the mirror saw since and goes (the row bound
	// last is the record for an address). A release keeps the bound time and
	// only ever brings the end forward (RFC 2131 §4.3.4), so at the same
	// bound time the row that ends sooner is the later one. Seqs can't break
	// the tie: a wiped node's counter starts over.
	dhcpLeaseIfBoundLater
)

// upsertDHCPLease writes a lease under its own sequence number, treating a
// stored row for the address as write says, and returns whether it wrote.
func (store *Store) upsertDHCPLease(ctx context.Context, transaction *sql.Tx, lease DHCPLease, write dhcpLeaseWrite) (bool, error) {
	conflict := `DO UPDATE SET
    scope_id = excluded.scope_id, client_key = excluded.client_key, mac = excluded.mac,
    client_id = excluded.client_id, hostname = excluded.hostname, label = excluded.label,
    state = excluded.state, bound_at_ns = excluded.bound_at_ns, expires_at_ns = excluded.expires_at_ns,
    seq = excluded.seq, relay = excluded.relay, vendor_class = excluded.vendor_class`
	switch write {
	case dhcpLeaseIfNewer:
		conflict += "\nWHERE sable_dhcp_leases.seq < excluded.seq"
	case dhcpLeaseIfBoundLater:
		conflict += "\nWHERE sable_dhcp_leases.bound_at_ns < excluded.bound_at_ns" +
			"\n   OR (sable_dhcp_leases.bound_at_ns = excluded.bound_at_ns AND sable_dhcp_leases.expires_at_ns > excluded.expires_at_ns)"
	}
	result, err := transaction.ExecContext(ctx, `
INSERT INTO sable_dhcp_leases (`+dhcpLeaseColumns+`)
VALUES (`+store.placeholders(14)+`)
ON CONFLICT (node_id, address) `+conflict,
		lease.NodeID, lease.Address.String(), lease.ScopeID, lease.ClientKey, lease.MAC, lease.ClientID,
		lease.Hostname, lease.Label, string(lease.State), unixNanos(lease.BoundAt), unixNanos(lease.ExpiresAt),
		lease.Seq, lease.Relay, lease.VendorClass)
	if err != nil {
		return false, fmt.Errorf("save DHCP lease %s: %w", lease.Address, err)
	}
	rows, err := result.RowsAffected()
	return rows > 0, err
}

// MirrorDHCPLeases writes rows another node owns, each keeping the owner's
// sequence number, and returns how many it wrote. A row only replaces one
// with a lower seq, so an older or repeated row never undoes a newer one. It
// leaves this node's own counters alone.
func (store *Store) MirrorDHCPLeases(ctx context.Context, leases []DHCPLease) (int, error) {
	return store.writeSequencedDHCPLeases(ctx, leases, dhcpLeaseIfNewer)
}

// RecoverDHCPLeases writes back this node's own rows from a primary's mirror
// after its database was wiped or put back from an older copy, each keeping
// its seq, and returns how many it wrote. A row replaces a stored one for
// its address only when it was bound later: a lease written since a wipe is
// the newer truth and stays, and a row from the copy gives way to the lease
// or renewal the mirror saw after it, so the client that was told last keeps
// its address (RFC 2131 §4.3.1); a release made since, bound at the same
// moment and ending sooner, ends the copy's lease (§4.3.4). Both times are
// this node's own clock. The
// caller raises the counter past them once the recovery is done
// (RaiseDHCPLeaseSeq).
func (store *Store) RecoverDHCPLeases(ctx context.Context, leases []DHCPLease) (int, error) {
	return store.writeSequencedDHCPLeases(ctx, leases, dhcpLeaseIfBoundLater)
}

// writeSequencedDHCPLeases writes rows that carry their owner's seq in one
// transaction, as write says, and returns how many it wrote.
func (store *Store) writeSequencedDHCPLeases(ctx context.Context, leases []DHCPLease, write dhcpLeaseWrite) (int, error) {
	for _, lease := range leases {
		if err := validDHCPLease(lease); err != nil {
			return 0, err
		}
		if lease.Seq <= 0 {
			return 0, fmt.Errorf("DHCP lease %s has no sequence number", lease.Address)
		}
	}
	written := 0
	err := store.withTx(ctx, "DHCP lease mirror", func(transaction *sql.Tx) error {
		written = 0
		for _, lease := range leases {
			wrote, err := store.upsertDHCPLease(ctx, transaction, lease, write)
			if err != nil {
				return err
			}
			if wrote {
				written++
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return written, nil
}

// DHCPLeaseHeld returns, for each node whose leases the database holds, the
// highest sequence number it has: what this node has already seen of it.
func (store *Store) DHCPLeaseHeld(ctx context.Context) (map[string]int64, error) {
	rows, err := store.database.QueryContext(ctx, "SELECT node_id, MAX(seq) FROM sable_dhcp_leases GROUP BY node_id")
	if err != nil {
		return nil, fmt.Errorf("read held DHCP lease sequences: %w", err)
	}
	defer rows.Close()
	held := map[string]int64{}
	for rows.Next() {
		var nodeID string
		var seq int64
		if err := rows.Scan(&nodeID, &seq); err != nil {
			return nil, fmt.Errorf("read held DHCP lease sequences: %w", err)
		}
		held[nodeID] = seq
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read held DHCP lease sequences: %w", err)
	}
	return held, nil
}

// RaiseDHCPLeaseSeq lifts a node's sequence counter to seq when it is lower
// or missing, and then renumbers the node's rows above it in their order, so
// they reach a primary that holds older rows under higher numbers, and the
// node's next write takes the number after them. It reports whether it raised
// the counter. A node whose database was wiped or restored uses it once the
// primary shows it holds a higher sequence of that node's rows.
func (store *Store) RaiseDHCPLeaseSeq(ctx context.Context, nodeID string, seq int64) (bool, error) {
	return store.raiseDHCPLeaseSeq(ctx, nodeID, seq, true)
}

// LiftDHCPLeaseSeq lifts a node's sequence counter to seq when it is lower
// or missing and leaves its rows' numbers alone, so its next write takes the
// number after seq. It reports whether it lifted the counter. A node that has
// yet to take its own rows back from a mirror uses it: a new number on a row
// it holds from before would carry that row over the newer one the mirror
// holds for the address, before the node has asked for it.
func (store *Store) LiftDHCPLeaseSeq(ctx context.Context, nodeID string, seq int64) (bool, error) {
	return store.raiseDHCPLeaseSeq(ctx, nodeID, seq, false)
}

func (store *Store) raiseDHCPLeaseSeq(ctx context.Context, nodeID string, seq int64, renumber bool) (bool, error) {
	raised := false
	err := store.withTx(ctx, "DHCP lease sequence", func(transaction *sql.Tx) error {
		result, err := transaction.ExecContext(ctx, `
INSERT INTO sable_dhcp_lease_seqs (node_id, seq) VALUES (`+store.placeholders(2)+`)
ON CONFLICT (node_id) DO UPDATE SET seq = excluded.seq
WHERE sable_dhcp_lease_seqs.seq < excluded.seq`, nodeID, seq)
		if err != nil {
			return fmt.Errorf("raise DHCP lease sequence: %w", err)
		}
		if rows, err := result.RowsAffected(); err != nil || rows == 0 {
			return err
		}
		raised = true
		if !renumber {
			return nil
		}
		return store.renumberDHCPLeases(ctx, transaction, nodeID)
	})
	return raised, err
}

// renumberDHCPLeases gives each of a node's rows its next sequence number,
// oldest first.
func (store *Store) renumberDHCPLeases(ctx context.Context, transaction *sql.Tx, nodeID string) error {
	rows, err := transaction.QueryContext(ctx, "SELECT address FROM sable_dhcp_leases WHERE node_id = "+
		store.placeholder(1)+" ORDER BY seq", nodeID)
	if err != nil {
		return fmt.Errorf("read DHCP leases to renumber: %w", err)
	}
	var addresses []string
	for rows.Next() {
		var address string
		if err := rows.Scan(&address); err != nil {
			rows.Close()
			return fmt.Errorf("read DHCP leases to renumber: %w", err)
		}
		addresses = append(addresses, address)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("read DHCP leases to renumber: %w", err)
	}
	for _, address := range addresses {
		next, err := store.nextDHCPLeaseSeq(ctx, transaction, nodeID)
		if err != nil {
			return err
		}
		if _, err := transaction.ExecContext(ctx, "UPDATE sable_dhcp_leases SET seq = "+store.placeholder(1)+
			" WHERE node_id = "+store.placeholder(2)+" AND address = "+store.placeholder(3), next, nodeID, address); err != nil {
			return fmt.Errorf("renumber DHCP lease %s: %w", address, err)
		}
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
