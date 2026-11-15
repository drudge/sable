package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// A node whose lease counter starts from nothing, as after a wipe, may have
// held leases the primary still mirrors. Its counter alone can't tell it so:
// leases granted since the wipe can number as many as it held before. So the
// first number it takes opens a recovery here, and the row stays until the
// node has taken back every row the primary holds of it, in the order of
// their numbers, through seq (docs/design/dhcp.md §3, RFC 2131 §4.3.1).

// migrateDHCPLeaseRecovery is schema step 3: where a node keeps how far it
// has taken its own leases back after its counter started over.
func (store *Store) migrateDHCPLeaseRecovery(ctx context.Context) error {
	_, err := store.database.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS sable_dhcp_lease_recovery (
    node_id TEXT PRIMARY KEY,
    seq BIGINT NOT NULL
)`)
	return err
}

// openDHCPLeaseRecovery opens a recovery for a node whose counter just
// took its first number.
func (store *Store) openDHCPLeaseRecovery(ctx context.Context, transaction *sql.Tx, nodeID string) error {
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_dhcp_lease_recovery (node_id, seq) VALUES (`+store.placeholders(2)+`)
ON CONFLICT (node_id) DO NOTHING`, nodeID, 0); err != nil {
		return fmt.Errorf("open DHCP lease recovery: %w", err)
	}
	return nil
}

// OpenDHCPLeaseRecoveryBelow opens a recovery for a node whose counter is
// below seq, or missing: another node holds leases of it under numbers it
// has never taken, so it lost them. A primary uses it before it raises its
// counter to what a replica holds of it, since a counter raised first takes
// no first number to open one. It reports whether the counter was behind.
func (store *Store) OpenDHCPLeaseRecoveryBelow(ctx context.Context, nodeID string, seq int64) (bool, error) {
	behind := false
	err := store.withTx(ctx, "DHCP lease recovery", func(transaction *sql.Tx) error {
		var counter int64
		err := transaction.QueryRowContext(ctx,
			"SELECT seq FROM sable_dhcp_lease_seqs WHERE node_id = "+store.placeholders(1), nodeID).Scan(&counter)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read DHCP lease sequence: %w", err)
		}
		if counter >= seq {
			return nil
		}
		behind = true
		return store.openDHCPLeaseRecovery(ctx, transaction, nodeID)
	})
	return behind, err
}

// DHCPLeaseRecovery reports whether a node is taking its own leases back,
// and through which number it has so far.
func (store *Store) DHCPLeaseRecovery(ctx context.Context, nodeID string) (int64, bool, error) {
	var seq int64
	err := store.database.QueryRowContext(ctx,
		"SELECT seq FROM sable_dhcp_lease_recovery WHERE node_id = "+store.placeholders(1), nodeID).Scan(&seq)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("read DHCP lease recovery: %w", err)
	}
	return seq, true, nil
}

// AdvanceDHCPLeaseRecovery notes that a node has taken its leases back
// through seq, or, when done, ends its recovery. It never moves an open
// recovery back, and never opens one.
func (store *Store) AdvanceDHCPLeaseRecovery(ctx context.Context, nodeID string, seq int64, done bool) error {
	statement := "UPDATE sable_dhcp_lease_recovery SET seq = " + store.placeholder(1) +
		" WHERE node_id = " + store.placeholder(2) + " AND seq < " + store.placeholder(3)
	arguments := []any{seq, nodeID, seq}
	if done {
		statement, arguments = "DELETE FROM sable_dhcp_lease_recovery WHERE node_id = "+store.placeholders(1), []any{nodeID}
	}
	if _, err := store.database.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("advance DHCP lease recovery: %w", err)
	}
	return nil
}
