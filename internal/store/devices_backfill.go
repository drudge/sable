package store

import (
	"context"
	"fmt"
	"time"
)

// clientSeenBackfilledKey records that first- and last-seen spans were filled
// in from the query history that predates tracking.
const clientSeenBackfilledKey = "query_log_client_seen_backfilled"

// BackfillClientSightings fills first- and last-seen spans from query history
// written before sighting tracking began, then moves the tracking marker back
// to the oldest query, so Insights knows who was already on the network from
// the first day instead of treating everything as new. It runs once per
// database, in the background, and never on the DNS request path.
func (store *Store) BackfillClientSightings(ctx context.Context) (bool, error) {
	if _, done, err := store.rollupMarker(ctx, clientSeenBackfilledKey); err != nil || done {
		return false, err
	}
	since, found, err := store.rollupMarker(ctx, clientSeenSinceKey)
	if err != nil || !found {
		return false, err
	}
	var raw any
	if err := store.database.QueryRowContext(ctx,
		"SELECT MIN(occurred_at) FROM sable_query_log WHERE client_ip_key <> '' AND occurred_at < "+store.placeholder(1), since.UTC(),
	).Scan(&raw); err != nil {
		return false, fmt.Errorf("find oldest query: %w", err)
	}
	var oldest time.Time
	if raw != nil {
		if oldest, err = databaseTime(raw); err != nil {
			return false, fmt.Errorf("read oldest query time: %w", err)
		}
	}

	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = transaction.Rollback() }()
	if !oldest.IsZero() {
		for _, fill := range []struct{ table, keys, groups string }{
			{"sable_client_seen", "client_key", "client_ip_key"},
			{"sable_client_domain_seen", "client_key, name_key", "client_ip_key, name_key"},
		} {
			// The WHERE clause also settles SQLite's parse of an upsert fed by a
			// SELECT, which otherwise reads ON CONFLICT as a join constraint.
			statement := "INSERT INTO " + fill.table + " (" + fill.keys + ", first_seen, last_seen) " +
				"SELECT " + fill.groups + ", MIN(occurred_at), MAX(occurred_at) FROM sable_query_log " +
				"WHERE client_ip_key <> '' AND occurred_at < " + store.placeholder(1) + " GROUP BY " + fill.groups +
				" ON CONFLICT (" + fill.keys + ") DO UPDATE SET " +
				"first_seen = CASE WHEN excluded.first_seen < " + fill.table + ".first_seen THEN excluded.first_seen ELSE " + fill.table + ".first_seen END, " +
				"last_seen = CASE WHEN excluded.last_seen > " + fill.table + ".last_seen THEN excluded.last_seen ELSE " + fill.table + ".last_seen END"
			if _, err := transaction.ExecContext(ctx, statement, since.UTC()); err != nil {
				return false, fmt.Errorf("backfill %s: %w", fill.table, err)
			}
		}
		if _, err := transaction.ExecContext(ctx,
			"UPDATE sable_metadata SET value = "+store.placeholder(1)+" WHERE key = "+store.placeholder(2),
			oldest.UTC().Format(time.RFC3339Nano), clientSeenSinceKey,
		); err != nil {
			return false, fmt.Errorf("move %s: %w", clientSeenSinceKey, err)
		}
	}
	if _, err := transaction.ExecContext(ctx,
		"INSERT INTO sable_metadata (key, value) VALUES ("+store.placeholders(2)+") ON CONFLICT(key) DO NOTHING",
		clientSeenBackfilledKey, time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return false, fmt.Errorf("record %s: %w", clientSeenBackfilledKey, err)
	}
	if err := transaction.Commit(); err != nil {
		return false, err
	}
	return !oldest.IsZero(), nil
}
