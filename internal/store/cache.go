package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// CachedResponse contains DNS wire data and absolute lifetimes. Cache rows are
// replaced only during controlled shutdown and read only during startup.
type CachedResponse struct {
	RequestWire  []byte
	ResponseWire []byte
	StoredAt     time.Time
	ExpiresAt    time.Time
	StaleUntil   time.Time
}

func (store *Store) cacheTable() string {
	binaryType := "BLOB"
	if store.driver == "postgres" {
		binaryType = "BYTEA"
	}
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS sable_dns_cache (
    request_wire %s PRIMARY KEY,
    response_wire %s NOT NULL,
    stored_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    stale_until TIMESTAMP
)`, binaryType, binaryType)
}

func (store *Store) CachedResponses(ctx context.Context) ([]CachedResponse, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT request_wire, response_wire, stored_at, expires_at, stale_until
FROM sable_dns_cache`)
	if err != nil {
		return nil, fmt.Errorf("read persisted DNS cache: %w", err)
	}
	defer rows.Close()
	var entries []CachedResponse
	for rows.Next() {
		var entry CachedResponse
		var staleUntil sql.NullTime
		if err := rows.Scan(&entry.RequestWire, &entry.ResponseWire, &entry.StoredAt, &entry.ExpiresAt, &staleUntil); err != nil {
			return nil, fmt.Errorf("scan persisted DNS cache: %w", err)
		}
		if staleUntil.Valid {
			entry.StaleUntil = staleUntil.Time
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate persisted DNS cache: %w", err)
	}
	return entries, nil
}

func (store *Store) ReplaceCachedResponses(ctx context.Context, entries []CachedResponse) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin DNS cache persistence: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_dns_cache"); err != nil {
		_ = transaction.Rollback()
		return fmt.Errorf("clear persisted DNS cache: %w", err)
	}
	statement := `INSERT INTO sable_dns_cache
(request_wire, response_wire, stored_at, expires_at, stale_until)
VALUES (` + store.placeholder(1) + `, ` + store.placeholder(2) + `, ` + store.placeholder(3) + `, ` + store.placeholder(4) + `, ` + store.placeholder(5) + `)`
	for _, entry := range entries {
		var staleUntil any
		if !entry.StaleUntil.IsZero() {
			staleUntil = entry.StaleUntil.UTC()
		}
		if _, err := transaction.ExecContext(
			ctx, statement, entry.RequestWire, entry.ResponseWire,
			entry.StoredAt.UTC(), entry.ExpiresAt.UTC(), staleUntil,
		); err != nil {
			_ = transaction.Rollback()
			return fmt.Errorf("persist DNS cache entry: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit DNS cache persistence: %w", err)
	}
	return nil
}
