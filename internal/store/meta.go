package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// metadataExecutor is what the sable_metadata helpers run on: the database
// itself or a transaction.
type metadataExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// getMeta reads one sable_metadata value. A missing key is not an error; it
// reports found as false. Errors are returned as they are, for the caller to
// wrap with what it was reading.
func (store *Store) getMeta(ctx context.Context, executor metadataExecutor, key string) (string, bool, error) {
	var value string
	err := executor.QueryRowContext(ctx,
		"SELECT value FROM sable_metadata WHERE key = "+store.placeholder(1), key,
	).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// setMeta writes a sable_metadata value, replacing any value already there.
func (store *Store) setMeta(ctx context.Context, executor metadataExecutor, key, value string) error {
	_, err := executor.ExecContext(ctx,
		"INSERT INTO sable_metadata (key, value) VALUES ("+store.placeholders(2)+") ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value,
	)
	return err
}

// setMetaIfAbsent writes a sable_metadata value only when the key has none,
// and reports whether it wrote one.
func (store *Store) setMetaIfAbsent(ctx context.Context, executor metadataExecutor, key, value string) (bool, error) {
	result, err := executor.ExecContext(ctx,
		"INSERT INTO sable_metadata (key, value) VALUES ("+store.placeholders(2)+") ON CONFLICT(key) DO NOTHING",
		key, value,
	)
	if err != nil {
		return false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return inserted > 0, nil
}

// updateMeta changes a sable_metadata value only when the key already has
// one. A marker that was never recorded stays unrecorded.
func (store *Store) updateMeta(ctx context.Context, executor metadataExecutor, key, value string) error {
	_, err := executor.ExecContext(ctx,
		"UPDATE sable_metadata SET value = "+store.placeholder(1)+" WHERE key = "+store.placeholder(2),
		value, key,
	)
	return err
}

// deleteMeta removes a sable_metadata value.
func (store *Store) deleteMeta(ctx context.Context, executor metadataExecutor, key string) error {
	_, err := executor.ExecContext(ctx, "DELETE FROM sable_metadata WHERE key = "+store.placeholder(1), key)
	return err
}

// metaTime formats a moment the way every time-valued marker is stored.
func metaTime(moment time.Time) string {
	return moment.UTC().Format(time.RFC3339Nano)
}
