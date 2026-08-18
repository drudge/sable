package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/drudge/sable/internal/serverlog"
)

const maximumServerLogPageSize = 250

func (store *Store) serverLogTable() string {
	primaryKey := "INTEGER PRIMARY KEY AUTOINCREMENT"
	if store.driver == "postgres" {
		primaryKey = "BIGSERIAL PRIMARY KEY"
	}
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS sable_server_log (
    id %s,
    occurred_at TIMESTAMP NOT NULL,
    level INTEGER NOT NULL,
    message TEXT NOT NULL,
    attributes TEXT NOT NULL DEFAULT ''
)`, primaryKey)
}

func (store *Store) WriteServerLogEntries(ctx context.Context, entries []serverlog.Entry) error {
	if len(entries) == 0 {
		return nil
	}
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin server log batch: %w", err)
	}
	statement, err := transaction.PrepareContext(ctx, store.serverLogInsert())
	if err != nil {
		_ = transaction.Rollback()
		return fmt.Errorf("prepare server log insert: %w", err)
	}
	defer statement.Close()
	for _, entry := range entries {
		if _, err := statement.ExecContext(
			ctx,
			entry.OccurredAt.UTC(),
			int64(entry.Level),
			entry.Message,
			encodeServerLogAttributes(entry.Attributes),
		); err != nil {
			_ = transaction.Rollback()
			return fmt.Errorf("insert server log entry: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit server log batch: %w", err)
	}
	return nil
}

func (store *Store) PruneServerLogEntries(ctx context.Context, before time.Time) error {
	if _, err := store.database.ExecContext(
		ctx,
		"DELETE FROM sable_server_log WHERE occurred_at < "+store.placeholder(1),
		before.UTC(),
	); err != nil {
		return fmt.Errorf("prune server log: %w", err)
	}
	return nil
}

// ServerLogEntries browses persisted runtime logs newest first.
func (store *Store) ServerLogEntries(ctx context.Context, query serverlog.Query) (serverlog.Page, error) {
	if query.Page < 1 {
		query.Page = 1
	}
	if query.PageSize < 1 {
		query.PageSize = 50
	}
	query.PageSize = min(query.PageSize, maximumServerLogPageSize)

	conditions := make([]string, 0, 4)
	arguments := make([]any, 0, 6)
	addCondition := func(clause string, values ...any) {
		arguments = append(arguments, values...)
		conditions = append(conditions, clause)
	}
	low, high := serverLogLevelBounds(query.Level)
	if low != nil {
		addCondition("level >= "+store.placeholder(len(arguments)+1), *low)
	}
	if high != nil {
		addCondition("level < "+store.placeholder(len(arguments)+1), *high)
	}
	// The message and the flattened attributes are searched together so the
	// persisted view answers the same query the live buffer does, where a
	// search matches an attribute key or value as readily as the message.
	if value := strings.TrimSpace(query.Search); value != "" {
		pattern := "%" + strings.ToLower(value) + "%"
		addCondition(
			"(LOWER(message) LIKE "+store.placeholder(len(arguments)+1)+" OR LOWER(attributes) LIKE "+store.placeholder(len(arguments)+2)+")",
			pattern, pattern,
		)
	}
	if !query.Since.IsZero() {
		addCondition("occurred_at >= "+store.placeholder(len(arguments)+1), query.Since.UTC())
	}
	if !query.Until.IsZero() {
		addCondition("occurred_at <= "+store.placeholder(len(arguments)+1), query.Until.UTC())
	}
	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}

	var total int
	if err := store.database.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM sable_server_log"+where,
		arguments...,
	).Scan(&total); err != nil {
		return serverlog.Page{}, fmt.Errorf("count server log entries: %w", err)
	}
	totalPages := 0
	if total > 0 {
		totalPages = (total + query.PageSize - 1) / query.PageSize
		query.Page = min(query.Page, totalPages)
	}

	selectArguments := append([]any(nil), arguments...)
	selectArguments = append(selectArguments, query.PageSize, (query.Page-1)*query.PageSize)
	rows, err := store.database.QueryContext(ctx, `
SELECT id, occurred_at, level, message, attributes
FROM sable_server_log`+where+`
ORDER BY occurred_at DESC, id DESC
LIMIT `+store.placeholder(len(selectArguments)-1)+` OFFSET `+store.placeholder(len(selectArguments)), selectArguments...)
	if err != nil {
		return serverlog.Page{}, fmt.Errorf("read server log entries: %w", err)
	}
	defer rows.Close()
	entries, err := scanServerLogEntries(rows, query.PageSize)
	if err != nil {
		return serverlog.Page{}, err
	}
	return serverlog.Page{
		Entries: entries, Page: query.Page, PageSize: query.PageSize,
		TotalEntries: total, TotalPages: totalPages,
	}, nil
}

func scanServerLogEntries(rows *sql.Rows, capacity int) ([]serverlog.Entry, error) {
	entries := make([]serverlog.Entry, 0, capacity)
	for rows.Next() {
		var entry serverlog.Entry
		var id int64
		var level int64
		var attributes string
		if err := rows.Scan(&id, &entry.OccurredAt, &level, &entry.Message, &attributes); err != nil {
			return nil, fmt.Errorf("scan server log entry: %w", err)
		}
		entry.ID = uint64(id)
		entry.Level = slog.Level(level)
		entry.Attributes = decodeServerLogAttributes(attributes)
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate server log entries: %w", err)
	}
	return entries, nil
}

// serverLogLevelBounds turns a level name into the half-open range of slog
// levels it covers, matching how the live buffer names a level: every value at
// or above a threshold and below the next one carries that name, so a record
// logged at slog.LevelInfo+2 stays "info" in both views. A nil bound is open,
// which is how error reaches above itself and debug reaches below.
func serverLogLevelBounds(name string) (low, high *int64) {
	bound := func(level slog.Level) *int64 { value := int64(level); return &value }
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "ERROR":
		return bound(slog.LevelError), nil
	case "WARN", "WARNING":
		return bound(slog.LevelWarn), bound(slog.LevelError)
	case "INFO":
		return bound(slog.LevelInfo), bound(slog.LevelWarn)
	case "DEBUG":
		return nil, bound(slog.LevelInfo)
	default:
		return nil, nil
	}
}

func encodeServerLogAttributes(attributes map[string]string) string {
	if len(attributes) == 0 {
		return ""
	}
	encoded, err := json.Marshal(attributes)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func decodeServerLogAttributes(encoded string) map[string]string {
	if strings.TrimSpace(encoded) == "" {
		return nil
	}
	attributes := make(map[string]string)
	if err := json.Unmarshal([]byte(encoded), &attributes); err != nil {
		return nil
	}
	if len(attributes) == 0 {
		return nil
	}
	return attributes
}

func (store *Store) serverLogInsert() string {
	if store.driver == "postgres" {
		return `INSERT INTO sable_server_log
(occurred_at, level, message, attributes)
VALUES ($1, $2, $3, $4)`
	}
	return `INSERT INTO sable_server_log
(occurred_at, level, message, attributes)
VALUES (?, ?, ?, ?)`
}
