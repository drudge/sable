package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/drudge/sable/internal/querylog"
)

type Store struct {
	database *sql.DB
	driver   string
}

const maximumRecentQueryEvents = 1_000

func Open(ctx context.Context, driver, dsn string) (*Store, error) {
	databaseDriver, err := databaseDriverName(driver)
	if err != nil {
		return nil, err
	}
	if driver == "sqlite" {
		if err := prepareSQLitePath(dsn); err != nil {
			return nil, err
		}
		dsn = sqliteDSN(dsn)
	}
	database, err := sql.Open(databaseDriver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", driver, err)
	}
	store := &Store{database: database, driver: driver}
	if err := database.PingContext(ctx); err != nil {
		database.Close()
		return nil, fmt.Errorf("ping %s database: %w", driver, err)
	}
	if err := store.migrate(ctx); err != nil {
		database.Close()
		return nil, err
	}
	return store, nil
}

func (store *Store) Close() error {
	return store.database.Close()
}

func (store *Store) Driver() string {
	return store.driver
}

// sqlitePragmas are the settings every connection to the database needs. Only
// journal_mode is a property of the file; busy_timeout and foreign_keys belong
// to a connection and start at their defaults on each new one.
var sqlitePragmas = [][2]string{
	{"journal_mode", "WAL"},
	{"busy_timeout", "5000"},
	{"foreign_keys", "1"},
}

// sqliteDSN carries the pragmas on the connection string. Running them once
// against the pool only reaches whichever connection happened to serve them,
// and database/sql opens more on demand: those arrived with busy_timeout at
// zero, so a writer that met another writer failed immediately with
// SQLITE_BUSY instead of waiting for the lock, and foreign keys went
// unenforced. The driver applies DSN pragmas to every connection it opens.
// Anything the operator configured already wins, under either the _pragma form
// or the driver's shorthand keys.
func sqliteDSN(dsn string) string {
	query := ""
	if separator := strings.IndexByte(dsn, '?'); separator >= 0 {
		query = dsn[separator+1:]
	}
	configured, err := url.ParseQuery(query)
	if err != nil {
		configured = nil
	}
	settings := make([]string, 0, len(sqlitePragmas))
	for _, pragma := range sqlitePragmas {
		if sqlitePragmaConfigured(configured, pragma[0]) {
			continue
		}
		settings = append(settings, "_pragma="+url.QueryEscape(pragma[0]+"("+pragma[1]+")"))
	}
	if len(settings) == 0 {
		return dsn
	}
	if query != "" {
		return dsn + "&" + strings.Join(settings, "&")
	}
	return dsn + "?" + strings.Join(settings, "&")
}

// sqlitePragmaShorthand maps a pragma to the driver's mattn-compatible keys for
// it, so a DSN that sets one of those is left alone.
var sqlitePragmaShorthand = map[string][]string{
	"journal_mode": {"_journal_mode", "_journal"},
	"busy_timeout": {"_busy_timeout", "_timeout"},
	"foreign_keys": {"_foreign_keys", "_fk"},
}

func sqlitePragmaConfigured(configured url.Values, name string) bool {
	for _, key := range sqlitePragmaShorthand[name] {
		if configured.Has(key) {
			return true
		}
	}
	for _, pragma := range configured["_pragma"] {
		setting, _, _ := strings.Cut(pragma, "(")
		setting, _, _ = strings.Cut(setting, "=")
		if strings.EqualFold(strings.TrimSpace(setting), name) {
			return true
		}
	}
	return false
}

func (store *Store) migrate(ctx context.Context) error {
	statements := []string{`
CREATE TABLE IF NOT EXISTS sable_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
)`, store.queryLogTable(), store.serverLogTable(), store.cacheTable(), `
CREATE INDEX IF NOT EXISTS sable_query_log_occurred_at_idx
ON sable_query_log (occurred_at)`, `
CREATE INDEX IF NOT EXISTS sable_server_log_occurred_at_idx
ON sable_server_log (occurred_at)`}
	statements = append(statements, queryStatsTables()...)
	statements = append(statements, store.authenticationTables()...)
	statements = append(statements, trustAnchorTables()...)
	statements = append(statements, store.zoneTables()...)
	for _, statement := range statements {
		if _, err := store.database.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate %s database: %w", store.driver, err)
		}
	}
	if err := store.migrateZoneIdentitySchema(ctx); err != nil {
		return fmt.Errorf("migrate %s database: %w", store.driver, err)
	}
	if err := store.migrateQueryLogSchema(ctx); err != nil {
		return fmt.Errorf("migrate %s database: %w", store.driver, err)
	}
	if err := store.migrateZoneRecordSchema(ctx); err != nil {
		return fmt.Errorf("migrate %s database: %w", store.driver, err)
	}
	if err := store.migrateZoneRecordSourceSchema(ctx); err != nil {
		return fmt.Errorf("migrate %s database: %w", store.driver, err)
	}
	if err := store.migrateZoneValidationSchema(ctx); err != nil {
		return fmt.Errorf("migrate %s database: %w", store.driver, err)
	}
	if err := store.migrateZoneAliasSchema(ctx); err != nil {
		return fmt.Errorf("migrate %s database: %w", store.driver, err)
	}
	if err := store.migrateZoneCatalogSchema(ctx); err != nil {
		return fmt.Errorf("migrate %s database: %w", store.driver, err)
	}
	if err := store.migrateAuthenticationSchema(ctx); err != nil {
		return fmt.Errorf("migrate %s database: %w", store.driver, err)
	}
	if err := store.seedAuthorization(ctx); err != nil {
		return fmt.Errorf("migrate %s database: %w", store.driver, err)
	}
	return nil
}

func (store *Store) migrateQueryLogSchema(ctx context.Context) error {
	for _, column := range []struct{ name, definition string }{
		{"protocol", "TEXT NOT NULL DEFAULT ''"},
		{"answer", "TEXT NOT NULL DEFAULT ''"},
	} {
		exists, err := store.tableHasColumn(ctx, "sable_query_log", column.name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := store.database.ExecContext(ctx, "ALTER TABLE sable_query_log ADD COLUMN "+column.name+" "+column.definition); err != nil {
				return fmt.Errorf("add query log %s: %w", column.name, err)
			}
		}
	}
	return nil
}

func (store *Store) tableHasColumn(ctx context.Context, table, column string) (bool, error) {
	if store.driver == "postgres" {
		var exists bool
		err := store.database.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2
)`, table, column).Scan(&exists)
		return exists, err
	}
	rows, err := store.database.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return false, fmt.Errorf("inspect %s columns: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var columnID, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&columnID, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, fmt.Errorf("scan %s column: %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (store *Store) WriteQueryEvents(ctx context.Context, events []querylog.Event) error {
	if len(events) == 0 {
		return nil
	}
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin query log batch: %w", err)
	}
	statement, err := transaction.PrepareContext(ctx, store.queryLogInsert())
	if err != nil {
		_ = transaction.Rollback()
		return fmt.Errorf("prepare query log insert: %w", err)
	}
	defer statement.Close()
	for _, event := range events {
		if _, err := statement.ExecContext(
			ctx,
			event.OccurredAt.UTC(),
			event.ClientIP,
			event.Name,
			event.RecordType,
			event.Class,
			event.ResponseCode,
			event.Source,
			event.Protocol,
			event.Answer,
			event.Duration.Microseconds(),
		); err != nil {
			_ = transaction.Rollback()
			return fmt.Errorf("insert query log event: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit query log batch: %w", err)
	}
	return nil
}

func (store *Store) PruneQueryEvents(ctx context.Context, before time.Time) error {
	placeholder := "?"
	if store.driver == "postgres" {
		placeholder = "$1"
	}
	if _, err := store.database.ExecContext(
		ctx,
		"DELETE FROM sable_query_log WHERE occurred_at < "+placeholder,
		before.UTC(),
	); err != nil {
		return fmt.Errorf("prune query log: %w", err)
	}
	return nil
}

func (store *Store) RecentQueryEvents(ctx context.Context, limit int) ([]querylog.Entry, error) {
	if limit <= 0 {
		return []querylog.Entry{}, nil
	}
	limit = min(limit, maximumRecentQueryEvents)
	placeholder := "?"
	if store.driver == "postgres" {
		placeholder = "$1"
	}
	rows, err := store.database.QueryContext(ctx, `
SELECT id, occurred_at, client_ip, name, record_type, class, response_code, source, protocol, answer, duration_us
FROM sable_query_log
ORDER BY id DESC
LIMIT `+placeholder, limit)
	if err != nil {
		return nil, fmt.Errorf("read recent query events: %w", err)
	}
	defer rows.Close()
	entries := make([]querylog.Entry, 0, limit)
	for rows.Next() {
		var entry querylog.Entry
		var source string
		var durationMicroseconds int64
		if err := rows.Scan(
			&entry.ID,
			&entry.OccurredAt,
			&entry.ClientIP,
			&entry.Name,
			&entry.RecordType,
			&entry.Class,
			&entry.ResponseCode,
			&source,
			&entry.Protocol,
			&entry.Answer,
			&durationMicroseconds,
		); err != nil {
			return nil, fmt.Errorf("scan recent query event: %w", err)
		}
		entry.Source = querylog.Source(source)
		entry.Duration = time.Duration(durationMicroseconds) * time.Microsecond
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate recent query events: %w", err)
	}
	return entries, nil
}

func (store *Store) QueryEvents(ctx context.Context, filter querylog.Filter) (querylog.Page, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PageSize < 1 {
		filter.PageSize = 50
	}
	filter.PageSize = min(filter.PageSize, 250)

	conditions := make([]string, 0, 5)
	arguments := make([]any, 0, 7)
	addCondition := func(column, operator string, value any) {
		arguments = append(arguments, value)
		conditions = append(conditions, column+" "+operator+" "+store.placeholder(len(arguments)))
	}
	if value := strings.TrimSpace(filter.ClientIP); value != "" {
		addCondition("LOWER(client_ip)", "LIKE", "%"+strings.ToLower(value)+"%")
	}
	if value := strings.TrimSpace(filter.Name); value != "" {
		addCondition("LOWER(name)", "LIKE", "%"+strings.ToLower(value)+"%")
	}
	if len(filter.RecordTypes) > 0 {
		placeholders := make([]string, 0, len(filter.RecordTypes))
		for _, recordType := range filter.RecordTypes {
			arguments = append(arguments, recordType)
			placeholders = append(placeholders, store.placeholder(len(arguments)))
		}
		conditions = append(conditions, "record_type IN ("+strings.Join(placeholders, ", ")+")")
	}
	if filter.ResponseCode != nil {
		addCondition("response_code", "=", *filter.ResponseCode)
	}
	if filter.Source != "" {
		addCondition("source", "=", filter.Source)
	}
	if filter.Protocol != "" {
		addCondition("protocol", "=", strings.ToUpper(filter.Protocol))
	}
	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}

	var total int
	if err := store.database.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM sable_query_log"+where,
		arguments...,
	).Scan(&total); err != nil {
		return querylog.Page{}, fmt.Errorf("count query events: %w", err)
	}
	totalPages := 0
	if total > 0 {
		totalPages = (total + filter.PageSize - 1) / filter.PageSize
		filter.Page = min(filter.Page, totalPages)
	}

	selectArguments := append([]any(nil), arguments...)
	selectArguments = append(selectArguments, filter.PageSize, (filter.Page-1)*filter.PageSize)
	rows, err := store.database.QueryContext(ctx, `
SELECT id, occurred_at, client_ip, name, record_type, class, response_code, source, protocol, answer, duration_us
FROM sable_query_log`+where+`
ORDER BY id DESC
LIMIT `+store.placeholder(len(selectArguments)-1)+` OFFSET `+store.placeholder(len(selectArguments)), selectArguments...)
	if err != nil {
		return querylog.Page{}, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()
	entries, err := scanQueryEvents(rows, filter.PageSize)
	if err != nil {
		return querylog.Page{}, err
	}
	return querylog.Page{
		Entries: entries, Page: filter.Page, PageSize: filter.PageSize,
		TotalEntries: total, TotalPages: totalPages,
	}, nil
}

func scanQueryEvents(rows *sql.Rows, capacity int) ([]querylog.Entry, error) {
	entries := make([]querylog.Entry, 0, capacity)
	for rows.Next() {
		var entry querylog.Entry
		var source string
		var durationMicroseconds int64
		if err := rows.Scan(
			&entry.ID, &entry.OccurredAt, &entry.ClientIP, &entry.Name,
			&entry.RecordType, &entry.Class, &entry.ResponseCode, &source, &entry.Protocol, &entry.Answer, &durationMicroseconds,
		); err != nil {
			return nil, fmt.Errorf("scan query event: %w", err)
		}
		entry.Source = querylog.Source(source)
		entry.Duration = time.Duration(durationMicroseconds) * time.Microsecond
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate query events: %w", err)
	}
	return entries, nil
}

func (store *Store) queryLogTable() string {
	primaryKey := "INTEGER PRIMARY KEY AUTOINCREMENT"
	if store.driver == "postgres" {
		primaryKey = "BIGSERIAL PRIMARY KEY"
	}
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS sable_query_log (
    id %s,
    occurred_at TIMESTAMP NOT NULL,
    client_ip TEXT NOT NULL,
    name TEXT NOT NULL,
    record_type INTEGER NOT NULL,
    class INTEGER NOT NULL,
    response_code INTEGER NOT NULL,
    source TEXT NOT NULL,
	protocol TEXT NOT NULL DEFAULT '',
	answer TEXT NOT NULL DEFAULT '',
    duration_us BIGINT NOT NULL
)`, primaryKey)
}

func (store *Store) queryLogInsert() string {
	if store.driver == "postgres" {
		return `INSERT INTO sable_query_log
(occurred_at, client_ip, name, record_type, class, response_code, source, protocol, answer, duration_us)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	}
	return `INSERT INTO sable_query_log
(occurred_at, client_ip, name, record_type, class, response_code, source, protocol, answer, duration_us)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
}

func databaseDriverName(driver string) (string, error) {
	switch driver {
	case "sqlite":
		return "sqlite", nil
	case "postgres":
		return "pgx", nil
	default:
		return "", fmt.Errorf("unsupported database driver %q", driver)
	}
}

func prepareSQLitePath(dsn string) error {
	if dsn == ":memory:" || strings.HasPrefix(dsn, "file:") {
		return nil
	}
	directory := filepath.Dir(dsn)
	if directory == "." {
		return nil
	}
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return fmt.Errorf("create SQLite directory: %w", err)
	}
	return nil
}

func IsBackendChange(activeDriver, activeDSN, candidateDriver, candidateDSN string) error {
	if activeDriver == candidateDriver && activeDSN == candidateDSN {
		return nil
	}
	return errors.New("database driver and DSN changes require a controlled restart")
}
