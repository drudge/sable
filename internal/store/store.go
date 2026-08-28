package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
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
)`, store.queryLogTable(), store.queryLogRollupTable(), store.serverLogTable(), store.cacheTable(), `
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
	if err := store.migrateQueryLogIndexes(ctx); err != nil {
		return fmt.Errorf("migrate %s query log indexes: %w", store.driver, err)
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
		{"decision", "TEXT NOT NULL DEFAULT '{}'"},
		{"client_ip_key", "TEXT NOT NULL DEFAULT ''"},
		{"name_key", "TEXT NOT NULL DEFAULT ''"},
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
	if _, err := store.database.ExecContext(ctx, `
UPDATE sable_query_log
SET client_ip_key = LOWER(client_ip), name_key = RTRIM(LOWER(name), '.')
WHERE client_ip_key = '' OR name_key = ''`); err != nil {
		return fmt.Errorf("backfill query log search keys: %w", err)
	}
	return nil
}

func (store *Store) migrateQueryLogIndexes(ctx context.Context) error {
	for _, statement := range []string{`
CREATE INDEX IF NOT EXISTS sable_query_log_client_key_idx
ON sable_query_log (client_ip_key, id DESC)`, `
CREATE INDEX IF NOT EXISTS sable_query_log_name_key_idx
ON sable_query_log (name_key, id DESC)`, `
CREATE INDEX IF NOT EXISTS sable_query_log_rollup_bucket_idx
ON sable_query_log_rollup (bucket_start)`} {
		if _, err := store.database.ExecContext(ctx, statement); err != nil {
			return err
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
		decision, err := json.Marshal(event.Decision)
		if err != nil {
			_ = transaction.Rollback()
			return fmt.Errorf("encode query decision: %w", err)
		}
		if _, err := statement.ExecContext(
			ctx,
			event.OccurredAt.UTC(),
			event.ClientIP,
			queryLogClientKey(event.ClientIP),
			event.Name,
			queryLogDomainKey(event.Name),
			event.RecordType,
			event.Class,
			event.ResponseCode,
			event.Source,
			event.Protocol,
			event.Answer,
			string(decision),
			event.Duration.Microseconds(),
		); err != nil {
			_ = transaction.Rollback()
			return fmt.Errorf("insert query log event: %w", err)
		}
	}
	if err := store.writeQueryLogRollups(ctx, transaction, events); err != nil {
		_ = transaction.Rollback()
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit query log batch: %w", err)
	}
	return nil
}

func (store *Store) PruneQueryEvents(ctx context.Context, before time.Time) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin query log prune: %w", err)
	}
	placeholder := store.placeholder(1)
	if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_query_log WHERE occurred_at < "+placeholder, before.UTC()); err != nil {
		_ = transaction.Rollback()
		return fmt.Errorf("prune query log: %w", err)
	}
	// Drop the cutoff minute as well because its aggregate can include rows
	// from before the exact cutoff. Surviving rows in that partial minute remain
	// available through the raw log boundary query.
	if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_query_log_rollup WHERE bucket_start <= "+placeholder, before.UTC().Truncate(time.Minute)); err != nil {
		_ = transaction.Rollback()
		return fmt.Errorf("prune query log rollups: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit query log prune: %w", err)
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
SELECT id, occurred_at, client_ip, name, record_type, class, response_code, source, protocol, answer, decision, duration_us
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
		var decision string
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
			&decision,
			&durationMicroseconds,
		); err != nil {
			return nil, fmt.Errorf("scan recent query event: %w", err)
		}
		entry.Source = querylog.Source(source)
		if err := json.Unmarshal([]byte(decision), &entry.Decision); err != nil {
			return nil, fmt.Errorf("decode recent query decision: %w", err)
		}
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
		if filter.Exact {
			addCondition("client_ip_key", "=", queryLogClientKey(value))
		} else {
			addCondition("client_ip_key", "LIKE", "%"+queryLogClientKey(value)+"%")
		}
	}
	if value := strings.TrimSpace(filter.Name); value != "" {
		if filter.Exact {
			addCondition(queryLogDomainExpression, "=", queryLogDomainKey(value))
		} else {
			addCondition(queryLogDomainExpression, "LIKE", "%"+queryLogDomainKey(value)+"%")
		}
	}
	if !filter.Since.IsZero() {
		addCondition("occurred_at", ">=", filter.Since.UTC())
	}
	if !filter.Until.IsZero() {
		addCondition("occurred_at", "<=", filter.Until.UTC())
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
	total := filter.KnownTotal
	countConditions := append([]string(nil), conditions...)
	countArguments := append([]any(nil), arguments...)
	if filter.Incremental {
		countArguments = append(countArguments, filter.AfterID)
		countConditions = append(countConditions, "id > "+store.placeholder(len(countArguments)))
	}
	if !filter.UseKnownTotal || filter.Incremental {
		countWhere := queryLogWhere(countConditions)
		var counted int
		if err := store.database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sable_query_log"+countWhere, countArguments...).Scan(&counted); err != nil {
			return querylog.Page{}, fmt.Errorf("count query events: %w", err)
		}
		if filter.Incremental {
			total += counted
		} else {
			total = counted
		}
	}
	totalPages := 0
	if total > 0 {
		totalPages = (total + filter.PageSize - 1) / filter.PageSize
		filter.Page = min(filter.Page, totalPages)
	}

	selectConditions := append([]string(nil), conditions...)
	selectArguments := append([]any(nil), arguments...)
	order := "DESC"
	useOffset := false
	switch filter.Direction {
	case "older":
		if filter.Cursor > 0 {
			selectArguments = append(selectArguments, filter.Cursor)
			selectConditions = append(selectConditions, "id < "+store.placeholder(len(selectArguments)))
		}
	case "newer":
		if filter.Cursor > 0 {
			selectArguments = append(selectArguments, filter.Cursor)
			selectConditions = append(selectConditions, "id > "+store.placeholder(len(selectArguments)))
			order = "ASC"
		}
	case "oldest":
		order = "ASC"
	default:
		useOffset = filter.Page > 1
	}
	selectWhere := queryLogWhere(selectConditions)
	selectionLimit := filter.PageSize
	if filter.Direction == "oldest" && total%filter.PageSize != 0 {
		selectionLimit = total % filter.PageSize
	}
	selectArguments = append(selectArguments, selectionLimit)
	query := `
	SELECT id, occurred_at, client_ip, name, record_type, class, response_code, source, protocol, answer, decision, duration_us
	FROM sable_query_log` + selectWhere + `
	ORDER BY id ` + order + `
	LIMIT ` + store.placeholder(len(selectArguments))
	if useOffset {
		selectArguments = append(selectArguments, (filter.Page-1)*filter.PageSize)
		query += ` OFFSET ` + store.placeholder(len(selectArguments))
	}
	rows, err := store.database.QueryContext(ctx, query, selectArguments...)
	if err != nil {
		return querylog.Page{}, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()
	entries, err := scanQueryEvents(rows, selectionLimit)
	if err != nil {
		return querylog.Page{}, err
	}
	if order == "ASC" {
		slices.Reverse(entries)
	}
	return querylog.Page{
		Entries: entries, Page: filter.Page, PageSize: filter.PageSize,
		TotalEntries: total, TotalPages: totalPages,
	}, nil
}

func queryLogWhere(conditions []string) string {
	if len(conditions) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(conditions, " AND ")
}

func scanQueryEvents(rows *sql.Rows, capacity int) ([]querylog.Entry, error) {
	entries := make([]querylog.Entry, 0, capacity)
	for rows.Next() {
		var entry querylog.Entry
		var source string
		var decision string
		var durationMicroseconds int64
		if err := rows.Scan(
			&entry.ID, &entry.OccurredAt, &entry.ClientIP, &entry.Name,
			&entry.RecordType, &entry.Class, &entry.ResponseCode, &source, &entry.Protocol, &entry.Answer, &decision, &durationMicroseconds,
		); err != nil {
			return nil, fmt.Errorf("scan query event: %w", err)
		}
		entry.Source = querylog.Source(source)
		if err := json.Unmarshal([]byte(decision), &entry.Decision); err != nil {
			return nil, fmt.Errorf("decode query decision: %w", err)
		}
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
	client_ip_key TEXT NOT NULL DEFAULT '',
	name TEXT NOT NULL,
	name_key TEXT NOT NULL DEFAULT '',
    record_type INTEGER NOT NULL,
    class INTEGER NOT NULL,
    response_code INTEGER NOT NULL,
    source TEXT NOT NULL,
	protocol TEXT NOT NULL DEFAULT '',
	answer TEXT NOT NULL DEFAULT '',
	decision TEXT NOT NULL DEFAULT '{}',
    duration_us BIGINT NOT NULL
)`, primaryKey)
}

func (store *Store) queryLogInsert() string {
	if store.driver == "postgres" {
		return `INSERT INTO sable_query_log
(occurred_at, client_ip, client_ip_key, name, name_key, record_type, class, response_code, source, protocol, answer, decision, duration_us)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	}
	return `INSERT INTO sable_query_log
(occurred_at, client_ip, client_ip_key, name, name_key, record_type, class, response_code, source, protocol, answer, decision, duration_us)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
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
