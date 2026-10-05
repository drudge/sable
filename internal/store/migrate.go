package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Schema changes are numbered steps that each run once. sable_schema_version
// records every step a database has taken, so a start whose database is
// current reads one number and changes nothing.
//
// A step runs outside a transaction, because some of what it does can't run
// inside one (CREATE INDEX CONCURRENTLY) or shouldn't (a backfill over the
// whole query log). It is recorded only once it finishes, so a step must be
// safe to run again after an interruption.
const schemaVersionTable = "sable_schema_version"

type migration struct {
	version     int
	description string
	apply       func(*Store, context.Context) error
}

// migrations are the steps in order. Add a step at the end; never renumber,
// change, or remove one that has shipped, since databases already record it.
var migrations = []migration{
	// Every database from before versioning takes this step once. It is the
	// idempotent upgrade every start used to run, so it brings any earlier
	// schema, 1.6.1's included, to the one this build expects.
	{1, "schema before versioned migrations", (*Store).migrateBaseline},
}

// queryLogBackfillChunk is how many query log IDs one backfill statement
// covers, so an upgrade never holds the log in one long statement.
const queryLogBackfillChunk = 10_000

// migrationLockPoll is how often a node waits for another to finish
// migrating a shared PostgreSQL database.
const migrationLockPoll = time.Second

func latestSchemaVersion() int {
	return migrations[len(migrations)-1].version
}

func (store *Store) migrate(ctx context.Context) error {
	current, err := store.schemaVersion(ctx)
	if err != nil {
		return fmt.Errorf("migrate %s database: %w", store.driver, err)
	}
	// A newer Sable may have taken steps this build doesn't know. Steps only
	// add, so this build runs on that schema as it is.
	if current < latestSchemaVersion() {
		if err := store.applyMigrations(ctx); err != nil {
			return fmt.Errorf("migrate %s database: %w", store.driver, err)
		}
	}
	if err := store.syncBuiltInRoles(ctx); err != nil {
		return fmt.Errorf("migrate %s database: %w", store.driver, err)
	}
	if err := store.checkQueryLogSearch(ctx); err != nil {
		return fmt.Errorf("migrate %s query log search: %w", store.driver, err)
	}
	return nil
}

func (store *Store) applyMigrations(ctx context.Context) error {
	unlock, err := store.lockMigrations(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := store.database.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS `+schemaVersionTable+` (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TIMESTAMP NOT NULL
)`); err != nil {
		return fmt.Errorf("create %s: %w", schemaVersionTable, err)
	}
	// Another node that shares the database may have taken the steps while
	// this one waited for the lock.
	current, err := store.schemaVersion(ctx)
	if err != nil {
		return err
	}
	for _, step := range migrations {
		if step.version <= current {
			continue
		}
		if err := step.apply(store, ctx); err != nil {
			return fmt.Errorf("schema step %d (%s): %w", step.version, step.description, err)
		}
		if _, err := store.database.ExecContext(ctx,
			"INSERT INTO "+schemaVersionTable+" (version, description, applied_at) VALUES ("+store.placeholders(3)+")",
			step.version, step.description, time.Now().UTC(),
		); err != nil {
			return fmt.Errorf("record schema step %d: %w", step.version, err)
		}
	}
	return nil
}

// schemaVersion is the newest step the database has taken, or zero before
// its first.
func (store *Store) schemaVersion(ctx context.Context) (int, error) {
	exists, err := store.tableExists(ctx, schemaVersionTable)
	if err != nil || !exists {
		return 0, err
	}
	var version int
	if err := store.database.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM "+schemaVersionTable).Scan(&version); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return version, nil
}

// lockMigrations keeps nodes that share a PostgreSQL database from migrating
// it at the same time. It polls for the lock instead of waiting in
// pg_advisory_lock: a session waiting there holds a snapshot, and CREATE INDEX
// CONCURRENTLY on the node that has the lock would wait for that snapshot in
// turn.
func (store *Store) lockMigrations(ctx context.Context) (func(), error) {
	if store.driver != "postgres" {
		return func() {}, nil
	}
	const key = "hashtext(current_schema() || '." + schemaVersionTable + "')"
	connection, err := store.database.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve a connection for the migration lock: %w", err)
	}
	for {
		var locked bool
		if err := connection.QueryRowContext(ctx, "SELECT pg_try_advisory_lock("+key+")").Scan(&locked); err != nil {
			connection.Close()
			return nil, fmt.Errorf("take the migration lock: %w", err)
		}
		if locked {
			break
		}
		select {
		case <-ctx.Done():
			connection.Close()
			return nil, ctx.Err()
		case <-time.After(migrationLockPoll):
		}
	}
	return func() {
		_, _ = connection.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock("+key+")")
		connection.Close()
	}, nil
}

// migrateBaseline creates every table a new database needs and upgrades one
// from any earlier Sable. Each part checks what is there before it changes
// anything, which is what lets it detect an existing database's schema.
func (store *Store) migrateBaseline(ctx context.Context) error {
	statements := []string{`
CREATE TABLE IF NOT EXISTS sable_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
)`, store.queryLogTable(), store.queryLogRollupTable(), store.serverLogTable(), store.cacheTable(), `
CREATE INDEX IF NOT EXISTS sable_server_log_occurred_at_idx
ON sable_server_log (occurred_at)`}
	statements = append(statements, queryStatsTables()...)
	statements = append(statements, rollupTierTables()...)
	statements = append(statements, clientSightingTables()...)
	statements = append(statements, unifiStationTables()...)
	statements = append(statements, insightFeedbackTable(), insightNotifiedTable(), pushSubscriptionTable())
	statements = append(statements, store.authenticationTables()...)
	statements = append(statements, passkeyTable, "CREATE INDEX IF NOT EXISTS sable_passkeys_user_idx ON sable_passkeys (user_id)")
	statements = append(statements, trustAnchorTables()...)
	statements = append(statements, store.zoneTables()...)
	for _, statement := range statements {
		if _, err := store.database.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if err := store.migrateZoneRevisionIdentity(ctx); err != nil {
		return fmt.Errorf("migrate zone revision identity: %w", err)
	}
	for _, step := range []func(*Store, context.Context) error{
		(*Store).migrateZoneIdentitySchema,
		(*Store).migrateQueryLogSchema,
		(*Store).migrateQueryLogIndexes,
		(*Store).createQueryLogSearch,
		(*Store).migrateActivityMarkers,
		(*Store).migrateZoneRecordSchema,
		(*Store).migrateZoneRecordSourceSchema,
		(*Store).migrateZoneValidationSchema,
		(*Store).migrateZoneAliasSchema,
		(*Store).migrateZoneCatalogSchema,
		(*Store).migrateAuthenticationSchema,
		(*Store).syncBuiltInRoles,
		(*Store).backfillUserAuthorization,
		(*Store).migrateClientIdentityKindSchema,
	} {
		if err := step(store, ctx); err != nil {
			return err
		}
	}
	return nil
}

// migrateClientIdentityKindSchema adds the device type a sighting's source
// suggests to databases created before sources could suggest one. The
// defaults leave every existing sighting without a suggestion.
func (store *Store) migrateClientIdentityKindSchema(ctx context.Context) error {
	for _, column := range []struct{ name, definition string }{
		{"kind", "TEXT NOT NULL DEFAULT ''"},
		{"kind_confidence", "INTEGER NOT NULL DEFAULT 0"},
		{"kind_set", "BOOLEAN NOT NULL DEFAULT FALSE"},
	} {
		exists, err := store.tableHasColumn(ctx, "sable_client_identity", column.name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := store.database.ExecContext(ctx, "ALTER TABLE sable_client_identity ADD COLUMN "+column.name+" "+column.definition); err != nil {
			return fmt.Errorf("add client identity %s: %w", column.name, err)
		}
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
	return store.backfillQueryLogKeys(ctx)
}

// backfillQueryLogKeys fills the search keys of rows written before the log
// stored them, a chunk of IDs at a time.
func (store *Store) backfillQueryLogKeys(ctx context.Context) error {
	var oldest, newest sql.NullInt64
	if err := store.database.QueryRowContext(ctx, "SELECT MIN(id), MAX(id) FROM sable_query_log").Scan(&oldest, &newest); err != nil {
		return fmt.Errorf("find the query log rows to backfill: %w", err)
	}
	statement := `
UPDATE sable_query_log
SET client_ip_key = LOWER(client_ip), name_key = RTRIM(LOWER(name), '.')
WHERE id > ` + store.placeholder(1) + ` AND id <= ` + store.placeholder(2) + `
  AND (client_ip_key = '' OR name_key = '')`
	for after := oldest.Int64 - 1; newest.Valid && after < newest.Int64; after += queryLogBackfillChunk {
		if _, err := store.database.ExecContext(ctx, statement, after, after+queryLogBackfillChunk); err != nil {
			return fmt.Errorf("backfill query log search keys: %w", err)
		}
	}
	return nil
}

func (store *Store) migrateQueryLogIndexes(ctx context.Context) error {
	for _, index := range [][2]string{
		{"sable_query_log_occurred_at_idx", "ON sable_query_log (occurred_at)"},
		{"sable_query_log_client_key_idx", "ON sable_query_log (client_ip_key, id DESC)"},
		{"sable_query_log_name_key_idx", "ON sable_query_log (name_key, id DESC)"},
	} {
		if _, err := store.createIndexConcurrently(ctx, index[0], index[1]); err != nil {
			return err
		}
	}
	// The rollup primary key already leads with bucket_start, so this index
	// only cost every batch an extra write.
	_, err := store.database.ExecContext(ctx, "DROP INDEX IF EXISTS sable_query_log_rollup_bucket_idx")
	return err
}

// createIndexConcurrently builds an index without blocking writes to its
// table, and reports whether it built one. On PostgreSQL that takes CREATE
// INDEX CONCURRENTLY, which can't run in a transaction. A build that was
// interrupted leaves an invalid index behind, which IF NOT EXISTS would keep
// forever, so that one is dropped and built again. SQLite has only one writer,
// so there it is a plain CREATE INDEX.
func (store *Store) createIndexConcurrently(ctx context.Context, name, definition string) (bool, error) {
	if store.driver != "postgres" {
		if _, err := store.database.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS "+name+" "+definition); err != nil {
			return false, fmt.Errorf("build %s: %w", name, err)
		}
		return true, nil
	}
	var valid bool
	err := store.database.QueryRowContext(ctx, `
SELECT index_state.indisvalid FROM pg_index index_state
JOIN pg_class index_class ON index_class.oid = index_state.indexrelid
WHERE index_class.relname = $1 AND index_class.relnamespace = to_regnamespace(current_schema())`, name).Scan(&valid)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return false, fmt.Errorf("inspect %s: %w", name, err)
	case valid:
		return false, nil
	default:
		if _, err := store.database.ExecContext(ctx, "DROP INDEX CONCURRENTLY IF EXISTS "+name); err != nil {
			return false, fmt.Errorf("drop unfinished %s: %w", name, err)
		}
	}
	if _, err := store.database.ExecContext(ctx, "CREATE INDEX CONCURRENTLY IF NOT EXISTS "+name+" "+definition); err != nil {
		return false, fmt.Errorf("build %s: %w", name, err)
	}
	return true, nil
}

func (store *Store) tableExists(ctx context.Context, table string) (bool, error) {
	query := "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)"
	if store.driver == "postgres" {
		query = `
SELECT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = current_schema() AND table_name = $1
)`
	}
	var exists bool
	if err := store.database.QueryRowContext(ctx, query, table).Scan(&exists); err != nil {
		return false, fmt.Errorf("inspect %s: %w", table, err)
	}
	return exists, nil
}

func (store *Store) tableHasColumn(ctx context.Context, table, column string) (bool, error) {
	found, _, err := store.tableColumn(ctx, table, column)
	return found, err
}

// tableColumn reports whether table has column and, if so, whether the
// column accepts NULL.
func (store *Store) tableColumn(ctx context.Context, table, column string) (found, nullable bool, err error) {
	if store.driver == "postgres" {
		var isNullable string
		err := store.database.QueryRowContext(ctx, `
SELECT is_nullable FROM information_schema.columns
WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`, table, column).Scan(&isNullable)
		if errors.Is(err, sql.ErrNoRows) {
			return false, false, nil
		}
		if err != nil {
			return false, false, fmt.Errorf("inspect %s columns: %w", table, err)
		}
		return true, isNullable == "YES", nil
	}
	rows, err := store.database.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return false, false, fmt.Errorf("inspect %s columns: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var columnID, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&columnID, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, false, fmt.Errorf("scan %s column: %w", table, err)
		}
		if name == column {
			return true, notNull == 0, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, false, fmt.Errorf("iterate %s columns: %w", table, err)
	}
	return false, false, nil
}
