package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// forgetSchemaVersion takes a database back to before versioned migrations,
// so the next Open upgrades it the way it upgrades one from an older Sable.
func forgetSchemaVersion(t *testing.T, storage *Store) {
	t.Helper()
	if _, err := storage.database.Exec("DROP TABLE " + schemaVersionTable); err != nil {
		t.Fatal(err)
	}
}

// legacyQueryLogRows are 1.6.1 rows whose search keys were never filled: the
// root name and an empty client match the old backfill at every start. Their
// IDs span several backfill chunks.
const legacyQueryLogRows = `
INSERT INTO sable_query_log (id, occurred_at, client_ip, client_ip_key, name, name_key, record_type, class, response_code, source, protocol, answer, decision, duration_us) VALUES
(1, '2026-09-01 00:00:00', '192.0.2.10', '192.0.2.10', 'example.com.', 'example.com', 1, 1, 0, 'cache', 'UDP', '', '{}', 10),
(2, '2026-09-01 00:00:01', 'FE80::1', '', 'Mixed.Example.ORG.', '', 1, 1, 0, 'cache', 'UDP', '', '{}', 10),
(25003, '2026-09-01 00:00:02', '', '', '.', '', 2, 1, 0, 'cache', 'UDP', '', '{}', 10);
INSERT INTO sable_users (id, username, password_hash, created_at) VALUES (7, 'legacy', 'hash', '2026-01-01 00:00:00');`

func TestOpenUpgradesSQLite161Database(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sable.db")
	loadLegacyDatabase(t, "sqlite", path, "testdata/schema-1.6.1-sqlite.sql")
	upgraded := testUpgradeFrom161(t, "sqlite", path, path+"?_pragma=query_only(1)")
	if upgraded.searchIndexed.Load() {
		t.Fatal("searches used the index before the upgraded log was in it")
	}
}

func TestOpenUpgradesPostgres161Database(t *testing.T) {
	dsn := os.Getenv("SABLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SABLE_TEST_POSTGRES_DSN is not set")
	}
	schemaDSN := postgresTestSchema(t, dsn)
	loadLegacyDatabase(t, "pgx", schemaDSN, "testdata/schema-1.6.1-postgres.sql")
	testUpgradeFrom161(t, "postgres", schemaDSN, schemaDSN+"&default_transaction_read_only=on")
}

func loadLegacyDatabase(t *testing.T, driver, dsn, schemaFile string) {
	t.Helper()
	schema, err := os.ReadFile(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, script := range []string{string(schema), legacyQueryLogRows} {
		if _, err := database.Exec(script); err != nil {
			t.Fatalf("load the 1.6.1 database: %v", err)
		}
	}
}

// testUpgradeFrom161 opens a 1.6.1 database, checks the upgrade, and then
// opens it again read-only: a start on a current database must change
// nothing. It returns the read-only store.
func testUpgradeFrom161(t *testing.T, driver, dsn, readOnlyDSN string) *Store {
	t.Helper()
	ctx := context.Background()
	upgraded, err := Open(ctx, driver, dsn)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if version, err := upgraded.schemaVersion(ctx); err != nil || version != latestSchemaVersion() {
		t.Fatalf("schema version = %d, %v; want %d", version, err, latestSchemaVersion())
	}
	keys := map[int64][2]string{}
	rows, err := upgraded.database.QueryContext(ctx, "SELECT id, client_ip_key, name_key FROM sable_query_log")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int64
		var client, name string
		if err := rows.Scan(&id, &client, &name); err != nil {
			t.Fatal(err)
		}
		keys[id] = [2]string{client, name}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if keys[2] != [2]string{"fe80::1", "mixed.example.org"} || keys[1] != [2]string{"192.0.2.10", "example.com"} {
		t.Fatalf("query log keys after upgrade = %v", keys)
	}
	var profiles, administrators int
	if err := upgraded.database.QueryRowContext(ctx, `
SELECT
    (SELECT COUNT(*) FROM sable_user_profiles WHERE user_id = 7),
    (SELECT COUNT(*) FROM sable_user_roles AS assignments
     JOIN sable_roles AS roles ON roles.id = assignments.role_id
     WHERE assignments.user_id = 7 AND roles.name = 'Administrator')`).Scan(&profiles, &administrators); err != nil {
		t.Fatal(err)
	}
	if profiles != 1 || administrators != 1 {
		t.Fatalf("legacy user profiles = %d, administrator roles = %d; want 1 and 1", profiles, administrators)
	}
	for _, index := range []string{"sable_query_log_occurred_at_idx", "sable_query_log_client_key_idx", "sable_query_log_name_key_idx", "sable_client_seen_last_idx"} {
		if !indexExists(t, upgraded, index) {
			t.Errorf("index %s is missing after the upgrade", index)
		}
	}
	if err := upgraded.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := Open(ctx, driver, readOnlyDSN)
	if err != nil {
		t.Fatalf("a second start wrote to the database: %v", err)
	}
	t.Cleanup(func() { again.Close() })
	if _, err := again.database.ExecContext(ctx, "INSERT INTO sable_metadata (key, value) VALUES ('probe', 'probe')"); err == nil {
		t.Fatal("the read-only store accepted a write, so it proves nothing")
	}
	return again
}

func indexExists(t *testing.T, storage *Store, name string) bool {
	t.Helper()
	query := "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?"
	if storage.driver == "postgres" {
		query = "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1"
	}
	var count int
	if err := storage.database.QueryRow(query, name).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count == 1
}

// A new database takes every step, and its next start writes nothing.
func TestOpenSQLiteSecondStartWritesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sable.db")
	created, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if version, err := created.schemaVersion(ctx); err != nil || version != latestSchemaVersion() {
		t.Fatalf("schema version = %d, %v; want %d", version, err, latestSchemaVersion())
	}
	created.Close()
	again, err := Open(ctx, "sqlite", path+"?_pragma=query_only(1)")
	if err != nil {
		t.Fatalf("a second start wrote to the database: %v", err)
	}
	again.Close()
}

// The built-in roles are written again when they differ from this build's,
// such as after a backup from another version replaced them.
func TestOpenRestoresBuiltInRoleGrants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sable.db")
	opened, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	state, err := opened.ExportAuthorizationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for index := range state.Roles {
		state.Roles[index].Grants = nil
	}
	if err := opened.ReplaceAuthorizationState(ctx, state); err != nil {
		t.Fatal(err)
	}
	opened.Close()

	reopened, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var grants int
	if err := reopened.database.QueryRowContext(ctx, `
SELECT COUNT(*) FROM sable_role_grants AS grants
JOIN sable_roles AS roles ON roles.id = grants.role_id
WHERE roles.name = 'Administrator'`).Scan(&grants); err != nil || grants == 0 {
		t.Fatalf("Administrator grants after a restart = %d, %v; want them back", grants, err)
	}
}
