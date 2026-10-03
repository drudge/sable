package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

// openPostgresTestStore opens a store in a schema of its own on the database
// SABLE_TEST_POSTGRES_DSN names, or skips the test without one.
func openPostgresTestStore(t *testing.T, dsn string) *Store {
	t.Helper()
	opened, err := Open(context.Background(), "postgres", postgresTestSchema(t, dsn))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { opened.Close() })
	return opened
}

// postgresTestSchema creates a schema of its own on the database dsn names,
// drops it when the test ends, and returns a DSN that works in it.
func postgresTestSchema(t *testing.T, dsn string) string {
	t.Helper()
	ctx := context.Background()
	schema := fmt.Sprintf("sable_test_%d", time.Now().UnixNano())
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, err := sql.Open("pgx", dsn)
		if err == nil {
			cleanup.Exec("DROP SCHEMA " + schema + " CASCADE")
			cleanup.Close()
		}
	})
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// On PostgreSQL the search is the same LIKE, and pg_trgm indexes serve it.
func TestQueryLogSearchBuildsPostgresTrigramIndexes(t *testing.T) {
	dsn := os.Getenv("SABLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SABLE_TEST_POSTGRES_DSN is not set")
	}
	ctx := context.Background()
	opened := openPostgresTestStore(t, dsn)
	if err := opened.WriteQueryEvents(ctx, searchTestEvents(time.Now().UTC().Truncate(time.Second))); err != nil {
		t.Fatal(err)
	}
	built, err := opened.BuildQueryLogSearch(ctx)
	if err != nil || !built {
		t.Fatalf("BuildQueryLogSearch() = %t, %v", built, err)
	}
	for _, index := range postgresQueryLogSearchIndexes {
		var valid bool
		if err := opened.database.QueryRowContext(ctx, `
SELECT index_state.indisvalid FROM pg_index index_state
JOIN pg_class index_class ON index_class.oid = index_state.indexrelid
WHERE index_class.relname = $1 AND index_class.relnamespace = to_regnamespace(current_schema())`, index[0]).Scan(&valid); err != nil || !valid {
			t.Fatalf("%s valid = %t, %v", index[0], valid, err)
		}
	}
	if again, err := opened.BuildQueryLogSearch(ctx); err != nil || again {
		t.Fatalf("a second pass = %t, %v; want nothing to do", again, err)
	}
	for search, want := range map[string]int{"remarkable": 2, "2603:7083": 1, "memfault": 1, "ab": 3, `"quote`: 1} {
		page, err := opened.QueryEvents(ctx, querylog.Filter{Search: search})
		if err != nil || page.TotalEntries != want {
			t.Errorf("search %q found %d, %v; want %d", search, page.TotalEntries, err, want)
		}
	}
	// With the planner told not to read whole tables, a search that can use
	// the trigram indexes does.
	transaction, err := opened.database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, "SET LOCAL enable_seqscan = off"); err != nil {
		t.Fatal(err)
	}
	rows, err := transaction.QueryContext(ctx, "EXPLAIN SELECT COUNT(*) FROM sable_query_log WHERE (name_key LIKE $1 OR client_ip_key LIKE $2 OR LOWER(answer) LIKE $3)", "%remarkable%", "%remarkable%", "%remarkable%")
	if err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	for rows.Next() {
		var line string
		rows.Scan(&line)
		plan.WriteString(line + "\n")
	}
	rows.Close()
	for _, index := range postgresQueryLogSearchIndexes {
		if !strings.Contains(plan.String(), index[0]) {
			t.Errorf("the search plan doesn't use %s:\n%s", index[0], plan.String())
		}
	}
}

// A role that can't enable pg_trgm keeps searching by reading every row.
func TestQueryLogSearchWithoutPgTrgmStillSearches(t *testing.T) {
	dsn := os.Getenv("SABLE_TEST_POSTGRES_PLAIN_DSN")
	if dsn == "" {
		t.Skip("SABLE_TEST_POSTGRES_PLAIN_DSN is not set")
	}
	ctx := context.Background()
	opened, err := Open(ctx, "postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := opened.WriteQueryEvents(ctx, searchTestEvents(time.Now().UTC().Truncate(time.Second))); err != nil {
		t.Fatal(err)
	}
	if built, err := opened.BuildQueryLogSearch(ctx); err == nil || built {
		t.Fatalf("BuildQueryLogSearch() = %t, %v; want it to say pg_trgm can't be enabled", built, err)
	}
	if again, err := opened.BuildQueryLogSearch(ctx); err != nil || again {
		t.Fatalf("a second pass = %t, %v; want it to try once per start", again, err)
	}
	page, err := opened.QueryEvents(ctx, querylog.Filter{Search: "remarkable"})
	if err != nil || page.TotalEntries < 2 {
		t.Fatalf("search found %d, %v; want the rows", page.TotalEntries, err)
	}
}

// PostgreSQL matches search wildcards as text too, and gets the sightings
// indexes the prune reads.
func TestQueryLogSearchMatchesWildcardsLiterallyOnPostgres(t *testing.T) {
	dsn := os.Getenv("SABLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SABLE_TEST_POSTGRES_DSN is not set")
	}
	ctx := context.Background()
	opened := openPostgresTestStore(t, dsn)
	if err := opened.WriteQueryEvents(ctx, append(searchTestEvents(time.Now().UTC()), querylog.Event{
		OccurredAt: time.Now().UTC(), ClientIP: "10.0.7.23", Name: "_dmarc.example.", Protocol: "UDP", Answer: "TXT v=DMARC1",
	})); err != nil {
		t.Fatal(err)
	}
	for search, want := range map[string]int{"_": 1, "_dmarc": 1, "%": 0, `\`: 0, "a_": 0} {
		page, err := opened.QueryEvents(ctx, querylog.Filter{Search: search})
		if err != nil {
			t.Fatalf("search %q: %v", search, err)
		}
		if page.TotalEntries != want {
			t.Errorf("search %q found %d rows, want %d", search, page.TotalEntries, want)
		}
	}
	var indexes []string
	rows, err := opened.database.QueryContext(ctx, "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() AND indexname LIKE '%last_idx' OR indexname = 'sable_query_log_rollup_bucket_idx' AND schemaname = current_schema() ORDER BY indexname")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		indexes = append(indexes, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(indexes, ","), "sable_client_domain_seen_last_idx,sable_client_identity_last_idx,sable_client_seen_last_idx"; got != want {
		t.Fatalf("indexes = %s, want %s", got, want)
	}
}
