package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

// A backlog many chunks deep prunes completely in one call: raw rows, minute
// rollups, both tiers, and client sightings, while recent history stays.
func TestPruneQueryEventsClearsALargeBacklogInChunks(t *testing.T) {
	t.Parallel()

	opened, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { opened.Close() })
	testPruneLargeBacklog(t, opened)
}

func TestPruneQueryEventsClearsALargeBacklogInChunksOnPostgres(t *testing.T) {
	dsn := os.Getenv("SABLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SABLE_TEST_POSTGRES_DSN is not set")
	}
	testPruneLargeBacklog(t, openPostgresTestStore(t, dsn))
}

func testPruneLargeBacklog(t *testing.T, opened *Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Minute)
	const backlog = 1_200
	opened.pruneChunk = 50

	events := make([]querylog.Event, 0, backlog+3)
	for index := range backlog {
		at := now.Add(-100*time.Hour + time.Duration(index)*4*time.Minute)
		events = append(events, blockingEvent(at, fmt.Sprintf("10.0.%d.%d", index/250, index%250),
			fmt.Sprintf("host-%d.example.com.", index), querylog.SourceUpstream))
	}
	for index := range 3 {
		events = append(events, blockingEvent(now.Add(-time.Duration(index+1)*time.Minute), "10.0.9.1", "recent.example.com.", querylog.SourceUpstream))
	}
	if err := opened.WriteQueryEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	// Blocked clients need no recount, so the tiers fill straight away.
	if _, err := opened.database.ExecContext(ctx, "INSERT INTO sable_metadata (key, value) VALUES ("+opened.placeholder(1)+", "+opened.placeholder(2)+")",
		blockedClientBackfilledKey, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := opened.CompactQueryLogRollups(ctx, now); err != nil {
		t.Fatal(err)
	}
	cutoff := now.Add(-time.Hour)
	tables := []string{
		"sable_query_log_rollup", "sable_query_log_rollup_hour", "sable_query_log_rollup_day",
		"sable_client_seen", "sable_client_domain_seen",
	}
	for _, table := range tables {
		if count := countPruneRows(t, opened, table, ""); count <= opened.pruneChunk {
			t.Fatalf("%s holds %d rows before the prune, want more than one chunk", table, count)
		}
	}

	if err := opened.PruneQueryEvents(ctx, cutoff); err != nil {
		t.Fatal(err)
	}
	if got := countPruneRows(t, opened, "sable_query_log", ""); got != 3 {
		t.Fatalf("query log keeps %d rows, want the 3 recent ones", got)
	}
	bucket := cutoff.Truncate(time.Minute)
	for _, table := range []string{"sable_query_log_rollup", "sable_query_log_rollup_hour", "sable_query_log_rollup_day"} {
		if got := countPruneRows(t, opened, table, "bucket_start <= "+opened.placeholder(1), bucket); got != 0 {
			t.Fatalf("%s keeps %d buckets at or before the cutoff", table, got)
		}
	}
	for _, table := range []string{"sable_client_seen", "sable_client_domain_seen"} {
		if got := countPruneRows(t, opened, table, "last_seen < "+opened.placeholder(1), cutoff); got != 0 {
			t.Fatalf("%s keeps %d sightings from before the cutoff", table, got)
		}
		if got := countPruneRows(t, opened, table, ""); got == 0 {
			t.Fatalf("%s lost the recent client's sighting", table)
		}
	}
	if got := countPruneRows(t, opened, "sable_query_log_rollup", ""); got == 0 {
		t.Fatal("minute rollups lost the recent queries")
	}
}

func countPruneRows(t *testing.T, opened *Store, table, condition string, arguments ...any) int {
	t.Helper()
	statement := "SELECT COUNT(*) FROM " + table
	if condition != "" {
		statement += " WHERE " + condition
	}
	var count int
	if err := opened.database.QueryRowContext(context.Background(), statement, arguments...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
