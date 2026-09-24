package store

import (
	"context"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

// A database upgraded to the blocked-client dimension holds weeks of rollup
// minutes written without it. The backfill counts them from the raw log once,
// so later windows read rollups instead of recounting that history each time,
// and every count stays what the raw log says.
func TestBackfillBlockedClientRollupsCountsHistoryOnce(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	began := now.Add(-20 * time.Minute).Truncate(time.Minute).Add(30 * time.Second)
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-26*time.Hour), "10.0.7.16", "ads.example.com.", querylog.SourceBlocked),
		blockingEvent(now.Add(-3*time.Hour), "10.0.7.16", "ads.example.com.", querylog.SourceBlocked),
		blockingEvent(now.Add(-3*time.Hour), "10.0.7.20", "pixel.example.net.", querylog.SourceBlocked),
		blockingEvent(now.Add(-2*time.Hour), "10.0.7.20", "www.example.org.", querylog.SourceUpstream),
		// Either side of the moment the dimension began, in the same minute.
		blockingEvent(began.Add(-10*time.Second), "10.0.7.16", "ads.example.com.", querylog.SourceBlocked),
		blockingEvent(began.Add(10*time.Second), "10.0.7.16", "ads.example.com.", querylog.SourceBlocked),
		blockingEvent(now.Add(-5*time.Minute), "10.0.7.20", "pixel.example.net.", querylog.SourceBlocked),
	})
	// Rewind the dimension to began: nothing before its minute, and only the
	// query written after it within that minute.
	for _, statement := range []struct {
		sql       string
		arguments []any
	}{
		{"UPDATE sable_metadata SET value = ? WHERE key = ?", []any{began.Format(time.RFC3339Nano), blockedClientRollupSinceKey}},
		{"DELETE FROM sable_query_log_rollup WHERE dimension = ? AND bucket_start < ?", []any{queryLogRollupBlockedClient, began.Truncate(time.Minute)}},
		{"UPDATE sable_query_log_rollup SET hits = 1 WHERE dimension = ? AND bucket_start = ?", []any{queryLogRollupBlockedClient, began.Truncate(time.Minute)}},
	} {
		if _, err := opened.database.ExecContext(ctx, statement.sql, statement.arguments...); err != nil {
			t.Fatal(err)
		}
	}
	want := map[string]uint64{"10.0.7.16": 4, "10.0.7.20": 2}
	check := func(stage string) {
		t.Helper()
		activity, err := opened.BlockingActivity(ctx, now.Add(-48*time.Hour), now)
		if err != nil {
			t.Fatal(err)
		}
		if len(activity.TopClients) != len(want) || activity.TopClients["10.0.7.16"] != want["10.0.7.16"] || activity.TopClients["10.0.7.20"] != want["10.0.7.20"] {
			t.Fatalf("%s: blocked clients = %+v, want %+v", stage, activity.TopClients, want)
		}
	}
	check("before the backfill")

	filled, err := opened.BackfillBlockedClientRollups(ctx)
	if err != nil || !filled {
		t.Fatalf("BackfillBlockedClientRollups = %t, %v", filled, err)
	}
	check("after the backfill")
	var rows int
	if err := opened.database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sable_query_log_rollup WHERE dimension = ? AND bucket_start < ?",
		queryLogRollupBlockedClient, began.Truncate(time.Minute)).Scan(&rows); err != nil || rows != 3 {
		t.Fatalf("backfilled minutes = %d, %v; want 3", rows, err)
	}
	since, _, err := opened.blockedClientRollupSince(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if start, _, _ := opened.queryLogRollupStart(ctx); !since.Equal(start) {
		t.Fatalf("marker = %s, want the first rollup minute %s", since, start)
	}

	// A second run is a no-op.
	if filled, err := opened.BackfillBlockedClientRollups(ctx); err != nil || filled {
		t.Fatalf("second BackfillBlockedClientRollups = %t, %v", filled, err)
	}
	check("after a second run")
}
