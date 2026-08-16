package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openStatsStore(t *testing.T) *Store {
	t.Helper()
	opened, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { opened.Close() })
	return opened
}

func TestQueryStatsAccumulateBucketsAndReplaceTotals(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	opened := openStatsStore(t)
	minute := time.Date(2026, time.August, 15, 10, 0, 0, 0, time.UTC)

	if err := opened.RecordQueryStats(ctx, []QueryStatsBucket{
		{Start: minute, QueryStatsDelta: QueryStatsDelta{Queries: 10, NoError: 8, CacheHits: 4}},
	}, QueryStatsTotals{Queries: 10, NoError: 8, CacheHits: 4}); err != nil {
		t.Fatalf("RecordQueryStats() error = %v", err)
	}
	// A second write for the same minute tops the bucket up instead of
	// replacing it, which is what a partial flush before shutdown produces.
	if err := opened.RecordQueryStats(ctx, []QueryStatsBucket{
		{Start: minute, QueryStatsDelta: QueryStatsDelta{Queries: 5, Blocked: 2}},
	}, QueryStatsTotals{Queries: 15, NoError: 8, CacheHits: 4, Blocked: 2}); err != nil {
		t.Fatalf("RecordQueryStats() error = %v", err)
	}

	buckets, err := opened.QueryStats(ctx, minute, minute.Add(time.Minute), time.Minute)
	if err != nil {
		t.Fatalf("QueryStats() error = %v", err)
	}
	if len(buckets) != 1 {
		t.Fatalf("QueryStats() returned %d buckets, want 1", len(buckets))
	}
	if buckets[0].Queries != 15 || buckets[0].Blocked != 2 || buckets[0].NoError != 8 {
		t.Fatalf("bucket = %+v", buckets[0])
	}
	if !buckets[0].Start.Equal(minute) {
		t.Fatalf("bucket start = %s, want %s", buckets[0].Start, minute)
	}

	totals, err := opened.QueryStatsTotals(ctx)
	if err != nil {
		t.Fatalf("QueryStatsTotals() error = %v", err)
	}
	if totals.Queries != 15 || totals.Blocked != 2 {
		t.Fatalf("totals = %+v", totals)
	}
}

func TestQueryStatsGroupsBucketsIntoSlots(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	opened := openStatsStore(t)
	start := time.Date(2026, time.August, 15, 10, 0, 0, 0, time.UTC)
	buckets := make([]QueryStatsBucket, 0, 30)
	for minute := range 30 {
		buckets = append(buckets, QueryStatsBucket{
			Start:           start.Add(time.Duration(minute) * time.Minute),
			QueryStatsDelta: QueryStatsDelta{Queries: 2, CacheHits: 1},
		})
	}
	if err := opened.RecordQueryStats(ctx, buckets, QueryStatsTotals{Queries: 60, CacheHits: 30}); err != nil {
		t.Fatalf("RecordQueryStats() error = %v", err)
	}

	slots, err := opened.QueryStats(ctx, start, start.Add(30*time.Minute), 10*time.Minute)
	if err != nil {
		t.Fatalf("QueryStats() error = %v", err)
	}
	if len(slots) != 3 {
		t.Fatalf("QueryStats() returned %d slots, want 3", len(slots))
	}
	for index, slot := range slots {
		if slot.Queries != 20 || slot.CacheHits != 10 {
			t.Fatalf("slot %d = %+v, want 20 queries and 10 cache hits", index, slot)
		}
		want := start.Add(time.Duration(index) * 10 * time.Minute)
		if !slot.Start.Equal(want) {
			t.Fatalf("slot %d start = %s, want %s", index, slot.Start, want)
		}
	}
}

func TestPruneQueryStatsKeepsLifetimeTotals(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	opened := openStatsStore(t)
	old := time.Now().Add(-48 * time.Hour).Truncate(time.Minute)
	recent := time.Now().Add(-time.Hour).Truncate(time.Minute)
	if err := opened.RecordQueryStats(ctx, []QueryStatsBucket{
		{Start: old, QueryStatsDelta: QueryStatsDelta{Queries: 7}},
		{Start: recent, QueryStatsDelta: QueryStatsDelta{Queries: 3}},
	}, QueryStatsTotals{Queries: 10}); err != nil {
		t.Fatalf("RecordQueryStats() error = %v", err)
	}
	if err := opened.PruneQueryStats(ctx, time.Now().Add(-24*time.Hour)); err != nil {
		t.Fatalf("PruneQueryStats() error = %v", err)
	}

	buckets, err := opened.QueryStats(ctx, old.Add(-time.Minute), time.Now(), time.Minute)
	if err != nil {
		t.Fatalf("QueryStats() error = %v", err)
	}
	if len(buckets) != 1 || buckets[0].Queries != 3 {
		t.Fatalf("buckets after prune = %+v, want only the recent one", buckets)
	}
	totals, err := opened.QueryStatsTotals(ctx)
	if err != nil {
		t.Fatalf("QueryStatsTotals() error = %v", err)
	}
	if totals.Queries != 10 {
		t.Fatalf("totals after prune = %+v, want 10 queries", totals)
	}
}

func TestQueryStatsTotalsAreZeroBeforeAnyWrite(t *testing.T) {
	t.Parallel()

	totals, err := openStatsStore(t).QueryStatsTotals(context.Background())
	if err != nil {
		t.Fatalf("QueryStatsTotals() error = %v", err)
	}
	if totals != (QueryStatsTotals{}) {
		t.Fatalf("totals = %+v, want zeroes", totals)
	}
}
