package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/web/pages"
)

// fakeStatsStore mirrors the aggregation the SQL store performs so chart tests
// can exercise persistence without a database.
type fakeStatsStore struct {
	mu       sync.Mutex
	buckets  map[int64]store.QueryStatsDelta
	totals   store.QueryStatsTotals
	writes   int
	failNext bool
	prunedAt time.Time
}

func newFakeStatsStore() *fakeStatsStore {
	return &fakeStatsStore{buckets: make(map[int64]store.QueryStatsDelta)}
}

func (fake *fakeStatsStore) RecordQueryStats(_ context.Context, buckets []store.QueryStatsBucket, totals store.QueryStatsTotals) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.failNext {
		fake.failNext = false
		return errors.New("write failed")
	}
	fake.writes++
	for _, bucket := range buckets {
		stored := fake.buckets[bucket.Start.Unix()]
		stored.Queries += bucket.Queries
		stored.NoError += bucket.NoError
		stored.ServerFailures += bucket.ServerFailures
		stored.NXDomain += bucket.NXDomain
		stored.Refused += bucket.Refused
		stored.Blocked += bucket.Blocked
		stored.CacheHits += bucket.CacheHits
		stored.CacheMisses += bucket.CacheMisses
		fake.buckets[bucket.Start.Unix()] = stored
	}
	fake.totals = totals
	return nil
}

func (fake *fakeStatsStore) QueryStats(_ context.Context, start, end time.Time, width time.Duration) ([]store.QueryStatsBucket, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	seconds := int64(width / time.Second)
	slots := make(map[int64]store.QueryStatsDelta)
	for key, delta := range fake.buckets {
		if key < start.Unix() || key >= end.Unix() {
			continue
		}
		slot := (key / seconds) * seconds
		merged := slots[slot]
		merged.Queries += delta.Queries
		merged.NoError += delta.NoError
		merged.ServerFailures += delta.ServerFailures
		merged.NXDomain += delta.NXDomain
		merged.Refused += delta.Refused
		merged.Blocked += delta.Blocked
		merged.CacheHits += delta.CacheHits
		merged.CacheMisses += delta.CacheMisses
		slots[slot] = merged
	}
	buckets := make([]store.QueryStatsBucket, 0, len(slots))
	for slot, delta := range slots {
		buckets = append(buckets, store.QueryStatsBucket{Start: time.Unix(slot, 0).UTC(), QueryStatsDelta: delta})
	}
	sort.Slice(buckets, func(left, right int) bool { return buckets[left].Start.Before(buckets[right].Start) })
	return buckets, nil
}

func (fake *fakeStatsStore) QueryStatsTotals(context.Context) (store.QueryStatsTotals, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.totals, nil
}

func (fake *fakeStatsStore) PruneQueryStats(_ context.Context, before time.Time) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.prunedAt = before
	for key := range fake.buckets {
		if key < before.Unix() {
			delete(fake.buckets, key)
		}
	}
	return nil
}

func TestStatsHistoryAppliesRetentionChanges(t *testing.T) {
	t.Parallel()

	backing := newFakeStatsStore()
	history := newStatsHistory(nil, 48*time.Hour)
	if err := history.attach(context.Background(), backing); err != nil {
		t.Fatalf("attach() error = %v", err)
	}
	history.setRetention(12 * time.Hour)
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	if err := history.prune(context.Background(), now); err != nil {
		t.Fatalf("prune() error = %v", err)
	}
	if want := now.Add(-12 * time.Hour); !backing.prunedAt.Equal(want) {
		t.Fatalf("prune cutoff = %s, want %s", backing.prunedAt, want)
	}
}

func lastCoordinate(polyline string) string {
	fields := strings.Fields(polyline)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

func TestStatsHistoryBuildsRealCounterDeltaSeries(t *testing.T) {
	t.Parallel()

	started := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	history := newStatsHistory(nil, config.Defaults().Statistics.Retention.Duration)
	history.record(started, dnsserver.Stats{Queries: 10, CacheHits: 2})
	history.record(started.Add(5*time.Second), dnsserver.Stats{
		Queries: 15, Blocked: 1, CacheHits: 5,
	})

	view := history.view(context.Background(), "hour", started.Add(5*time.Second), dnsserver.Stats{
		Queries: 15, Blocked: 1, CacheHits: 5,
	}, pages.TimeDisplay{Format: pages.TimeFormat12})
	if !view.HasActivity || view.ActiveRange != "hour" {
		t.Fatalf("chart view = %+v", view)
	}
	// The activity belongs to the newest slot, and the empty hour before it
	// stays on the baseline instead of being stretched across the plot.
	if got := lastCoordinate(view.Total); got != "1190.0,24.0" {
		t.Fatalf("last total coordinate = %q, want 1190.0,24.0", got)
	}
	if !strings.HasPrefix(view.Total, "58.0,296.0") {
		t.Fatalf("total polyline should start on the baseline: %q", view.Total)
	}
	if view.Blocked == "" || view.CacheHits == "" {
		t.Fatalf("chart coordinates = blocked %q cache %q", view.Blocked, view.CacheHits)
	}
	if view.RangeLabel != "Last hour" {
		t.Fatalf("overview range label = %q, want Last hour", view.RangeLabel)
	}
	if view.Stats.Queries != 5 || view.Stats.Blocked != 1 || view.Stats.CacheHits != 3 || view.Stats.CacheHitRatio != "100.0%" {
		t.Fatalf("range overview = %+v, want 5 queries, 1 blocked, 3 cache hits, and a 100%% hit rate", view.Stats)
	}
	wantCustomStart := started.Add(5 * time.Second).Add(-7 * 24 * time.Hour).Local().Format("2006-01-02T15:04")
	if view.CustomStart != wantCustomStart {
		t.Fatalf("default custom start = %q, want %q", view.CustomStart, wantCustomStart)
	}
}

func TestChartHoverDataMatchesPlottedPoints(t *testing.T) {
	t.Parallel()

	started := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	history := newStatsHistory(nil, config.Defaults().Statistics.Retention.Duration)
	history.record(started, dnsserver.Stats{Queries: 10, NoError: 8, CacheHits: 2})
	history.record(started.Add(5*time.Second), dnsserver.Stats{Queries: 25, NoError: 20, Blocked: 3, CacheHits: 6})

	view := history.view(context.Background(), "hour", started.Add(5*time.Second), dnsserver.Stats{
		Queries: 25, NoError: 20, Blocked: 3, CacheHits: 6,
	}, pages.TimeDisplay{Format: pages.TimeFormat12})

	var payload chartHoverPayload
	if err := json.Unmarshal([]byte(view.HoverData), &payload); err != nil {
		t.Fatalf("hover payload = %q: %v", view.HoverData, err)
	}
	if payload.Maximum != view.Maximum || payload.Box.Left != chartLeft || payload.Box.Bottom != chartBottom {
		t.Fatalf("hover payload header = %+v", payload)
	}
	if len(payload.Series) != len(chartSeriesDefinitions) {
		t.Fatalf("hover series count = %d, want %d", len(payload.Series), len(chartSeriesDefinitions))
	}
	for _, series := range payload.Series {
		if len(series.Values) != len(payload.X) || len(payload.Times) != len(payload.X) {
			t.Fatalf("series %q has %d values for %d points (%d times)", series.Class, len(series.Values), len(payload.X), len(payload.Times))
		}
	}
	// The hover x positions must land on the same coordinates the polylines use.
	if !strings.HasPrefix(view.Total, fmt.Sprintf("%.1f,", payload.X[0])) {
		t.Fatalf("hover x %v does not match plotted total %q", payload.X, view.Total)
	}
	newest := len(payload.X) - 1
	if payload.Series[0].Values[newest] != 15 || payload.Series[1].Values[newest] != 12 {
		t.Fatalf("hover values = total %d noError %d, want 15 and 12",
			payload.Series[0].Values[newest], payload.Series[1].Values[newest])
	}
}

func TestChartDurationRejectsUnknownRange(t *testing.T) {
	t.Parallel()

	if _, valid := chartDuration("forever"); valid {
		t.Fatal("chartDuration() accepted an unknown range")
	}
}

func TestChartSlotWidthStaysWithinPlottedPoints(t *testing.T) {
	t.Parallel()

	for _, rangeName := range []string{"hour", "day", "week", "month", "year"} {
		duration, _ := chartDuration(rangeName)
		width := chartSlotWidth(duration)
		if width < statsBucketInterval || width%statsBucketInterval != 0 {
			t.Fatalf("%s slot width = %s, want a whole number of %s buckets", rangeName, width, statsBucketInterval)
		}
		if slots := int(duration / width); slots > maxChartPoints {
			t.Fatalf("%s produces %d slots, want at most %d", rangeName, slots, maxChartPoints)
		}
	}
}

func TestChartTimeFormatHonorsDisplayPreference(t *testing.T) {
	t.Parallel()

	if got := chartTimeFormat(time.Hour, pages.TimeDisplay{Format: pages.TimeFormat12}); got != "3:04:05 PM" {
		t.Fatalf("12-hour chart format = %q", got)
	}
	if got := chartTimeFormat(time.Hour, pages.TimeDisplay{Format: pages.TimeFormat24}); got != "15:04:05" {
		t.Fatalf("24-hour chart format = %q", got)
	}
	if got := chartTimeFormat(24*time.Hour, pages.TimeDisplay{Format: pages.TimeFormat12}); got != "Jan 2, 3:04 PM" {
		t.Fatalf("12-hour day chart format = %q", got)
	}
	if got := chartTimeFormat(24*time.Hour, pages.TimeDisplay{Format: pages.TimeFormat24}); got != "Jan 2, 15:04" {
		t.Fatalf("24-hour day chart format = %q", got)
	}
}

func TestStatsHistoryBuildsCustomRange(t *testing.T) {
	t.Parallel()

	started := time.Now().Add(-30 * time.Minute).Truncate(time.Minute)
	history := newStatsHistory(nil, config.Defaults().Statistics.Retention.Duration)
	history.record(started, dnsserver.Stats{Queries: 10, NoError: 8})
	history.record(started.Add(5*time.Minute), dnsserver.Stats{Queries: 14, NoError: 12})

	view := history.customView(
		context.Background(),
		started.Add(-time.Minute),
		started.Add(10*time.Minute),
		dnsserver.Stats{Queries: 14, NoError: 12},
		pages.TimeDisplay{Format: pages.TimeFormat12},
	)
	if !view.HasActivity || view.ActiveRange != "custom" {
		t.Fatalf("custom chart view = %+v", view)
	}
	if view.CustomStart == "" || view.CustomEnd == "" || view.Total == "" {
		t.Fatalf("custom chart fields = %+v", view)
	}
}

func TestChartLiveBadgeFollowsRecentQueries(t *testing.T) {
	t.Parallel()

	at := time.Now().Add(-2 * time.Minute).Truncate(time.Minute)
	history := newStatsHistory(nil, config.Defaults().Statistics.Retention.Duration)
	history.record(at, dnsserver.Stats{Queries: 4})
	history.record(at.Add(time.Second), dnsserver.Stats{Queries: 9})

	if !history.serving(at.Add(chartLiveWindow)) {
		t.Fatal("badge should stay live for a resolver that just answered queries")
	}
	if history.serving(at.Add(chartLiveWindow + time.Minute)) {
		t.Fatal("badge should settle once queries stop arriving")
	}

	display := pages.TimeDisplay{Format: pages.TimeFormat24}
	// The counters do not move, so the second view sees an idle resolver.
	live := history.view(context.Background(), "hour", at.Add(5*time.Second), dnsserver.Stats{Queries: 9}, display)
	idle := history.view(context.Background(), "hour", at.Add(10*time.Minute), dnsserver.Stats{Queries: 9}, display)
	if !live.Live || idle.Live {
		t.Fatalf("chart live flags = %t then %t, want true then false", live.Live, idle.Live)
	}
}

func TestEmptyChartSeparatesAClosedRangeFromALiveOne(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	display := pages.TimeDisplay{Format: pages.TimeFormat24}
	history := newStatsHistory(nil, config.Defaults().Statistics.Retention.Duration)
	now := time.Now()

	live := history.view(ctx, "hour", now, dnsserver.Stats{}, display)
	if live.HasActivity || live.Historical {
		t.Fatalf("a range ending now is still collecting: %+v", live)
	}
	lastWeek := now.Add(-7 * 24 * time.Hour)
	past := history.customView(ctx, lastWeek, lastWeek.Add(time.Hour), dnsserver.Stats{}, display)
	if past.HasActivity || !past.Historical {
		t.Fatalf("a range that closed a week ago has its final answer: %+v", past)
	}
}

func TestStatsHistoryChartsActivityRecordedBeforeARestart(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backing := newFakeStatsStore()
	yesterday := time.Now().Add(-20 * time.Hour).Truncate(time.Minute)

	first := newStatsHistory(nil, config.Defaults().Statistics.Retention.Duration)
	if err := first.attach(ctx, backing); err != nil {
		t.Fatalf("attach() error = %v", err)
	}
	first.record(yesterday, dnsserver.Stats{Queries: 100, NoError: 90, CacheHits: 40})
	first.record(yesterday.Add(time.Minute), dnsserver.Stats{Queries: 400, NoError: 380, CacheHits: 150, Blocked: 12})
	if err := first.flush(ctx); err != nil {
		t.Fatalf("flush() error = %v", err)
	}

	// A restart zeroes the handler counters and empties the in-memory history.
	restarted := newStatsHistory(nil, config.Defaults().Statistics.Retention.Duration)
	if err := restarted.attach(ctx, backing); err != nil {
		t.Fatalf("attach() error = %v", err)
	}
	view := restarted.view(context.Background(), "day", time.Now(), dnsserver.Stats{}, pages.TimeDisplay{Format: pages.TimeFormat24})
	if !view.HasActivity {
		t.Fatalf("day range lost the persisted history: %+v", view)
	}
	if view.Maximum != 300 {
		t.Fatalf("day range maximum = %d, want 300", view.Maximum)
	}

	// Lifetime totals continue from the stored ones rather than restarting.
	totals := restarted.totals(time.Now(), dnsserver.Stats{Queries: 7, NoError: 5})
	if totals.Queries != 307 || totals.NoError != 295 || totals.Blocked != 12 {
		t.Fatalf("totals after restart = %+v", totals)
	}
	if view := restarted.view(context.Background(), "hour", time.Now(), dnsserver.Stats{Queries: 7, NoError: 5}, pages.TimeDisplay{Format: pages.TimeFormat24}); !view.HasActivity {
		t.Fatalf("hour range should show the current activity: %+v", view)
	}
}

func TestStatsHistoryRetriesAFailedFlush(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backing := newFakeStatsStore()
	history := newStatsHistory(nil, config.Defaults().Statistics.Retention.Duration)
	if err := history.attach(ctx, backing); err != nil {
		t.Fatalf("attach() error = %v", err)
	}
	at := time.Now().Truncate(time.Minute)
	history.record(at, dnsserver.Stats{Queries: 10})
	history.record(at.Add(time.Second), dnsserver.Stats{Queries: 25, Blocked: 4})

	backing.failNext = true
	if err := history.flush(ctx); err == nil {
		t.Fatal("flush() returned no error for a failing store")
	}
	if err := history.flush(ctx); err != nil {
		t.Fatalf("retry flush() error = %v", err)
	}
	stored, err := backing.QueryStats(ctx, at.Add(-time.Minute), at.Add(time.Minute), statsBucketInterval)
	if err != nil {
		t.Fatalf("QueryStats() error = %v", err)
	}
	if len(stored) != 1 || stored[0].Queries != 15 || stored[0].Blocked != 4 {
		t.Fatalf("stored buckets = %+v, want one bucket with 15 queries and 4 blocked", stored)
	}
	if backing.totals.Queries != 15 {
		t.Fatalf("stored totals = %+v", backing.totals)
	}
}

func TestStatsHistoryCountsWindowsFromPersistedBuckets(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	backing := newFakeStatsStore()
	history := newStatsHistory(nil, config.Defaults().Statistics.Retention.Duration)
	if err := history.attach(ctx, backing); err != nil {
		t.Fatalf("attach() error = %v", err)
	}
	at := time.Now().Add(-30 * time.Minute).Truncate(time.Minute)
	history.record(at, dnsserver.Stats{})
	history.record(at.Add(time.Second), dnsserver.Stats{CacheHits: 9, Blocked: 3})
	if err := history.flush(ctx); err != nil {
		t.Fatalf("flush() error = %v", err)
	}
	if hits := history.cacheHitsSince(ctx, time.Hour, time.Now(), dnsserver.Stats{CacheHits: 9, Blocked: 3}); hits != 9 {
		t.Fatalf("cacheHitsSince() = %d, want 9", hits)
	}
	if blocked := history.blockedSince(ctx, time.Hour, time.Now(), dnsserver.Stats{CacheHits: 9, Blocked: 3}); blocked != 3 {
		t.Fatalf("blockedSince() = %d, want 3", blocked)
	}
	if hits := history.cacheHitsSince(ctx, time.Minute, time.Now(), dnsserver.Stats{CacheHits: 9, Blocked: 3}); hits != 0 {
		t.Fatalf("cacheHitsSince(minute) = %d, want 0", hits)
	}
}
