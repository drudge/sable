package store

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

func TestSplitRollupSpansUsesTheCoarsestWholeBuckets(t *testing.T) {
	t.Parallel()

	day := 24 * time.Hour
	midnight := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	tiers := []tierCoverage{
		{rollupTier: dayRollupTier, from: midnight.Add(-2 * day), until: midnight.Add(day)},
		{rollupTier: hourRollupTier, from: midnight.Add(-2 * day), until: midnight.Add(day + 5*time.Hour)},
	}
	start, end := midnight.Add(-day-90*time.Minute+7*time.Minute), midnight.Add(day+6*time.Hour+11*time.Minute)
	got := splitRollupSpans(start, end, tiers)
	want := []rollupSpan{
		{minuteRollupTable, start, midnight.Add(-day - time.Hour)},
		{hourRollupTier.table, midnight.Add(-day - time.Hour), midnight.Add(-day)},
		{dayRollupTier.table, midnight.Add(-day), midnight.Add(day)},
		{hourRollupTier.table, midnight.Add(day), midnight.Add(day + 5*time.Hour)},
		{minuteRollupTable, midnight.Add(day + 5*time.Hour), end},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("spans =\n%v\nwant\n%v", got, want)
	}
	if spans := splitRollupSpans(start, end, nil); len(spans) != 1 || spans[0].table != minuteRollupTable {
		t.Fatalf("spans without tiers = %v, want the minutes alone", spans)
	}
}

// The tiers are only ever a faster way to reach the same numbers: every read
// must answer exactly as it does from the minutes and the raw log alone, before
// and after old history is pruned.
func TestRollupTiersNeverChangeAnAnswer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	random := rand.New(rand.NewSource(7))
	clients := []string{"10.0.7.16", "10.0.7.20", "10.0.7.31", "fd00::5"}
	names := []string{"ads.example.com.", "www.example.org.", "api.example.net.", "cdn.example.com.", "pixel.example.net."}
	events := make([]querylog.Event, 0, 3000)
	for range 3000 {
		event := blockingEvent(now.Add(-time.Duration(random.Int63n(int64(80*time.Hour)))), clients[random.Intn(len(clients))], names[random.Intn(len(names))], querylog.SourceUpstream)
		if event.Name == "ads.example.com." || event.Name == "pixel.example.net." {
			event.Source = querylog.SourceBlocked
			event.Decision = querylog.Decision{PolicySources: []string{"Big List", "Small List"}[:1+random.Intn(2)]}
		}
		events = append(events, event)
	}
	opened := openQueryLogStore(t, events)
	// Count everything from the rollups: the dimensions began before this
	// history, and blocked clients need no recount.
	for _, key := range []string{blockedClientRollupSinceKey, blockedSourceRollupSinceKey} {
		if _, err := opened.database.ExecContext(ctx, "UPDATE sable_metadata SET value = ? WHERE key = ?", now.Add(-100*time.Hour).Format(time.RFC3339Nano), key); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := opened.database.ExecContext(ctx, "INSERT INTO sable_metadata (key, value) VALUES (?, ?)", blockedClientBackfilledKey, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	answers := func() string {
		t.Helper()
		var report string
		for _, window := range []time.Duration{3 * time.Hour, 26 * time.Hour, 79 * time.Hour} {
			since := now.Add(-window).Add(-17 * time.Second)
			blocking, err := opened.BlockingActivity(ctx, since, now)
			if err != nil {
				t.Fatal(err)
			}
			clients, err := opened.ClientActivity(ctx, since, now)
			if err != nil {
				t.Fatal(err)
			}
			counted, err := opened.QueryLogInsights(ctx, since, now)
			if err != nil {
				t.Fatal(err)
			}
			hourly, err := opened.ClientHourlyActivity(ctx, since, now)
			if err != nil {
				t.Fatal(err)
			}
			report += fmt.Sprintf("%s: %+v\n%+v\n%+v\n%v\n", window, blocking, clients.Clients, counted, hourly)
		}
		return report
	}
	withoutTiers := func() string {
		t.Helper()
		for _, tier := range rollupTiers {
			for _, key := range []string{tier.fromKey, tier.untilKey} {
				if _, err := opened.database.ExecContext(ctx, "DELETE FROM sable_metadata WHERE key = ?", key); err != nil {
					t.Fatal(err)
				}
			}
		}
		return answers()
	}

	want := answers()
	if err := opened.CompactQueryLogRollups(ctx, now); err != nil {
		t.Fatal(err)
	}
	for _, tier := range rollupTiers {
		coverage, found, err := opened.tierCoverage(ctx, tier)
		if err != nil || !found || !coverage.from.Before(coverage.until) {
			t.Fatalf("%s covers %+v (%t, %v) after compaction", tier.table, coverage, found, err)
		}
	}
	if got := answers(); got != want {
		t.Fatalf("answers changed once the tiers were filled:\n%s\nwant\n%s", got, want)
	}
	// A second pass changes nothing.
	if err := opened.CompactQueryLogRollups(ctx, now.Add(20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := answers(); got != want {
		t.Fatalf("answers changed after a second compaction:\n%s\nwant\n%s", got, want)
	}

	if err := opened.PruneQueryEvents(ctx, now.Add(-50*time.Hour-23*time.Minute)); err != nil {
		t.Fatal(err)
	}
	pruned := answers()
	if got := withoutTiers(); got != pruned {
		t.Fatalf("after pruning the tiers answer\n%s\nbut the minutes answer\n%s", pruned, got)
	}
}

// Nothing is summed until blocked-client history has been counted, because an
// hour summed without it would stay short once that history is filled in.
func TestCompactQueryLogRollupsWaitsForBlockedClientHistory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC()
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-5*time.Hour), "10.0.7.16", "ads.example.com.", querylog.SourceBlocked),
	})
	if err := opened.CompactQueryLogRollups(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, found, err := opened.tierCoverage(ctx, hourRollupTier); err != nil || found {
		t.Fatalf("hour tier filled before blocked clients were counted (%t, %v)", found, err)
	}
}
