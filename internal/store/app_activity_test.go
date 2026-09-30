package store

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

// rewindAppMarker dates the app dimensions back to since, as though they had
// been written for all the history a test seeds.
func rewindAppMarker(t *testing.T, opened *Store, since time.Time) {
	t.Helper()
	if _, err := opened.database.ExecContext(context.Background(), "UPDATE sable_metadata SET value = ? WHERE key = ?",
		since.UTC().Format(time.RFC3339Nano), appRollupSinceKey); err != nil {
		t.Fatal(err)
	}
}

func TestAppActivityCountsEveryAppByClient(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	opened := openQueryLogStore(t, []querylog.Event{
		// The oldest minute is read from the raw log; the rest from rollups.
		blockingEvent(now.Add(-50*time.Minute), "10.0.7.16", "rr3---sn-abc.googlevideo.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-40*time.Minute), "10.0.7.16", "WWW.YouTube.com", querylog.SourceCache),
		blockingEvent(now.Add(-30*time.Minute), "10.0.7.20", "eu.tectonic.remarkable.com.", querylog.SourceError),
		blockingEvent(now.Add(-30*time.Minute), "10.0.7.20", "ping.remarkable.com.", querylog.SourceError),
		blockingEvent(now.Add(-20*time.Minute), "10.0.7.20", "ping.remarkable.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-10*time.Minute), "10.0.7.9", "www.netflix.com.", querylog.SourceBlocked),
		// A name no app owns is left out.
		blockingEvent(now.Add(-10*time.Minute), "10.0.7.9", "www.example.org.", querylog.SourceError),
		// Outside the window.
		blockingEvent(now.Add(-3*time.Hour), "10.0.7.99", "www.youtube.com.", querylog.SourceUpstream),
	})
	rewindAppMarker(t, opened, now.Add(-4*time.Hour))

	activity, err := opened.AppActivity(context.Background(), now.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]querylog.AppCounts{
		"youtube":    {"10.0.7.16": {Queries: 2}},
		"remarkable": {"10.0.7.20": {Queries: 3, Failed: 2}},
		"netflix":    {"10.0.7.9": {Queries: 1, Blocked: 1}},
	}
	if len(activity.Clients) != len(want) {
		t.Fatalf("apps = %+v, want %+v", activity.Clients, want)
	}
	for app, clients := range want {
		for client, counts := range clients {
			if got := activity.Clients[app][client]; got != counts || len(activity.Clients[app]) != len(clients) {
				t.Fatalf("%s from %s = %+v (of %d clients), want %+v", app, client, got, len(activity.Clients[app]), counts)
			}
		}
	}
	if !activity.Since.IsZero() {
		t.Fatalf("Since = %s, want zero for a window counted whole", activity.Since)
	}
}

func TestAppActivityReportsWhenCountingBegan(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	began := now.Add(-30 * time.Minute)
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-50*time.Minute), "10.0.7.16", "www.youtube.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-10*time.Minute), "10.0.7.16", "www.youtube.com.", querylog.SourceUpstream),
	})
	rewindAppMarker(t, opened, began)

	activity, err := opened.AppActivity(context.Background(), now.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if got := activity.Clients["youtube"]["10.0.7.16"].Queries; got != 1 {
		t.Fatalf("queries = %d, want only the one after counting began", got)
	}
	if !activity.Since.Equal(began) {
		t.Fatalf("Since = %s, want %s", activity.Since, began)
	}
	if _, err := opened.AppActivity(context.Background(), now.Add(-time.Hour), now.Add(-45*time.Minute)); err != nil {
		t.Fatalf("a window before counting began: %v", err)
	}
}

func TestAppDomainsCountsAnAppsNamesWithFailures(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-50*time.Minute), "10.0.7.20", "eu.tectonic.remarkable.com.", querylog.SourceError),
		blockingEvent(now.Add(-40*time.Minute), "10.0.7.20", "eu.tectonic.remarkable.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-30*time.Minute), "10.0.7.20", "ping.remarkable.com.", querylog.SourceError),
		// The company's website is not one of the app's names.
		blockingEvent(now.Add(-20*time.Minute), "10.0.7.20", "remarkable.com.", querylog.SourceUpstream),
	})
	rewindAppMarker(t, opened, now.Add(-4*time.Hour))

	domains, err := opened.AppDomains(context.Background(), now.Add(-time.Hour), now,
		[]string{"device.cloud.remarkable.com", "tectonic.remarkable.com", "ping.remarkable.com", "cloud.remarkable.engineering"})
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(domains, func(left, right querylog.AppDomain) int { return compareStrings(left.Name, right.Name) })
	want := []querylog.AppDomain{
		{Name: "eu.tectonic.remarkable.com", Queries: 2, Failed: 1},
		{Name: "ping.remarkable.com", Queries: 1, Failed: 1},
	}
	if !slices.Equal(domains, want) {
		t.Fatalf("domains = %+v, want %+v", domains, want)
	}
}

func compareStrings(left, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func TestAppSightingsSpanEveryClient(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-3*time.Hour), "10.0.7.16", "www.youtube.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-2*time.Hour), "10.0.7.20", "i.ytimg.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-time.Hour), "10.0.7.16", "rr1---sn-abc.googlevideo.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-time.Hour), "10.0.7.16", "www.example.org.", querylog.SourceUpstream),
	})
	sightings, err := opened.AppSightings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	youtube := sightings.Apps["youtube"]
	if len(sightings.Apps) != 1 || !youtube.FirstSeen.Equal(now.Add(-3*time.Hour)) || !youtube.LastSeen.Equal(now.Add(-time.Hour)) {
		t.Fatalf("sightings = %+v", sightings.Apps)
	}
	if sightings.SeenSince.IsZero() {
		t.Fatal("SeenSince is zero, want when tracking began")
	}
}

func TestBackfillAppRollupsCountsHistoryIntoEveryTier(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	began := now.Add(-20 * time.Minute).Truncate(time.Minute).Add(30 * time.Second)
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-30*time.Hour), "10.0.7.16", "www.youtube.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-26*time.Hour), "10.0.7.20", "ping.remarkable.com.", querylog.SourceError),
		blockingEvent(now.Add(-3*time.Hour), "10.0.7.16", "www.youtube.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-3*time.Hour), "10.0.7.9", "www.netflix.com.", querylog.SourceBlocked),
		// Either side of the moment the dimensions began, in the same minute.
		blockingEvent(began.Add(-10*time.Second), "10.0.7.20", "ping.remarkable.com.", querylog.SourceError),
		blockingEvent(began.Add(10*time.Second), "10.0.7.20", "ping.remarkable.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-5*time.Minute), "10.0.7.16", "www.youtube.com.", querylog.SourceUpstream),
	})
	// Sum the history into hours and days first, as a server upgraded from a
	// version without the app dimensions already has.
	if _, err := opened.database.ExecContext(ctx, "INSERT INTO sable_metadata (key, value) VALUES (?, ?)",
		blockedClientBackfilledKey, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := opened.CompactQueryLogRollups(ctx, now); err != nil {
		t.Fatal(err)
	}
	// Rewind the app dimensions to began: nothing before its minute, and only
	// the query written after it within that minute.
	for _, statement := range []struct {
		sql       string
		arguments []any
	}{
		{"UPDATE sable_metadata SET value = ? WHERE key = ?", []any{began.Format(time.RFC3339Nano), appRollupSinceKey}},
		{"DELETE FROM sable_query_log_rollup WHERE dimension IN (?, ?, ?, ?) AND bucket_start < ?", []any{
			queryLogRollupFailed, queryLogRollupAppClient, queryLogRollupAppClientFailed, queryLogRollupAppClientBlocked, began.Truncate(time.Minute),
		}},
		{"DELETE FROM sable_query_log_rollup WHERE dimension IN (?, ?) AND bucket_start = ?", []any{
			queryLogRollupFailed, queryLogRollupAppClientFailed, began.Truncate(time.Minute),
		}},
		{"DELETE FROM sable_query_log_rollup_hour WHERE dimension IN (?, ?, ?, ?)", []any{
			queryLogRollupFailed, queryLogRollupAppClient, queryLogRollupAppClientFailed, queryLogRollupAppClientBlocked,
		}},
		{"DELETE FROM sable_query_log_rollup_day WHERE dimension IN (?, ?, ?, ?)", []any{
			queryLogRollupFailed, queryLogRollupAppClient, queryLogRollupAppClientFailed, queryLogRollupAppClientBlocked,
		}},
	} {
		if _, err := opened.database.ExecContext(ctx, statement.sql, statement.arguments...); err != nil {
			t.Fatal(err)
		}
	}
	window := now.Add(-48 * time.Hour)
	if activity, err := opened.AppActivity(ctx, window, now); err != nil || activity.Since.IsZero() {
		t.Fatalf("before the backfill: Since = %v, %v; want when counting began", activity.Since, err)
	}

	filled, err := opened.BackfillAppRollups(ctx)
	if err != nil || !filled {
		t.Fatalf("BackfillAppRollups = %t, %v", filled, err)
	}
	check := func(stage string) {
		t.Helper()
		activity, err := opened.AppActivity(ctx, window, now)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]querylog.AppCounts{
			"youtube":    {Queries: 3},
			"remarkable": {Queries: 3, Failed: 2},
			"netflix":    {Queries: 1, Blocked: 1},
		}
		for app, counts := range want {
			var total querylog.AppCounts
			for _, client := range activity.Clients[app] {
				total.Queries, total.Failed, total.Blocked = total.Queries+client.Queries, total.Failed+client.Failed, total.Blocked+client.Blocked
			}
			if total != counts {
				t.Fatalf("%s: %s = %+v, want %+v", stage, app, total, counts)
			}
		}
		if !activity.Since.IsZero() {
			t.Fatalf("%s: Since = %s, want zero once history is counted", stage, activity.Since)
		}
	}
	check("after the backfill")
	var hours int
	if err := opened.database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sable_query_log_rollup_hour WHERE dimension = ?",
		queryLogRollupAppClient).Scan(&hours); err != nil || hours == 0 {
		t.Fatalf("hour rows = %d, %v; want the backfill summed into hours", hours, err)
	}
	if filled, err := opened.BackfillAppRollups(ctx); err != nil || filled {
		t.Fatalf("second BackfillAppRollups = %t, %v", filled, err)
	}
	check("after a second run")
}
