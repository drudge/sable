package store

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

func blockingEvent(at time.Time, client, name string, source querylog.Source) querylog.Event {
	return querylog.Event{
		OccurredAt: at, ClientIP: client, Name: name, RecordType: dns.TypeA,
		Class: dns.ClassINET, ResponseCode: dns.RcodeNameError, Source: source, Protocol: "UDP",
	}
}

func TestBlockingActivityCountsTheBoundedWindowExactly(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	opened := openQueryLogStore(t, []querylog.Event{
		// The oldest minute is read from the raw log; the rest from rollups.
		blockingEvent(now.Add(-50*time.Minute), "10.0.7.16", "ads.example.com.", querylog.SourceBlocked),
		blockingEvent(now.Add(-40*time.Minute), "10.0.7.16", "Ads.Example.com", querylog.SourceBlocked),
		blockingEvent(now.Add(-30*time.Minute), "10.0.7.168", "ads.example.com.", querylog.SourceBlocked),
		blockingEvent(now.Add(-20*time.Minute), "10.0.7.168", "pixel.example.net.", querylog.SourceBlocked),
		blockingEvent(now.Add(-10*time.Minute), "10.0.7.9", "www.example.org.", querylog.SourceUpstream),
		// Outside the window on both sides.
		blockingEvent(now.Add(-3*time.Hour), "10.0.7.99", "old.example.com.", querylog.SourceBlocked),
	})

	activity, err := opened.BlockingActivity(context.Background(), now.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if activity.Queries != 5 || activity.Blocked != 4 {
		t.Fatalf("queries = %d, blocked = %d, want 5 and 4", activity.Queries, activity.Blocked)
	}
	if activity.BlockedDomains != 2 || activity.BlockedClients != 2 {
		t.Fatalf("distinct domains = %d, clients = %d, want 2 and 2", activity.BlockedDomains, activity.BlockedClients)
	}
	if activity.TopDomains["ads.example.com"] != 3 || activity.TopDomains["pixel.example.net"] != 1 {
		t.Fatalf("top domains = %+v", activity.TopDomains)
	}
	if activity.TopClients["10.0.7.16"] != 2 || activity.TopClients["10.0.7.168"] != 2 {
		t.Fatalf("top clients = %+v", activity.TopClients)
	}
	if _, found := activity.TopClients["10.0.7.99"]; found {
		t.Fatal("a client blocked only outside the window was ranked")
	}

	// The Logs link carries the same client, the blocked source, an exact
	// match, and the window, so it has to report the same number.
	page, err := opened.QueryEvents(context.Background(), querylog.Filter{
		ClientIP: "10.0.7.168", Source: querylog.SourceBlocked, Exact: true,
		Since: now.Add(-time.Hour), Until: now, PageSize: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if uint64(page.TotalEntries) != activity.TopClients["10.0.7.168"] {
		t.Fatalf("query log reports %d blocked queries for the client, insights %d", page.TotalEntries, activity.TopClients["10.0.7.168"])
	}
}

// A database upgraded to the blocked-client dimension still holds rollup
// minutes written without it. Those minutes must be recounted from the raw log
// rather than silently counted as zero.
func TestBlockingActivityRecountsClientsRolledUpBeforeTheDimensionExisted(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-50*time.Minute), "10.0.7.16", "ads.example.com.", querylog.SourceBlocked),
		blockingEvent(now.Add(-40*time.Minute), "10.0.7.16", "ads.example.com.", querylog.SourceBlocked),
		blockingEvent(now.Add(-30*time.Minute), "10.0.7.16", "ads.example.com.", querylog.SourceBlocked),
		blockingEvent(now.Add(-5*time.Minute), "10.0.7.16", "ads.example.com.", querylog.SourceBlocked),
	})
	marker := now.Add(-20 * time.Minute)
	ctx := context.Background()
	if _, err := opened.database.ExecContext(ctx,
		"UPDATE sable_metadata SET value = ? WHERE key = ?", marker.Format(time.RFC3339Nano), blockedClientRollupSinceKey,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.database.ExecContext(ctx,
		"DELETE FROM sable_query_log_rollup WHERE dimension = ? AND bucket_start < ?", queryLogRollupBlockedClient, marker,
	); err != nil {
		t.Fatal(err)
	}

	activity, err := opened.BlockingActivity(ctx, now.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if activity.TopClients["10.0.7.16"] != 4 || activity.BlockedClients != 1 {
		t.Fatalf("clients = %+v (%d distinct), want 4 blocked queries from one client", activity.TopClients, activity.BlockedClients)
	}
}

func TestBlockingActivityRejectsAnUnboundedWindow(t *testing.T) {
	t.Parallel()
	opened := openQueryLogStore(t, nil)
	if _, err := opened.BlockingActivity(context.Background(), time.Time{}, time.Now()); err == nil {
		t.Fatal("BlockingActivity accepted an open-ended window")
	}
}

func TestBlockedNamesMatchingAppliesAllowRuleSemantics(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-50*time.Minute), "10.0.7.16", "telemetry.example.com.", querylog.SourceBlocked),
		blockingEvent(now.Add(-40*time.Minute), "10.0.7.16", "telemetry.example.com.", querylog.SourceBlocked),
		blockingEvent(now.Add(-30*time.Minute), "10.0.7.16", "cdn.shop.example.", querylog.SourceBlocked),
		// A wildcard rule does not cover the name it is written against.
		blockingEvent(now.Add(-30*time.Minute), "10.0.7.16", "shop.example.", querylog.SourceBlocked),
		// The underscore is a LIKE wildcard and must be matched literally.
		blockingEvent(now.Add(-25*time.Minute), "10.0.7.16", "a.x_y.example.", querylog.SourceBlocked),
		blockingEvent(now.Add(-25*time.Minute), "10.0.7.16", "a.xzy.example.", querylog.SourceBlocked),
		// Allowed traffic for a matching name is not a past block.
		blockingEvent(now.Add(-10*time.Minute), "10.0.7.16", "telemetry.example.com.", querylog.SourceUpstream),
	})

	matched, err := opened.BlockedNamesMatching(context.Background(), now.Add(-time.Hour), now,
		[]string{"telemetry.example.com", "never-blocked.example"}, []string{"shop.example", "x_y.example"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint64{"telemetry.example.com": 2, "cdn.shop.example": 1, "a.x_y.example": 1}
	if len(matched) != len(want) {
		t.Fatalf("matched = %+v, want %+v", matched, want)
	}
	for name, hits := range want {
		if matched[name] != hits {
			t.Fatalf("matched[%s] = %d, want %d (all: %+v)", name, matched[name], hits, matched)
		}
	}
}

func TestBlockedNameEvidenceMatchesTheQueryLogLink(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	first, last := now.Add(-50*time.Minute), now.Add(-5*time.Minute)
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(first, "10.0.7.16", "telemetry.example.com.", querylog.SourceBlocked),
		blockingEvent(now.Add(-30*time.Minute), "10.0.7.16", "telemetry.example.com.", querylog.SourceBlocked),
		blockingEvent(last, "10.0.7.168", "Telemetry.Example.com", querylog.SourceBlocked),
		// A longer name is a different name, not a substring match.
		blockingEvent(now.Add(-6*time.Minute), "10.0.7.9", "eu.telemetry.example.com.", querylog.SourceBlocked),
		blockingEvent(now.Add(-2*time.Hour), "10.0.7.16", "telemetry.example.com.", querylog.SourceBlocked),
	})

	evidence, err := opened.BlockedNameEvidence(context.Background(), now.Add(-time.Hour), now, "telemetry.example.com.", 10)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Blocked != 3 || evidence.Clients["10.0.7.16"] != 2 || evidence.Clients["10.0.7.168"] != 1 || len(evidence.Clients) != 2 {
		t.Fatalf("evidence = %+v", evidence)
	}
	if !evidence.FirstBlocked.Equal(first) || !evidence.LastBlocked.Equal(last) {
		t.Fatalf("first/last blocked = %s / %s, want %s / %s", evidence.FirstBlocked, evidence.LastBlocked, first, last)
	}

	page, err := opened.QueryEvents(context.Background(), querylog.Filter{
		Name: "telemetry.example.com", Source: querylog.SourceBlocked, Exact: true,
		Since: now.Add(-time.Hour), Until: now, PageSize: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if uint64(page.TotalEntries) != evidence.Blocked {
		t.Fatalf("query log reports %d, evidence %d", page.TotalEntries, evidence.Blocked)
	}

	limited, err := opened.BlockedNameEvidence(context.Background(), now.Add(-time.Hour), now, "telemetry.example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	if limited.Blocked != 3 || limited.ClientCount != 2 || len(limited.Clients) != 1 || limited.Clients["10.0.7.16"] != 2 {
		t.Fatalf("limited evidence = %+v, want the full total and the busiest client", limited)
	}
}
