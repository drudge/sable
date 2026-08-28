package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

func openQueryLogStore(t testing.TB, events []querylog.Event) *Store {
	t.Helper()
	opened, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { opened.Close() })
	if err := opened.WriteQueryEvents(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	return opened
}

func TestQueryLogInsightsCountsOnlyTheSelectedWindow(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	event := func(offset time.Duration, client, name string, source querylog.Source) querylog.Event {
		return querylog.Event{
			OccurredAt: now.Add(offset), ClientIP: client, Name: name, RecordType: dns.TypeA,
			Class: dns.ClassINET, ResponseCode: dns.RcodeSuccess, Source: source, Protocol: "UDP",
		}
	}
	opened := openQueryLogStore(t, []querylog.Event{
		event(-10*time.Minute, "10.0.7.16", "API.Example.COM.", querylog.SourceCache),
		event(-20*time.Minute, "10.0.7.16", "api.example.com", querylog.SourceUpstream),
		event(-30*time.Minute, "10.0.7.168", "ads.example.com.", querylog.SourceBlocked),
		// Older than the window: counted by the day range, never by the hour.
		event(-5*time.Hour, "10.0.7.16", "api.example.com.", querylog.SourceCache),
	})

	hour, err := opened.QueryLogInsights(context.Background(), now.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if hour.Clients["10.0.7.16"] != 2 || hour.Clients["10.0.7.168"] != 1 {
		t.Fatalf("clients within the hour = %+v", hour.Clients)
	}
	// Case and the trailing root label fold together, so one domain is one row.
	if hour.Domains["api.example.com"] != 2 {
		t.Fatalf("domains within the hour = %+v", hour.Domains)
	}
	if hour.Blocked["ads.example.com"] != 1 || len(hour.Blocked) != 1 {
		t.Fatalf("blocked within the hour = %+v", hour.Blocked)
	}
	if hour.RecordTypes[dns.TypeA] != 3 || hour.ResponseCodes[dns.RcodeSuccess] != 3 {
		t.Fatalf("distributions within the hour = %+v %+v", hour.RecordTypes, hour.ResponseCodes)
	}
	if hour.Sources[string(querylog.SourceCache)] != 1 || hour.Sources[string(querylog.SourceBlocked)] != 1 {
		t.Fatalf("sources within the hour = %+v", hour.Sources)
	}

	day, err := opened.QueryLogInsights(context.Background(), now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if day.Clients["10.0.7.16"] != 3 {
		t.Fatalf("clients within the day = %+v", day.Clients)
	}
}

// A ranking links to the query log with the window it counted and an exact
// match, so the two screens have to report the same number for the same client.
func TestQueryEventsMatchesTheRankingItLinksFrom(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	event := func(offset time.Duration, client, name string) querylog.Event {
		return querylog.Event{
			OccurredAt: now.Add(offset), ClientIP: client, Name: name, RecordType: dns.TypeA,
			Class: dns.ClassINET, ResponseCode: dns.RcodeSuccess, Source: querylog.SourceCache, Protocol: "UDP",
		}
	}
	opened := openQueryLogStore(t, []querylog.Event{
		event(-10*time.Minute, "10.0.7.16", "api.example.com."),
		event(-20*time.Minute, "10.0.7.16", "api.example.com."),
		event(-30*time.Minute, "10.0.7.168", "api.example.com."),
		event(-5*time.Hour, "10.0.7.16", "api.example.com."),
	})

	insights, err := opened.QueryLogInsights(context.Background(), now.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	page, err := opened.QueryEvents(context.Background(), querylog.Filter{
		ClientIP: "10.0.7.16", Exact: true, Since: now.Add(-time.Hour), Until: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if uint64(page.TotalEntries) != insights.Clients["10.0.7.16"] {
		t.Fatalf("query log total = %d, ranking counted %d", page.TotalEntries, insights.Clients["10.0.7.16"])
	}

	// Without the exact flag the search box behaviour still matches substrings,
	// which is what the ranking link must avoid.
	loose, err := opened.QueryEvents(context.Background(), querylog.Filter{
		ClientIP: "10.0.7.16", Since: now.Add(-time.Hour), Until: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if loose.TotalEntries != 3 {
		t.Fatalf("substring search total = %d, want 3", loose.TotalEntries)
	}
}

func TestQueryEventsExactDomainIgnoresSubdomains(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	opened := openQueryLogStore(t, []querylog.Event{
		{OccurredAt: now, ClientIP: "10.0.7.16", Name: "example.com.", RecordType: dns.TypeA, Class: dns.ClassINET, Source: querylog.SourceCache, Protocol: "UDP"},
		{OccurredAt: now, ClientIP: "10.0.7.16", Name: "www.example.com.", RecordType: dns.TypeA, Class: dns.ClassINET, Source: querylog.SourceCache, Protocol: "UDP"},
	})

	exact, err := opened.QueryEvents(context.Background(), querylog.Filter{Name: "example.com", Exact: true})
	if err != nil {
		t.Fatal(err)
	}
	if exact.TotalEntries != 1 {
		t.Fatalf("exact domain total = %d, want 1", exact.TotalEntries)
	}
	loose, err := opened.QueryEvents(context.Background(), querylog.Filter{Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if loose.TotalEntries != 2 {
		t.Fatalf("substring domain total = %d, want 2", loose.TotalEntries)
	}
}

func TestQueryLogInsightsMergesLegacyBoundaryRowsWithRollups(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	opened := openQueryLogStore(t, nil)
	insertRawQueryEvent(t, opened, querylog.Event{
		OccurredAt: base.Add(time.Minute), ClientIP: "192.0.2.1", Name: "legacy.example.",
		RecordType: dns.TypeA, Class: dns.ClassINET, ResponseCode: dns.RcodeSuccess, Source: querylog.SourceCache, Protocol: "UDP",
	})
	// This legacy row shares the first rollup minute with a newly written row.
	// Reading that boundary from rollups alone would silently lose it.
	insertRawQueryEvent(t, opened, querylog.Event{
		OccurredAt: base.Add(3*time.Minute + 10*time.Second), ClientIP: "192.0.2.2", Name: "boundary.example.",
		RecordType: dns.TypeAAAA, Class: dns.ClassINET, ResponseCode: dns.RcodeSuccess, Source: querylog.SourceUpstream, Protocol: "UDP",
	})
	if err := opened.WriteQueryEvents(context.Background(), []querylog.Event{
		{OccurredAt: base.Add(3*time.Minute + 40*time.Second), ClientIP: "192.0.2.3", Name: "boundary.example.", RecordType: dns.TypeA, Class: dns.ClassINET, ResponseCode: dns.RcodeSuccess, Source: querylog.SourceBlocked, Protocol: "UDP"},
		{OccurredAt: base.Add(4*time.Minute + 10*time.Second), ClientIP: "192.0.2.4", Name: "rolled.example.", RecordType: dns.TypeA, Class: dns.ClassINET, ResponseCode: dns.RcodeNameError, Source: querylog.SourceUpstream, Protocol: "TCP"},
		{OccurredAt: base.Add(5 * time.Minute), ClientIP: "192.0.2.5", Name: "endpoint.example.", RecordType: dns.TypeA, Class: dns.ClassINET, ResponseCode: dns.RcodeSuccess, Source: querylog.SourceCache, Protocol: "UDP"},
	}); err != nil {
		t.Fatal(err)
	}

	insights, err := opened.QueryLogInsights(context.Background(), base, base.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if totalCounts(insights.Clients) != 5 || insights.Domains["boundary.example"] != 2 || insights.Domains["endpoint.example"] != 1 {
		t.Fatalf("merged insights = %+v %+v, want all five rows", insights.Clients, insights.Domains)
	}
	if insights.Blocked["boundary.example"] != 1 || insights.ResponseCodes[dns.RcodeNameError] != 1 {
		t.Fatalf("merged distributions = %+v %+v", insights.Blocked, insights.ResponseCodes)
	}
}

func TestQueryEventsUsesStableCursorPagesAndIncrementalTotals(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	events := make([]querylog.Event, 7)
	for index := range events {
		events[index] = querylog.Event{
			OccurredAt: base.Add(time.Duration(index) * time.Second), ClientIP: "192.0.2.1", Name: "page.example.",
			RecordType: dns.TypeA, Class: dns.ClassINET, ResponseCode: dns.RcodeSuccess, Source: querylog.SourceCache, Protocol: "UDP",
		}
	}
	opened := openQueryLogStore(t, events)
	first, err := opened.QueryEvents(context.Background(), querylog.Filter{Page: 1, PageSize: 3})
	if err != nil {
		t.Fatal(err)
	}
	assertQueryEventIDs(t, first.Entries, []int64{7, 6, 5})

	second, err := opened.QueryEvents(context.Background(), querylog.Filter{
		Page: 2, PageSize: 3, Cursor: 5, Direction: "older", KnownTotal: 7, UseKnownTotal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertQueryEventIDs(t, second.Entries, []int64{4, 3, 2})

	previous, err := opened.QueryEvents(context.Background(), querylog.Filter{
		Page: 1, PageSize: 3, Cursor: 4, Direction: "newer", KnownTotal: 7, UseKnownTotal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertQueryEventIDs(t, previous.Entries, []int64{7, 6, 5})

	last, err := opened.QueryEvents(context.Background(), querylog.Filter{
		Page: 3, PageSize: 3, Direction: "oldest", KnownTotal: 7, UseKnownTotal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertQueryEventIDs(t, last.Entries, []int64{1})

	if err := opened.WriteQueryEvents(context.Background(), []querylog.Event{
		{OccurredAt: base.Add(8 * time.Second), ClientIP: "192.0.2.1", Name: "page.example.", RecordType: dns.TypeA, Class: dns.ClassINET, Source: querylog.SourceCache, Protocol: "UDP"},
		{OccurredAt: base.Add(9 * time.Second), ClientIP: "192.0.2.1", Name: "page.example.", RecordType: dns.TypeA, Class: dns.ClassINET, Source: querylog.SourceCache, Protocol: "UDP"},
	}); err != nil {
		t.Fatal(err)
	}
	live, err := opened.QueryEvents(context.Background(), querylog.Filter{
		Page: 1, PageSize: 3, KnownTotal: first.TotalEntries, UseKnownTotal: true,
		AfterID: first.Entries[0].ID, Incremental: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if live.TotalEntries != 9 {
		t.Fatalf("incremental total = %d, want 9", live.TotalEntries)
	}
	assertQueryEventIDs(t, live.Entries, []int64{9, 8, 7})

	fromEmpty, err := opened.QueryEvents(context.Background(), querylog.Filter{
		Page: 1, PageSize: 3, KnownTotal: 0, UseKnownTotal: true,
		AfterID: 0, Incremental: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fromEmpty.TotalEntries != 9 {
		t.Fatalf("empty-log incremental total = %d, want 9", fromEmpty.TotalEntries)
	}
}

func TestQueryLogInsightsRanksAfterCombiningRollupsAndBoundaries(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	events := []querylog.Event{{
		OccurredAt: base.Add(time.Minute), ClientIP: "192.0.2.1", Name: "coverage.example.",
		RecordType: dns.TypeA, Class: dns.ClassINET, Source: querylog.SourceCache, Protocol: "UDP",
	}}
	for index := 0; index <= maximumInsightRanks; index++ {
		events = append(events, querylog.Event{
			OccurredAt: base.Add(2*time.Minute + time.Duration(index)*time.Millisecond),
			ClientIP:   "192.0.2.1", Name: fmt.Sprintf("domain-%04d.example.", index),
			RecordType: dns.TypeA, Class: dns.ClassINET, Source: querylog.SourceCache, Protocol: "UDP",
		})
	}
	for range 10 {
		events = append(events, querylog.Event{
			OccurredAt: base.Add(4*time.Minute + 10*time.Second),
			ClientIP:   "192.0.2.1", Name: "domain-1000.example.",
			RecordType: dns.TypeA, Class: dns.ClassINET, Source: querylog.SourceCache, Protocol: "UDP",
		})
	}
	opened := openQueryLogStore(t, events)
	insights, err := opened.QueryLogInsights(context.Background(), base, base.Add(4*time.Minute+30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got := insights.Domains["domain-1000.example"]; got != 11 {
		t.Fatalf("combined boundary and rollup count = %d, want 11", got)
	}
}

func insertRawQueryEvent(t *testing.T, opened *Store, event querylog.Event) {
	t.Helper()
	_, err := opened.database.Exec(opened.queryLogInsert(),
		event.OccurredAt.UTC(), event.ClientIP, queryLogClientKey(event.ClientIP), event.Name, queryLogDomainKey(event.Name),
		event.RecordType, event.Class, event.ResponseCode, event.Source, event.Protocol, event.Answer, "{}", event.Duration.Microseconds(),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func totalCounts(values map[string]uint64) uint64 {
	var total uint64
	for _, count := range values {
		total += count
	}
	return total
}

func assertQueryEventIDs(t *testing.T, entries []querylog.Entry, want []int64) {
	t.Helper()
	if len(entries) != len(want) {
		t.Fatalf("entry count = %d, want %d: %+v", len(entries), len(want), entries)
	}
	for index, entry := range entries {
		if entry.ID != want[index] {
			t.Fatalf("entry IDs[%d] = %d, want %d", index, entry.ID, want[index])
		}
	}
}

func BenchmarkQueryLogInsightsHundredThousandEvents(b *testing.B) {
	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	events := make([]querylog.Event, 100_000)
	for index := range events {
		events[index] = querylog.Event{
			OccurredAt: base.Add(time.Duration(index) * 10 * time.Millisecond),
			ClientIP:   fmt.Sprintf("192.0.2.%d", index%64+1),
			Name:       fmt.Sprintf("service-%d.example.", index%256),
			RecordType: dns.TypeA, Class: dns.ClassINET, ResponseCode: dns.RcodeSuccess,
			Source: querylog.SourceCache, Protocol: "UDP",
		}
	}
	opened := openQueryLogStore(b, nil)
	for start := 0; start < len(events); start += 256 {
		end := min(start+256, len(events))
		if err := opened.WriteQueryEvents(context.Background(), events[start:end]); err != nil {
			b.Fatal(err)
		}
	}
	since, until := base, base.Add(20*time.Minute)

	b.Run("rollups", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := opened.QueryLogInsights(context.Background(), since, until); err != nil {
				b.Fatal(err)
			}
		}
	})
	if _, err := opened.database.Exec("DELETE FROM sable_query_log_rollup"); err != nil {
		b.Fatal(err)
	}
	b.Run("raw_log", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := opened.QueryLogInsights(context.Background(), since, until); err != nil {
				b.Fatal(err)
			}
		}
	})
}
