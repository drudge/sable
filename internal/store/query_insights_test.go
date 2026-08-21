package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

func openQueryLogStore(t *testing.T, events []querylog.Event) *Store {
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
