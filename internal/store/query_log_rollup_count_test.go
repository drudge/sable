package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

func TestQueryEventsCountsOneDimensionFiltersFromRollups(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	sources := []querylog.Source{querylog.SourceBlocked, querylog.SourceCache, querylog.SourceUpstream}
	events := make([]querylog.Event, 0, 1100)
	for index := range 1100 {
		// Every 4 minutes 10 seconds over three days, so the rollups fill
		// whole days, whole hours, and ragged minutes at each end.
		at := now.Add(-76*time.Hour + time.Duration(index)*250*time.Second)
		event := blockingEvent(at, fmt.Sprintf("10.0.7.%d", index%7), fmt.Sprintf("host-%d.example.com.", index%13), sources[index%3])
		event.ResponseCode = []int{dns.RcodeSuccess, dns.RcodeNameError}[index%2]
		event.RecordType = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS, dns.TypeA, dns.TypePTR}[index%5]
		events = append(events, event)
	}
	opened := openQueryLogStore(t, events)
	opened.exactCountRows = 5
	// Before the hour tier fills, a month of minutes is no faster to sum
	// than the log is to count, so the log is counted.
	uncompacted, err := opened.QueryEvents(ctx, querylog.Filter{Source: querylog.SourceBlocked, EstimateTotal: true})
	if err != nil {
		t.Fatal(err)
	}
	if uncompacted.TotalEntries != 367 || uncompacted.TotalEstimated {
		t.Fatalf("before compaction: total %d, estimated %t; want 367, false", uncompacted.TotalEntries, uncompacted.TotalEstimated)
	}
	if _, err := opened.database.ExecContext(ctx, "INSERT INTO sable_metadata (key, value) VALUES (?, ?)",
		blockedClientBackfilledKey, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := opened.CompactQueryLogRollups(ctx, now); err != nil {
		t.Fatal(err)
	}
	// Prune mid-minute, so rows of the cutoff minute outlive its rollup.
	if err := opened.PruneQueryEvents(ctx, now.Add(-70*time.Hour+30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if days := countPruneRows(t, opened, "sable_query_log_rollup_day", ""); days == 0 {
		t.Fatal("the day tier is empty, so the test would not read it")
	}

	nxdomain := dns.RcodeNameError
	filters := []struct {
		name   string
		filter querylog.Filter
		rolled bool
	}{
		{"source", querylog.Filter{Source: querylog.SourceBlocked}, true},
		{"response code", querylog.Filter{ResponseCode: &nxdomain}, true},
		{"record type", querylog.Filter{RecordTypes: []uint16{dns.TypeAAAA}}, true},
		{"whole client", querylog.Filter{ClientIP: "10.0.7.3", ExactClient: true}, false},
		{"two record types", querylog.Filter{RecordTypes: []uint16{dns.TypeA, dns.TypeAAAA}}, false},
		{"source and response code", querylog.Filter{Source: querylog.SourceCache, ResponseCode: &nxdomain}, false},
		{"source in a window", querylog.Filter{Source: querylog.SourceBlocked, Since: now.Add(-24 * time.Hour)}, false},
		{"protocol", querylog.Filter{Protocol: "udp"}, false},
	}
	for _, test := range filters {
		exact := test.filter
		exact.PageSize = 10
		counted, err := opened.QueryEvents(ctx, exact)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		estimate := exact
		estimate.EstimateTotal = true
		page, err := opened.QueryEvents(ctx, estimate)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if counted.TotalEntries == 0 || page.TotalEntries != counted.TotalEntries || page.TotalEstimated != test.rolled {
			t.Fatalf("%s: total %d, estimated %t; want %d, %t",
				test.name, page.TotalEntries, page.TotalEstimated, counted.TotalEntries, test.rolled)
		}
	}

	// Rows from before the rollups began have none, so the log is counted.
	if _, err := opened.database.ExecContext(ctx, "DELETE FROM sable_query_log_rollup WHERE bucket_start < ?", now.Add(-60*time.Hour)); err != nil {
		t.Fatal(err)
	}
	counted, err := opened.QueryEvents(ctx, querylog.Filter{Source: querylog.SourceBlocked})
	if err != nil {
		t.Fatal(err)
	}
	page, err := opened.QueryEvents(ctx, querylog.Filter{Source: querylog.SourceBlocked, EstimateTotal: true})
	if err != nil {
		t.Fatal(err)
	}
	if page.TotalEntries != counted.TotalEntries || page.TotalEstimated {
		t.Fatalf("before the rollups: total %d, estimated %t; want %d, false", page.TotalEntries, page.TotalEstimated, counted.TotalEntries)
	}
}
