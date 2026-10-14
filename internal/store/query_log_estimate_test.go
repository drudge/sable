package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

func TestQueryEventsEstimatesOnlyTheUnfilteredTotal(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	events := make([]querylog.Event, 10)
	for index := range events {
		source := querylog.SourceCache
		if index%2 == 0 {
			source = querylog.SourceBlocked
		}
		events[index] = querylog.Event{
			OccurredAt: base.Add(time.Duration(index) * time.Minute), ClientIP: "192.0.2.1", Name: "estimate.example.",
			RecordType: dns.TypeA, Class: dns.ClassINET, Source: source, Protocol: "UDP",
		}
	}
	opened := openQueryLogStore(t, events)
	opened.exactCountRows = 5
	ctx := context.Background()
	// Pruning the oldest three leaves IDs 4 through 10.
	if err := opened.PruneQueryEvents(ctx, base.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}

	estimated, err := opened.QueryEvents(ctx, querylog.Filter{Page: 1, PageSize: 3, EstimateTotal: true})
	if err != nil {
		t.Fatal(err)
	}
	if estimated.TotalEntries != 7 || estimated.TotalPages != 3 || !estimated.TotalEstimated {
		t.Fatalf("estimated page = %d entries, %d pages, estimated %t; want 7, 3, true", estimated.TotalEntries, estimated.TotalPages, estimated.TotalEstimated)
	}
	assertQueryEventIDs(t, estimated.Entries, []int64{10, 9, 8})

	counted, err := opened.QueryEvents(ctx, querylog.Filter{Page: 1, PageSize: 3})
	if err != nil {
		t.Fatal(err)
	}
	if counted.TotalEntries != 7 || counted.TotalEstimated {
		t.Fatalf("counted page = %d entries, estimated %t; want 7, false", counted.TotalEntries, counted.TotalEstimated)
	}

	// A filter still counts exactly: the ID span says nothing about it.
	filtered, err := opened.QueryEvents(ctx, querylog.Filter{Page: 1, PageSize: 3, Source: querylog.SourceBlocked, EstimateTotal: true})
	if err != nil {
		t.Fatal(err)
	}
	if filtered.TotalEntries != 3 || filtered.TotalEstimated {
		t.Fatalf("filtered page = %d entries, estimated %t; want 3, false", filtered.TotalEntries, filtered.TotalEstimated)
	}

	// The oldest page of an estimate is a full page, since the remainder
	// isn't known.
	oldest, err := opened.QueryEvents(ctx, querylog.Filter{
		Page: 3, PageSize: 3, Direction: "oldest", KnownTotal: 7, UseKnownTotal: true, KnownTotalEstimated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !oldest.TotalEstimated {
		t.Fatal("a carried estimate lost its mark")
	}
	assertQueryEventIDs(t, oldest.Entries, []int64{6, 5, 4})

	live, err := opened.QueryEvents(ctx, querylog.Filter{
		Page: 1, PageSize: 3, KnownTotal: 6, UseKnownTotal: true, KnownTotalEstimated: true, AfterID: 9, Incremental: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if live.TotalEntries != 7 || !live.TotalEstimated {
		t.Fatalf("live page = %d entries, estimated %t; want 7, true", live.TotalEntries, live.TotalEstimated)
	}

	// A log small enough to count is counted, even when an estimate would do.
	opened.exactCountRows = 0
	small, err := opened.QueryEvents(ctx, querylog.Filter{Page: 1, PageSize: 3, EstimateTotal: true})
	if err != nil {
		t.Fatal(err)
	}
	if small.TotalEntries != 7 || small.TotalEstimated {
		t.Fatalf("small log = %d entries, estimated %t; want 7, false", small.TotalEntries, small.TotalEstimated)
	}

	empty := openQueryLogStore(t, nil)
	none, err := empty.QueryEvents(ctx, querylog.Filter{Page: 1, PageSize: 3, EstimateTotal: true})
	if err != nil {
		t.Fatal(err)
	}
	if none.TotalEntries != 0 || len(none.Entries) != 0 {
		t.Fatalf("empty log = %d entries, %d rows; want none", none.TotalEntries, len(none.Entries))
	}
}

// The estimate is only worth having while it reads the ends of the primary
// key; a plan that scans the log is the COUNT(*) it replaced.
func TestQueryLogSpanQuerySeeksRatherThanScans(t *testing.T) {
	t.Parallel()

	opened := openQueryLogStore(t, nil)
	rows, err := opened.database.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+queryLogSpanQuery)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, step := range plan {
		if strings.HasPrefix(step, "SCAN sable_query_log") {
			t.Fatalf("span query scans the log:\n%s", strings.Join(plan, "\n"))
		}
	}
}
