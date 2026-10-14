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

	// Paging older from the second page reaches the oldest row on a short
	// page, which is then the last.
	older, err := opened.QueryEvents(ctx, querylog.Filter{
		Page: 3, PageSize: 3, Direction: "older", Cursor: 5, KnownTotal: 7, UseKnownTotal: true, KnownTotalEstimated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if older.Page != 3 || older.TotalPages != 3 {
		t.Fatalf("short older page = page %d of %d; want 3 of 3", older.Page, older.TotalPages)
	}
	assertQueryEventIDs(t, older.Entries, []int64{4})

	// An estimate that runs a page high ends on the page that held the
	// oldest row, not on an empty one.
	high, err := opened.QueryEvents(ctx, querylog.Filter{
		Page: 4, PageSize: 3, Direction: "older", Cursor: 4, KnownTotal: 10, UseKnownTotal: true, KnownTotalEstimated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if high.Page != 3 || high.TotalPages != 3 {
		t.Fatalf("past the oldest row = page %d of %d; want 3 of 3", high.Page, high.TotalPages)
	}
	assertQueryEventIDs(t, high.Entries, []int64{6, 5, 4})

	// An exact total already knows where the log ends.
	exact, err := opened.QueryEvents(ctx, querylog.Filter{
		Page: 3, PageSize: 3, Direction: "older", Cursor: 4, KnownTotal: 7, UseKnownTotal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if exact.TotalPages != 3 || len(exact.Entries) != 0 {
		t.Fatalf("exact older page = %d pages, %d rows; want 3, 0", exact.TotalPages, len(exact.Entries))
	}

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

// Pruning by time leaves holes wherever IDs and times disagree, which the ID
// span keeps counting. Once a prune has counted the log, the estimate follows
// the real row count: deletions come off it and new rows are added on.
func TestQueryEventsEstimateDoesNotCountPrunedHoles(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	event := func(minute int) querylog.Event {
		return querylog.Event{
			OccurredAt: base.Add(time.Duration(minute) * time.Minute), ClientIP: "192.0.2.1", Name: "holes.example.",
			RecordType: dns.TypeA, Class: dns.ClassINET, Source: querylog.SourceCache, Protocol: "UDP",
		}
	}
	// IDs 1 through 10; the even IDs were logged an hour late, as a replica
	// catching up or a clock step can leave them.
	events := make([]querylog.Event, 10)
	for index := range events {
		minute := index
		if index%2 == 1 {
			minute = index + 60
		}
		events[index] = event(minute)
	}
	opened := openQueryLogStore(t, events)
	opened.exactCountRows = 1
	ctx := context.Background()
	estimate := func(want int) {
		t.Helper()
		page, err := opened.QueryEvents(ctx, querylog.Filter{Page: 1, PageSize: 3, EstimateTotal: true})
		if err != nil {
			t.Fatal(err)
		}
		if page.TotalEntries != want || !page.TotalEstimated {
			t.Fatalf("estimate = %d, estimated %t; want %d, true", page.TotalEntries, page.TotalEstimated, want)
		}
	}

	// Before any prune the span is all there is.
	estimate(10)
	// Pruning before minute 9 deletes the odd IDs 1 through 9, leaving the
	// even IDs 2 through 10: a span of 9 holding 5 rows.
	if err := opened.PruneQueryEvents(ctx, base.Add(9*time.Minute)); err != nil {
		t.Fatal(err)
	}
	estimate(5)
	// New rows add on from the newest ID counted.
	if err := opened.WriteQueryEvents(ctx, []querylog.Event{event(120), event(121)}); err != nil {
		t.Fatal(err)
	}
	estimate(7)
	// A later prune takes off what it deleted without counting again.
	if err := opened.PruneQueryEvents(ctx, base.Add(62*time.Minute)); err != nil {
		t.Fatal(err)
	}
	estimate(6)
	counted, err := opened.QueryEvents(ctx, querylog.Filter{Page: 1, PageSize: 3})
	if err != nil {
		t.Fatal(err)
	}
	if counted.TotalEntries != 6 {
		t.Fatalf("exact count = %d, want 6", counted.TotalEntries)
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

// The one-time count only sharpens the estimate, so a prune runs it after the
// rest of retention: rollups, tiers and client sightings. A prune that fails
// before then leaves the log uncounted, and the next one counts it.
func TestPruneQueryEventsCountsTheLogLast(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.October, 14, 12, 0, 0, 0, time.UTC)
	events := make([]querylog.Event, 6)
	for index := range events {
		events[index] = querylog.Event{
			OccurredAt: base.Add(time.Duration(index) * time.Minute), ClientIP: "192.0.2.1", Name: "order.example.",
			RecordType: dns.TypeA, Class: dns.ClassINET, Source: querylog.SourceCache, Protocol: "UDP",
		}
	}
	opened := openQueryLogStore(t, events)
	ctx := context.Background()
	// Client sightings are pruned last before the count; make that fail.
	if _, err := opened.database.ExecContext(ctx, "ALTER TABLE sable_client_identity RENAME TO sable_client_identity_moved"); err != nil {
		t.Fatal(err)
	}
	if err := opened.PruneQueryEvents(ctx, base.Add(2*time.Minute)); err == nil {
		t.Fatal("prune succeeded without the client identity table")
	}
	if _, ok := opened.queryLogRows.since(6); ok {
		t.Fatal("the log was counted before client sightings were pruned")
	}
	if rows := countPruneRows(t, opened, minuteRollupTable, "bucket_start <= ?", base.Add(2*time.Minute)); rows != 0 {
		t.Fatalf("%d minute rollups survived the failed prune, want 0", rows)
	}

	if _, err := opened.database.ExecContext(ctx, "ALTER TABLE sable_client_identity_moved RENAME TO sable_client_identity"); err != nil {
		t.Fatal(err)
	}
	if err := opened.PruneQueryEvents(ctx, base.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if counted, ok := opened.queryLogRows.since(6); !ok || counted != 3 {
		t.Fatalf("count after prune = %d, %t; want 3, true", counted, ok)
	}
}
