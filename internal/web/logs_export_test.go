package web

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/store"
)

// insertingPager logs more queries after the first page is read, the way a
// busy server keeps logging while an operator downloads the log.
type insertingPager struct {
	*store.Store
	t       *testing.T
	pending []querylog.Event
	reads   int
}

func (pager *insertingPager) QueryEvents(ctx context.Context, filter querylog.Filter) (querylog.Page, error) {
	pager.reads++
	page, err := pager.Store.QueryEvents(ctx, filter)
	if pager.reads == 1 {
		if err := pager.WriteQueryEvents(ctx, pager.pending); err != nil {
			pager.t.Fatal(err)
		}
	}
	return page, err
}

func exportTestEvents(prefix string, count int, at time.Time) []querylog.Event {
	events := make([]querylog.Event, 0, count)
	for index := range count {
		events = append(events, querylog.Event{
			OccurredAt: at.Add(time.Duration(index) * time.Millisecond), ClientIP: "192.0.2.10",
			Name: fmt.Sprintf("%s%04d.example.", prefix, index), RecordType: dns.TypeA, Class: dns.ClassINET,
			Source: querylog.SourceUpstream, Protocol: "UDP",
		})
	}
	return events
}

func TestQueryLogExportIgnoresRowsLoggedDuringTheExport(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	opened, err := store.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { opened.Close() })
	start := time.Now().UTC().Add(-time.Hour)
	const existing = 2*queryLogExportPageSize + 37
	if err := opened.WriteQueryEvents(ctx, exportTestEvents("old", existing, start)); err != nil {
		t.Fatal(err)
	}
	pager := &insertingPager{Store: opened, t: t, pending: exportTestEvents("new", queryLogExportPageSize, start.Add(time.Minute))}
	filter := querylog.Filter{Page: 1, PageSize: queryLogExportPageSize}
	first, err := pager.QueryEvents(ctx, filter)
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := writeQueryLogCSV(ctx, &output, pager, filter, first); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&output).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	rows = rows[1:]
	if len(rows) != existing {
		t.Fatalf("exported %d rows, want the %d that existed when the export began", len(rows), existing)
	}
	for index, row := range rows {
		if want := fmt.Sprintf("old%04d.example.", existing-1-index); row[2] != want {
			t.Fatalf("row %d = %s, want %s", index, row[2], want)
		}
	}
	if pager.reads != 3 {
		t.Fatalf("export read %d pages, want 3", pager.reads)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("client went away") }

func TestQueryLogExportReportsWriteErrors(t *testing.T) {
	t.Parallel()
	entries := make([]querylog.Entry, 0, 3)
	for index := range 3 {
		entries = append(entries, querylog.Entry{ID: int64(3 - index), Event: querylog.Event{Name: "example.test.", OccurredAt: time.Now()}})
	}
	page := querylog.Page{Entries: entries, Page: 1, PageSize: queryLogExportPageSize, TotalEntries: 3, TotalPages: 1}
	err := writeQueryLogCSV(context.Background(), failingWriter{}, testQueryLog{}, querylog.Filter{PageSize: queryLogExportPageSize}, page)
	if err == nil {
		t.Fatal("an export to a closed connection reported success")
	}
}
