package store

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/drudge/sable/internal/serverlog"
)

func openServerLogStore(t *testing.T) *Store {
	t.Helper()
	opened, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { opened.Close() })
	return opened
}

func TestServerLogEntriesRoundTripWithAttributes(t *testing.T) {
	t.Parallel()

	opened := openServerLogStore(t)
	occurred := time.Now().Add(-time.Minute).UTC().Truncate(time.Millisecond)
	if err := opened.WriteServerLogEntries(context.Background(), []serverlog.Entry{{
		OccurredAt: occurred,
		Level:      slog.LevelError,
		Message:    "zone transfer failed",
		Attributes: map[string]string{"zone": "example.com", "peer": "192.0.2.53"},
	}}); err != nil {
		t.Fatalf("WriteServerLogEntries() error = %v", err)
	}

	page, err := opened.ServerLogEntries(context.Background(), serverlog.Query{})
	if err != nil {
		t.Fatalf("ServerLogEntries() error = %v", err)
	}
	if page.TotalEntries != 1 || len(page.Entries) != 1 {
		t.Fatalf("page = %+v, want a single entry", page)
	}
	entry := page.Entries[0]
	if entry.Message != "zone transfer failed" || entry.Level != slog.LevelError {
		t.Fatalf("entry = %+v, want the error it was written as", entry)
	}
	if entry.Attributes["zone"] != "example.com" || entry.Attributes["peer"] != "192.0.2.53" {
		t.Fatalf("attributes = %v, want both to survive the round trip", entry.Attributes)
	}
	if !entry.OccurredAt.UTC().Equal(occurred) {
		t.Fatalf("OccurredAt = %v, want %v", entry.OccurredAt.UTC(), occurred)
	}
}

func TestServerLogEntriesOrderNewestFirstAndPage(t *testing.T) {
	t.Parallel()

	opened := openServerLogStore(t)
	base := time.Now().Add(-time.Hour).UTC()
	entries := make([]serverlog.Entry, 0, 5)
	for index := range 5 {
		entries = append(entries, serverlog.Entry{
			OccurredAt: base.Add(time.Duration(index) * time.Minute),
			Level:      slog.LevelInfo,
			Message:    "entry " + string(rune('a'+index)),
		})
	}
	if err := opened.WriteServerLogEntries(context.Background(), entries); err != nil {
		t.Fatalf("WriteServerLogEntries() error = %v", err)
	}

	first, err := opened.ServerLogEntries(context.Background(), serverlog.Query{Page: 1, PageSize: 2})
	if err != nil {
		t.Fatalf("ServerLogEntries() error = %v", err)
	}
	if first.TotalEntries != 5 || first.TotalPages != 3 {
		t.Fatalf("first page = %+v, want 5 entries over 3 pages", first)
	}
	if len(first.Entries) != 2 || first.Entries[0].Message != "entry e" || first.Entries[1].Message != "entry d" {
		t.Fatalf("first page entries = %+v, want the newest two", first.Entries)
	}
	last, err := opened.ServerLogEntries(context.Background(), serverlog.Query{Page: 3, PageSize: 2})
	if err != nil {
		t.Fatalf("ServerLogEntries() error = %v", err)
	}
	if len(last.Entries) != 1 || last.Entries[0].Message != "entry a" {
		t.Fatalf("last page entries = %+v, want the oldest entry alone", last.Entries)
	}
}

// A page past the end clamps rather than returning nothing, so a filter that
// shrinks the result set does not strand the reader on an empty page.
func TestServerLogEntriesClampPageBeyondTheEnd(t *testing.T) {
	t.Parallel()

	opened := openServerLogStore(t)
	if err := opened.WriteServerLogEntries(context.Background(), []serverlog.Entry{
		{OccurredAt: time.Now(), Level: slog.LevelInfo, Message: "only"},
	}); err != nil {
		t.Fatalf("WriteServerLogEntries() error = %v", err)
	}
	page, err := opened.ServerLogEntries(context.Background(), serverlog.Query{Page: 99, PageSize: 50})
	if err != nil {
		t.Fatalf("ServerLogEntries() error = %v", err)
	}
	if page.Page != 1 || len(page.Entries) != 1 {
		t.Fatalf("page = %+v, want the request clamped back to the only page", page)
	}
}

// Level filtering has to match how the live buffer names levels, where every
// value between one threshold and the next carries the lower name.
func TestServerLogEntriesFilterByLevelName(t *testing.T) {
	t.Parallel()

	opened := openServerLogStore(t)
	if err := opened.WriteServerLogEntries(context.Background(), []serverlog.Entry{
		{OccurredAt: time.Now(), Level: slog.LevelDebug, Message: "debug entry"},
		{OccurredAt: time.Now(), Level: slog.LevelInfo, Message: "info entry"},
		{OccurredAt: time.Now(), Level: slog.LevelInfo + 2, Message: "still info"},
		{OccurredAt: time.Now(), Level: slog.LevelWarn, Message: "warn entry"},
		{OccurredAt: time.Now(), Level: slog.LevelError, Message: "error entry"},
		{OccurredAt: time.Now(), Level: slog.LevelError + 4, Message: "still error"},
	}); err != nil {
		t.Fatalf("WriteServerLogEntries() error = %v", err)
	}

	for _, testCase := range []struct {
		level string
		want  int
	}{
		{"debug", 1},
		{"info", 2},
		{"warn", 1},
		{"error", 2},
		{"all", 6},
		{"", 6},
	} {
		page, err := opened.ServerLogEntries(context.Background(), serverlog.Query{Level: testCase.level})
		if err != nil {
			t.Fatalf("ServerLogEntries(%q) error = %v", testCase.level, err)
		}
		if page.TotalEntries != testCase.want {
			t.Fatalf("level %q matched %d entries, want %d", testCase.level, page.TotalEntries, testCase.want)
		}
	}
}

// The live buffer matches a search against attributes as well as the message,
// so the persisted view has to answer the same question the same way.
func TestServerLogEntriesSearchMessageAndAttributes(t *testing.T) {
	t.Parallel()

	opened := openServerLogStore(t)
	if err := opened.WriteServerLogEntries(context.Background(), []serverlog.Entry{
		{OccurredAt: time.Now(), Level: slog.LevelInfo, Message: "listener started", Attributes: map[string]string{"address": "127.0.0.1:53"}},
		{OccurredAt: time.Now(), Level: slog.LevelInfo, Message: "zone loaded", Attributes: map[string]string{"zone": "example.com"}},
	}); err != nil {
		t.Fatalf("WriteServerLogEntries() error = %v", err)
	}

	byMessage, err := opened.ServerLogEntries(context.Background(), serverlog.Query{Search: "LISTENER"})
	if err != nil {
		t.Fatalf("ServerLogEntries() error = %v", err)
	}
	if byMessage.TotalEntries != 1 || byMessage.Entries[0].Message != "listener started" {
		t.Fatalf("message search = %+v, want the listener entry", byMessage.Entries)
	}
	byAttribute, err := opened.ServerLogEntries(context.Background(), serverlog.Query{Search: "example.com"})
	if err != nil {
		t.Fatalf("ServerLogEntries() error = %v", err)
	}
	if byAttribute.TotalEntries != 1 || byAttribute.Entries[0].Message != "zone loaded" {
		t.Fatalf("attribute search = %+v, want the zone entry", byAttribute.Entries)
	}
}

func TestPruneServerLogEntriesRemovesOnlyOlderThanTheCutoff(t *testing.T) {
	t.Parallel()

	opened := openServerLogStore(t)
	now := time.Now().UTC()
	if err := opened.WriteServerLogEntries(context.Background(), []serverlog.Entry{
		{OccurredAt: now.Add(-90 * 24 * time.Hour), Level: slog.LevelInfo, Message: "ancient"},
		{OccurredAt: now.Add(-30 * 24 * time.Hour), Level: slog.LevelInfo, Message: "recent"},
	}); err != nil {
		t.Fatalf("WriteServerLogEntries() error = %v", err)
	}
	if err := opened.PruneServerLogEntries(context.Background(), now.Add(-60*24*time.Hour)); err != nil {
		t.Fatalf("PruneServerLogEntries() error = %v", err)
	}
	page, err := opened.ServerLogEntries(context.Background(), serverlog.Query{})
	if err != nil {
		t.Fatalf("ServerLogEntries() error = %v", err)
	}
	if page.TotalEntries != 1 || page.Entries[0].Message != "recent" {
		t.Fatalf("after prune = %+v, want only the entry inside retention", page.Entries)
	}
}

func TestServerLogEntriesFilterBySinceAndUntil(t *testing.T) {
	t.Parallel()

	opened := openServerLogStore(t)
	base := time.Now().Add(-4 * time.Hour).UTC()
	if err := opened.WriteServerLogEntries(context.Background(), []serverlog.Entry{
		{OccurredAt: base, Level: slog.LevelInfo, Message: "oldest"},
		{OccurredAt: base.Add(2 * time.Hour), Level: slog.LevelInfo, Message: "middle"},
		{OccurredAt: base.Add(4 * time.Hour), Level: slog.LevelInfo, Message: "newest"},
	}); err != nil {
		t.Fatalf("WriteServerLogEntries() error = %v", err)
	}
	page, err := opened.ServerLogEntries(context.Background(), serverlog.Query{
		Since: base.Add(time.Hour), Until: base.Add(3 * time.Hour),
	})
	if err != nil {
		t.Fatalf("ServerLogEntries() error = %v", err)
	}
	if page.TotalEntries != 1 || page.Entries[0].Message != "middle" {
		t.Fatalf("window = %+v, want only the entry inside it", page.Entries)
	}
}

func TestWriteServerLogEntriesAcceptsEmptyBatch(t *testing.T) {
	t.Parallel()

	opened := openServerLogStore(t)
	if err := opened.WriteServerLogEntries(context.Background(), nil); err != nil {
		t.Fatalf("WriteServerLogEntries(nil) error = %v", err)
	}
}
