package serverlog

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
)

func TestHandlerCapturesStructuredEntriesAndFilters(t *testing.T) {
	buffer := New(2)
	logger := slog.New(NewHandler(slog.NewTextHandler(io.Discard, nil), buffer))
	logger.InfoContext(context.Background(), "started", "listener", "127.0.0.1:53")
	logger.WarnContext(context.Background(), "slow upstream", "server", "192.0.2.53")
	logger.ErrorContext(context.Background(), "query failed", "domain", "example.com")

	entries := buffer.Entries(Filter{Search: "example.com", Level: "error", Limit: 10})
	if len(entries) != 1 || entries[0].Message != "query failed" || entries[0].Attributes["domain"] != "example.com" {
		t.Fatalf("Entries() = %+v", entries)
	}
	all := buffer.Entries(Filter{Limit: 10})
	if len(all) != 2 || all[0].Message != "query failed" || all[1].Message != "slow upstream" {
		t.Fatalf("bounded Entries() = %+v", all)
	}
}

type recordingSink struct {
	mu      sync.Mutex
	entries []Entry
}

func (sink *recordingSink) Record(entry Entry) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.entries = append(sink.entries, entry)
}

func (sink *recordingSink) messages() []string {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	messages := make([]string, 0, len(sink.entries))
	for _, entry := range sink.entries {
		messages = append(messages, entry.Message)
	}
	return messages
}

// The sink attaches only once the database is open, which is well after
// logging starts. Replaying what the buffer already holds is what keeps
// configuration loading and migrations in the persisted history, and those are
// exactly the entries wanted after a start that failed.
func TestAttachReplaysBufferedEntriesThenForwardsNewOnes(t *testing.T) {
	buffer := New(4)
	logger := slog.New(NewHandler(slog.NewTextHandler(io.Discard, nil), buffer))
	logger.InfoContext(context.Background(), "before attach")

	sink := &recordingSink{}
	buffer.Attach(sink)
	logger.InfoContext(context.Background(), "after attach")

	got := sink.messages()
	if len(got) != 2 || got[0] != "before attach" || got[1] != "after attach" {
		t.Fatalf("sink received %v, want the replay then the new entry in order", got)
	}
}

// The replay is bounded by the ring, not by everything ever logged, so an
// attach after a long unpersisted run cannot flood the sink.
func TestAttachReplaysOnlyWhatTheBufferStillHolds(t *testing.T) {
	buffer := New(2)
	logger := slog.New(NewHandler(slog.NewTextHandler(io.Discard, nil), buffer))
	for _, message := range []string{"evicted", "kept one", "kept two"} {
		logger.InfoContext(context.Background(), message)
	}

	sink := &recordingSink{}
	buffer.Attach(sink)

	got := sink.messages()
	if len(got) != 2 || got[0] != "kept one" || got[1] != "kept two" {
		t.Fatalf("sink received %v, want only the two entries still buffered", got)
	}
}

func TestAttachedSinkReceivesAttributesAndAssignedIdentifiers(t *testing.T) {
	buffer := New(4)
	sink := &recordingSink{}
	buffer.Attach(sink)
	logger := slog.New(NewHandler(slog.NewTextHandler(io.Discard, nil), buffer))
	logger.ErrorContext(context.Background(), "query failed", "domain", "example.com")

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.entries) != 1 {
		t.Fatalf("sink received %d entries, want 1", len(sink.entries))
	}
	entry := sink.entries[0]
	if entry.ID == 0 || entry.OccurredAt.IsZero() {
		t.Fatalf("entry reached the sink unstamped: %+v", entry)
	}
	if entry.Level != slog.LevelError || entry.Attributes["domain"] != "example.com" {
		t.Fatalf("entry = %+v, want the error level and its attribute", entry)
	}
}
