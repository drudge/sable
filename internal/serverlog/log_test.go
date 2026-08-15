package serverlog

import (
	"context"
	"io"
	"log/slog"
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
