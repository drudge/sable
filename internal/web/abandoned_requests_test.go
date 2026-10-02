package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"syscall"
	"testing"
)

// A request the browser gave up on is logged at debug, not as an error, and
// says so; real errors are logged as before.
func TestAbandonedRequestsStayOutOfTheErrorLog(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	logger := quietAbandoned(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))

	logger.Error("browse query log", "error", fmt.Errorf("count query events: %w", context.Canceled))
	logger.Error("render query logs", "error", fmt.Errorf("write: %w", syscall.EPIPE))
	logger.With("tab", "queries").Error("render logs page", "error", context.Canceled)
	logger.Error("browse query log", "error", errors.New("database is locked"))
	logger.Error("browse query log", "error", fmt.Errorf("count query events: %w", context.DeadlineExceeded))

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("logged %d lines, want 5:\n%s", len(lines), output.String())
	}
	for _, line := range lines[:3] {
		if !strings.Contains(line, "level=DEBUG") || !strings.Contains(line, "(the browser stopped waiting)") {
			t.Errorf("an abandoned request logged %q, want it at debug and saying why", line)
		}
	}
	if !strings.Contains(lines[2], "tab=queries") {
		t.Errorf("an abandoned request lost the logger's own attributes: %q", lines[2])
	}
	for _, line := range lines[3:] {
		if !strings.Contains(line, "level=ERROR") || strings.Contains(line, "stopped waiting") {
			t.Errorf("a real failure logged %q, want it as an error", line)
		}
	}

	output.Reset()
	quiet := quietAbandoned(slog.New(slog.NewTextHandler(&output, nil)))
	quiet.Error("browse query log", "error", context.Canceled)
	if output.Len() != 0 {
		t.Fatalf("with debug off, an abandoned request still logged %q", output.String())
	}
}
