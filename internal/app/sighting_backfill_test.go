package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBackfillClientSightingsReportsWhatHappened(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		filled bool
		err    error
		want   string
	}{
		{"filled", true, nil, "filled device history"},
		{"nothing to fill", false, nil, ""},
		{"failed", false, errors.New("disk full"), "disk full"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			backfillClientSightings(context.Background(), func(context.Context) (bool, error) { return test.filled, test.err }, logger)
			if test.want == "" && logs.Len() != 0 || test.want != "" && !strings.Contains(logs.String(), test.want) {
				t.Fatalf("logs = %q, want %q", logs.String(), test.want)
			}
		})
	}
}

func TestBackfillBlockedClientRollupsReportsWhatHappened(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		filled bool
		err    error
		want   string
	}{
		{"filled", true, nil, "counted blocked queries per client"},
		{"nothing to fill", false, nil, ""},
		{"failed", false, errors.New("disk full"), "disk full"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			backfillBlockedClientRollups(context.Background(), func(context.Context) (bool, error) { return test.filled, test.err }, logger)
			if test.want == "" && logs.Len() != 0 || test.want != "" && !strings.Contains(logs.String(), test.want) {
				t.Fatalf("logs = %q, want %q", logs.String(), test.want)
			}
		})
	}
}

func TestCompactQueryLogRollupsRunsUntilTheRuntimeStops(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	var passes atomic.Int32
	var logs bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		compactQueryLogRollups(ctx, func(context.Context, time.Time) error {
			if passes.Add(1) == 3 {
				cancel()
				return context.Canceled
			}
			return errors.New("disk full")
		}, time.Millisecond, slog.New(slog.NewTextHandler(&logs, nil)))
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("compaction kept running after the runtime stopped")
	}
	if passes.Load() != 3 {
		t.Fatalf("passes = %d, want 3", passes.Load())
	}
	// Failures are reported, but not the one the shutdown caused.
	if got := strings.Count(logs.String(), "disk full"); got != 2 || strings.Contains(logs.String(), "canceled") {
		t.Fatalf("logs = %q", logs.String())
	}
}
