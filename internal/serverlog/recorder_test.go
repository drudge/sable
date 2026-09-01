package serverlog

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type memoryWriter struct {
	mu      sync.Mutex
	entries []Entry
	pruned  []time.Time
	gate    <-chan struct{}
	failure error
}

func (writer *memoryWriter) WriteServerLogEntries(ctx context.Context, entries []Entry) error {
	if writer.gate != nil {
		select {
		case <-writer.gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.failure != nil {
		return writer.failure
	}
	writer.entries = append(writer.entries, entries...)
	return nil
}

func (writer *memoryWriter) PruneServerLogEntries(_ context.Context, before time.Time) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.pruned = append(writer.pruned, before)
	return nil
}

func (writer *memoryWriter) count() int {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return len(writer.entries)
}

func (writer *memoryWriter) pruneCount() int {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return len(writer.pruned)
}

func TestRecorderFlushesBatchAndShutdownRemainder(t *testing.T) {
	t.Parallel()

	writer := &memoryWriter{}
	recorder := newTestRecorder(t, writer, Options{
		Enabled: true, BufferSize: 16, BatchSize: 2, FlushInterval: time.Hour, Retention: 24 * time.Hour,
	})
	recorder.Record(Entry{Message: "one"})
	recorder.Record(Entry{Message: "two"})
	recorder.Record(Entry{Message: "three"})

	deadline := time.Now().Add(time.Second)
	for writer.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if writer.count() != 2 {
		t.Fatalf("persisted before shutdown = %d, want 2", writer.count())
	}
	if err := recorder.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if writer.count() != 3 {
		t.Fatalf("persisted after shutdown = %d, want 3", writer.count())
	}
}

// A stalled database must not stall whichever goroutine happened to log, so a
// full queue drops and counts instead of waiting for room.
func TestRecorderDropsInsteadOfBlockingWhenBufferIsFull(t *testing.T) {
	t.Parallel()

	gate := make(chan struct{})
	writer := &memoryWriter{gate: gate}
	recorder := newTestRecorder(t, writer, Options{
		Enabled: true, BufferSize: 1, BatchSize: 1, FlushInterval: time.Hour, Retention: 24 * time.Hour,
	})
	recorder.Record(Entry{Message: "blocks-writer"})
	deadline := time.Now().Add(time.Second)
	for recorder.Stats().Queued != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	recorder.Record(Entry{Message: "queued"})
	recorder.Record(Entry{Message: "dropped"})
	if recorder.Stats().Dropped != 1 {
		t.Fatalf("Dropped = %d, want 1", recorder.Stats().Dropped)
	}
	close(gate)
	if err := recorder.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestRecorderCanBeDisabledWithoutStoppingWorker(t *testing.T) {
	t.Parallel()

	writer := &memoryWriter{}
	recorder := newTestRecorder(t, writer, Options{
		Enabled: false, BufferSize: 4, BatchSize: 2, FlushInterval: time.Hour, Retention: 24 * time.Hour,
	})
	recorder.Record(Entry{Message: "ignored"})
	recorder.SetEnabled(true)
	recorder.Record(Entry{Message: "stored"})
	if err := recorder.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if writer.count() != 1 {
		t.Fatalf("persisted = %d, want 1", writer.count())
	}
}

func TestRecorderPrunesOnStartSoRetentionAppliesWithoutWaitingAnHour(t *testing.T) {
	t.Parallel()

	writer := &memoryWriter{}
	recorder := newTestRecorder(t, writer, Options{
		Enabled: true, BufferSize: 4, BatchSize: 2, FlushInterval: time.Hour, Retention: 48 * time.Hour,
	})
	deadline := time.Now().Add(time.Second)
	for writer.pruneCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if writer.pruneCount() == 0 {
		t.Fatal("recorder did not prune on start")
	}
	writer.mu.Lock()
	cutoff := writer.pruned[0]
	writer.mu.Unlock()
	if elapsed := time.Since(cutoff); elapsed < 47*time.Hour || elapsed > 49*time.Hour {
		t.Fatalf("prune cutoff was %v ago, want about 48h", elapsed)
	}
	if err := recorder.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestRecorderAppliesRetentionChangesWithoutRestart(t *testing.T) {
	t.Parallel()

	writer := &memoryWriter{}
	recorder := newTestRecorder(t, writer, Options{
		Enabled: true, BufferSize: 4, BatchSize: 2, FlushInterval: time.Hour, Retention: 48 * time.Hour,
	})
	deadline := time.Now().Add(time.Second)
	for writer.pruneCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	initialPrunes := writer.pruneCount()
	if err := recorder.SetRetention(12 * time.Hour); err != nil {
		t.Fatalf("SetRetention() error = %v", err)
	}
	deadline = time.Now().Add(time.Second)
	for writer.pruneCount() == initialPrunes && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if writer.pruneCount() == initialPrunes {
		t.Fatal("retention change did not trigger pruning")
	}
	writer.mu.Lock()
	cutoff := writer.pruned[len(writer.pruned)-1]
	writer.mu.Unlock()
	if elapsed := time.Since(cutoff); elapsed < 11*time.Hour || elapsed > 13*time.Hour {
		t.Fatalf("prune cutoff was %v ago, want about 12h", elapsed)
	}
	if err := recorder.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

// A failed write is counted rather than retried forever, and the batch is
// released so a broken database cannot pin the queue.
func TestRecorderCountsWriteFailuresAndReleasesTheBatch(t *testing.T) {
	t.Parallel()

	writer := &memoryWriter{failure: errors.New("database is gone")}
	recorder := newTestRecorder(t, writer, Options{
		Enabled: true, BufferSize: 8, BatchSize: 1, FlushInterval: time.Hour, Retention: time.Hour,
	})
	recorder.Record(Entry{Message: "unwritable"})
	deadline := time.Now().Add(time.Second)
	for recorder.Stats().WriteErrors == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stats := recorder.Stats()
	if stats.WriteErrors == 0 {
		t.Fatal("WriteErrors = 0, want at least one")
	}
	if stats.Dropped == 0 {
		t.Fatal("Dropped = 0, want the unwritable entry counted")
	}
	if err := recorder.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestNewRecorderRejectsMissingLoggerSoFailuresCannotFeedTheBuffer(t *testing.T) {
	t.Parallel()

	if _, err := NewRecorder(&memoryWriter{}, Options{
		Enabled: true, BufferSize: 4, BatchSize: 1, FlushInterval: time.Second, Retention: time.Hour,
	}, nil); err == nil {
		t.Fatal("NewRecorder() with a nil logger error = nil, want an error")
	}
}

func newTestRecorder(t *testing.T, writer Writer, options Options) *Recorder {
	t.Helper()
	recorder, err := NewRecorder(writer, options, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	return recorder
}
