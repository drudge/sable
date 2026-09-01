package querylog

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type memoryWriter struct {
	mu     sync.Mutex
	events []Event
	pruned []time.Time
	gate   <-chan struct{}
}

func (writer *memoryWriter) WriteQueryEvents(ctx context.Context, events []Event) error {
	if writer.gate != nil {
		select {
		case <-writer.gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	writer.mu.Lock()
	writer.events = append(writer.events, events...)
	writer.mu.Unlock()
	return nil
}

func (writer *memoryWriter) PruneQueryEvents(_ context.Context, before time.Time) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.pruned = append(writer.pruned, before)
	return nil
}

func (writer *memoryWriter) count() int {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return len(writer.events)
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
	recorder.Record(Event{Name: "one.example"})
	recorder.Record(Event{Name: "two.example"})
	recorder.Record(Event{Name: "three.example"})

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

func TestRecorderDropsInsteadOfBlockingWhenBufferIsFull(t *testing.T) {
	t.Parallel()

	gate := make(chan struct{})
	writer := &memoryWriter{gate: gate}
	recorder := newTestRecorder(t, writer, Options{
		Enabled: true, BufferSize: 1, BatchSize: 1, FlushInterval: time.Hour, Retention: 24 * time.Hour,
	})
	recorder.Record(Event{Name: "blocks-writer.example"})
	deadline := time.Now().Add(time.Second)
	for recorder.Stats().Queued != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	recorder.Record(Event{Name: "queued.example"})
	recorder.Record(Event{Name: "dropped.example"})
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
	recorder.Record(Event{Name: "ignored.example"})
	recorder.SetEnabled(true)
	recorder.Record(Event{Name: "stored.example"})
	if err := recorder.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if writer.count() != 1 {
		t.Fatalf("persisted = %d, want 1", writer.count())
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

func newTestRecorder(t *testing.T, writer Writer, options Options) *Recorder {
	t.Helper()
	recorder, err := NewRecorder(writer, options, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewRecorder() error = %v", err)
	}
	return recorder
}
