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
	mu            sync.Mutex
	events        []Event
	pruned        []time.Time
	gate          chan struct{}
	pruneGate     <-chan struct{}
	writeStarted  chan struct{}
	writeCanceled chan struct{}
	pruneStarted  chan struct{}
	writeOnce     sync.Once
	cancelOnce    sync.Once
	pruneOnce     sync.Once
}

func (writer *memoryWriter) WriteQueryEvents(ctx context.Context, events []Event) error {
	if writer.writeStarted != nil {
		writer.writeOnce.Do(func() { close(writer.writeStarted) })
	}
	if writer.gate != nil {
		select {
		case <-writer.gate:
		case <-ctx.Done():
			if writer.writeCanceled != nil {
				writer.cancelOnce.Do(func() { close(writer.writeCanceled) })
			}
			return ctx.Err()
		}
	}
	writer.mu.Lock()
	writer.events = append(writer.events, events...)
	writer.mu.Unlock()
	return nil
}

func (writer *memoryWriter) PruneQueryEvents(ctx context.Context, before time.Time) error {
	if writer.pruneStarted != nil {
		writer.pruneOnce.Do(func() { close(writer.pruneStarted) })
	}
	if writer.pruneGate != nil {
		select {
		case <-writer.pruneGate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
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

func TestRecorderCloseCancelsBlockedWriteAndCountsBatch(t *testing.T) {
	t.Parallel()

	writer := &memoryWriter{gate: make(chan struct{}), writeStarted: make(chan struct{})}
	recorder := newTestRecorder(t, writer, Options{
		Enabled: true, BufferSize: 4, BatchSize: 1, FlushInterval: time.Hour, Retention: 24 * time.Hour,
	})
	recorder.Record(Event{Name: "blocked.example"})
	select {
	case <-writer.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("writer did not start")
	}
	if err := recorder.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	stats := recorder.Stats()
	if stats.WriteErrors != 1 || stats.Dropped != 1 || stats.Queued != 0 {
		t.Fatalf("canceled write stats = %+v, want one error and dropped batch", stats)
	}
}

func TestRecorderCloseDrainsQueuedBatchAfterCanceledWrite(t *testing.T) {
	t.Parallel()

	writer := &memoryWriter{
		gate:          make(chan struct{}),
		writeStarted:  make(chan struct{}),
		writeCanceled: make(chan struct{}),
	}
	recorder := newTestRecorder(t, writer, Options{
		Enabled: true, BufferSize: 4, BatchSize: 1, FlushInterval: time.Hour, Retention: 24 * time.Hour,
	})
	recorder.Record(Event{Name: "uncertain.example"})
	select {
	case <-writer.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("writer did not start")
	}
	recorder.Record(Event{Name: "queued.example"})
	deadline := time.Now().Add(time.Second)
	for recorder.Stats().Queued != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if stats := recorder.Stats(); stats.Queued != 1 {
		t.Fatalf("queued stats = %+v, want second event queued", stats)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- recorder.Close(context.Background()) }()
	select {
	case <-writer.writeCanceled:
	case <-time.After(time.Second):
		t.Fatal("normal write was not canceled")
	}
	close(writer.gate)
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	stats := recorder.Stats()
	if stats.WriteErrors != 1 || stats.Dropped != 1 || stats.Persisted != 1 || stats.Queued != 0 {
		t.Fatalf("shutdown stats = %+v, want one uncertain drop and one queued event persisted", stats)
	}
	if got := writer.count(); got != 1 {
		t.Fatalf("persisted events = %d, want queued event only", got)
	}
}

func TestRecorderCloseCancelsBlockedPrune(t *testing.T) {
	t.Parallel()

	writer := &memoryWriter{pruneGate: make(chan struct{}), pruneStarted: make(chan struct{})}
	recorder := newTestRecorder(t, writer, Options{
		Enabled: true, BufferSize: 4, BatchSize: 2, FlushInterval: time.Hour, Retention: 24 * time.Hour,
	})
	select {
	case <-writer.pruneStarted:
	case <-time.After(time.Second):
		t.Fatal("pruner did not start")
	}
	if err := recorder.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if stats := recorder.Stats(); stats.WriteErrors != 1 {
		t.Fatalf("canceled prune stats = %+v, want one error", stats)
	}
}

func TestRecorderExpiredCloseStillStopsWorker(t *testing.T) {
	t.Parallel()

	writer := &memoryWriter{gate: make(chan struct{}), writeStarted: make(chan struct{})}
	recorder := newTestRecorder(t, writer, Options{
		Enabled: true, BufferSize: 4, BatchSize: 1, FlushInterval: time.Hour, Retention: 24 * time.Hour,
	})
	recorder.Record(Event{Name: "expired-close.example"})
	select {
	case <-writer.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("writer did not start")
	}
	closeContext, cancel := context.WithCancel(context.Background())
	cancel()
	if err := recorder.Close(closeContext); err != context.Canceled {
		t.Fatalf("expired Close() error = %v, want context canceled", err)
	}
	if err := recorder.Close(context.Background()); err != nil {
		t.Fatalf("repeated Close() error = %v", err)
	}
	if stats := recorder.Stats(); stats.WriteErrors != 1 || stats.Dropped != 1 {
		t.Fatalf("expired Close() stats = %+v, want canceled batch accounted", stats)
	}
}

func TestRecorderCloseCanBeCalledConcurrently(t *testing.T) {
	t.Parallel()

	recorder := newTestRecorder(t, &memoryWriter{}, Options{
		Enabled: true, BufferSize: 4, BatchSize: 2, FlushInterval: time.Hour, Retention: 24 * time.Hour,
	})
	const closers = 8
	errorsByCloser := make(chan error, closers)
	var wait sync.WaitGroup
	wait.Add(closers)
	for range closers {
		go func() {
			defer wait.Done()
			errorsByCloser <- recorder.Close(context.Background())
		}()
	}
	wait.Wait()
	close(errorsByCloser)
	for err := range errorsByCloser {
		if err != nil {
			t.Fatalf("concurrent Close() error = %v", err)
		}
	}
	before := recorder.Stats()
	recorder.Record(Event{Name: "after-close.example"})
	if after := recorder.Stats(); after != before {
		t.Fatalf("Record after Close changed stats from %+v to %+v", before, after)
	}
}

func BenchmarkRecorderRecord(b *testing.B) {
	recorder, err := NewRecorder(&memoryWriter{}, Options{
		Enabled: true, BufferSize: 1_024, BatchSize: 1_024, FlushInterval: time.Hour, Retention: 24 * time.Hour,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		b.Fatal(err)
	}
	defer recorder.Close(context.Background())
	event := Event{Name: "benchmark.example"}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		recorder.Record(event)
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
