package serverlog

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"
)

const (
	shutdownDrainBatchSize = 1_024
	retentionSweepInterval = time.Hour
)

// Writer persists runtime log entries. The store implements it.
type Writer interface {
	WriteServerLogEntries(context.Context, []Entry) error
	PruneServerLogEntries(context.Context, time.Time) error
}

type Options struct {
	Enabled       bool
	BufferSize    int
	BatchSize     int
	FlushInterval time.Duration
	Retention     time.Duration
}

type Stats struct {
	Queued      int    `json:"queued"`
	Persisted   uint64 `json:"persisted"`
	Dropped     uint64 `json:"dropped"`
	WriteErrors uint64 `json:"write_errors"`
}

// Recorder drains runtime log entries to the store in batches and enforces the
// configured retention.
//
// Its logger must be the base logger, the one writing straight to stderr, and
// never the logger wrapped by Handler. A recorder that reported a failed write
// through the buffer feeding it would enqueue an entry describing the failure,
// try to persist that against the same broken database, fail again, and log
// again. Passing the unwrapped logger keeps a database outage reportable on
// stderr, and on systemd and Docker that is exactly where the operator already
// reads it from.
type Recorder struct {
	writer      Writer
	logger      *slog.Logger
	entries     chan Entry
	batchSize   int
	flushEvery  time.Duration
	retention   atomic.Int64
	pruneNow    chan struct{}
	shutdown    chan context.Context
	done        chan struct{}
	enabled     atomic.Bool
	closed      atomic.Bool
	persisted   atomic.Uint64
	dropped     atomic.Uint64
	writeErrors atomic.Uint64
}

func NewRecorder(writer Writer, options Options, logger *slog.Logger) (*Recorder, error) {
	if writer == nil {
		return nil, errors.New("server log writer is required")
	}
	if options.BufferSize <= 0 {
		return nil, errors.New("server log buffer size must be positive")
	}
	if options.BatchSize <= 0 || options.BatchSize > options.BufferSize {
		return nil, errors.New("server log batch size must be positive and no larger than the buffer")
	}
	if options.FlushInterval <= 0 {
		return nil, errors.New("server log flush interval must be positive")
	}
	if options.Retention <= 0 {
		return nil, errors.New("server log retention must be positive")
	}
	if logger == nil {
		return nil, errors.New("server log recorder requires a logger that does not feed the runtime buffer")
	}
	recorder := &Recorder{
		writer:     writer,
		logger:     logger,
		entries:    make(chan Entry, options.BufferSize),
		batchSize:  options.BatchSize,
		flushEvery: options.FlushInterval,
		pruneNow:   make(chan struct{}, 1),
		shutdown:   make(chan context.Context, 1),
		done:       make(chan struct{}),
	}
	recorder.retention.Store(int64(options.Retention))
	recorder.enabled.Store(options.Enabled)
	go recorder.run()
	return recorder, nil
}

func (recorder *Recorder) Enabled() bool {
	return recorder.enabled.Load() && !recorder.closed.Load()
}

func (recorder *Recorder) SetEnabled(enabled bool) {
	recorder.enabled.Store(enabled)
}

func (recorder *Recorder) SetRetention(retention time.Duration) error {
	if retention <= 0 {
		return errors.New("server log retention must be positive")
	}
	if previous := recorder.retention.Swap(int64(retention)); previous == int64(retention) {
		return nil
	}
	select {
	case recorder.pruneNow <- struct{}{}:
	default:
	}
	return nil
}

// Record satisfies Sink. It never blocks: a full queue drops the entry and
// counts it, because stalling here would stall whichever goroutine happened to
// log, and the live buffer and stderr still hold the entry either way.
func (recorder *Recorder) Record(entry Entry) {
	if !recorder.Enabled() {
		return
	}
	select {
	case recorder.entries <- entry:
	default:
		recorder.dropped.Add(1)
	}
}

func (recorder *Recorder) Stats() Stats {
	return Stats{
		Queued:      len(recorder.entries),
		Persisted:   recorder.persisted.Load(),
		Dropped:     recorder.dropped.Load(),
		WriteErrors: recorder.writeErrors.Load(),
	}
}

func (recorder *Recorder) Close(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !recorder.closed.CompareAndSwap(false, true) {
		select {
		case <-recorder.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	recorder.shutdown <- ctx
	select {
	case <-recorder.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (recorder *Recorder) run() {
	defer close(recorder.done)
	recorder.prune(context.Background())
	ticker := time.NewTicker(recorder.flushEvery)
	defer ticker.Stop()
	retentionTicker := time.NewTicker(retentionSweepInterval)
	defer retentionTicker.Stop()
	batch := make([]Entry, 0, recorder.batchSize)
	for {
		select {
		case entry := <-recorder.entries:
			batch = append(batch, entry)
			if len(batch) >= recorder.batchSize {
				batch = recorder.write(context.Background(), batch)
			}
		case <-ticker.C:
			batch = recorder.write(context.Background(), batch)
		case <-retentionTicker.C:
			recorder.prune(context.Background())
		case <-recorder.pruneNow:
			recorder.prune(context.Background())
		case ctx := <-recorder.shutdown:
			batch = recorder.drain(ctx, batch)
			recorder.write(ctx, batch)
			return
		}
	}
}

func (recorder *Recorder) prune(ctx context.Context) {
	retention := time.Duration(recorder.retention.Load())
	if err := recorder.writer.PruneServerLogEntries(ctx, time.Now().Add(-retention)); err != nil {
		recorder.writeErrors.Add(1)
		recorder.logger.Error("prune server log", "error", err)
	}
}

func (recorder *Recorder) drain(ctx context.Context, batch []Entry) []Entry {
	for len(batch) < shutdownDrainBatchSize {
		select {
		case entry := <-recorder.entries:
			batch = append(batch, entry)
		default:
			return batch
		}
	}
	batch = recorder.write(ctx, batch)
	return recorder.drain(ctx, batch)
}

func (recorder *Recorder) write(ctx context.Context, batch []Entry) []Entry {
	if len(batch) == 0 {
		return batch
	}
	if err := recorder.writer.WriteServerLogEntries(ctx, batch); err != nil {
		recorder.writeErrors.Add(1)
		recorder.dropped.Add(uint64(len(batch)))
		recorder.logger.Error("persist server log batch", "entries", len(batch), "error", err)
	} else {
		recorder.persisted.Add(uint64(len(batch)))
	}
	return batch[:0]
}
