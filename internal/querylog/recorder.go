package querylog

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

type Writer interface {
	WriteQueryEvents(context.Context, []Event) error
	PruneQueryEvents(context.Context, time.Time) error
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

type Recorder struct {
	writer      Writer
	logger      *slog.Logger
	events      chan Event
	batchSize   int
	flushEvery  time.Duration
	retention   time.Duration
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
		return nil, errors.New("query log writer is required")
	}
	if options.BufferSize <= 0 {
		return nil, errors.New("query log buffer size must be positive")
	}
	if options.BatchSize <= 0 || options.BatchSize > options.BufferSize {
		return nil, errors.New("query log batch size must be positive and no larger than the buffer")
	}
	if options.FlushInterval <= 0 {
		return nil, errors.New("query log flush interval must be positive")
	}
	if options.Retention <= 0 {
		return nil, errors.New("query log retention must be positive")
	}
	recorder := &Recorder{
		writer:     writer,
		logger:     logger,
		events:     make(chan Event, options.BufferSize),
		batchSize:  options.BatchSize,
		flushEvery: options.FlushInterval,
		retention:  options.Retention,
		shutdown:   make(chan context.Context, 1),
		done:       make(chan struct{}),
	}
	recorder.enabled.Store(options.Enabled)
	if recorder.logger == nil {
		recorder.logger = slog.Default()
	}
	go recorder.run()
	return recorder, nil
}

func (recorder *Recorder) Enabled() bool {
	return recorder.enabled.Load() && !recorder.closed.Load()
}

func (recorder *Recorder) SetEnabled(enabled bool) {
	recorder.enabled.Store(enabled)
}

func (recorder *Recorder) Record(event Event) {
	if !recorder.Enabled() {
		return
	}
	select {
	case recorder.events <- event:
	default:
		recorder.dropped.Add(1)
	}
}

func (recorder *Recorder) Stats() Stats {
	return Stats{
		Queued:      len(recorder.events),
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
	batch := make([]Event, 0, recorder.batchSize)
	for {
		select {
		case event := <-recorder.events:
			batch = append(batch, event)
			if len(batch) >= recorder.batchSize {
				batch = recorder.write(context.Background(), batch)
			}
		case <-ticker.C:
			batch = recorder.write(context.Background(), batch)
		case <-retentionTicker.C:
			recorder.prune(context.Background())
		case ctx := <-recorder.shutdown:
			batch = recorder.drain(ctx, batch)
			recorder.write(ctx, batch)
			return
		}
	}
}

func (recorder *Recorder) prune(ctx context.Context) {
	if err := recorder.writer.PruneQueryEvents(ctx, time.Now().Add(-recorder.retention)); err != nil {
		recorder.writeErrors.Add(1)
		recorder.logger.Error("prune query log", "error", err)
	}
}

func (recorder *Recorder) drain(ctx context.Context, batch []Event) []Event {
	for len(batch) < shutdownDrainBatchSize {
		select {
		case event := <-recorder.events:
			batch = append(batch, event)
		default:
			return batch
		}
	}
	batch = recorder.write(ctx, batch)
	return recorder.drain(ctx, batch)
}

func (recorder *Recorder) write(ctx context.Context, batch []Event) []Event {
	if len(batch) == 0 {
		return batch
	}
	if err := recorder.writer.WriteQueryEvents(ctx, batch); err != nil {
		recorder.writeErrors.Add(1)
		recorder.dropped.Add(uint64(len(batch)))
		recorder.logger.Error("persist query log batch", "events", len(batch), "error", err)
	} else {
		recorder.persisted.Add(uint64(len(batch)))
	}
	return batch[:0]
}
