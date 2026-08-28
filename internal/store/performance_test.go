package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

const (
	benchmarkQueryLogRows      = 100_000
	benchmarkQueryLogBatchSize = 256
)

func BenchmarkWriteQueryEventsBatch(b *testing.B) {
	opened, err := Open(context.Background(), "sqlite", filepath.Join(b.TempDir(), "sable.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer opened.Close()
	events := benchmarkQueryEvents(benchmarkQueryLogBatchSize, time.Now())
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := opened.WriteQueryEvents(context.Background(), events); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQueryLogInsightsHundredThousandRows(b *testing.B) {
	ctx := context.Background()
	opened, err := Open(ctx, "sqlite", ":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer opened.Close()
	now := time.Now().UTC().Truncate(time.Second)
	for written := 0; written < benchmarkQueryLogRows; written += benchmarkQueryLogBatchSize {
		batchSize := min(benchmarkQueryLogBatchSize, benchmarkQueryLogRows-written)
		if err := opened.WriteQueryEvents(ctx, benchmarkQueryEvents(batchSize, now)); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(benchmarkQueryLogRows, "rows")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := opened.QueryLogInsights(ctx, now.Add(-time.Hour), now.Add(time.Minute)); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkQueryEvents(count int, occurredAt time.Time) []querylog.Event {
	events := make([]querylog.Event, count)
	for index := range events {
		events[index] = querylog.Event{
			OccurredAt: occurredAt.Add(-time.Duration(index%3_600) * time.Second),
			ClientIP:   fmt.Sprintf("192.0.2.%d", index%250+1),
			Name:       fmt.Sprintf("host-%d.example.test.", index%1_000),
			RecordType: 1,
			Class:      1,
			Source:     querylog.SourceCache,
			Protocol:   "UDP",
			Answer:     "192.0.2.1",
			Duration:   time.Millisecond,
			Decision: querylog.Decision{
				Cache: querylog.CacheHit, Resolver: querylog.ResolverCache,
			},
		}
	}
	return events
}
