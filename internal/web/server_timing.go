package web

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// serverTimings collects how long each part of a page took to build, for a
// Server-Timing header (W3C Server Timing), so a slow console page on a real
// deployment can be read from the browser's network panel rather than
// guessed at. The page is only served to a signed-in operator, so the
// numbers say nothing a visitor could use.
type serverTimings struct {
	mu      sync.Mutex
	entries []serverTiming
}

type serverTiming struct {
	name     string
	duration time.Duration
}

type serverTimingsKey struct{}

// withServerTimings returns a context that collects timings into timings.
func withServerTimings(ctx context.Context, timings *serverTimings) context.Context {
	return context.WithValue(ctx, serverTimingsKey{}, timings)
}

// serverTimingsFrom returns the context's collector, or nil, whose measure
// only runs the work.
func serverTimingsFrom(ctx context.Context) *serverTimings {
	timings, _ := ctx.Value(serverTimingsKey{}).(*serverTimings)
	return timings
}

// measure runs work and, with a collector, records how long it took under
// name, a token such as "backups".
func (timings *serverTimings) measure(name string, work func()) {
	if timings == nil {
		work()
		return
	}
	started := time.Now()
	work()
	elapsed := time.Since(started)
	timings.mu.Lock()
	timings.entries = append(timings.entries, serverTiming{name: name, duration: elapsed})
	timings.mu.Unlock()
}

// header formats the timings as a Server-Timing value, in milliseconds.
func (timings *serverTimings) header() string {
	if timings == nil {
		return ""
	}
	timings.mu.Lock()
	defer timings.mu.Unlock()
	parts := make([]string, 0, len(timings.entries))
	for _, entry := range timings.entries {
		parts = append(parts, fmt.Sprintf("%s;dur=%.1f", entry.name, float64(entry.duration)/float64(time.Millisecond)))
	}
	return strings.Join(parts, ", ")
}
