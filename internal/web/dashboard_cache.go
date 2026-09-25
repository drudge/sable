package web

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

const (
	dashboardInsightCacheTTL     = 55 * time.Second
	dashboardInsightQueryTimeout = 5 * time.Second
	// insightsStaleFor is how long Insights keeps answering from a count that
	// has expired while a fresh one runs in the background. Insights describes
	// days and weeks, so a count a few minutes old reads the same, and waiting
	// on a recount every minute is what made the page slow to open.
	insightsStaleFor = 15 * time.Minute
	// insightsQueryTimeout bounds one Insights recount. Nobody waits on a
	// background refresh, so it may take as long as a slow disk needs.
	insightsQueryTimeout = time.Minute
)

type windowCacheEntry[T any] struct {
	insights T
	window   insightWindow
	expires  time.Time
}

type windowCacheFlight[T any] struct {
	done     chan struct{}
	insights T
	window   insightWindow
	err      error
}

// windowCache shares one exact aggregation across every console session
// looking at the same preset range. The gate also keeps different ranges from
// launching competing GROUP BY scans against the query log.
type windowCache[T any] struct {
	mu      sync.Mutex
	entries map[string]windowCacheEntry[T]
	flights map[string]*windowCacheFlight[T]
	gate    chan struct{}
	// staleFor lets an expired entry answer for that much longer while a fresh
	// count runs in the background. Zero recounts before answering, which the
	// dashboard's live numbers need.
	staleFor time.Duration
	// timeout bounds one count; zero means dashboardInsightQueryTimeout.
	timeout time.Duration
	// background runs each count, on a context that ends with the server, so
	// the server can wait for counts still running when it closes. Nil runs
	// them in a goroutine of their own.
	background func(func(context.Context))
}

// dashboardInsightCache holds the dashboard rankings and distributions.
type dashboardInsightCache = windowCache[querylog.Insights]

// serveStale sets a cache up for Insights, which answers from a recent count
// while it refreshes rather than making a visitor wait.
func (cache *windowCache[T]) serveStale() {
	cache.staleFor, cache.timeout = insightsStaleFor, insightsQueryTimeout
}

func (cache *windowCache[T]) load(
	ctx context.Context,
	window insightWindow,
	load func(context.Context, time.Time, time.Time) (T, error),
) (T, insightWindow, error) {
	key, cacheable := dashboardInsightCacheKey(window)
	now := time.Now()

	cache.mu.Lock()
	if cache.entries == nil {
		cache.entries = make(map[string]windowCacheEntry[T])
		cache.flights = make(map[string]*windowCacheFlight[T])
		cache.gate = make(chan struct{}, 1)
	}
	if entry, found := cache.entries[key]; cacheable && found && now.Before(entry.expires.Add(cache.staleFor)) {
		if !now.Before(entry.expires) && cache.flights[key] == nil {
			cache.start(key, window, load, cacheable)
		}
		cache.mu.Unlock()
		return entry.insights, entry.window, nil
	}
	flight := cache.flights[key]
	if flight == nil {
		flight = cache.start(key, window, load, cacheable)
	}
	cache.mu.Unlock()
	select {
	case <-flight.done:
		return flight.insights, flight.window, flight.err
	case <-ctx.Done():
		var empty T
		return empty, insightWindow{}, ctx.Err()
	}
}

// start counts the window in the background, detached from any one request so
// a visitor who leaves never wastes the count for the next one. The caller
// holds the lock.
func (cache *windowCache[T]) start(
	key string,
	window insightWindow,
	load func(context.Context, time.Time, time.Time) (T, error),
	cacheable bool,
) *windowCacheFlight[T] {
	flight := &windowCacheFlight[T]{done: make(chan struct{})}
	cache.flights[key] = flight
	gate, timeout := cache.gate, cache.timeout
	if timeout <= 0 {
		timeout = dashboardInsightQueryTimeout
	}
	background := cache.background
	if background == nil {
		background = func(work func(context.Context)) { go work(context.Background()) }
	}
	background(func(ctx context.Context) {
		queryContext, cancel := context.WithTimeout(ctx, timeout)
		select {
		case gate <- struct{}{}:
			flight.insights, flight.err = load(queryContext, window.Start, window.End)
			<-gate
		case <-queryContext.Done():
			flight.err = queryContext.Err()
		}
		cancel()
		flight.window = window

		cache.mu.Lock()
		if flight.err == nil && cacheable {
			cache.entries[key] = windowCacheEntry[T]{
				insights: flight.insights,
				window:   window,
				expires:  time.Now().Add(dashboardInsightCacheTTL),
			}
		}
		delete(cache.flights, key)
		close(flight.done)
		cache.mu.Unlock()
	})
	return flight
}

func dashboardInsightCacheKey(window insightWindow) (string, bool) {
	if _, valid := chartDuration(window.Range); valid {
		return "range:" + window.Range, true
	}
	// Custom ranges share an in-flight query only when their exact bounds match;
	// they are not retained, so arbitrary operator input cannot grow the cache.
	return "custom:" + strconv.FormatInt(window.Start.UnixNano(), 10) + ":" + strconv.FormatInt(window.End.UnixNano(), 10), false
}
