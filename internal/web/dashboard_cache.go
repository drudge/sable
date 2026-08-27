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
)

type dashboardInsightCacheEntry struct {
	insights querylog.Insights
	window   insightWindow
	expires  time.Time
}

type dashboardInsightFlight struct {
	done     chan struct{}
	insights querylog.Insights
	window   insightWindow
	err      error
}

// dashboardInsightCache shares one exact aggregation across every console
// session looking at the same preset range. The gate also keeps different
// ranges from launching competing GROUP BY scans against the query log.
type dashboardInsightCache struct {
	mu      sync.Mutex
	entries map[string]dashboardInsightCacheEntry
	flights map[string]*dashboardInsightFlight
	gate    chan struct{}
}

func (cache *dashboardInsightCache) load(
	ctx context.Context,
	window insightWindow,
	load func(context.Context, time.Time, time.Time) (querylog.Insights, error),
) (querylog.Insights, insightWindow, error) {
	key, cacheable := dashboardInsightCacheKey(window)
	now := time.Now()

	cache.mu.Lock()
	if cache.entries == nil {
		cache.entries = make(map[string]dashboardInsightCacheEntry)
		cache.flights = make(map[string]*dashboardInsightFlight)
		cache.gate = make(chan struct{}, 1)
	}
	if entry, found := cache.entries[key]; cacheable && found && now.Before(entry.expires) {
		cache.mu.Unlock()
		return entry.insights, entry.window, nil
	}
	if flight, found := cache.flights[key]; found {
		cache.mu.Unlock()
		select {
		case <-flight.done:
			return flight.insights, flight.window, flight.err
		case <-ctx.Done():
			return querylog.Insights{}, insightWindow{}, ctx.Err()
		}
	}
	flight := &dashboardInsightFlight{done: make(chan struct{})}
	cache.flights[key] = flight
	gate := cache.gate
	cache.mu.Unlock()

	queryContext, cancel := context.WithTimeout(context.Background(), dashboardInsightQueryTimeout)
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
		cache.entries[key] = dashboardInsightCacheEntry{
			insights: flight.insights,
			window:   window,
			expires:  time.Now().Add(dashboardInsightCacheTTL),
		}
	}
	delete(cache.flights, key)
	close(flight.done)
	cache.mu.Unlock()
	return flight.insights, flight.window, flight.err
}

func dashboardInsightCacheKey(window insightWindow) (string, bool) {
	if _, valid := chartDuration(window.Range); valid {
		return "range:" + window.Range, true
	}
	// Custom ranges share an in-flight query only when their exact bounds match;
	// they are not retained, so arbitrary operator input cannot grow the cache.
	return "custom:" + strconv.FormatInt(window.Start.UnixNano(), 10) + ":" + strconv.FormatInt(window.End.UnixNano(), 10), false
}
