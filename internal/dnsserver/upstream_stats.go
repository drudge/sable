package dnsserver

import (
	"cmp"
	"context"
	"errors"
	"math"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/forwarding"
)

// recentForwarderSamples is how many of a forwarder's latest response times
// its median and 95th percentile are taken from.
const recentForwarderSamples = 128

// maximumTrackedForwarders bounds the stats table. Forwarders come from the
// configuration and FWD records, so this only matters on a server whose
// forwarders keep changing.
const maximumTrackedForwarders = 512

// forwarderStatsTable keeps, for each forwarder this node sends queries to,
// how its attempts went and how long its answers took. Only forwarders are
// counted; the authoritative servers iterative resolution asks are not.
type forwarderStatsTable struct {
	mu          sync.RWMutex
	byForwarder map[string]*forwarderStats
	now         func() time.Time
}

func newForwarderStatsTable() *forwarderStatsTable {
	return &forwarderStatsTable{byForwarder: make(map[string]*forwarderStats), now: time.Now}
}

type forwarderStats struct {
	attempts     atomic.Uint64
	answers      atomic.Uint64
	failedAnswer atomic.Uint64
	timeouts     atomic.Uint64
	errors       atomic.Uint64
	// connections counts the answers that waited for a new connection;
	// timed counts the others, whose times are kept.
	connections atomic.Uint64
	timed       atomic.Uint64
	// smoothed is the smoothed response time in nanoseconds, kept the way
	// TCP keeps SRTT (RFC 6298 §2): each answer moves it an eighth of the
	// way. Until a forwarder has answered eight times it is the plain
	// average instead, so one early outlier does not hold a fast forwarder
	// back for long. Zero
	// means no answer yet. Fastest-first ordering reads it on every query,
	// so it is an atomic rather than behind mu.
	smoothed atomic.Int64
	lastUsed atomic.Int64

	mu          sync.Mutex
	recent      [recentForwarderSamples]time.Duration
	next        int
	filled      int
	lastError   string
	lastErrorAt time.Time
}

// entry returns the stats for a forwarder, adding it when it is new.
func (table *forwarderStatsTable) entry(forwarder string) *forwarderStats {
	table.mu.RLock()
	stats, found := table.byForwarder[forwarder]
	table.mu.RUnlock()
	if found {
		return stats
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	if stats, found = table.byForwarder[forwarder]; found {
		return stats
	}
	if len(table.byForwarder) >= maximumTrackedForwarders {
		table.evictLocked()
	}
	stats = new(forwarderStats)
	table.byForwarder[forwarder] = stats
	return stats
}

// evictLocked forgets the least recently used half of the table.
func (table *forwarderStatsTable) evictLocked() {
	type used struct {
		forwarder string
		at        int64
	}
	entries := make([]used, 0, len(table.byForwarder))
	for forwarder, stats := range table.byForwarder {
		entries = append(entries, used{forwarder, stats.lastUsed.Load()})
	}
	slices.SortFunc(entries, func(left, right used) int { return cmp.Compare(left.at, right.at) })
	for _, entry := range entries[:len(entries)/2] {
		delete(table.byForwarder, entry.forwarder)
	}
}

// lookup returns the stats for a forwarder without adding it.
func (table *forwarderStatsTable) lookup(forwarder string) *forwarderStats {
	table.mu.RLock()
	defer table.mu.RUnlock()
	return table.byForwarder[forwarder]
}

// lastUsedAt is when a forwarder was last sent a query, or zero if never.
func (table *forwarderStatsTable) lastUsedAt(forwarder string) int64 {
	if stats := table.lookup(forwarder); stats != nil {
		return stats.lastUsed.Load()
	}
	return 0
}

// orderingRTT is the response time fastest-first ordering sorts a forwarder
// by: zero before it has been asked anything, so it is measured, its smoothed
// response time once it has answered, and the longest possible time while it
// has been asked but never answered, so one that only fails is never put
// first.
func (table *forwarderStatsTable) orderingRTT(forwarder string) time.Duration {
	stats := table.lookup(forwarder)
	if stats == nil {
		return 0
	}
	if smoothed := stats.smoothed.Load(); smoothed != 0 {
		return time.Duration(smoothed)
	}
	if stats.attempts.Load() == 0 || stats.answers.Load() != 0 {
		// Never asked, or it has answered only over new connections: give
		// it a turn so it gets a time.
		return 0
	}
	return math.MaxInt64
}

// observe records one attempt: how long it took and how it ended. The time
// of an answer that waited for a new TCP, TLS, or QUIC connection is left
// out of the response times, since it measures the handshake as much as the
// forwarder; a forwarder used now and then would otherwise look slow only
// because its connection had closed in between.
func (table *forwarderStatsTable) observe(forwarder string, elapsed time.Duration, response *dns.Msg, err error, connected bool) {
	stats := table.entry(forwarder)
	now := table.now()
	stats.attempts.Add(1)
	stats.lastUsed.Store(now.UnixNano())
	if err != nil || response == nil {
		if isForwarderTimeout(err) {
			stats.timeouts.Add(1)
		} else {
			stats.errors.Add(1)
		}
		if err != nil {
			stats.mu.Lock()
			stats.lastError, stats.lastErrorAt = forwarderTestError(err), now
			stats.mu.Unlock()
		}
		return
	}
	stats.answers.Add(1)
	if response.Rcode == dns.RcodeServerFailure || response.Rcode == dns.RcodeRefused {
		stats.failedAnswer.Add(1)
	}
	if connected {
		stats.connections.Add(1)
		return
	}
	answers := stats.timed.Add(1)
	elapsed = max(elapsed, time.Microsecond)
	for {
		previous := stats.smoothed.Load()
		next := int64(elapsed)
		if previous != 0 {
			next = previous + (int64(elapsed)-previous)/int64(min(answers, 8))
		}
		if stats.smoothed.CompareAndSwap(previous, next) {
			break
		}
	}
	stats.mu.Lock()
	stats.recent[stats.next] = elapsed
	stats.next = (stats.next + 1) % recentForwarderSamples
	stats.filled = min(stats.filled+1, recentForwarderSamples)
	stats.mu.Unlock()
}

type connectionOpenedKey struct{}

// withConnectionMark returns a context the forwarder pool marks when an
// exchange has to open a connection, or wait for one being opened, before it
// can send its query.
func withConnectionMark(ctx context.Context) (context.Context, *atomic.Bool) {
	opened := new(atomic.Bool)
	return context.WithValue(ctx, connectionOpenedKey{}, opened), opened
}

// markConnectionOpened records on a context from withConnectionMark that the
// exchange opened a connection.
func markConnectionOpened(ctx context.Context) {
	if opened, ok := ctx.Value(connectionOpenedKey{}).(*atomic.Bool); ok {
		opened.Store(true)
	}
}

// isForwarderTimeout reports whether an attempt failed because no answer came in
// time, as opposed to an answer that could not be used or a connection that
// was refused.
func isForwarderTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && networkErr.Timeout()
}

// ForwarderStats is how one forwarder has been answering this node since it
// started.
type ForwarderStats struct {
	Forwarder string `json:"forwarder"`
	// Route is the domain a conditional route, forwarder zone, or FWD record
	// sends to this forwarder; empty for resolver.forwarders.
	Route string `json:"route,omitempty"`
	// Attempts counts every query sent, retries included. Answers counts the
	// replies, FailedAnswers the ones among them that were SERVFAIL or
	// REFUSED, Timeouts the attempts nothing came back for in time, and
	// Errors every other failure, such as a refused connection or a TLS
	// handshake that did not verify.
	Attempts      uint64 `json:"attempts"`
	Answers       uint64 `json:"answers"`
	FailedAnswers uint64 `json:"failed_answers"`
	Timeouts      uint64 `json:"timeouts"`
	Errors        uint64 `json:"errors"`
	// Connections counts the answers that waited for a new connection, whose
	// times are left out of Median, P95, and Smoothed.
	Connections uint64 `json:"connections"`
	// Median and P95 are over the most recent answers; Smoothed is the
	// moving average fastest-first ordering sorts by.
	Median   time.Duration `json:"median_ns"`
	P95      time.Duration `json:"p95_ns"`
	Smoothed time.Duration `json:"smoothed_ns"`
	Samples  int           `json:"samples"`
	// CoolingUntil is set while the forwarder is tried last after failing.
	CoolingUntil time.Time `json:"cooling_until,omitzero"`
	LastUsed     time.Time `json:"last_used,omitzero"`
	LastError    string    `json:"last_error,omitempty"`
	LastErrorAt  time.Time `json:"last_error_at,omitzero"`
}

func (table *forwarderStatsTable) snapshot(forwarder string) ForwarderStats {
	result := ForwarderStats{Forwarder: forwarder}
	stats := table.lookup(forwarder)
	if stats == nil {
		return result
	}
	result.Attempts, result.Answers, result.FailedAnswers = stats.attempts.Load(), stats.answers.Load(), stats.failedAnswer.Load()
	result.Timeouts, result.Errors, result.Connections = stats.timeouts.Load(), stats.errors.Load(), stats.connections.Load()
	result.Smoothed = time.Duration(stats.smoothed.Load())
	if used := stats.lastUsed.Load(); used != 0 {
		result.LastUsed = time.Unix(0, used)
	}
	stats.mu.Lock()
	recent := slices.Clone(stats.recent[:stats.filled])
	result.LastError, result.LastErrorAt = stats.lastError, stats.lastErrorAt
	stats.mu.Unlock()
	if len(recent) > 0 {
		slices.Sort(recent)
		result.Samples = len(recent)
		result.Median = recent[(len(recent)-1)/2]
		result.P95 = recent[(len(recent)*95+99)/100-1]
	}
	return result
}

// ForwarderStats reports every forwarder the active configuration sends to:
// resolver.forwarders in their configured order, then each route's
// forwarders by route name.
func (handler *Handler) ForwarderStats() []ForwarderStats {
	runtime := handler.runtime.Load()
	if runtime == nil {
		return nil
	}
	var result []ForwarderStats
	add := func(route string, endpoints []string) {
		for _, forwarder := range endpoints {
			if forwarder == forwarding.ThisServer {
				continue
			}
			stats := handler.forwarderStats.snapshot(forwarder)
			stats.Route = route
			stats.CoolingUntil = handler.upstreamHealth.coolingUntil(forwarder)
			result = append(result, stats)
		}
	}
	add("", runtime.forwarders)
	routes := make([]string, 0, len(runtime.routes))
	for route := range runtime.routes {
		routes = append(routes, route)
	}
	slices.Sort(routes)
	for _, route := range routes {
		add(route, runtime.routes[route].endpoints)
	}
	return result
}
