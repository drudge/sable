package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/web/pages"
)

const (
	// Counters are sampled often so the live chart tip moves, but they are
	// stored one bucket per minute: a year of buckets stays small enough to
	// aggregate in SQL, and every chart range needs coarser slots than that.
	statsSampleInterval = 5 * time.Second
	statsBucketInterval = time.Minute
	statsFlushInterval  = 30 * time.Second
	statsPruneInterval  = time.Hour
	memoryBucketWindow  = 48 * time.Hour
	maxChartPoints      = 160
	// The live badge pulses while queries are still arriving. The window
	// spans a few refreshes of the card so the dot does not flicker between
	// polls on a quiet but not idle resolver.
	chartLiveWindow = 30 * time.Second
)

// Plot geometry inside the chart's 1200x320 viewBox. The hover layer receives
// the same numbers so the crosshair lands on the drawn series.
const (
	chartLeft   = 58.0
	chartRight  = 1190.0
	chartTop    = 24.0
	chartBottom = 296.0
	chartWidth  = 1200.0
	chartHeight = 320.0
)

var chartSeriesDefinitions = []struct {
	class string
	label string
	value func(chartPoint) uint64
}{
	{"total", "total", func(point chartPoint) uint64 { return point.total }},
	{"success", "noError", func(point chartPoint) uint64 { return point.successful }},
	{"server-failure", "serverFailure", func(point chartPoint) uint64 { return point.serverFailure }},
	{"nx-domain", "nxDomain", func(point chartPoint) uint64 { return point.nxDomain }},
	{"refused", "refused", func(point chartPoint) uint64 { return point.refused }},
	{"recursive", "recursive", func(point chartPoint) uint64 { return point.recursive }},
	{"cache", "cached", func(point chartPoint) uint64 { return point.cacheHits }},
	{"blocked", "blocked", func(point chartPoint) uint64 { return point.blocked }},
}

type chartSeriesPayload struct {
	Class  string   `json:"class"`
	Label  string   `json:"label"`
	Values []uint64 `json:"values"`
}

type chartHoverPayload struct {
	Maximum uint64               `json:"max"`
	Box     chartBoxPayload      `json:"box"`
	X       []float64            `json:"x"`
	Times   []string             `json:"times"`
	Series  []chartSeriesPayload `json:"series"`
}

type chartBoxPayload struct {
	Left   float64 `json:"left"`
	Right  float64 `json:"right"`
	Top    float64 `json:"top"`
	Bottom float64 `json:"bottom"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

// statsStore persists chart history. The console still works without one; the
// history is then limited to what this process has observed.
type statsStore interface {
	RecordQueryStats(context.Context, []store.QueryStatsBucket, store.QueryStatsTotals) error
	QueryStats(context.Context, time.Time, time.Time, time.Duration) ([]store.QueryStatsBucket, error)
	QueryStatsTotals(context.Context) (store.QueryStatsTotals, error)
	PruneQueryStats(context.Context, time.Time) error
}

// chartedCounters are the per-bucket series the query chart draws.
type chartedCounters struct {
	queries        uint64
	noError        uint64
	serverFailures uint64
	nxDomain       uint64
	refused        uint64
	blocked        uint64
	cacheHits      uint64
	cacheMisses    uint64
}

func (counters *chartedCounters) add(other chartedCounters) {
	counters.queries += other.queries
	counters.noError += other.noError
	counters.serverFailures += other.serverFailures
	counters.nxDomain += other.nxDomain
	counters.refused += other.refused
	counters.blocked += other.blocked
	counters.cacheHits += other.cacheHits
	counters.cacheMisses += other.cacheMisses
}

func (counters chartedCounters) empty() bool {
	return counters == chartedCounters{}
}

// lifetimeCounters accumulate every cumulative counter the dashboard shows, so
// the stat cards keep counting across restarts.
type lifetimeCounters struct {
	chartedCounters
	failures             uint64
	upstreamErrors       uint64
	routedQueries        uint64
	localAnswers         uint64
	authoritativeAnswers uint64
	dnssecSecure         uint64
	dnssecInsecure       uint64
	dnssecBogus          uint64
}

func (counters *lifetimeCounters) add(other lifetimeCounters) {
	counters.chartedCounters.add(other.chartedCounters)
	counters.failures += other.failures
	counters.upstreamErrors += other.upstreamErrors
	counters.routedQueries += other.routedQueries
	counters.localAnswers += other.localAnswers
	counters.authoritativeAnswers += other.authoritativeAnswers
	counters.dnssecSecure += other.dnssecSecure
	counters.dnssecInsecure += other.dnssecInsecure
	counters.dnssecBogus += other.dnssecBogus
}

func (counters lifetimeCounters) empty() bool {
	return counters == lifetimeCounters{}
}

// statsDelta measures what happened between two readings of the in-process
// counters. A counter that moved backwards means the handler restarted, so the
// current value is the whole delta.
func statsDelta(previous, current dnsserver.Stats) lifetimeCounters {
	return lifetimeCounters{
		chartedCounters: chartedCounters{
			queries:        counterDelta(current.Queries, previous.Queries),
			noError:        counterDelta(current.NoError, previous.NoError),
			serverFailures: counterDelta(current.ServerFailures, previous.ServerFailures),
			nxDomain:       counterDelta(current.NXDomain, previous.NXDomain),
			refused:        counterDelta(current.Refused, previous.Refused),
			blocked:        counterDelta(current.Blocked, previous.Blocked),
			cacheHits:      counterDelta(current.CacheHits, previous.CacheHits),
			cacheMisses:    counterDelta(current.CacheMisses, previous.CacheMisses),
		},
		failures:             counterDelta(current.Failures, previous.Failures),
		upstreamErrors:       counterDelta(current.UpstreamErrors, previous.UpstreamErrors),
		routedQueries:        counterDelta(current.RoutedQueries, previous.RoutedQueries),
		localAnswers:         counterDelta(current.LocalAnswers, previous.LocalAnswers),
		authoritativeAnswers: counterDelta(current.AuthoritativeAnswers, previous.AuthoritativeAnswers),
		dnssecSecure:         counterDelta(current.DNSSECSecure, previous.DNSSECSecure),
		dnssecInsecure:       counterDelta(current.DNSSECInsecure, previous.DNSSECInsecure),
		dnssecBogus:          counterDelta(current.DNSSECBogus, previous.DNSSECBogus),
	}
}

func (counters lifetimeCounters) storeTotals() store.QueryStatsTotals {
	return store.QueryStatsTotals{
		Queries: counters.queries, NoError: counters.noError, ServerFailures: counters.serverFailures,
		NXDomain: counters.nxDomain, Refused: counters.refused, Blocked: counters.blocked,
		Failures: counters.failures, UpstreamErrors: counters.upstreamErrors,
		CacheHits: counters.cacheHits, CacheMisses: counters.cacheMisses,
		RoutedQueries: counters.routedQueries, LocalAnswers: counters.localAnswers,
		AuthoritativeAnswers: counters.authoritativeAnswers, DNSSECSecure: counters.dnssecSecure,
		DNSSECInsecure: counters.dnssecInsecure, DNSSECBogus: counters.dnssecBogus,
	}
}

func lifetimeFromStore(totals store.QueryStatsTotals) lifetimeCounters {
	return lifetimeCounters{
		chartedCounters: chartedCounters{
			queries: totals.Queries, noError: totals.NoError, serverFailures: totals.ServerFailures,
			nxDomain: totals.NXDomain, refused: totals.Refused, blocked: totals.Blocked,
			cacheHits: totals.CacheHits, cacheMisses: totals.CacheMisses,
		},
		failures: totals.Failures, upstreamErrors: totals.UpstreamErrors,
		routedQueries: totals.RoutedQueries, localAnswers: totals.LocalAnswers,
		authoritativeAnswers: totals.AuthoritativeAnswers, dnssecSecure: totals.DNSSECSecure,
		dnssecInsecure: totals.DNSSECInsecure, dnssecBogus: totals.DNSSECBogus,
	}
}

func chartedFromStore(bucket store.QueryStatsBucket) chartedCounters {
	return chartedCounters{
		queries: bucket.Queries, noError: bucket.NoError, serverFailures: bucket.ServerFailures,
		nxDomain: bucket.NXDomain, refused: bucket.Refused, blocked: bucket.Blocked,
		cacheHits: bucket.CacheHits, cacheMisses: bucket.CacheMisses,
	}
}

func (counters chartedCounters) storeBucket(start time.Time) store.QueryStatsBucket {
	return store.QueryStatsBucket{
		Start: start,
		QueryStatsDelta: store.QueryStatsDelta{
			Queries: counters.queries, NoError: counters.noError, ServerFailures: counters.serverFailures,
			NXDomain: counters.nxDomain, Refused: counters.refused, Blocked: counters.blocked,
			CacheHits: counters.cacheHits, CacheMisses: counters.cacheMisses,
		},
	}
}

// statsHistory turns cumulative handler counters into per-bucket deltas, keeps
// a short window of them in memory, and hands the rest to the store.
type statsHistory struct {
	mu            sync.RWMutex
	store         statsStore
	logger        *slog.Logger
	previous      dnsserver.Stats
	seeded        bool
	buckets       map[int64]chartedCounters
	pending       map[int64]chartedCounters
	lastActivity  time.Time
	retention     time.Duration
	lifetime      lifetimeCounters
	lifetimeDirty bool
}

type chartPoint struct {
	at            time.Time
	total         uint64
	successful    uint64
	serverFailure uint64
	nxDomain      uint64
	refused       uint64
	recursive     uint64
	blocked       uint64
	cacheHits     uint64
}

func newStatsHistory(logger *slog.Logger, retention time.Duration) *statsHistory {
	if logger == nil {
		logger = slog.Default()
	}
	return &statsHistory{
		logger:    logger,
		retention: retention,
		buckets:   make(map[int64]chartedCounters),
		pending:   make(map[int64]chartedCounters),
	}
}

func (history *statsHistory) setRetention(retention time.Duration) bool {
	history.mu.Lock()
	defer history.mu.Unlock()
	if history.retention == retention {
		return false
	}
	history.retention = retention
	return true
}

// attach wires persistence and adopts the stored lifetime totals as the
// baseline the in-process deltas accumulate onto.
func (history *statsHistory) attach(ctx context.Context, backing statsStore) error {
	totals, err := backing.QueryStatsTotals(ctx)
	if err != nil {
		return err
	}
	history.mu.Lock()
	defer history.mu.Unlock()
	history.store = backing
	baseline := lifetimeFromStore(totals)
	baseline.add(history.lifetime)
	history.lifetime = baseline
	return nil
}

func (history *statsHistory) record(at time.Time, stats dnsserver.Stats) {
	history.mu.Lock()
	defer history.mu.Unlock()
	if !history.seeded {
		history.previous, history.seeded = stats, true
		return
	}
	delta := statsDelta(history.previous, stats)
	history.previous = stats
	if delta.empty() {
		return
	}
	history.lifetime.add(delta)
	history.lifetimeDirty = true
	if delta.chartedCounters.empty() {
		return
	}
	if at.After(history.lastActivity) {
		history.lastActivity = at
	}
	key := bucketKey(at)
	bucket := history.buckets[key]
	bucket.add(delta.chartedCounters)
	history.buckets[key] = bucket
	unwritten := history.pending[key]
	unwritten.add(delta.chartedCounters)
	history.pending[key] = unwritten
	history.trimMemory(at)
}

// trimMemory drops in-memory buckets that have aged out of the window served
// without a store.
func (history *statsHistory) trimMemory(now time.Time) {
	if len(history.buckets) <= int(memoryBucketWindow/statsBucketInterval) {
		return
	}
	cutoff := now.Add(-memoryBucketWindow).Unix()
	for key := range history.buckets {
		if key < cutoff {
			delete(history.buckets, key)
		}
	}
}

// flush writes every bucket delta observed since the last successful write.
// Failed deltas are returned to the pending set so the next attempt retries
// them instead of losing the activity.
func (history *statsHistory) flush(ctx context.Context) error {
	history.mu.Lock()
	if history.store == nil || (len(history.pending) == 0 && !history.lifetimeDirty) {
		history.mu.Unlock()
		return nil
	}
	backing := history.store
	buckets := make([]store.QueryStatsBucket, 0, len(history.pending))
	for key, counters := range history.pending {
		buckets = append(buckets, counters.storeBucket(time.Unix(key, 0).UTC()))
	}
	sort.Slice(buckets, func(left, right int) bool { return buckets[left].Start.Before(buckets[right].Start) })
	totals := history.lifetime
	history.pending = make(map[int64]chartedCounters)
	history.lifetimeDirty = false
	history.mu.Unlock()

	if err := backing.RecordQueryStats(ctx, buckets, totals.storeTotals()); err != nil {
		history.mu.Lock()
		for _, bucket := range buckets {
			key := bucket.Start.Unix()
			retry := history.pending[key]
			retry.add(chartedFromStore(bucket))
			history.pending[key] = retry
		}
		history.lifetimeDirty = true
		history.mu.Unlock()
		return err
	}
	return nil
}

func (history *statsHistory) prune(ctx context.Context, now time.Time) error {
	history.mu.RLock()
	backing := history.store
	retention := history.retention
	history.mu.RUnlock()
	if backing == nil {
		return nil
	}
	return backing.PruneQueryStats(ctx, now.Add(-retention))
}

// totals reports the cumulative counters the stat cards display: everything
// persisted plus what this process has seen since. Gauges and uptime stay live.
func (history *statsHistory) totals(now time.Time, current dnsserver.Stats) dnsserver.Stats {
	history.record(now, current)
	history.mu.RLock()
	lifetime := history.lifetime
	history.mu.RUnlock()
	current.Queries = lifetime.queries
	current.NoError = lifetime.noError
	current.ServerFailures = lifetime.serverFailures
	current.NXDomain = lifetime.nxDomain
	current.Refused = lifetime.refused
	current.Blocked = lifetime.blocked
	current.Failures = lifetime.failures
	current.UpstreamErrors = lifetime.upstreamErrors
	current.CacheHits = lifetime.cacheHits
	current.CacheMisses = lifetime.cacheMisses
	current.RoutedQueries = lifetime.routedQueries
	current.LocalAnswers = lifetime.localAnswers
	current.AuthoritativeAnswers = lifetime.authoritativeAnswers
	current.DNSSECSecure = lifetime.dnssecSecure
	current.DNSSECInsecure = lifetime.dnssecInsecure
	current.DNSSECBogus = lifetime.dnssecBogus
	return current
}

func (history *statsHistory) view(
	ctx context.Context,
	rangeName string,
	now time.Time,
	current dnsserver.Stats,
	display pages.TimeDisplay,
) pages.QueryChartView {
	duration, valid := chartDuration(rangeName)
	if !valid {
		rangeName = "hour"
		duration = time.Hour
	}
	history.record(now, current)
	return history.buildView(ctx, rangeName, now.Add(-duration), now, now, display)
}

func (history *statsHistory) customView(
	ctx context.Context,
	start, end time.Time,
	current dnsserver.Stats,
	display pages.TimeDisplay,
) pages.QueryChartView {
	now := time.Now()
	history.record(now, current)
	return history.buildView(ctx, "custom", start, end, now, display)
}

func (history *statsHistory) buildView(
	ctx context.Context,
	rangeName string,
	start, end, now time.Time,
	display pages.TimeDisplay,
) pages.QueryChartView {
	format := chartTimeFormat(end.Sub(start), display)
	customStart := start
	if rangeName != "custom" {
		customStart = end.Add(-7 * 24 * time.Hour)
	}
	view := pages.QueryChartView{
		ActiveRange: rangeName,
		RangeLabel:  chartRangeLabel(rangeName),
		StartLabel:  display.In(start).Format(format),
		EndLabel:    display.In(end).Format(format),
		CustomStart: display.In(customStart).Format("2006-01-02T15:04"),
		CustomEnd:   display.In(end).Format("2006-01-02T15:04"),
		// A window that closed before the newest bucket could fill is done
		// collecting, so an empty one is an answer rather than a wait.
		Historical: end.Before(now.Add(-statsBucketInterval)),
	}
	view.Live = history.serving(end)
	points := history.points(ctx, start, end)
	view.Stats = chartStats(points)
	if len(points) < 2 {
		return view
	}
	view.StartLabel = display.In(points[0].at).Format(format)
	maximum := chartMaximum(points)
	if maximum == 0 {
		return view
	}
	view.HasActivity = true
	view.Maximum = maximum
	view.Total = chartCoordinates(points, maximum, func(point chartPoint) uint64 { return point.total })
	view.Successful = chartCoordinates(points, maximum, func(point chartPoint) uint64 { return point.successful })
	view.ServerFailure = chartCoordinates(points, maximum, func(point chartPoint) uint64 { return point.serverFailure })
	view.NXDomain = chartCoordinates(points, maximum, func(point chartPoint) uint64 { return point.nxDomain })
	view.Refused = chartCoordinates(points, maximum, func(point chartPoint) uint64 { return point.refused })
	view.Recursive = chartCoordinates(points, maximum, func(point chartPoint) uint64 { return point.recursive })
	view.Blocked = chartCoordinates(points, maximum, func(point chartPoint) uint64 { return point.blocked })
	view.CacheHits = chartCoordinates(points, maximum, func(point chartPoint) uint64 { return point.cacheHits })
	view.HoverData = chartHoverData(points, maximum, chartTooltipFormat(end.Sub(start), display), display)
	return view
}

// chartStats keeps the dashboard overview on the same buckets as the plot.
// Summing the plotted points also means a custom range and an empty range have
// the same semantics everywhere on the dashboard.
func chartStats(points []chartPoint) pages.StatsView {
	var view pages.StatsView
	for _, point := range points {
		view.Queries += point.total
		view.NoError += point.successful
		view.ServerFailures += point.serverFailure
		view.NXDomain += point.nxDomain
		view.Refused += point.refused
		view.Recursive += point.recursive
		view.Blocked += point.blocked
		view.CacheHits += point.cacheHits
		view.CacheMisses += point.recursive - point.cacheHits
	}
	view.CacheHitRatio = cacheHitRatio(view.CacheHits, view.CacheMisses)
	return view
}

// points lays the requested window out as fixed-width slots. Slots without
// activity stay zero, so a gap left by downtime reads as a gap instead of the
// chart stretching the surrounding samples over it.
func (history *statsHistory) points(ctx context.Context, start, end time.Time) []chartPoint {
	if !start.Before(end) {
		return nil
	}
	width := chartSlotWidth(end.Sub(start))
	seconds := int64(width / time.Second)
	first := floorDiv(start.UTC().Unix(), seconds) * seconds
	last := floorDiv(end.UTC().Unix(), seconds) * seconds
	slots := int((last-first)/seconds) + 1
	if slots < 2 {
		return nil
	}
	if slots > maxChartPoints+1 {
		slots = maxChartPoints + 1
		first = last - int64(slots-1)*seconds
	}
	totals := make([]chartedCounters, slots)
	index := func(bucketStart int64) (int, bool) {
		slot := int((floorDiv(bucketStart, seconds)*seconds - first) / seconds)
		if slot < 0 || slot >= slots {
			return 0, false
		}
		return slot, true
	}
	windowStart := time.Unix(first, 0).UTC()
	windowEnd := time.Unix(last+seconds, 0).UTC()
	buckets, err := history.readBuckets(ctx, windowStart, windowEnd, width)
	if err != nil {
		history.logger.Warn("read persisted query statistics", "error", err)
	}
	for _, bucket := range buckets {
		if slot, ok := index(bucket.Start.Unix()); ok {
			totals[slot].add(chartedFromStore(bucket))
		}
	}

	points := make([]chartPoint, 0, slots)
	for slot, counters := range totals {
		points = append(points, chartPoint{
			at:            time.Unix(first+int64(slot)*seconds, 0),
			total:         counters.queries,
			successful:    counters.noError,
			serverFailure: counters.serverFailures,
			nxDomain:      counters.nxDomain,
			refused:       counters.refused,
			recursive:     counters.cacheHits + counters.cacheMisses,
			blocked:       counters.blocked,
			cacheHits:     counters.cacheHits,
		})
	}
	return points
}

// readBuckets combines persisted activity with samples awaiting persistence.
// Callers choose the aggregation width and fill any gaps in the result.
func (history *statsHistory) readBuckets(ctx context.Context, start, end time.Time, width time.Duration) ([]store.QueryStatsBucket, error) {
	history.mu.RLock()
	backing := history.store
	history.mu.RUnlock()
	var buckets []store.QueryStatsBucket
	var err error
	if backing != nil {
		buckets, err = backing.QueryStats(ctx, start, end, width)
	}
	history.mu.RLock()
	source := history.pending
	if backing == nil {
		source = history.buckets
	}
	for key, counters := range source {
		if key >= start.Unix() && key < end.Unix() {
			buckets = append(buckets, counters.storeBucket(time.Unix(key, 0).UTC()))
		}
	}
	history.mu.RUnlock()
	return buckets, err
}

// serving reports whether queries arrived recently enough for the console to
// call the chart live.
func (history *statsHistory) serving(now time.Time) bool {
	history.mu.RLock()
	defer history.mu.RUnlock()
	return !history.lastActivity.IsZero() && now.Sub(history.lastActivity) <= chartLiveWindow
}

// sinceWindow sums the charted counters over the trailing window.
func (history *statsHistory) sinceWindow(ctx context.Context, duration time.Duration, now time.Time, current dnsserver.Stats) chartedCounters {
	history.record(now, current)
	var summed chartedCounters
	for _, point := range history.points(ctx, now.Add(-duration), now) {
		summed.add(chartedCounters{
			queries: point.total, noError: point.successful, serverFailures: point.serverFailure,
			nxDomain: point.nxDomain, refused: point.refused, blocked: point.blocked,
			cacheHits: point.cacheHits, cacheMisses: point.recursive - point.cacheHits,
		})
	}
	return summed
}

func (history *statsHistory) cacheHitsSince(ctx context.Context, duration time.Duration, now time.Time, current dnsserver.Stats) uint64 {
	return history.sinceWindow(ctx, duration, now, current).cacheHits
}

func (history *statsHistory) blockedSince(ctx context.Context, duration time.Duration, now time.Time, current dnsserver.Stats) uint64 {
	return history.sinceWindow(ctx, duration, now, current).blocked
}

func (server *Server) collectStatsHistory() {
	sampler := time.NewTicker(statsSampleInterval)
	defer sampler.Stop()
	flusher := time.NewTicker(statsFlushInterval)
	defer flusher.Stop()
	pruner := time.NewTicker(statsPruneInterval)
	defer pruner.Stop()
	for {
		select {
		case at := <-sampler.C:
			server.history.record(at, server.stats.Stats())
		case <-flusher.C:
			server.flushStatsHistory()
		case at := <-pruner.C:
			server.pruneStatsHistory(at)
		case <-server.historyPrune:
			server.pruneStatsHistory(time.Now())
		case <-server.historyStop:
			server.flushStatsHistory()
			return
		}
	}
}

func (server *Server) pruneStatsHistory(at time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), statsStoreTimeout)
	defer cancel()
	if err := server.history.prune(ctx, at); err != nil {
		server.logger.Warn("prune query statistics", "error", err)
	}
}

const statsStoreTimeout = 10 * time.Second

func (server *Server) flushStatsHistory() {
	server.history.record(time.Now(), server.stats.Stats())
	ctx, cancel := context.WithTimeout(context.Background(), statsStoreTimeout)
	defer cancel()
	if err := server.history.flush(ctx); err != nil {
		server.logger.Warn("persist query statistics", "error", err)
	}
}

func bucketKey(at time.Time) int64 {
	seconds := int64(statsBucketInterval / time.Second)
	return floorDiv(at.UTC().Unix(), seconds) * seconds
}

func floorDiv(value, divisor int64) int64 {
	quotient := value / divisor
	if value%divisor != 0 && (value < 0) != (divisor < 0) {
		quotient--
	}
	return quotient
}

// chartSlotWidth keeps the drawn point count at or below maxChartPoints while
// staying a whole number of stored buckets.
func chartSlotWidth(span time.Duration) time.Duration {
	if span <= 0 {
		return statsBucketInterval
	}
	needed := (span + maxChartPoints - 1) / maxChartPoints
	if needed <= statsBucketInterval {
		return statsBucketInterval
	}
	buckets := (needed + statsBucketInterval - 1) / statsBucketInterval
	return buckets * statsBucketInterval
}

func chartDuration(rangeName string) (time.Duration, bool) {
	switch rangeName {
	case "hour":
		return time.Hour, true
	case "day":
		return 24 * time.Hour, true
	case "week":
		return 7 * 24 * time.Hour, true
	case "month":
		return 30 * 24 * time.Hour, true
	case "year":
		return 365 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

func chartTimeFormat(duration time.Duration, display pages.TimeDisplay) string {
	if duration > 24*time.Hour {
		return "Jan 2"
	}
	if !display.TwentyFourHour() {
		if duration == 24*time.Hour {
			return "Jan 2, 3:04 PM"
		}
		return "3:04:05 PM"
	}
	if duration == 24*time.Hour {
		return "Jan 2, 15:04"
	}
	return "15:04:05"
}

// chartTooltipFormat keeps the hovered timestamp unambiguous. Axis labels can
// drop the clock on long ranges; a tooltip pinned to one sample cannot.
func chartTooltipFormat(duration time.Duration, display pages.TimeDisplay) string {
	if display.TwentyFourHour() {
		if duration > 24*time.Hour {
			return "Jan 2, 15:04"
		}
		return "15:04:05"
	}
	if duration > 24*time.Hour {
		return "Jan 2, 3:04 PM"
	}
	return "3:04:05 PM"
}

func counterDelta(current, previous uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}

func chartMaximum(points []chartPoint) uint64 {
	var maximum uint64
	for _, point := range points {
		maximum = max(maximum, point.total, point.successful, point.serverFailure, point.nxDomain, point.refused, point.recursive, point.blocked, point.cacheHits)
	}
	return maximum
}

func chartCoordinates(points []chartPoint, maximum uint64, value func(chartPoint) uint64) string {
	positions := chartXPositions(len(points))
	coordinates := make([]string, 0, len(points))
	for index, point := range points {
		y := chartBottom - (float64(value(point))/float64(maximum))*(chartBottom-chartTop)
		coordinates = append(coordinates, fmt.Sprintf("%.1f,%.1f", positions[index], y))
	}
	return strings.Join(coordinates, " ")
}

func chartXPositions(count int) []float64 {
	positions := make([]float64, 0, count)
	step := (chartRight - chartLeft) / float64(max(count-1, 1))
	for index := range count {
		positions = append(positions, math.Round((chartLeft+step*float64(index))*10)/10)
	}
	return positions
}

// chartHoverData describes every plotted point so the browser can draw a
// crosshair and a tooltip without asking the server again.
func chartHoverData(points []chartPoint, maximum uint64, format string, display pages.TimeDisplay) string {
	payload := chartHoverPayload{
		Maximum: maximum,
		Box: chartBoxPayload{
			Left:   chartLeft,
			Right:  chartRight,
			Top:    chartTop,
			Bottom: chartBottom,
			Width:  chartWidth,
			Height: chartHeight,
		},
		X:      chartXPositions(len(points)),
		Times:  make([]string, 0, len(points)),
		Series: make([]chartSeriesPayload, 0, len(chartSeriesDefinitions)),
	}
	for _, point := range points {
		payload.Times = append(payload.Times, display.In(point.at).Format(format))
	}
	for _, definition := range chartSeriesDefinitions {
		values := make([]uint64, 0, len(points))
		for _, point := range points {
			values = append(values, definition.value(point))
		}
		payload.Series = append(payload.Series, chartSeriesPayload{
			Class:  definition.class,
			Label:  definition.label,
			Values: values,
		})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(encoded)
}
