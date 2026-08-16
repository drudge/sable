package web

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/web/pages"
)

const (
	statsSampleInterval = 5 * time.Second
	maxStatsSamples     = 17_280
	maxChartPoints      = 160
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

type statsSample struct {
	at    time.Time
	stats dnsserver.Stats
}

type statsHistory struct {
	mu      sync.RWMutex
	samples []statsSample
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

func newStatsHistory() *statsHistory {
	return &statsHistory{samples: make([]statsSample, 0, maxStatsSamples)}
}

func (history *statsHistory) record(at time.Time, stats dnsserver.Stats) {
	history.mu.Lock()
	defer history.mu.Unlock()
	if len(history.samples) > 0 && at.Sub(history.samples[len(history.samples)-1].at) < time.Second {
		history.samples[len(history.samples)-1] = statsSample{at: at, stats: stats}
		return
	}
	if len(history.samples) == maxStatsSamples {
		copy(history.samples, history.samples[1:])
		history.samples = history.samples[:maxStatsSamples-1]
	}
	history.samples = append(history.samples, statsSample{at: at, stats: stats})
}

func (history *statsHistory) view(
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

	history.mu.RLock()
	cutoff := now.Add(-duration)
	selected := make([]statsSample, 0, len(history.samples))
	for _, sample := range history.samples {
		if !sample.at.Before(cutoff) {
			selected = append(selected, sample)
		}
	}
	history.mu.RUnlock()
	return buildChartView(rangeName, cutoff, now, selected, display)
}

func (history *statsHistory) customView(start, end time.Time, current dnsserver.Stats, display pages.TimeDisplay) pages.QueryChartView {
	history.record(time.Now(), current)
	history.mu.RLock()
	selected := make([]statsSample, 0, len(history.samples))
	for _, sample := range history.samples {
		if !sample.at.Before(start) && !sample.at.After(end) {
			selected = append(selected, sample)
		}
	}
	history.mu.RUnlock()
	return buildChartView("custom", start, end, selected, display)
}

func buildChartView(rangeName string, start, end time.Time, selected []statsSample, display pages.TimeDisplay) pages.QueryChartView {
	format := chartTimeFormat(end.Sub(start), display)
	customStart := start
	if rangeName != "custom" {
		customStart = end.Add(-7 * 24 * time.Hour)
	}
	view := pages.QueryChartView{
		ActiveRange: rangeName,
		StartLabel:  display.In(start).Format(format),
		EndLabel:    display.In(end).Format(format),
		CustomStart: display.In(customStart).Format("2006-01-02T15:04"),
		CustomEnd:   display.In(end).Format("2006-01-02T15:04"),
	}
	if len(selected) < 2 {
		return view
	}
	view.StartLabel = display.In(selected[0].at).Format(format)
	points := compactChartPoints(chartDeltas(selected), maxChartPoints)
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

func (history *statsHistory) cacheHitsSince(duration time.Duration, now time.Time, current dnsserver.Stats) uint64 {
	history.record(now, current)
	cutoff := now.Add(-duration)
	history.mu.RLock()
	defer history.mu.RUnlock()
	for _, sample := range history.samples {
		if !sample.at.Before(cutoff) {
			return counterDelta(current.CacheHits, sample.stats.CacheHits)
		}
	}
	return current.CacheHits
}

func (history *statsHistory) blockedSince(duration time.Duration, now time.Time, current dnsserver.Stats) uint64 {
	history.record(now, current)
	cutoff := now.Add(-duration)
	history.mu.RLock()
	defer history.mu.RUnlock()
	for _, sample := range history.samples {
		if !sample.at.Before(cutoff) {
			return counterDelta(current.Blocked, sample.stats.Blocked)
		}
	}
	return current.Blocked
}

func (server *Server) collectStatsHistory() {
	ticker := time.NewTicker(statsSampleInterval)
	defer ticker.Stop()
	for {
		select {
		case at := <-ticker.C:
			server.history.record(at, server.stats.Stats())
		case <-server.historyStop:
			return
		}
	}
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
			return "3:04 PM"
		}
		return "3:04:05 PM"
	}
	if duration == 24*time.Hour {
		return "15:04"
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

func chartDeltas(samples []statsSample) []chartPoint {
	points := make([]chartPoint, 0, len(samples)-1)
	for index := 1; index < len(samples); index++ {
		previous, current := samples[index-1].stats, samples[index].stats
		total := counterDelta(current.Queries, previous.Queries)
		points = append(points, chartPoint{
			at:            samples[index].at,
			total:         total,
			successful:    counterDelta(current.NoError, previous.NoError),
			serverFailure: counterDelta(current.ServerFailures, previous.ServerFailures),
			nxDomain:      counterDelta(current.NXDomain, previous.NXDomain),
			refused:       counterDelta(current.Refused, previous.Refused),
			recursive:     counterDelta(current.CacheHits+current.CacheMisses, previous.CacheHits+previous.CacheMisses),
			blocked:       counterDelta(current.Blocked, previous.Blocked),
			cacheHits:     counterDelta(current.CacheHits, previous.CacheHits),
		})
	}
	return points
}

func counterDelta(current, previous uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}

func compactChartPoints(points []chartPoint, maximum int) []chartPoint {
	if len(points) <= maximum {
		return points
	}
	bucketSize := int(math.Ceil(float64(len(points)) / float64(maximum)))
	compacted := make([]chartPoint, 0, maximum)
	for start := 0; start < len(points); start += bucketSize {
		end := min(start+bucketSize, len(points))
		var point chartPoint
		for _, sample := range points[start:end] {
			point.total += sample.total
			point.successful += sample.successful
			point.serverFailure += sample.serverFailure
			point.nxDomain += sample.nxDomain
			point.refused += sample.refused
			point.recursive += sample.recursive
			point.blocked += sample.blocked
			point.cacheHits += sample.cacheHits
		}
		point.at = points[end-1].at
		compacted = append(compacted, point)
	}
	return compacted
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
