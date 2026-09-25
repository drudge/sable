package pages

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/drudge/sable/internal/insights"
)

// Evidence charts are drawn on the server as inline SVG in their own units and
// scale to the drawer's width. Their labels are HTML beside the SVG, so they
// keep the page's type size at any width, and sit at fixed shares of the width
// because the console's content security policy allows no inline styles. The
// bar charts split their width into equal slots, one per bar, and carry a
// reading for each slot that the console shows when a slot is pointed at,
// tapped, or stepped to with the arrow keys.
const (
	chartWidth    = 480.0
	chartBaseline = 112.0
	chartTop      = 10.0
	scheduleTop   = 4.0
	scheduleEnd   = 32.0
)

// chartMark is one bar of a chart, in the slot whose reading it belongs to.
type chartMark struct {
	Path  string
	Class string
	Slot  int
}

// chartReading is what a chart says about one slot: the slot's name and each
// series' value there, keyed to the chart's legend.
type chartReading struct {
	Label string       `json:"label"`
	Rows  []chartValue `json:"rows"`
}

// chartValue is one series' value in a reading. Key is the legend swatch that
// marks the series.
type chartValue struct {
	Key    string `json:"key"`
	Series string `json:"series"`
	Value  string `json:"value"`
}

// chartReadingsJSON encodes a chart's readings for the page's script, which
// sets them as text.
func chartReadingsJSON(readings []chartReading) string {
	encoded, err := json.Marshal(readings)
	if err != nil {
		return "[]"
	}
	return string(encoded)
}

// barPath draws a bar rising from the baseline with its top corners rounded.
func barPath(x, width, height float64) string {
	if height <= 0 {
		return ""
	}
	radius := min(4, width/2, height)
	top := chartBaseline - height
	return fmt.Sprintf("M%.1f %.1fV%.1fQ%.1f %.1f %.1f %.1fH%.1fQ%.1f %.1f %.1f %.1fV%.1fZ",
		x, chartBaseline, top+radius, x, top, x+radius, top, x+width-radius, x+width, top, x+width, top+radius, chartBaseline)
}

// chartScale turns a count into a bar height, leaving headroom above the
// largest value.
func chartScale(largest float64) func(float64) float64 {
	if largest <= 0 {
		largest = 1
	}
	return func(value float64) float64 { return value / largest * (chartBaseline - chartTop) }
}

// dayChartView is a DayChart laid out: the days before in the muted fill, the
// last 24 hours in the finding's color, and a dashed line at the average. An
// empty last day is drawn as an outline where it would usually reach. Focus is
// the slot a keyboard reading starts on, the last 24 hours.
type dayChartView struct {
	Marks      []chartMark
	AverageY   float64
	AverageEnd float64
	Readings   []chartReading
	Focus      int
	Summary    string
}

func dayChartLayout(chart insights.DayChart) dayChartView {
	slots := len(chart.Before) + 1
	slot := chartWidth / float64(slots)
	width := math.Min(24, slot*.6)
	largest := math.Max(float64(chart.Last), chart.Average)
	for _, count := range chart.Before {
		largest = math.Max(largest, float64(count))
	}
	scale := chartScale(largest)
	last := len(chart.Before)
	view := dayChartView{AverageY: chartBaseline - scale(chart.Average), AverageEnd: slot * float64(last), Focus: last}
	average := formatNumber(uint64(chart.Average + .5))
	reading := func(label, key string, count uint64) chartReading {
		return chartReading{Label: label, Rows: []chartValue{
			{Key: key, Series: "Queries", Value: formatNumber(count)},
			{Key: "average", Series: "Daily average", Value: average},
		}}
	}
	for index, count := range chart.Before {
		x := slot*float64(index) + (slot-width)/2
		view.Marks = append(view.Marks, chartMark{Path: barPath(x, width, scale(float64(count))), Class: "insight-chart-muted", Slot: index})
		view.Readings = append(view.Readings, reading(daysBeforeLabel(last-index), "muted", count))
	}
	x := slot*float64(last) + (slot-width)/2
	view.Readings = append(view.Readings, reading("Last 24 hours", "emphasis", chart.Last))
	if chart.Last == 0 {
		height := scale(chart.Average)
		view.Marks = append(view.Marks, chartMark{
			Path:  fmt.Sprintf("M%.1f %.1fV%.1fH%.1fV%.1f", x, chartBaseline, chartBaseline-height, x+width, chartBaseline),
			Class: "insight-chart-expected", Slot: last,
		})
		view.Summary = "Queries per day. The week before averaged " + average + " a day; the last 24 hours had none."
	} else {
		view.Marks = append(view.Marks, chartMark{Path: barPath(x, width, scale(float64(chart.Last))), Class: "insight-chart-emphasis", Slot: last})
		view.Summary = "Queries per day. The week before averaged " + average + " a day; the last 24 hours had " + formatNumber(chart.Last) + "."
	}
	return view
}

func daysBeforeLabel(days int) string {
	if days == 1 {
		return "The day before"
	}
	return fmt.Sprintf("%d days before", days)
}

func countLabel(count uint64, singular, plural string) string {
	if count == 1 {
		return "1 " + singular
	}
	return formatNumber(count) + " " + plural
}

// hourChartView is an HourChart laid out: the usual day in the muted fill and
// the unusual hours of the last day in the finding's color. Focus is the slot
// a keyboard reading starts on, the first unusual hour.
type hourChartView struct {
	Marks    []chartMark
	Readings []chartReading
	Focus    int
	Summary  string
}

func hourChartLayout(chart insights.HourChart) hourChartView {
	slot := chartWidth / 24
	width := slot * .6
	largest := 0.0
	for hour := range 24 {
		largest = math.Max(largest, math.Max(chart.Usual[hour], float64(chart.Unusual[hour])))
	}
	scale := chartScale(largest)
	view := hourChartView{Focus: -1}
	unusual := make([]string, 0, 2)
	for hour := range 24 {
		x := slot*float64(hour) + (slot-width)/2
		usual := chartValue{Key: "muted", Series: "Usual day", Value: usualValue(chart.Usual[hour])}
		if chart.Unusual[hour] > 0 {
			view.Marks = append(view.Marks, chartMark{Path: barPath(x, width, scale(float64(chart.Unusual[hour]))), Class: "insight-chart-emphasis", Slot: hour})
			view.Readings = append(view.Readings, chartReading{Label: chartHour(hour), Rows: []chartValue{
				{Key: "emphasis", Series: "Last 24 hours", Value: formatNumber(chart.Unusual[hour])}, usual,
			}})
			if view.Focus < 0 {
				view.Focus = hour
			}
			unusual = append(unusual, chartHour(hour))
			continue
		}
		view.Marks = append(view.Marks, chartMark{Path: barPath(x, width, scale(chart.Usual[hour])), Class: "insight-chart-muted", Slot: hour})
		view.Readings = append(view.Readings, chartReading{Label: chartHour(hour), Rows: []chartValue{usual}})
	}
	view.Focus = max(view.Focus, 0)
	view.Summary = "Queries by hour of the day. Gray bars are the usual day. Highlighted, busy in the last 24 hours at an hour that is usually silent: " +
		strings.Join(unusual, ", ") + "."
	return view
}

// usualValue states an hour's average in whole queries, or that it is more
// than none but less than one.
func usualValue(average float64) string {
	if rounded := uint64(average + .5); rounded > 0 || average == 0 {
		return formatNumber(rounded)
	}
	return "<1"
}

func chartHour(hour int) string {
	switch {
	case hour == 0:
		return "12 AM"
	case hour < 12:
		return fmt.Sprintf("%d AM", hour)
	case hour == 12:
		return "12 PM"
	default:
		return fmt.Sprintf("%d PM", hour-12)
	}
}

// scheduleChartView is a ScheduleChart laid out as one tick per moment.
type scheduleChartView struct {
	Ticks   string
	Summary string
}

func scheduleChartLayout(chart insights.ScheduleChart) scheduleChartView {
	span := chart.End.Sub(chart.Start)
	if span <= 0 {
		return scheduleChartView{}
	}
	var ticks strings.Builder
	count := uint64(0)
	for _, moment := range chart.Times {
		if moment.Before(chart.Start) || moment.After(chart.End) {
			continue
		}
		x := float64(moment.Sub(chart.Start)) / float64(span) * chartWidth
		fmt.Fprintf(&ticks, "M%.1f %.1fV%.1f", x, scheduleTop, scheduleEnd)
		count++
	}
	return scheduleChartView{
		Ticks:   ticks.String(),
		Summary: fmt.Sprintf("%s over the last %d hours, one mark each.", countLabel(count, "lookup", "lookups"), int(math.Round(span.Hours()))),
	}
}
