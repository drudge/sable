package pages

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/insights/services"
)

func TestInsightCausesReadAsOneSentence(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		causes []string
		want   string
	}{
		{[]string{"Switched off or unplugged"}, "switched off or unplugged."},
		{[]string{"A software update", "DNS moved elsewhere"}, "a software update or DNS moved elsewhere."},
		{[]string{"Switched off or unplugged", "Moved to another network", "Set to use a different DNS server"},
			"switched off or unplugged, moved to another network, or set to use a different DNS server."},
	} {
		if got := insightCauses(test.causes); got != test.want {
			t.Errorf("insightCauses(%q) = %q, want %q", test.causes, got, test.want)
		}
	}
}

func TestInsightEvidenceShowsWhereTheNameCameFromBesideIt(t *testing.T) {
	t.Parallel()
	finding := InsightFindingView{ID: "insight-finding-1", Title: "New device on the network", Subject: "front-door-doorbell", SubjectSource: "UniFi"}
	markup := renderComponent(t, InsightEvidence(finding, InsightsOverviewView{}))
	if !strings.Contains(markup, `<span class="sr-only">Name from </span>UniFi</span>`) {
		t.Errorf("drawer header is missing the name source badge:\n%s", markup)
	}
	if strings.Contains(markup, "<dt>Name from</dt>") {
		t.Error("the name source is still a fact card")
	}
}

func TestInsightDeviceDrawerShowsWhereTheNameCameFromBesideIt(t *testing.T) {
	t.Parallel()
	view := InsightDeviceDrawerView{Device: InsightDeviceView{Key: "mac:b8:27:eb:33:0c:c6", Label: "front-door-doorbell", NameSource: "UniFi"}}
	for _, canName := range []bool{false, true} {
		view.CanName = canName
		markup := renderComponent(t, InsightDeviceDrawer(view))
		if !strings.Contains(markup, `<span class="sr-only">Name from </span>UniFi</span>`) {
			t.Errorf("CanName=%v: drawer header is missing the name source badge", canName)
		}
		if count := strings.Count(markup, ">UniFi</span>"); count != 1 {
			t.Errorf("CanName=%v: name source shown %d times, want once", canName, count)
		}
		if got := strings.Contains(markup, `title="Rename device"`); got != canName {
			t.Errorf("CanName=%v: rename button shown = %v", canName, got)
		}
	}
}

// Every device type has an icon the console can draw, and a device Sable can't
// place still gets one, so the Devices list lines up. The icon stands in for a
// Type column: each row starts with it, the drawer sets it beside the name,
// and its tooltip says the type in words.
func TestDeviceTypesHaveIcons(t *testing.T) {
	t.Parallel()
	shapes := regexp.MustCompile(`<(path|circle|rect|line|polyline)\b`)
	for _, kind := range append(devices.TypeLabels(), [2]string{"", "unknown"}) {
		drawn := renderComponent(t, Icon(insightTypeIcon(kind[0])))
		if !shapes.MatchString(drawn) {
			t.Errorf("%s icon %q draws nothing", kind[1], insightTypeIcon(kind[0]))
		}
	}
	tv := InsightDeviceView{Key: "mac:aa:00:00:00:00:02", Label: "Living Room TV", Named: true, Type: "tv", TypeLabel: "TV", TypeConfidence: "medium"}
	tile := `<span class="insight-type-tile" role="img" aria-label="TV" title="TV"><svg class="nav-icon icon-tv"`
	list := renderComponent(t, InsightDevices(InsightsOverviewView{Devices: []InsightDeviceView{tv}}))
	if strings.Count(list, tile) != 2 || strings.Contains(list, `<th scope="col">Type</th>`) {
		t.Errorf("the phone and desktop rows do not both start with the TV icon in place of a Type column:\n%s", list)
	}
	drawer := renderComponent(t, InsightDeviceDrawer(InsightDeviceDrawerView{Device: tv}))
	if !strings.Contains(drawer, `<header class="query-detail-header">`+tile) {
		t.Errorf("the drawer does not set the TV icon beside the name:\n%s", drawer)
	}
	// A guess Sable is unsure of shows a plain device and says so in words.
	unsure := tv
	unsure.TypeConfidence = "low"
	if got := renderComponent(t, insightTypeTile(unsure)); !strings.Contains(got, `aria-label="Maybe a TV" title="Maybe a TV"><svg class="nav-icon icon-monitor-smartphone"`) {
		t.Errorf("an unsure guess shows %s", got)
	}
	// The type picker gives every choice its icon, and the choice to leave the
	// device untyped the icon of the type it then takes.
	tv.TypeOptions, tv.DefaultType = devices.TypeLabels(), "tv"
	picker := renderComponent(t, InsightDeviceDrawer(InsightDeviceDrawerView{Device: tv, CanName: true, EditingType: true}))
	if !strings.Contains(picker, `<template data-option-icon=""><svg class="nav-icon icon-tv"`) ||
		!strings.Contains(picker, `<template data-option-icon="camera"><svg class="nav-icon icon-cctv"`) ||
		strings.Count(picker, "<template data-option-icon=") != len(tv.TypeOptions)+1 {
		t.Errorf("the type picker does not give each choice its icon:\n%s", picker)
	}
}

// Every app Sable recognizes has an icon: its logo as an app tile, with the
// mark in whichever of white or black reads on the brand's color, or its
// category's icon on a gray tile when Simple Icons has no logo for it.
func TestAppsHaveIcons(t *testing.T) {
	t.Parallel()
	shapes := regexp.MustCompile(`<(path|circle|rect|line|polyline)\b`)
	for _, service := range services.All() {
		drawn := renderComponent(t, AppIcon(service.ID, service.Category))
		if !shapes.MatchString(drawn) {
			t.Errorf("%s draws nothing", service.ID)
		}
		if _, logo := appLogos[service.ID]; !logo && appCategoryIcon(service.Category) == "apps" {
			t.Errorf("%s has neither a logo nor an icon for %s", service.ID, service.Category)
		}
	}
	for id, want := range map[string]string{
		"netflix":  `<rect width="24" height="24" rx="6" fill="#E50914"></rect>`,
		"snapchat": `fill="#FFFC00"`,
		// ChatGPT keeps OpenAI's mark from before it left Simple Icons.
		"chatgpt": `fill="#412991"`,
	} {
		if drawn := renderComponent(t, AppIcon(id, "")); !strings.Contains(drawn, want) {
			t.Errorf("%s logo = %s", id, drawn)
		}
	}
	// Brands draw their marks in white on their color unless it is very light,
	// or their own look is a dark mark, as Spotify's is.
	for id, ink := range map[string]string{"netflix": "#fff", "youtube": "#fff", "reddit": "#fff", "instagram": "#fff", "snapchat": "#000", "spotify": "#000"} {
		if drawn := renderComponent(t, AppIcon(id, "")); !strings.Contains(drawn, `fill="`+ink+`" transform=`) {
			t.Errorf("%s mark is not drawn in %s: %s", id, ink, drawn)
		}
	}
	if drawn := renderComponent(t, AppIcon("microsoft-365", services.CategoryProductivity)); !strings.Contains(drawn, `class="app-icon app-icon-category"`) || !strings.Contains(drawn, "icon-briefcase") {
		t.Errorf("an app without a logo shows %s", drawn)
	}
}

// An app in a device's drawer opens the app's drawer, and the row keeps the
// device's count of queries to it.
func TestDeviceAppsOpenTheirDrawers(t *testing.T) {
	t.Parallel()
	view := InsightDeviceDrawerView{Range: "week", Device: InsightDeviceView{Key: "mac:aa:00:00:00:00:01", Label: "iPad"},
		Apps: []InsightAppView{{ID: "discord", Name: "Discord", Category: services.CategoryMessaging, Queries: 120, Domains: 1}}}
	markup := renderComponent(t, InsightDeviceDrawer(view))
	for _, want := range []string{
		`data-dialog-open="insight-app-dialog"`, `hx-get="/ui/insights/app?id=discord&amp;range=week"`,
		`aria-label="View details for Discord"`,
	} {
		if !strings.Contains(markup, want) {
			t.Errorf("the device's app row is missing %q", want)
		}
	}
	if !regexp.MustCompile(`aria-label="View details for Discord">\s*120\s*</button>`).MatchString(markup) {
		t.Errorf("the app row lost its count:\n%s", markup)
	}
}

// A full-width card waits for the row before it to fill, so a half-width card
// after it slots into the gap instead of leaving one.
func TestInsightFactRowsLeaveNoHoles(t *testing.T) {
	t.Parallel()
	facts := []InsightFactView{
		{Label: "Looks like", Value: "Probably a printer"},
		{Label: "Hardware address", Value: "aa:00:00:00:00:04 (private address)"},
		{Label: "Address", Value: "10.99.7.4"},
		{Label: "First seen", Value: "Sep 23, 11:18 PM"},
		{Label: "Queries in period", Value: "10"},
	}
	layout := func(facts []InsightFactView) string {
		cards := make([]string, 0, len(facts))
		for _, card := range insightFactRows(facts) {
			cards = append(cards, card.Label+ifThen(card.Full, " (full)", ""))
		}
		return strings.Join(cards, ", ")
	}
	if got := layout(facts); got != "Looks like, Address, Hardware address (full), First seen, Queries in period" {
		t.Fatalf("rows = %s", got)
	}
	// A half card left over at the end stretches across its row.
	odd := append(slices.Clone(facts), InsightFactView{Label: "Last 24 hours", Value: "2,754"})
	if got := layout(odd); got != "Looks like, Address, Hardware address (full), First seen, Queries in period, Last 24 hours (full)" {
		t.Fatalf("rows = %s", got)
	}
	// A DNS name breaks mid-name when it wraps, so one that fills half a
	// phone-width card takes a row of its own and the short card after it
	// pairs up instead. An address still fits half a card.
	checkIn := []InsightFactView{
		{Label: "Looks like", Value: "Probably a TV"},
		{Label: "Address", Value: "255.255.255.255", Monospace: true},
		{Label: "Hardware address", Value: "aa:00:00:00:00:02 (private address)", Monospace: true},
		{Label: "Queries in period", Value: "598"},
		{Label: "Name", Value: "tv-heartbeat.vendor.example", Monospace: true},
		{Label: "Schedule", Value: "Every 5 minutes"},
	}
	if got := layout(checkIn); got != "Looks like, Address, Hardware address (full), Queries in period, Schedule, Name (full)" {
		t.Fatalf("rows = %s", got)
	}
}

// The Overview's sentence lists the findings that stand out, sets each subject
// apart, and opens a finding the page shows from its subject.
func TestInsightsHeadlineReadsAsOneSentence(t *testing.T) {
	t.Parallel()
	clauses := []InsightHeadlineClause{
		{Subject: "dock-camera-02", Rest: " went quiet", Tone: "attention", Dialog: "insight-finding-1"},
		{Subject: "front-door-doorbell", Rest: " joined the network", Tone: "notice", Dialog: "insight-finding-2"},
		{Subject: "ads.example", Rest: " was blocked 3 times before you allowed it", Tone: "attention", Monospace: true},
	}
	markup := renderComponent(t, insightsHeadline(InsightHeadlineView{Clauses: clauses, More: 1}))
	if got := sentenceText(markup); got != "dock-camera-02 went quiet, front-door-doorbell joined the network, and ads.example was blocked 3 times before you allowed it. 1 more thing below." {
		t.Errorf("headline reads %q", got)
	}
	for _, expected := range []string{
		// Lucide's search-alert: a magnifier with an exclamation mark in it.
		`class="insights-headline tone-attention"`, `<path d="M11 7v4"></path><path d="M11 15h.01"></path>`,
		`<button type="button" class="insights-headline-subject tone-attention" data-dialog-open="insight-finding-1">dock-camera-02</button>`,
		`<strong class="insights-headline-subject tone-attention mono">ads.example</strong>`,
		`<a class="insights-headline-more" href="#insight-findings">1 more thing below</a>`,
	} {
		if !strings.Contains(markup, expected) {
			t.Errorf("headline is missing %q:\n%s", expected, markup)
		}
	}
	for count, want := range map[int]string{
		1: "dock-camera-02 went quiet.",
		2: "dock-camera-02 went quiet and front-door-doorbell joined the network.",
	} {
		if got := sentenceText(renderComponent(t, insightsHeadline(InsightHeadlineView{Clauses: clauses[:count]}))); got != want {
			t.Errorf("%d clauses read %q, want %q", count, got, want)
		}
	}
	quiet := renderComponent(t, insightsHeadline(InsightHeadlineView{}))
	if got := sentenceText(quiet); got != "All quiet. Nothing on your network changed in a way that needs a look." || !strings.Contains(quiet, "tone-positive") {
		t.Errorf("quiet headline reads %q:\n%s", got, quiet)
	}
}

var markupTags = regexp.MustCompile(`<[^>]*>`)

// sentenceText is the text a reader sees in markup, with its spacing collapsed.
func sentenceText(markup string) string {
	return strings.Join(strings.Fields(markupTags.ReplaceAllString(markup, "")), " ")
}

func renderChart(t *testing.T, chart *insights.Chart, tone string) string {
	t.Helper()
	var body strings.Builder
	if err := insightChart(InsightFindingView{ID: "finding", Tone: tone, Chart: chart}).Render(context.Background(), &body); err != nil {
		t.Fatal(err)
	}
	return body.String()
}

// readingText is a chart reading as one line, the way the tooltip shows it.
func readingText(reading chartReading) string {
	values := make([]string, 0, len(reading.Rows))
	for _, row := range reading.Rows {
		values = append(values, row.Key+" "+row.Series+" "+row.Value)
	}
	return reading.Label + ": " + strings.Join(values, ", ")
}

// Each chart draws its evidence in the finding's color, says in words what it
// shows, and gives every bar a reading with its count, so tapping a bar shows
// the number without a hover.
func TestInsightChartsPictureTheEvidence(t *testing.T) {
	t.Parallel()
	week := insights.DayChart{Before: []uint64{560, 590, 548, 612, 571, 583, 566}, Average: 575.7}
	quiet := renderChart(t, &insights.Chart{Days: &week}, "attention")
	for _, expected := range []string{
		`class="query-detail-answer insight-chart tone-attention"`, "Queries per day", `data-insight-chart data-chart-readings="[`,
		`aria-label="Queries per day. The week before averaged 576 a day; the last 24 hours had none. Use Left and Right Arrow keys to read each bar."`,
		`data-chart-focus="7"`, `data-chart-slot="7"`, `class="insight-chart-expected"`, `class="insight-chart-average"`, `data-chart-tooltip`,
	} {
		if !strings.Contains(quiet, expected) {
			t.Errorf("went-quiet chart is missing %q", expected)
		}
	}
	if strings.Count(quiet, `class="insight-chart-muted"`) != 7 || strings.Contains(quiet, "<title>") {
		t.Errorf("went-quiet chart does not draw the seven days before as plain bars")
	}
	quietReadings := dayChartLayout(week).Readings
	for slot, want := range map[int]string{
		0: "7 days before: muted Queries 560, average Daily average 576",
		6: "The day before: muted Queries 566, average Daily average 576",
		7: "Last 24 hours: emphasis Queries 0, average Daily average 576",
	} {
		if got := readingText(quietReadings[slot]); got != want {
			t.Errorf("went-quiet slot %d reads %q, want %q", slot, got, want)
		}
	}

	spike := insights.DayChart{Before: []uint64{500, 510, 520, 530, 540, 550, 560}, Average: 530, Last: 7755}
	busy := renderChart(t, &insights.Chart{Days: &spike}, "attention")
	if !strings.Contains(busy, `class="insight-chart-emphasis"`) || strings.Contains(busy, "insight-chart-expected") {
		t.Errorf("busy chart does not draw its last day as a bar")
	}
	if got := readingText(dayChartLayout(spike).Readings[7]); got != "Last 24 hours: emphasis Queries 7,755, average Daily average 530" {
		t.Errorf("busy chart's last day reads %q", got)
	}

	var usual [24]float64
	for hour := 8; hour < 23; hour++ {
		usual[hour] = 42
	}
	var unusual [24]uint64
	unusual[3] = 54
	usual[7] = .3
	day := insights.HourChart{Usual: usual, Unusual: unusual}
	hours := renderChart(t, &insights.Chart{Hours: &day}, "attention")
	for _, expected := range []string{
		"Queries by hour of the day", `data-chart-focus="3"`, `data-chart-slot="22"`,
		"Highlighted, busy in the last 24 hours at an hour that is usually silent: 3 AM.", "<span>12 AM</span><span>6 AM</span><span>12 PM</span><span>6 PM</span>",
	} {
		if !strings.Contains(hours, expected) {
			t.Errorf("hour chart is missing %q", expected)
		}
	}
	if strings.Count(hours, `class="insight-chart-emphasis"`) != 1 {
		t.Errorf("hour chart highlights more than the unusual hour")
	}
	hourReadings := hourChartLayout(day).Readings
	for slot, want := range map[int]string{
		3:  "3 AM: emphasis Last 24 hours 54, muted Usual day 0",
		7:  "7 AM: muted Usual day <1",
		14: "2 PM: muted Usual day 42",
	} {
		if got := readingText(hourReadings[slot]); got != want {
			t.Errorf("hour slot %d reads %q, want %q", slot, got, want)
		}
	}

	end := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	times := make([]time.Time, 0, 288)
	for minute := 0; minute < 24*60; minute += 5 {
		times = append(times, end.Add(-24*time.Hour+time.Duration(minute)*time.Minute))
	}
	schedule := renderChart(t, &insights.Chart{Schedule: &insights.ScheduleChart{Start: end.Add(-24 * time.Hour), End: end, Times: times}}, "notice")
	if !strings.Contains(schedule, "tone-notice") || !strings.Contains(schedule, `aria-label="288 lookups over the last 24 hours, one mark each."`) ||
		strings.Count(schedule, "V32.0") != 288 {
		t.Errorf("schedule chart = %s", schedule[:min(len(schedule), 400)])
	}
	if renderChart(t, nil, "notice") != "" {
		t.Error("a finding without a chart drew one")
	}
}
