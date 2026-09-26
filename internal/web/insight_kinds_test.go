package web

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights"
	blockinginsights "github.com/drudge/sable/internal/insights/blocking"
	"github.com/drudge/sable/internal/insights/devices"
)

// updateTestConfiguration changes the test server's configuration the way
// the console would.
func (server insightsTestServer) updateTestConfiguration(t *testing.T, change func(*config.Config)) {
	t.Helper()
	if err := server.config.(settingsEditor).Update(context.Background(), func(configuration *config.Config) error {
		change(configuration)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Off takes a kind off the page and out of alerts. Show only keeps it on the
// page and out of alerts.
func TestInsightModesDecideWhatThePageShowsAndWhatAlerts(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	shows := func(title string) bool {
		body := server.get(t, "everything", "/ui/insights/overview?range=day", true).Body.String()
		return strings.Contains(body, `<span class="insight-finding-title">`+title+`</span>`)
	}
	alerts := func() []string {
		kinds := make([]string, 0)
		for _, finding := range server.insightNews(context.Background(), time.Now()) {
			kinds = append(kinds, finding.Kind)
		}
		return kinds
	}
	if !shows("Possible past blocking issue") || !shows("Little unique coverage") || !slices.Contains(alerts(), blockinginsights.KindPastBlock) {
		t.Fatalf("with the defaults the page and alerts are missing findings; alerts = %v", alerts())
	}
	// Coverage findings are not news, so they never alert whatever they are
	// set to.
	if slices.Contains(alerts(), blockinginsights.KindLowUnique) {
		t.Fatal("a coverage finding alerted")
	}

	server.updateTestConfiguration(t, func(configuration *config.Config) {
		configuration.Insights.Findings.PastBlock.Mode = config.InsightModeShow
	})
	if !shows("Possible past blocking issue") || slices.Contains(alerts(), blockinginsights.KindPastBlock) {
		t.Fatalf("a kind set to show only: shown = %t, alerts = %v", shows("Possible past blocking issue"), alerts())
	}
	if !slices.Contains(alerts(), devices.KindNewDevice) {
		t.Fatalf("other kinds stopped alerting: %v", alerts())
	}

	server.updateTestConfiguration(t, func(configuration *config.Config) {
		configuration.Insights.Findings.PastBlock.Mode = config.InsightModeOff
		configuration.Insights.Findings.LowUniqueCoverage.Mode = config.InsightModeOff
		configuration.Insights.Findings.NewDevice.Mode = config.InsightModeOff
	})
	if shows("Possible past blocking issue") || shows("Little unique coverage") || len(alerts()) != 0 {
		t.Fatalf("kinds that are off are still shown or sent; alerts = %v", alerts())
	}
	// The headline sentence is built from what the page shows.
	if body := server.get(t, "everything", "/ui/insights/overview?range=day", true).Body.String(); strings.Contains(body, "telemetry.example.com</button>") {
		t.Fatal("the headline still names a finding whose kind is off")
	}
}

// Insights as an alert source keeps its answer for a few minutes, but a change
// to the settings counts from the next round.
func TestInsightAlertsFollowASettingsChangeAtOnce(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	source := server.InsightAlerts()
	now := time.Now()
	kinds := func(at time.Time) []string {
		found, err := source.Alerts(context.Background(), at)
		if err != nil {
			t.Fatal(err)
		}
		kinds := make([]string, 0, len(found))
		for _, alert := range found {
			kinds = append(kinds, alert.Kind)
		}
		return kinds
	}
	if !slices.Contains(kinds(now), blockinginsights.KindPastBlock) {
		t.Fatal("the past block did not alert")
	}
	server.updateTestConfiguration(t, func(configuration *config.Config) {
		configuration.Insights.Findings.PastBlock.Mode = config.InsightModeShow
	})
	if got := kinds(now.Add(time.Second)); slices.Contains(got, blockinginsights.KindPastBlock) {
		t.Fatalf("a kind set to show only still alerts from the kept answer: %v", got)
	}
}

// The settings list every kind of finding the analyzers make, their fields
// offer exactly the ranges the configuration accepts, and the defaults are
// the analyzers' own.
func TestInsightSettingsCoverEveryKindWithTheConfigurationsRanges(t *testing.T) {
	t.Parallel()
	listed := make([]string, 0)
	for _, kind := range insightKindSettings() {
		listed = append(listed, kind.kind)
	}
	every := []string{
		devices.KindNewDevice, devices.KindWentQuiet, devices.KindTrafficSpike, devices.KindNewDestinations, devices.KindNewApp,
		devices.KindUnusualHours, devices.KindCheckIn, devices.KindApplianceDrift,
		blockinginsights.KindUpdateFailing, blockinginsights.KindPastBlock, blockinginsights.KindListUnreadable,
		blockinginsights.KindLowUnique, blockinginsights.KindUniqueCoverage,
	}
	if !slices.Equal(listed, every) {
		t.Fatalf("settings list %v, want %v", listed, every)
	}
	defaults := config.DefaultInsightFindings()
	if got := insightDeviceLimits(defaults); got != devices.DefaultLimits() {
		t.Errorf("default device limits = %+v, want %+v", got, devices.DefaultLimits())
	}
	if got := insightBlockingLimits(defaults); got != blockinginsights.DefaultLimits() {
		t.Errorf("default blocking limits = %+v, want %+v", got, blockinginsights.DefaultLimits())
	}
	for _, kind := range insightKindSettings() {
		for _, limit := range kind.limits {
			setting := kind.key + "." + limit.key
			step := 0.1
			if limit.whole {
				step = 1
			}
			for value, accepted := range map[float64]bool{
				limit.minimum: true, limit.maximum: true, limit.minimum - step: false, limit.maximum + step: false,
			} {
				findings := config.DefaultInsightFindings()
				limit.set(&findings, value)
				problems := findings.Problems()
				if refused := len(problems) == 1 && problems[0].Setting == setting; refused == accepted || (accepted && len(problems) != 0) {
					t.Errorf("%s = %v: the configuration says %v, the field says accepted = %t", setting, value, problems, accepted)
				}
			}
		}
	}
	// A kind can alert exactly when the configuration lets it.
	for _, kind := range insightKindSettings() {
		findings := config.DefaultInsightFindings()
		*kind.mode(&findings) = config.InsightModeAlert
		if canAlert := len(findings.Problems()) == 0; canAlert != (kind.note == "") {
			t.Errorf("%s can alert = %t, but the settings say %t", kind.kind, canAlert, kind.note == "")
		}
	}
}

func TestInsightModesTreatKindsWithoutSettingsAsTheyAlwaysWere(t *testing.T) {
	t.Parallel()
	settings := config.DefaultInsightFindings()
	settings.NewApp.Mode = config.InsightModeOff
	settings.WentQuiet.Mode = config.InsightModeShow
	modes := insightModesOf(settings)
	for _, test := range []struct {
		kind          string
		shows, alerts bool
		off           bool
	}{
		{devices.KindNewApp, false, false, true},
		{devices.KindWentQuiet, true, false, false},
		{devices.KindTrafficSpike, true, true, false},
		{blockinginsights.KindLowUnique, true, false, false},
		// A kind a newer analyzer adds before it has settings.
		{"devices.something-new", true, true, false},
	} {
		if modes.shows(test.kind) != test.shows || modes.alerts(test.kind) != test.alerts || modes.off()[test.kind] != test.off {
			t.Errorf("%s: shows %t, alerts %t, off %t", test.kind, modes.shows(test.kind), modes.alerts(test.kind), modes.off()[test.kind])
		}
	}
	shown := modes.shown([]insights.Finding{{Kind: devices.KindNewApp}, {Kind: devices.KindWentQuiet}, {Kind: "devices.something-new"}})
	if len(shown) != 2 || shown[0].Kind != devices.KindWentQuiet {
		t.Fatalf("shown = %+v", shown)
	}
}
