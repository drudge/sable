package config

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"
)

// Before these settings existed, every finding with news alerted and the
// block list coverage findings were only shown, with fixed limits. A file that
// says nothing about Insights keeps exactly that.
func TestInsightFindingsDefaultToWhatInsightsAlwaysDid(t *testing.T) {
	t.Parallel()
	want := InsightFindings{
		NewDevice:           InsightFinding{Mode: "alert"},
		WentQuiet:           InsightWentQuiet{Mode: "alert", MinimumDailyLookups: 50},
		TrafficSpike:        InsightTrafficSpike{Mode: "alert", Factor: 3, MinimumLookups: 500},
		NewDestinations:     InsightNewDestinations{Mode: "alert", MinimumNewDomains: 20},
		NewApp:              InsightFinding{Mode: "alert"},
		UnusualHours:        InsightUnusualHours{Mode: "alert", MinimumLookups: 30},
		CheckIn:             InsightCheckIn{Mode: "alert", LongestInterval: Duration{2 * time.Hour}, ShortestSpan: Duration{12 * time.Hour}},
		ApplianceNewDomains: InsightApplianceNewDomains{Mode: "alert", MinimumNewDomains: 3},
		UpdateFailing:       InsightUpdateFailing{Mode: "alert", MissedUpdates: 2},
		PastBlock:           InsightFinding{Mode: "alert"},
		ListUnreadable:      InsightFinding{Mode: "show"},
		LowUniqueCoverage:   InsightFinding{Mode: "show"},
		UniqueCoverage:      InsightFinding{Mode: "show"},
	}
	loaded, err := Decode(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	// A configuration built in code without ever loading one, such as an
	// older replica's, fills in the same values once it is normalized.
	blank := Defaults()
	blank.Insights = Insights{}
	blank.normalize()
	for name, got := range map[string]InsightFindings{
		"Defaults":                  Defaults().Insights.Findings,
		"DefaultInsightFindings":    DefaultInsightFindings(),
		"an empty file":             loaded.Insights.Findings,
		"a normalized empty struct": blank.Insights.Findings,
	} {
		if got != want {
			t.Errorf("%s = %+v, want %+v", name, got, want)
		}
	}
	if problems := want.Problems(); len(problems) != 0 {
		t.Fatalf("the defaults have problems: %v", problems)
	}
}

// A table written by hand can name only what it changes. Modes are read the
// way people type them, and every limit it leaves out or sets to 0 keeps its
// default.
func TestInsightFindingsFillInWhatAFileLeavesOut(t *testing.T) {
	t.Parallel()
	loaded, err := Decode(strings.NewReader(`
[insights.findings.went_quiet]
mode = " Show "

[insights.findings.traffic_spike]
factor = 4.5

[insights.findings.new_destinations]
minimum_new_domains = 0

[insights.findings.check_in]
mode = "OFF"
shortest_span = "6h"

[insights.findings.unique_coverage]
mode = "off"
`))
	if err != nil {
		t.Fatal(err)
	}
	findings := loaded.Insights.Findings
	for _, test := range []struct {
		name      string
		got, want any
	}{
		{"went_quiet.mode", findings.WentQuiet.Mode, InsightModeShow},
		{"went_quiet.minimum_daily_lookups", findings.WentQuiet.MinimumDailyLookups, 50},
		{"traffic_spike.mode", findings.TrafficSpike.Mode, InsightModeAlert},
		{"traffic_spike.factor", findings.TrafficSpike.Factor, 4.5},
		{"traffic_spike.minimum_lookups", findings.TrafficSpike.MinimumLookups, 500},
		{"new_destinations.minimum_new_domains", findings.NewDestinations.MinimumNewDomains, 20},
		{"check_in.mode", findings.CheckIn.Mode, InsightModeOff},
		{"check_in.longest_interval", findings.CheckIn.LongestInterval.Duration, 2 * time.Hour},
		{"check_in.shortest_span", findings.CheckIn.ShortestSpan.Duration, 6 * time.Hour},
		{"unique_coverage.mode", findings.UniqueCoverage.Mode, InsightModeOff},
		{"low_unique_coverage.mode", findings.LowUniqueCoverage.Mode, InsightModeShow},
	} {
		if test.got != test.want {
			t.Errorf("%s = %v, want %v", test.name, test.got, test.want)
		}
	}
}

func TestInsightFindingsRefuseSettingsInsightsCannotUse(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		change  func(*InsightFindings)
		setting string
	}{
		{"an unknown mode", func(findings *InsightFindings) { findings.NewApp.Mode = "loud" }, "new_app.mode"},
		{"an alert for findings that are never news", func(findings *InsightFindings) { findings.LowUniqueCoverage.Mode = InsightModeAlert }, "low_unique_coverage.mode"},
		{"a negative daily minimum", func(findings *InsightFindings) { findings.WentQuiet.MinimumDailyLookups = -1 }, "went_quiet.minimum_daily_lookups"},
		{"a daily minimum past the range", func(findings *InsightFindings) { findings.WentQuiet.MinimumDailyLookups = 100_001 }, "went_quiet.minimum_daily_lookups"},
		{"a spike factor of normal variation", func(findings *InsightFindings) { findings.TrafficSpike.Factor = 1.4 }, "traffic_spike.factor"},
		{"a spike factor that is not a number", func(findings *InsightFindings) { findings.TrafficSpike.Factor = math.NaN() }, "traffic_spike.factor"},
		{"a spike factor past the range", func(findings *InsightFindings) { findings.TrafficSpike.Factor = 101 }, "traffic_spike.factor"},
		{"too many spike lookups", func(findings *InsightFindings) { findings.TrafficSpike.MinimumLookups = 1_000_001 }, "traffic_spike.minimum_lookups"},
		{"too many new domains", func(findings *InsightFindings) { findings.NewDestinations.MinimumNewDomains = 10_001 }, "new_destinations.minimum_new_domains"},
		{"too many lookups in an hour", func(findings *InsightFindings) { findings.UnusualHours.MinimumLookups = 100_001 }, "unusual_hours.minimum_lookups"},
		{"a check-in faster than an app in use", func(findings *InsightFindings) { findings.CheckIn.LongestInterval = Duration{time.Minute} }, "check_in.longest_interval"},
		{"a check-in too slow to see in a day", func(findings *InsightFindings) { findings.CheckIn.LongestInterval = Duration{3 * time.Hour} }, "check_in.longest_interval"},
		{"a check-in run shorter than an hour", func(findings *InsightFindings) { findings.CheckIn.ShortestSpan = Duration{30 * time.Minute} }, "check_in.shortest_span"},
		{"a check-in run longer than the day it is read from", func(findings *InsightFindings) { findings.CheckIn.ShortestSpan = Duration{24 * time.Hour} }, "check_in.shortest_span"},
		{"too many appliance domains", func(findings *InsightFindings) { findings.ApplianceNewDomains.MinimumNewDomains = 1_001 }, "appliance_new_domains.minimum_new_domains"},
		{"too many missed updates", func(findings *InsightFindings) { findings.UpdateFailing.MissedUpdates = 101 }, "update_failing.missed_updates"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			configuration := Defaults()
			test.change(&configuration.Insights.Findings)
			problems := configuration.Insights.Findings.Problems()
			if len(problems) != 1 || problems[0].Setting != test.setting {
				t.Fatalf("problems = %v, want one for %s", problems, test.setting)
			}
			if err := configuration.Validate(); err == nil || !strings.Contains(err.Error(), "insights.findings."+test.setting+" must be") {
				t.Fatalf("Validate() = %v, want the problem with %s", err, test.setting)
			}
		})
	}
	// Each range includes both of its ends.
	edges := DefaultInsightFindings()
	edges.WentQuiet.MinimumDailyLookups = 100_000
	edges.TrafficSpike.Factor, edges.TrafficSpike.MinimumLookups = 1.5, 1
	edges.NewDestinations.MinimumNewDomains = 10_000
	edges.UnusualHours.MinimumLookups = 1
	edges.CheckIn.LongestInterval, edges.CheckIn.ShortestSpan = Duration{2 * time.Minute}, Duration{23 * time.Hour}
	edges.ApplianceNewDomains.MinimumNewDomains = 1_000
	edges.UpdateFailing.MissedUpdates = 100
	if problems := edges.Problems(); len(problems) != 0 {
		t.Fatalf("the ends of each range were refused: %v", problems)
	}
}

// What the console saves is written to the file whole and reads back the same.
func TestInsightFindingsRoundTripThroughTheFile(t *testing.T) {
	t.Parallel()
	path := writeConfiguration(t, "")
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(path, initial, func(context.Context, Config, Config) error { return nil })
	changed := DefaultInsightFindings()
	changed.WentQuiet = InsightWentQuiet{Mode: InsightModeShow, MinimumDailyLookups: 200}
	changed.TrafficSpike.Factor = 2.5
	changed.CheckIn = InsightCheckIn{Mode: InsightModeOff, LongestInterval: Duration{30 * time.Minute}, ShortestSpan: Duration{8 * time.Hour}}
	changed.UniqueCoverage.Mode = InsightModeOff
	if err := manager.Update(context.Background(), func(candidate *Config) error {
		candidate.Insights.Findings = changed
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Insights.Findings != changed || manager.Current().Config.Insights.Findings != changed {
		t.Fatalf("loaded %+v, want %+v", loaded.Insights.Findings, changed)
	}
	encoded, err := Marshal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"[insights.findings.went_quiet]", "minimum_daily_lookups = 200", "factor = 2.5", "[insights.findings.unique_coverage]"} {
		if !strings.Contains(string(encoded), expected) {
			t.Errorf("the file does not contain %q:\n%s", expected, encoded)
		}
	}
	if strings.Contains(string(encoded), "[insights.webhook]") {
		t.Errorf("the file kept the old webhook table:\n%s", encoded)
	}

	// A change that Insights cannot use leaves the file as it was.
	if err := manager.Update(context.Background(), func(candidate *Config) error {
		candidate.Insights.Findings.UnusualHours.MinimumLookups = -5
		return nil
	}); err == nil || !strings.Contains(err.Error(), "insights.findings.unusual_hours.minimum_lookups") {
		t.Fatalf("Update() = %v, want the unusual hours limit refused", err)
	}
	if reloaded, err := Load(path); err != nil || reloaded.Insights.Findings != changed {
		t.Fatalf("after a refused change the file holds %+v, %v", reloaded.Insights.Findings, err)
	}
}

func TestClonedConfigurationsOwnTheirInsightFindings(t *testing.T) {
	t.Parallel()
	source := Defaults()
	cloned := cloneConfig(source)
	cloned.Insights.Findings.NewDevice.Mode = InsightModeOff
	cloned.Insights.Findings.TrafficSpike.Factor = 9
	if source.Insights.Findings != DefaultInsightFindings() {
		t.Fatalf("changing a clone changed its source: %+v", source.Insights.Findings)
	}
}
