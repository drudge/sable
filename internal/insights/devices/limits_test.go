package devices

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/querylog"
)

// officeHours is two weeks of lookups from 9 AM to 5 PM before the last day,
// with lookups at 2 AM in the last day.
func officeHours(now time.Time, lastNight uint64) map[time.Time]uint64 {
	day := 24 * time.Hour
	hourly := map[time.Time]uint64{}
	for date := now.Add(-15 * day).Truncate(day); date.Before(now.Add(-day)); date = date.Add(day) {
		for hour := 9; hour < 17; hour++ {
			hourly[date.Add(time.Duration(hour)*time.Hour)] = 40
		}
	}
	hourly[now.Truncate(day).Add(2*time.Hour)] = lastNight
	return hourly
}

// Every limit an operator can move changes what is reported: each case is a
// device that sits on one side of its default and the other side of the
// changed limit.
func TestChangesHonorTheLimitsAnOperatorSets(t *testing.T) {
	t.Parallel()
	day := 24 * time.Hour
	old := testNow.Add(-40 * day)
	base := func() ChangesInput {
		return ChangesInput{Now: testNow, WindowStart: testNow.Add(-7 * day), SeenSince: testNow.Add(-60 * day), Location: time.UTC}
	}
	camera := Device{
		Key: "mac:9c:8e:cd:33:0c:c2", MAC: "9c:8e:cd:33:0c:c2", Name: "dock-camera-01", Queries: 3_000, Recent: 400, Baseline: 2_800,
		FirstSeen: old, Guess: Guess{Type: "camera", Confidence: ConfidenceHigh}, Addresses: []Address{{Address: "10.20.30.42"}},
	}
	every5 := func(hours int) []querylog.LookupTimes {
		return []querylog.LookupTimes{{Client: "10.20.30.42", Name: "heartbeat.camlink-cn.com",
			Times: every(testNow.Add(-time.Duration(hours)*time.Hour), 5*time.Minute, hours*12, func(int) time.Duration { return 0 })}}
	}
	for _, test := range []struct {
		name   string
		kind   string
		input  func() ChangesInput
		limits Limits
		// method is part of the rule's description, which names the limit.
		method string
		// unclaimed is something the reasons must no longer claim.
		unclaimed string
	}{
		{
			name: "a quieter device can go quiet", kind: KindWentQuiet, limits: Limits{QuietDailyLookups: 30},
			input: func() ChangesInput {
				input := base()
				input.Devices = []Device{{Key: "mac:aa:00:00:00:00:02", MAC: "aa:00:00:00:00:02", Name: "sensor", FirstSeen: old, Baseline: 7 * 40}}
				return input
			},
		},
		{
			name: "doubling counts as busy", kind: KindTrafficSpike, limits: Limits{SpikeFactor: 2}, method: "at least doubled their usual volume",
			input: func() ChangesInput {
				input := base()
				input.Devices = []Device{{Key: "mac:aa:00:00:00:00:03", MAC: "aa:00:00:00:00:03", Name: "laptop", FirstSeen: old, Recent: 2_500, Baseline: 7 * 1_000}}
				return input
			},
		},
		{
			name: "a smaller day can be a spike", kind: KindTrafficSpike, limits: Limits{SpikeLookups: 300}, method: "at least tripled",
			input: func() ChangesInput {
				input := base()
				input.Devices = []Device{{Key: "mac:aa:00:00:00:00:04", MAC: "aa:00:00:00:00:04", Name: "printer", FirstSeen: old, Recent: 400, Baseline: 7 * 100}}
				return input
			},
		},
		{
			name: "fewer new domains are worth a look", kind: KindNewDestinations, limits: Limits{NewDomains: 10}, method: "at least 10 it had never queried",
			input: func() ChangesInput {
				input := base()
				input.Devices = []Device{{Key: "mac:aa:00:00:00:00:05", MAC: "aa:00:00:00:00:05", Name: "tablet", Queries: 900, NewDomains: 12, FirstSeen: old}}
				return input
			},
		},
		{
			name: "fewer lookups make an hour unusual", kind: KindUnusualHours, limits: Limits{UnusualHourLookups: 15}, method: "at least 15 queries in an hour",
			input: func() ChangesInput {
				input := base()
				hourly := officeHours(testNow, 20)
				input.Devices = []Device{{Key: "mac:00:0b:db:11:04:a7", MAC: "00:0b:db:11:04:a7", Name: "payroll-server", Queries: 9_000, Recent: 700, FirstSeen: old}}
				input.Hourly = func(Device) map[time.Time]uint64 { return hourly }
				return input
			},
		},
		{
			name: "a shorter schedule counts as a check-in", kind: KindCheckIn, limits: Limits{CheckInSpan: 6 * time.Hour}, method: "for at least 6 hours",
			// Eight hours of lookups are not a night.
			unclaimed: "through the night",
			input: func() ChangesInput {
				input := base()
				input.Devices = []Device{camera}
				input.RepeatedLookups = every5(8)
				return input
			},
		},
		{
			name: "one new domain is worth a look for an appliance", kind: KindApplianceDrift, limits: Limits{ApplianceNewDomains: 1}, method: "at least one domain it had never used",
			input: func() ChangesInput {
				input := base()
				quietCamera := camera
				quietCamera.RecentNewDomains = 1
				input.Devices = []Device{quietCamera}
				return input
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if findings := findingsOfKind(Changes(test.input()), test.kind); len(findings) != 0 {
				t.Fatalf("the default limits already report it: %+v", findings)
			}
			input := test.input()
			input.Limits = test.limits
			findings := findingsOfKind(Changes(input), test.kind)
			if len(findings) != 1 {
				t.Fatalf("findings = %+v, want one %s", findings, test.kind)
			}
			if !strings.Contains(findings[0].Method, test.method) {
				t.Fatalf("method = %q, want it to say %q", findings[0].Method, test.method)
			}
			for _, reason := range findings[0].Reasons {
				if test.unclaimed != "" && strings.Contains(reason.Text, test.unclaimed) {
					t.Fatalf("reason %q claims %q", reason.Text, test.unclaimed)
				}
			}
		})
	}
}

// Limits can also be raised, and a stricter one keeps quiet about what the
// default would report.
func TestChangesStayQuietUnderStricterLimits(t *testing.T) {
	t.Parallel()
	day := 24 * time.Hour
	old := testNow.Add(-40 * day)
	camera := Device{Key: "mac:9c:8e:cd:33:0c:c2", Name: "dock-camera-01", Queries: 300, FirstSeen: old, Addresses: []Address{{Address: "10.20.30.42"}}}
	input := ChangesInput{
		Now: testNow, WindowStart: testNow.Add(-7 * day), SeenSince: testNow.Add(-60 * day),
		Devices: []Device{
			camera,
			{Key: "mac:aa:00:00:00:00:01", MAC: "aa:00:00:00:00:01", Name: "tv", FirstSeen: old, Recent: 12_480, Baseline: 7 * 2_970},
			{Key: "mac:3c:22:fb:01:02:03", MAC: "3c:22:fb:01:02:03", Name: "george-laptop", Queries: 5_000, NewDomains: 48, FirstSeen: old},
		},
		// Every half hour for 20 hours.
		RepeatedLookups: []querylog.LookupTimes{{Client: "10.20.30.42", Name: "heartbeat.camlink-cn.com",
			Times: every(testNow.Add(-20*time.Hour), 30*time.Minute, 40, func(int) time.Duration { return 0 })}},
	}
	for _, kind := range []string{KindTrafficSpike, KindNewDestinations, KindCheckIn} {
		if len(findingsOfKind(Changes(input), kind)) != 1 {
			t.Fatalf("the default limits do not report %s", kind)
		}
	}
	input.Limits = Limits{SpikeFactor: 5, NewDomains: 50, CheckInInterval: 20 * time.Minute}
	if findings := Changes(input); len(findings) != 0 {
		t.Fatalf("findings under stricter limits = %+v", findings)
	}
}

// A kind an operator turned off is never looked for, so it cannot keep
// another kind from reporting the same device.
func TestChangesLeaveOutKindsThatAreOff(t *testing.T) {
	t.Parallel()
	day := 24 * time.Hour
	camera := Device{
		Key: "mac:9c:8e:cd:33:0c:c2", MAC: "9c:8e:cd:33:0c:c2", Name: "dock-camera-01", Vendor: "Amcrest", Queries: 3_000,
		Recent: 400, Baseline: 2_800, NewDomains: 25, RecentNewDomains: 5, BaselineNewDomains: 1, FirstSeen: testNow.Add(-40 * day),
		Guess: Guess{Type: "camera", Confidence: ConfidenceHigh},
	}
	quiet := Device{Key: "mac:aa:00:00:00:00:02", MAC: "aa:00:00:00:00:02", Name: "sensor", FirstSeen: testNow.Add(-40 * day), Baseline: 7 * 1_000}
	input := ChangesInput{Now: testNow, WindowStart: testNow.Add(-7 * day), SeenSince: testNow.Add(-60 * day), Devices: []Device{camera, quiet}}
	kinds := func(findings []insights.Finding) string {
		names := make([]string, 0, len(findings))
		for _, finding := range findings {
			names = append(names, finding.Kind)
		}
		return strings.Join(names, " ")
	}
	// The camera's new services explain its new domains, so they are not
	// counted twice.
	if got := kinds(Changes(input)); got != KindWentQuiet+" "+KindApplianceDrift {
		t.Fatalf("with every kind on, findings = %s", got)
	}
	input.Off = map[string]bool{KindApplianceDrift: true, KindWentQuiet: true}
	if got := kinds(Changes(input)); got != KindNewDestinations {
		t.Fatalf("with appliances and quiet devices off, findings = %s", got)
	}
}

// countingSources counts what the analyzer reads.
type countingSources struct {
	devices       []Device
	hourlyReads   int
	repeatedReads int
}

func (sources *countingSources) Devices(context.Context, insights.Window) (Report, error) {
	return Report{Devices: sources.devices, SeenSince: testNow.Add(-60 * 24 * time.Hour),
		Window: insights.Window{Start: testNow.Add(-7 * 24 * time.Hour), End: testNow}}, nil
}
func (*countingSources) NewDomains(context.Context, Device, insights.Window) ([]insights.DomainEvidence, error) {
	return nil, nil
}
func (sources *countingSources) RepeatedLookups(context.Context, time.Time) ([]querylog.LookupTimes, error) {
	sources.repeatedReads++
	return nil, nil
}
func (sources *countingSources) HourlyActivity(context.Context, time.Time) (map[string]map[time.Time]uint64, error) {
	sources.hourlyReads++
	return nil, nil
}
func (*countingSources) DomainHistory(context.Context, Device) ([]insights.DomainEvidence, bool, error) {
	return nil, false, nil
}

// The reads only some kinds need are skipped when those kinds are all off.
func TestAnalyzerSkipsReadsForKindsThatAreOff(t *testing.T) {
	t.Parallel()
	window := insights.Window{Start: testNow.Add(-7 * 24 * time.Hour), End: testNow}
	for _, test := range []struct {
		name                   string
		off                    map[string]bool
		wantHourly, wantRepeat int
	}{
		{"everything on", nil, 1, 1},
		{"check-ins off", map[string]bool{KindCheckIn: true}, 1, 0},
		{"one hourly kind still on", map[string]bool{KindWentQuiet: true, KindTrafficSpike: true}, 1, 1},
		{"every hourly kind off", map[string]bool{KindWentQuiet: true, KindTrafficSpike: true, KindUnusualHours: true}, 0, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			sources := &countingSources{}
			if _, err := (Analyzer{Sources: sources, Off: test.off}).Analyze(context.Background(), window); err != nil {
				t.Fatal(err)
			}
			if sources.hourlyReads != test.wantHourly || sources.repeatedReads != test.wantRepeat {
				t.Fatalf("hourly reads = %d, repeated reads = %d, want %d and %d",
					sources.hourlyReads, sources.repeatedReads, test.wantHourly, test.wantRepeat)
			}
		})
	}
}

func TestLimitsLeftAtZeroTakeTheirDefaults(t *testing.T) {
	t.Parallel()
	if got := (Limits{}).withDefaults(); got != DefaultLimits() {
		t.Fatalf("zero limits = %+v, want %+v", got, DefaultLimits())
	}
	custom := Limits{QuietDailyLookups: 9, SpikeFactor: 1.5, CheckInSpan: time.Hour}
	got := custom.withDefaults()
	if got.QuietDailyLookups != 9 || got.SpikeFactor != 1.5 || got.CheckInSpan != time.Hour || got.SpikeLookups != 500 || got.CheckInInterval != 2*time.Hour {
		t.Fatalf("custom limits = %+v", got)
	}
}

func findingsOfKind(findings []insights.Finding, kind string) []insights.Finding {
	matched := make([]insights.Finding, 0)
	for _, finding := range findings {
		if finding.Kind == kind {
			matched = append(matched, finding)
		}
	}
	return matched
}
