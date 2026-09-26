package devices

import (
	"testing"
	"time"

	"github.com/drudge/sable/internal/insights"
)

func TestChangesReportActivityAtAnHourADeviceNeverUses(t *testing.T) {
	t.Parallel()
	day := 24 * time.Hour
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	server := Device{Key: "mac:00:0b:db:11:04:a7", MAC: "00:0b:db:11:04:a7", Name: "payroll-server", Queries: 9_000, Recent: 700, FirstSeen: now.Add(-40 * day)}
	hourly := map[time.Time]uint64{}
	// Two weeks of office hours, 9 AM to 5 PM.
	for date := now.Add(-15 * day).Truncate(day); date.Before(now.Add(-day)); date = date.Add(day) {
		for hour := 9; hour < 17; hour++ {
			hourly[date.Add(time.Duration(hour)*time.Hour)] = 40
		}
	}
	// Last night it woke up between 2 and 4 AM.
	lastNight := now.Truncate(day)
	hourly[lastNight.Add(2*time.Hour)] = 120
	hourly[lastNight.Add(3*time.Hour)] = 90
	hourly[lastNight.Add(10*time.Hour)] = 40
	findings := Changes(ChangesInput{
		Now: now, WindowStart: now.Add(-7 * day), SeenSince: now.Add(-60 * day), Location: time.UTC,
		Devices: []Device{server},
		Hourly:  func(Device) map[time.Time]uint64 { return hourly },
	})
	if len(findings) != 1 || findings[0].Kind != KindUnusualHours {
		t.Fatalf("findings = %+v", findings)
	}
	if findings[0].Summary != "Sent 210 queries between 2 AM and 4 AM in the last day, a time it had been silent every day for the two weeks before." {
		t.Fatalf("summary = %q", findings[0].Summary)
	}
	// The chart sets the usual day beside the unusual hours alone.
	if chart := findings[0].Chart; chart == nil || chart.Hours == nil || chart.Hours.Usual[9] != 40 || chart.Hours.Usual[2] != 0 ||
		chart.Hours.Unusual[2] != 120 || chart.Hours.Unusual[3] != 90 || chart.Hours.Unusual[10] != 0 {
		t.Fatalf("chart = %+v", chart)
	}

	// A device watched for only ten days has no routine to break yet.
	server.FirstSeen = now.Add(-10 * day)
	if findings := Changes(ChangesInput{
		Now: now, WindowStart: now.Add(-7 * day), SeenSince: now.Add(-60 * day), Location: time.UTC,
		Devices: []Device{server}, Hourly: func(Device) map[time.Time]uint64 { return hourly },
	}); len(findings) != 0 {
		t.Fatalf("findings for a new device = %+v", findings)
	}
}

func TestChangesReportAppliancesTalkingSomewhereNew(t *testing.T) {
	t.Parallel()
	day := 24 * time.Hour
	camera := Device{
		Key: "mac:9c:8e:cd:33:0c:c2", MAC: "9c:8e:cd:33:0c:c2", Name: "dock-camera-01", Vendor: "Amcrest", Queries: 3_000,
		Recent: 400, Baseline: 2_800, RecentNewDomains: 5, BaselineNewDomains: 1, FirstSeen: testNow.Add(-40 * day),
		Guess: Guess{Type: "camera", Confidence: ConfidenceHigh},
	}
	// A laptop picking up the same number of new names is ordinary.
	laptop := camera
	laptop.Key, laptop.Name, laptop.Guess = "ip:10.0.0.5", "george-laptop", Guess{Type: "computer", Confidence: ConfidenceHigh}
	findings := Changes(ChangesInput{
		Now: testNow, WindowStart: testNow.Add(-7 * day), SeenSince: testNow.Add(-60 * day),
		Devices: []Device{camera, laptop},
		RecentDomains: func(Device) []insights.DomainEvidence {
			return []insights.DomainEvidence{{Name: "relay.unknown-cloud.example", FirstSeen: testNow.Add(-time.Hour)}}
		},
	})
	if len(findings) != 1 || findings[0].Kind != KindApplianceDrift || findings[0].Title != "Camera talking somewhere new" {
		t.Fatalf("findings = %+v", findings)
	}
	if len(findings[0].Domains) != 1 || findings[0].Subject.Device != camera.Key {
		t.Fatalf("finding = %+v", findings[0])
	}
}

func TestUnusualHoursNeedARoutine(t *testing.T) {
	t.Parallel()
	day := 24 * time.Hour
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	// Back after two weeks away: every hour is "new", so none is unusual.
	hourly := map[time.Time]uint64{now.Add(-3 * time.Hour).Truncate(time.Hour): 500, now.Add(-20 * day).Truncate(time.Hour): 10}
	if span, found := unusualSpan(hourly, now, time.UTC, DefaultLimits().UnusualHourLookups); found {
		t.Fatalf("span = %+v for a device with no routine", span)
	}
}
