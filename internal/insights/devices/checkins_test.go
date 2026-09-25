package devices

import (
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

func every(start time.Time, interval time.Duration, count int, jitter func(int) time.Duration) []time.Time {
	times := make([]time.Time, 0, count*2)
	for index := range count {
		at := start.Add(time.Duration(index)*interval + jitter(index))
		// Each resolution asks for A and AAAA a moment apart.
		times = append(times, at, at.Add(200*time.Millisecond))
	}
	return times
}

func TestChangesReportLookupsOnASteadySchedule(t *testing.T) {
	t.Parallel()
	start := testNow.Add(-24 * time.Hour)
	steady := func(index int) time.Duration { return time.Duration(index%3) * 10 * time.Second }
	camera := Device{Key: "mac:9c:8e:cd:33:0c:c2", Name: "dock-camera-01", Queries: 300, Addresses: []Address{{Address: "10.20.30.42"}}}
	laptop := Device{Key: "ip:10.0.0.5", Queries: 900, Addresses: []Address{{Address: "10.0.0.5"}}}
	findings := Changes(ChangesInput{
		Now: testNow, WindowStart: testNow.Add(-7 * 24 * time.Hour), SeenSince: testNow.Add(-60 * 24 * time.Hour),
		Devices: []Device{camera, laptop},
		RepeatedLookups: []querylog.LookupTimes{
			{Client: "10.20.30.42", Name: "heartbeat.camlink-cn.com", Times: every(start, 5*time.Minute, 280, steady)},
			// Recognized services are never reported as check-ins.
			{Client: "10.0.0.5", Name: "outlook.office365.com", Times: every(start, 5*time.Minute, 280, steady)},
			// Irregular bursts are someone using an app, not a schedule.
			{Client: "10.0.0.5", Name: "news.example.net", Times: every(start, 5*time.Minute, 280, func(index int) time.Duration {
				return time.Duration(index*index%7) * time.Minute
			})},
		},
	})
	if len(findings) != 1 || findings[0].Kind != KindCheckIn {
		t.Fatalf("findings = %+v", findings)
	}
	if findings[0].Summary != "Looked up heartbeat.camlink-cn.com every 5 minutes, 280 times in the last day. No other device uses that name." {
		t.Fatalf("summary = %q", findings[0].Summary)
	}
	if findings[0].Query == nil || findings[0].Query.ClientIP != "10.20.30.42" {
		t.Fatalf("query = %+v", findings[0].Query)
	}
	// One mark per resolution, with its A and AAAA queries as one.
	if chart := findings[0].Chart; chart == nil || chart.Schedule == nil || len(chart.Schedule.Times) != 280 ||
		!chart.Schedule.End.Equal(testNow) || !chart.Schedule.Start.Equal(testNow.Add(-24*time.Hour)) {
		t.Fatalf("chart = %+v", chart)
	}
}

func TestSteadyScheduleNeedsTheNight(t *testing.T) {
	t.Parallel()
	// Every five minutes, but only for a two-hour afternoon.
	times := every(testNow.Add(-3*time.Hour), 5*time.Minute, 24, func(int) time.Duration { return 0 })
	if plan, steady := steadySchedule(times); steady {
		t.Fatalf("schedule = %+v for a busy afternoon", plan)
	}
}
