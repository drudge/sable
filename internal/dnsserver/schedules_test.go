package dnsserver

import (
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

func TestScheduleWindows(t *testing.T) {
	t.Parallel()
	newYork, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	at := func(month time.Month, day, hour, minute int) time.Time {
		return time.Date(2026, month, day, hour, minute, 0, 0, newYork)
	}
	bedtime, err := compileSchedule("Kids", SchedulePolicy{
		Name: "Bedtime", Days: []time.Weekday{time.Sunday, time.Monday, time.Tuesday, time.Wednesday, time.Thursday},
		Start: 21 * 60, End: 7 * 60, Location: newYork, Everything: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	everyNight, err := compileSchedule("Kids", SchedulePolicy{
		Name: "Every night", Days: []time.Weekday{0, 1, 2, 3, 4, 5, 6}, Start: 21 * 60, End: 7 * 60, Location: newYork, Everything: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	afternoon, err := compileSchedule("Kids", SchedulePolicy{
		Name: "Homework", Days: []time.Weekday{time.Monday}, Start: 15*60 + 30, End: 17*60 + 30, Location: newYork,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		schedule    *schedule
		now         time.Time
		on          bool
		from, until time.Time
	}{
		{"Monday night", bedtime, at(10, 12, 22, 0), true, at(10, 12, 21, 0), at(10, 13, 7, 0)},
		{"the start counts", bedtime, at(10, 12, 21, 0), true, at(10, 12, 21, 0), at(10, 13, 7, 0)},
		{"the end doesn't", bedtime, at(10, 13, 7, 0), false, at(10, 13, 7, 0), at(10, 13, 21, 0)},
		{"Thursday night runs into Friday", bedtime, at(10, 16, 6, 59), true, at(10, 15, 21, 0), at(10, 16, 7, 0)},
		{"Friday night is off", bedtime, at(10, 16, 22, 0), false, at(10, 16, 7, 0), at(10, 18, 21, 0)},
		{"Saturday is off", bedtime, at(10, 17, 3, 0), false, at(10, 16, 7, 0), at(10, 18, 21, 0)},
		{"same-day window", afternoon, at(10, 12, 16, 0), true, at(10, 12, 15, 30), at(10, 12, 17, 30)},
		{"a week until the next one", afternoon, at(10, 12, 18, 0), false, at(10, 12, 17, 30), at(10, 19, 15, 30)},
		// Clocks fall back at 2:00 on November 1, so that night is an hour longer.
		{"daylight saving ends", everyNight, at(11, 1, 1, 30), true, at(10, 31, 21, 0), at(11, 1, 7, 0)},
		// And spring forward at 2:00 on March 8, an hour shorter.
		{"daylight saving starts", everyNight, at(3, 8, 4, 0), true, at(3, 7, 21, 0), at(3, 8, 7, 0)},
	} {
		on, from, until := test.schedule.window(test.now)
		if on != test.on || !from.Equal(test.from) || !until.Equal(test.until) {
			t.Errorf("%s: window(%s) = %t from %s until %s, want %t from %s until %s", test.name, test.now, on, from, until, test.on, test.from, test.until)
		}
	}
	if on, from, until := everyNight.window(at(11, 1, 1, 30)); !on || until.Sub(from) != 11*time.Hour {
		t.Errorf("the night clocks fall back lasts %s, want 11h", until.Sub(from))
	}
	if on, from, until := everyNight.window(at(3, 8, 4, 0)); !on || until.Sub(from) != 9*time.Hour {
		t.Errorf("the night clocks spring forward lasts %s, want 9h", until.Sub(from))
	}

	// on keeps its answer for the span it holds, and works it out again
	// outside it, whichever way the clock moved.
	for _, check := range []struct {
		now time.Time
		on  bool
	}{
		{at(10, 12, 22, 0), true},
		{at(10, 13, 6, 0), true},
		{at(10, 13, 7, 0), false},
		{at(10, 13, 20, 59), false},
		{at(10, 13, 21, 0), true},
		{at(10, 12, 12, 0), false},
		{at(10, 12, 23, 0), true},
	} {
		if got := bedtime.on(check.now); got != check.on {
			t.Errorf("on(%s) = %t, want %t", check.now, got, check.on)
		}
	}
}

// minutesFromNow is a time of day, in UTC, that many minutes from now.
func minutesFromNow(minutes int) int {
	now := time.Now().UTC()
	return ((now.Hour()*60+now.Minute()+minutes)%1440 + 1440) % 1440
}

func TestSchedulesBlockForTheirRuleSet(t *testing.T) {
	t.Parallel()
	everyDay := []time.Weekday{0, 1, 2, 3, 4, 5, 6}
	onNow := func(name string, everything bool, domains ...string) SchedulePolicy {
		return SchedulePolicy{Name: name, Days: everyDay, Start: minutesFromNow(-60), End: minutesFromNow(60), Location: time.UTC, Everything: everything, Domains: domains}
	}
	later := SchedulePolicy{Name: "Later", Days: everyDay, Start: minutesFromNow(120), End: minutesFromNow(180), Location: time.UTC, Domains: []string{"later.example"}}
	configuration := ruleSetTestConfig()
	configuration.RuleSets[0].Schedules = []SchedulePolicy{later, onNow("Homework", false, "tiktok.example")}
	configuration.RuleSets[1].Schedules = []SchedulePolicy{onNow("Bedtime", true)}
	configuration.RuleSets[5].Schedules = []SchedulePolicy{onNow("Lights out", true)}
	configuration.Holds = []HoldPolicy{{Client: "192.0.2.50"}}
	configuration.RuleSets[1].Clients = append(configuration.RuleSets[1].Clients, "192.0.2.51")
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	for _, test := range []struct {
		name, client, query string
		paused              bool
		want                DomainPolicy
	}{
		{"an app schedule blocks", "192.0.2.4", "www.tiktok.example", false, DomainPolicy{Decision: querylog.PolicyBlocked, Rule: "tiktok.example", RuleSet: "Kids", OwnRule: true, Schedule: "Homework"}},
		{"an app schedule that hasn't started", "192.0.2.4", "later.example", false, DomainPolicy{Decision: querylog.PolicyNoMatch, RuleSet: "Kids"}},
		{"the set's own block comes first", "192.0.2.4", "games.example", false, DomainPolicy{Decision: querylog.PolicyBlocked, Rule: "games.example", RuleSet: "Kids", OwnRule: true}},
		{"an app schedule stops while paused", "192.0.2.4", "www.tiktok.example", true, DomainPolicy{Decision: querylog.PolicyPaused}},
		{"bedtime blocks everything", "192.0.2.51", "example.com", false, DomainPolicy{Decision: querylog.PolicyHeld, RuleSet: "Work", Schedule: "Bedtime"}},
		{"bedtime while paused", "192.0.2.51", "example.com", true, DomainPolicy{Decision: querylog.PolicyHeld, RuleSet: "Work", Schedule: "Bedtime"}},
		{"bedtime keeps the set's allowed domains", "192.0.2.51", "cdn.tracker.example", false, DomainPolicy{Decision: querylog.PolicyAllowed, Rule: "*.tracker.example", RuleSet: "Work", OwnRule: true}},
		{"bedtime keeps the global allowed domains", "192.0.2.51", "allowed.example", false, DomainPolicy{Decision: querylog.PolicyAllowed, Rule: "allowed.example", RuleSet: "Work"}},
		{"a hold comes before bedtime", "192.0.2.50", "example.com", false, DomainPolicy{Decision: querylog.PolicyHeld}},
		{"bedtime with blocking off", "192.0.2.99", "example.com", false, DomainPolicy{Decision: querylog.PolicyHeld, RuleSet: "No Blocking", Schedule: "Lights out"}},
		{"other rule sets aren't touched", "198.51.100.7", "example.com", false, DomainPolicy{Decision: querylog.PolicyNoMatch, RuleSet: "Strict only"}},
		{"nor the Default rules", "10.0.0.1", "www.tiktok.example", false, DomainPolicy{Decision: querylog.PolicyNoMatch}},
	} {
		got := runtime.policyDecision(test.query, test.client, nil, test.paused)
		if got.Decision != test.want.Decision || got.Rule != test.want.Rule || got.RuleSet != test.want.RuleSet || got.OwnRule != test.want.OwnRule || got.Schedule != test.want.Schedule {
			t.Errorf("%s: policyDecision(%q, %q) = %+v, want %+v", test.name, test.query, test.client, got, test.want)
		}
	}
	decision := runtime.policyDecision("example.com", "192.0.2.51", nil, false).decision(querylog.CacheMiss, querylog.ResolverBlocked)
	if decision.Policy != querylog.PolicyHeld || decision.RuleSet != "Work" || decision.Schedule != "Bedtime" {
		t.Errorf("decision() = %+v, want Work's Bedtime", decision)
	}
}

func TestScheduleNeedsATimeZone(t *testing.T) {
	t.Parallel()
	configuration := ruleSetTestConfig()
	configuration.RuleSets[0].Schedules = []SchedulePolicy{{Name: "Bedtime", Days: []time.Weekday{time.Monday}, Start: 60, End: 120, Everything: true}}
	if _, err := Compile(configuration); err == nil {
		t.Fatal("Compile() accepted a schedule without a time zone")
	}
}
