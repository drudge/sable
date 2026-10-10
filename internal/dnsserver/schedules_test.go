package dnsserver

import (
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/weekly"
)

func TestScheduleKeepsItsAnswer(t *testing.T) {
	t.Parallel()
	newYork, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	at := func(day, hour, minute int) time.Time {
		return time.Date(2026, time.October, day, hour, minute, 0, 0, newYork)
	}
	bedtime, err := compileSchedule("Kids", SchedulePolicy{
		Name: "Bedtime", Window: weekly.Window{Days: [7]bool{true, true, true, true, true}, Start: 21 * 60, End: 7 * 60, Location: newYork}, Everything: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// on keeps its answer for the span it holds, and works it out again
	// outside it, whichever way the clock moved.
	for _, check := range []struct {
		now time.Time
		on  bool
	}{
		{at(12, 22, 0), true},
		{at(13, 6, 0), true},
		{at(13, 7, 0), false},
		{at(13, 20, 59), false},
		{at(13, 21, 0), true},
		{at(12, 12, 0), false},
		{at(12, 23, 0), true},
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
	everyDay := [7]bool{true, true, true, true, true, true, true}
	onNow := func(name string, everything bool, domains ...string) SchedulePolicy {
		return SchedulePolicy{Name: name, Window: weekly.Window{Days: everyDay, Start: minutesFromNow(-60), End: minutesFromNow(60), Location: time.UTC}, Everything: everything, Domains: domains}
	}
	later := SchedulePolicy{Name: "Later", Window: weekly.Window{Days: everyDay, Start: minutesFromNow(120), End: minutesFromNow(180), Location: time.UTC}, Domains: []string{"later.example"}}
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
	configuration.RuleSets[0].Schedules = []SchedulePolicy{{Name: "Bedtime", Window: weekly.Window{Days: [7]bool{time.Monday: true}, Start: 60, End: 120}, Everything: true}}
	if _, err := Compile(configuration); err == nil {
		t.Fatal("Compile() accepted a schedule without a time zone")
	}
}
