package dnsserver

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/drudge/sable/internal/dnsname"
)

// SchedulePolicy turns blocking on for a rule set's clients at set times
// each week, such as a bedtime.
type SchedulePolicy struct {
	Name string
	Days []time.Weekday
	// Start and End are minutes past midnight in Location. An End at or
	// before Start falls on the next day.
	Start, End int
	Location   *time.Location
	// Everything blocks everything for the set's clients while the schedule
	// is on, as a hold does. Otherwise Domains are blocked as if they were the
	// set's own.
	Everything bool
	Domains    []string
}

// schedule is a SchedulePolicy compiled for the policy check. Whether it is
// on only changes at the start or end of a window, so the answer is kept
// with the span it holds for, and a check inside that span is a comparison.
type schedule struct {
	name       string
	days       [7]bool
	start, end int
	location   *time.Location
	everything bool
	blocked    map[string]uint32
	state      atomic.Pointer[scheduleState]
}

// scheduleState says whether a schedule is on from from until until, in
// Unix nanoseconds.
type scheduleState struct {
	on          bool
	from, until int64
}

func compileSchedule(set string, policy SchedulePolicy) (*schedule, error) {
	if policy.Location == nil {
		return nil, fmt.Errorf("rule set %q: schedule %q has no time zone", set, policy.Name)
	}
	compiled := &schedule{name: policy.Name, start: policy.Start, end: policy.End, location: policy.Location, everything: policy.Everything}
	for _, day := range policy.Days {
		compiled.days[day%7] = true
	}
	if policy.Everything {
		return compiled, nil
	}
	compiled.blocked = make(map[string]uint32, len(policy.Domains))
	for _, domain := range policy.Domains {
		normalized, err := dnsname.Normalize(strings.TrimPrefix(strings.TrimSpace(domain), "*."))
		if err != nil {
			return nil, fmt.Errorf("rule set %q: schedule %q: invalid blocked domain %q: %w", set, policy.Name, domain, err)
		}
		compiled.blocked[normalized] = 0
	}
	return compiled, nil
}

// on reports whether the schedule blocks at now.
func (schedule *schedule) on(now time.Time) bool {
	nanos := now.UnixNano()
	if state := schedule.state.Load(); state != nil && state.from <= nanos && nanos < state.until {
		return state.on
	}
	on, from, until := schedule.window(now)
	schedule.state.Store(&scheduleState{on: on, from: from.UnixNano(), until: until.UnixNano()})
	return on
}

// window works out whether the schedule is on at now, and the span around
// now that answer holds for: the window it is in, or the gap between the
// window before and the one after.
func (schedule *schedule) window(now time.Time) (on bool, from, until time.Time) {
	local := now.In(schedule.location)
	today := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, schedule.location)
	from = now.Add(-7 * 24 * time.Hour)
	until = now.Add(8 * 24 * time.Hour)
	// A window that crosses midnight started the day before, so the search
	// starts a week back to find the end of the last one.
	for offset := -7; offset <= 7; offset++ {
		day := today.AddDate(0, 0, offset)
		if !schedule.days[day.Weekday()] {
			continue
		}
		start, end := schedule.span(day)
		switch {
		case !now.Before(start) && now.Before(end):
			return true, start, end
		case !end.After(now) && end.After(from):
			from = end
		case start.After(now) && start.Before(until):
			until = start
		}
	}
	return false, from, until
}

// span is the window that starts on day.
func (schedule *schedule) span(day time.Time) (start, end time.Time) {
	start = schedule.at(day, schedule.start)
	if schedule.end <= schedule.start {
		day = day.AddDate(0, 0, 1)
	}
	return start, schedule.at(day, schedule.end)
}

func (schedule *schedule) at(day time.Time, minutes int) time.Time {
	return time.Date(day.Year(), day.Month(), day.Day(), minutes/60, minutes%60, 0, 0, schedule.location)
}

// scheduleBlockingEverything returns the set's schedule that blocks
// everything at now, or nil.
func (set *ruleSet) scheduleBlockingEverything(now time.Time) *schedule {
	for _, schedule := range set.schedules {
		if schedule.everything && schedule.on(now) {
			return schedule
		}
	}
	return nil
}

// scheduledBlock finds the set's schedule blocking name at now, and the rule
// that matched.
func (set *ruleSet) scheduledBlock(name string, now time.Time) (string, *schedule) {
	for _, schedule := range set.schedules {
		if schedule.everything || !schedule.on(now) {
			continue
		}
		if rule, _ := matchingDomainRule(schedule.blocked, name, nil); rule != "" {
			return rule, schedule
		}
	}
	return "", nil
}
