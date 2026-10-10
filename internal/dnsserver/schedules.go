package dnsserver

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/weekly"
)

// SchedulePolicy turns blocking on for a rule set's clients at set times
// each week, such as a bedtime.
type SchedulePolicy struct {
	Name   string
	Window weekly.Window
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
	window     weekly.Window
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
	if policy.Window.Location == nil {
		return nil, fmt.Errorf("rule set %q: schedule %q has no time zone", set, policy.Name)
	}
	compiled := &schedule{name: policy.Name, window: policy.Window, everything: policy.Everything}
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
	on, from, until := schedule.window.At(now)
	schedule.state.Store(&scheduleState{on: on, from: from.UnixNano(), until: until.UnixNano()})
	return on
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
