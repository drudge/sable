package devices

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/insights/services"
	"github.com/drudge/sable/internal/querylog"
)

// KindCheckIn reports a device that looks up one name on a steady schedule.
const KindCheckIn = "devices.check-in"

const (
	// A check-in repeats at least every two hours and at most every minute;
	// anything faster is an app in use, not a schedule.
	minimumCheckInInterval = time.Minute
	maximumCheckInInterval = 2 * time.Hour
	// minimumCheckInSpan makes a schedule run through the night, not just a
	// busy afternoon.
	minimumCheckInSpan = 12 * time.Hour
	// checkInTolerance is how far an interval may stray from the typical one,
	// and checkInRegularity the share of intervals that must stay within it.
	checkInTolerance  = 0.2
	checkInRegularity = 0.8
	// lookupBurst merges lookups this close together, such as the A and AAAA
	// queries of one resolution.
	lookupBurst     = 5 * time.Second
	maximumCheckIns = 2
)

// schedule is how regularly a device repeated a lookup, and when: times holds
// one moment per lookup, with the A and AAAA queries of one resolution merged.
type schedule struct {
	interval time.Duration
	lookups  int
	span     time.Duration
	times    []time.Time
}

// steadySchedule reports whether lookup times follow a steady clock, and at
// what interval.
func steadySchedule(times []time.Time) (schedule, bool) {
	if len(times) < 2 {
		return schedule{}, false
	}
	sorted := slices.Clone(times)
	slices.SortFunc(sorted, func(left, right time.Time) int { return left.Compare(right) })
	merged := []time.Time{sorted[0]}
	for _, moment := range sorted[1:] {
		if moment.Sub(merged[len(merged)-1]) > lookupBurst {
			merged = append(merged, moment)
		}
	}
	if len(merged) < 24 {
		return schedule{}, false
	}
	intervals := make([]time.Duration, 0, len(merged)-1)
	for index := 1; index < len(merged); index++ {
		intervals = append(intervals, merged[index].Sub(merged[index-1]))
	}
	sortedIntervals := slices.Clone(intervals)
	slices.Sort(sortedIntervals)
	typical := sortedIntervals[len(sortedIntervals)/2]
	if typical < minimumCheckInInterval || typical > maximumCheckInInterval {
		return schedule{}, false
	}
	steady := 0
	for _, interval := range intervals {
		if math.Abs(float64(interval-typical)) <= checkInTolerance*float64(typical) {
			steady++
		}
	}
	span := merged[len(merged)-1].Sub(merged[0])
	if float64(steady) < checkInRegularity*float64(len(intervals)) || span < minimumCheckInSpan {
		return schedule{}, false
	}
	return schedule{interval: typical, lookups: len(merged), span: span, times: merged}, true
}

// checkInCandidate reports whether a name could be a check-in worth showing:
// not a service Sable recognizes, not a reverse lookup, and not a bare host.
func checkInCandidate(name string) bool {
	if _, known := services.Lookup(name); known {
		return false
	}
	return strings.Contains(name, ".") && !strings.HasSuffix(name, ".arpa")
}

func everyText(interval time.Duration) string {
	minutes := int(math.Round(interval.Minutes()))
	switch {
	case minutes < 2:
		return "every minute"
	case minutes < 60:
		return fmt.Sprintf("every %d minutes", minutes)
	case minutes%60 == 0 && minutes == 60:
		return "every hour"
	case minutes%60 == 0:
		return fmt.Sprintf("every %d hours", minutes/60)
	default:
		return fmt.Sprintf("every %d minutes", minutes)
	}
}

func checkInFindings(input ChangesInput) []insights.Finding {
	if len(input.RepeatedLookups) == 0 {
		return nil
	}
	byAddress := make(map[string]Device)
	for _, device := range input.Devices {
		for _, address := range device.Addresses {
			byAddress[address.Address] = device
		}
	}
	type candidate struct {
		device Device
		lookup querylog.LookupTimes
		plan   schedule
	}
	candidates := make([]candidate, 0)
	seen := make(map[string]bool)
	for _, lookup := range input.RepeatedLookups {
		device, found := byAddress[lookup.Client]
		if !found || seen[device.Key] || !checkInCandidate(lookup.Name) {
			continue
		}
		if plan, steady := steadySchedule(lookup.Times); steady {
			seen[device.Key] = true
			candidates = append(candidates, candidate{device: device, lookup: lookup, plan: plan})
		}
	}
	slices.SortFunc(candidates, func(left, right candidate) int { return cmp.Compare(right.plan.lookups, left.plan.lookups) })
	findings := make([]insights.Finding, 0, min(len(candidates), maximumCheckIns))
	for _, entry := range candidates[:min(len(candidates), maximumCheckIns)] {
		device, lookup, plan := entry.device, entry.lookup, entry.plan
		every := everyText(plan.interval)
		finding := insights.Finding{
			Kind: KindCheckIn, Tone: insights.ToneNotice, Title: "Checks in on a schedule",
			Subject:  deviceSubject(device),
			Headline: Label(device) + " checks in " + every,
			Summary:  fmt.Sprintf("Looked up %s %s, %d times in the last day. No other device uses that name.", lookup.Name, every, plan.lookups),
			Reasons: []insights.Reason{
				{Text: fmt.Sprintf("%d lookups in the last 24 hours, %s like clockwork:", plan.lookups, every), Code: lookup.Name},
				{Text: "Kept it up for " + insights.FormatDuration(plan.span) + ", through the night"},
				{Text: "No other device on the network looks this name up"},
				{Text: "Not a service Sable recognizes"},
			},
			Facts: append(deviceFacts(device, false),
				insights.Fact{Label: "Name", Value: lookup.Name, Monospace: true},
				insights.Fact{Label: "Schedule", Value: strings.ToUpper(every[:1]) + every[1:]},
			),
			Explanations: []string{
				"A smart device's normal heartbeat to its maker",
				"An app polling for updates or messages",
				"Software phoning home that should not be there",
			},
			Method: "Sable looks for names only one device looks up, again and again, at a steady interval for at least 12 hours. " +
				"Services it recognizes, reverse lookups, and Sable's own lookups, such as its dynamic DNS updates, are left out.",
			Chart: &insights.Chart{Schedule: &insights.ScheduleChart{Start: input.Now.Add(-24 * time.Hour), End: input.Now, Times: plan.times}},
		}
		if len(device.Addresses) == 1 {
			finding.Query = &insights.QueryFilter{Name: lookup.Name, ClientIP: lookup.Client}
		}
		findings = append(findings, finding)
	}
	return findings
}
