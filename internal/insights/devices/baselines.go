package devices

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/insights"
)

// Finding kinds that compare a device with its own routine.
const (
	KindUnusualHours   = "devices.unusual-hours"
	KindApplianceDrift = "devices.appliance-new-domains"
)

const (
	// routineDays is how long a device must have been watched before its
	// daily routine is trusted.
	routineDays = 14
	// minimumUnusualHourQueries ignores a stray lookup at an odd hour.
	minimumUnusualHourQueries = 30
	// minimumRoutineDays is how many of the fourteen routine days a device
	// must have been active on for its quiet hours to mean anything.
	minimumRoutineDays = 10
	// minimumApplianceNewDomains is how many first-time names in a day make an
	// appliance worth a look.
	minimumApplianceNewDomains = 3
	maximumUnusualHours        = 2
	maximumApplianceDrift      = 2
)

// appliances are device types that normally talk to the same few services, so
// new destinations mean more than they do for a computer or a phone.
var appliances = map[string]bool{
	"camera": true, "doorbell": true, "thermostat": true, "lighting": true, "smart-plug": true,
	"smart-home": true, "tv": true, "streaming-player": true, "smart-speaker": true, "speaker": true,
	"printer": true, "storage": true, "network": true,
}

// hourSpan is a run of consecutive local hours, such as 2 AM to 5 AM.
type hourSpan struct {
	start, length int
	queries       uint64
}

func (span hourSpan) String() string {
	return hourLabel(span.start) + " and " + hourLabel((span.start+span.length)%24)
}

func hourLabel(hour int) string {
	switch {
	case hour == 0:
		return "12 AM"
	case hour < 12:
		return fmt.Sprintf("%d AM", hour)
	case hour == 12:
		return "12 PM"
	default:
		return fmt.Sprintf("%d PM", hour-12)
	}
}

// routineReady reports whether a device was watched for two full weeks before
// the last day, so an hour it never used is really an hour it never uses.
func (input ChangesInput) routineReady(device Device) bool {
	start := input.Now.Add(-(routineDays + 1) * 24 * time.Hour)
	return !device.FirstSeen.IsZero() && !device.FirstSeen.After(start) && input.trackedBefore(start)
}

// unusualSpan finds the busiest run of hours in the last day during which the
// device had been silent every day of the two weeks before.
func unusualSpan(hourly map[time.Time]uint64, now time.Time, location *time.Location) (hourSpan, bool) {
	recentStart := now.Add(-24 * time.Hour)
	routineStart := recentStart.Add(-routineDays * 24 * time.Hour)
	var recent, routine [24]uint64
	activeDays := make(map[string]bool)
	for hour, hits := range hourly {
		local := hour.In(location).Hour()
		switch {
		case !hour.Before(recentStart) && hour.Before(now):
			recent[local] += hits
		case !hour.Before(routineStart) && hour.Before(recentStart):
			routine[local] += hits
			if hits > 0 {
				activeDays[hour.In(location).Format(time.DateOnly)] = true
			}
		}
	}
	if len(activeDays) < minimumRoutineDays {
		// A device that was mostly away has no routine to break.
		return hourSpan{}, false
	}
	var unusual [24]bool
	for hour := range 24 {
		unusual[hour] = recent[hour] >= minimumUnusualHourQueries && routine[hour] == 0
	}
	best := hourSpan{}
	for start := range 24 {
		// A span starts where the hour before it is usual.
		if !unusual[start] || unusual[(start+23)%24] {
			continue
		}
		span := hourSpan{start: start}
		for span.length < 24 && unusual[(start+span.length)%24] {
			span.queries += recent[(start+span.length)%24]
			span.length++
		}
		if span.queries > best.queries {
			best = span
		}
	}
	return best, best.length > 0
}

func unusualHourFindings(input ChangesInput) []insights.Finding {
	if input.Hourly == nil {
		return nil
	}
	location := input.Location
	if location == nil {
		location = time.Local
	}
	type candidate struct {
		device Device
		span   hourSpan
	}
	candidates := make([]candidate, 0)
	for _, device := range input.Devices {
		if device.Recent == 0 || !input.routineReady(device) {
			continue
		}
		if span, found := unusualSpan(input.Hourly(device), input.Now, location); found {
			candidates = append(candidates, candidate{device: device, span: span})
		}
	}
	slices.SortFunc(candidates, func(left, right candidate) int { return cmp.Compare(right.span.queries, left.span.queries) })
	findings := make([]insights.Finding, 0, min(len(candidates), maximumUnusualHours))
	for _, entry := range candidates[:min(len(candidates), maximumUnusualHours)] {
		device, span := entry.device, entry.span
		between := "between " + span.String()
		findings = append(findings, insights.Finding{
			Kind: KindUnusualHours, Tone: insights.ToneAttention, Title: "Active at an unusual hour",
			Subject:  deviceSubject(device),
			Headline: Label(device) + " woke up at " + hourLabel(span.start),
			Summary: fmt.Sprintf("Sent %s %s %s in the last day, a time it had been silent every day for the two weeks before.",
				insights.FormatCount(span.queries), insights.Plural(span.queries, "query", "queries"), between),
			Reasons: insights.Reasons(
				fmt.Sprintf("%s %s %s in the last 24 hours", insights.FormatCount(span.queries), insights.Plural(span.queries, "query", "queries"), between),
				"No queries at that time on any of the 14 days before",
				"Seen on the network for "+insights.FormatDuration(input.Now.Sub(device.FirstSeen))+", so it has a real routine",
			),
			Facts: append(deviceFacts(device, false),
				insights.Fact{Label: "Unusual hours", Value: hourLabel(span.start) + " to " + hourLabel((span.start+span.length)%24)},
				insights.Fact{Label: "Queries then", Value: insights.FormatCount(span.queries)},
			),
			Explanations: []string{
				"A scheduled update or backup ran at a new time",
				"Someone used the device at an odd hour",
				"Software on it started doing something on its own",
			},
			Method: "Sable learns the hours each " + noun(device) + " is active. It reports one that was active on most of the previous 14 days " +
				"and then sent at least 30 queries in an hour of the day it had not used at all in that time.",
		})
	}
	return findings
}

func applianceFindings(input ChangesInput, skip map[string]bool) []insights.Finding {
	candidates := make([]Device, 0)
	for _, device := range input.Devices {
		guess := device.Guess
		if skip[device.Key] || !appliances[guess.Type] || guess.Confidence == ConfidenceLow || !input.baselineReady(device) {
			continue
		}
		daily := float64(device.BaselineNewDomains) / baselineDays
		if device.RecentNewDomains >= minimumApplianceNewDomains && float64(device.RecentNewDomains) >= 3*max(daily, 1) {
			candidates = append(candidates, device)
		}
	}
	slices.SortFunc(candidates, func(left, right Device) int { return cmp.Compare(right.RecentNewDomains, left.RecentNewDomains) })
	findings := make([]insights.Finding, 0, min(len(candidates), maximumApplianceDrift))
	for _, device := range candidates[:min(len(candidates), maximumApplianceDrift)] {
		label := TypeLabel(device.Guess.Type)
		finding := insights.Finding{
			Kind: KindApplianceDrift, Tone: insights.ToneAttention, Title: label + " talking somewhere new",
			Subject:  deviceSubject(device),
			Headline: Label(device) + " started calling new services",
			Summary: fmt.Sprintf("Queried %s %s it had never used in the last 24 hours. A %s usually sticks to the same few services.",
				insights.FormatCount(device.RecentNewDomains), insights.Plural(device.RecentNewDomains, "domain", "domains"), strings.ToLower(label)),
			Reasons: []insights.Reason{
				{Text: fmt.Sprintf("%s first-time %s in the last 24 hours", insights.FormatCount(device.RecentNewDomains), insights.Plural(device.RecentNewDomains, "domain", "domains"))},
				{Text: fmt.Sprintf("%s in the whole week before", insights.FormatCount(device.BaselineNewDomains))},
				{Text: GuessText(device.Guess) + ", which normally keeps to a few services"},
			},
			Facts: append(deviceFacts(device, false),
				insights.Fact{Label: "New in last 24 hours", Value: insights.FormatCount(device.RecentNewDomains)},
				insights.Fact{Label: "New in week before", Value: insights.FormatCount(device.BaselineNewDomains)},
			),
			Explanations: []string{
				"A firmware update moved it to new services",
				"Its maker changed the cloud service it uses",
				"Software on it that should not be there",
			},
			Method: "Appliances such as cameras, doorbells, and TVs talk to the same few services day after day. Sable reports one that queried " +
				"at least three domains it had never used in a single day, and at least three times its usual daily count.",
		}
		if input.RecentDomains != nil {
			finding.Domains = input.RecentDomains(device)
			if len(finding.Domains) > maximumListedNames {
				finding.Domains = finding.Domains[:maximumListedNames]
			}
		}
		findings = append(findings, finding)
	}
	return findings
}
