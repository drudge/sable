package web

import (
	"slices"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights"
	blockinginsights "github.com/drudge/sable/internal/insights/blocking"
	"github.com/drudge/sable/internal/insights/devices"
)

// insightKindSetting is one kind of finding as Insights settings shows it:
// its plain name, what it means, and where its settings live.
type insightKindSetting struct {
	kind string
	// key names the kind's table under [insights.findings] and prefixes its
	// form fields, so a problem the configuration reports points at a field.
	key         string
	title       string
	description string
	// note says why a kind cannot alert. Only findings that are news can.
	note   string
	mode   func(*config.InsightFindings) *string
	limits []insightLimitSetting
}

// insightLimitSetting is one limit's field, in the unit the field shows.
type insightLimitSetting struct {
	// key names the limit in its kind's table.
	key   string
	label string
	help  string
	// unit follows the value in the audit log.
	unit string
	// minimum and maximum are the range the configuration accepts, which
	// the field offers too. whole limits take whole numbers.
	minimum, maximum float64
	whole            bool
	get              func(config.InsightFindings) float64
	set              func(*config.InsightFindings, float64)
}

// insightSettingGroup is the kinds of finding one area of Insights makes, in
// the order Insights settings lists them.
type insightSettingGroup struct {
	id, title string
	kinds     []insightKindSetting
}

// neverNews explains why the coverage kinds cannot alert.
const neverNews = "It describes your lists rather than news, so it never alerts."

// insightSettingGroups lists every kind of finding Insights makes. Each title
// reads the way the finding's own title does.
func insightSettingGroups() []insightSettingGroup {
	count := func(value int) float64 { return float64(value) }
	return []insightSettingGroup{
		{id: "devices", title: "Devices", kinds: []insightKindSetting{
			{
				kind: devices.KindNewDevice, key: "new_device", title: "New device on the network",
				description: "A device Sable has not seen before joins the network.",
				mode:        func(findings *config.InsightFindings) *string { return &findings.NewDevice.Mode },
			},
			{
				kind: devices.KindWentQuiet, key: "went_quiet", title: "Went quiet",
				description: "A device that was busy all week sends nothing for a day.",
				mode:        func(findings *config.InsightFindings) *string { return &findings.WentQuiet.Mode },
				limits: []insightLimitSetting{{
					key: "minimum_daily_lookups", label: "Lookups a day before", help: "It must have averaged at least this many.",
					unit: "lookups a day", minimum: 1, maximum: 100_000, whole: true,
					get: func(findings config.InsightFindings) float64 { return count(findings.WentQuiet.MinimumDailyLookups) },
					set: func(findings *config.InsightFindings, value float64) {
						findings.WentQuiet.MinimumDailyLookups = int(value)
					},
				}},
			},
			{
				kind: devices.KindTrafficSpike, key: "traffic_spike", title: "Unusually busy",
				description: "A device sends far more lookups than it usually does.",
				mode:        func(findings *config.InsightFindings) *string { return &findings.TrafficSpike.Mode },
				limits: []insightLimitSetting{
					{
						key: "factor", label: "Times its usual day", help: "How many times its daily average.",
						unit: "times", minimum: 1.5, maximum: 100,
						get: func(findings config.InsightFindings) float64 { return findings.TrafficSpike.Factor },
						set: func(findings *config.InsightFindings, value float64) { findings.TrafficSpike.Factor = value },
					},
					{
						key: "minimum_lookups", label: "Lookups in the day", help: "It must also send at least this many.",
						unit: "lookups", minimum: 1, maximum: 1_000_000, whole: true,
						get: func(findings config.InsightFindings) float64 { return count(findings.TrafficSpike.MinimumLookups) },
						set: func(findings *config.InsightFindings, value float64) {
							findings.TrafficSpike.MinimumLookups = int(value)
						},
					},
				},
			},
			{
				kind: devices.KindNewDestinations, key: "new_destinations", title: "Talking to new places",
				description: "A device looks up many domains it never used before.",
				mode:        func(findings *config.InsightFindings) *string { return &findings.NewDestinations.Mode },
				limits: []insightLimitSetting{{
					key: "minimum_new_domains", label: "New domains", help: "Ones it had never looked up before the period.",
					unit: "domains", minimum: 1, maximum: 10_000, whole: true,
					get: func(findings config.InsightFindings) float64 {
						return count(findings.NewDestinations.MinimumNewDomains)
					},
					set: func(findings *config.InsightFindings, value float64) {
						findings.NewDestinations.MinimumNewDomains = int(value)
					},
				}},
			},
			{
				kind: devices.KindNewApp, key: "new_app", title: "Started using a new app",
				description: "A device starts using an app it never used before.",
				mode:        func(findings *config.InsightFindings) *string { return &findings.NewApp.Mode },
			},
			{
				kind: devices.KindUnusualHours, key: "unusual_hours", title: "Active at an unusual hour",
				description: "A device is busy at an hour it has not used in two weeks.",
				mode:        func(findings *config.InsightFindings) *string { return &findings.UnusualHours.Mode },
				limits: []insightLimitSetting{{
					key: "minimum_lookups", label: "Lookups in the hour", help: "So a stray lookup at an odd hour is ignored.",
					unit: "lookups", minimum: 1, maximum: 100_000, whole: true,
					get: func(findings config.InsightFindings) float64 { return count(findings.UnusualHours.MinimumLookups) },
					set: func(findings *config.InsightFindings, value float64) {
						findings.UnusualHours.MinimumLookups = int(value)
					},
				}},
			},
			{
				kind: devices.KindCheckIn, key: "check_in", title: "Checks in on a schedule",
				description: "One device looks up the same name like clockwork.",
				mode:        func(findings *config.InsightFindings) *string { return &findings.CheckIn.Mode },
				limits: []insightLimitSetting{
					{
						key: "longest_interval", label: "Longest gap (minutes)", help: "The most time between two lookups.",
						unit: "minutes", minimum: 2, maximum: 120,
						get: func(findings config.InsightFindings) float64 { return findings.CheckIn.LongestInterval.Minutes() },
						set: func(findings *config.InsightFindings, value float64) {
							findings.CheckIn.LongestInterval = config.Duration{Duration: time.Duration(value * float64(time.Minute)).Round(time.Second)}
						},
					},
					{
						key: "shortest_span", label: "Shortest run (hours)", help: "How long it must keep to the schedule.",
						unit: "hours", minimum: 1, maximum: 23,
						get: func(findings config.InsightFindings) float64 { return findings.CheckIn.ShortestSpan.Hours() },
						set: func(findings *config.InsightFindings, value float64) {
							findings.CheckIn.ShortestSpan = config.Duration{Duration: time.Duration(value * float64(time.Hour)).Round(time.Second)}
						},
					},
				},
			},
			{
				kind: devices.KindApplianceDrift, key: "appliance_new_domains", title: "Appliance talking somewhere new",
				description: "A camera, TV, or other appliance calls services it never used.",
				mode:        func(findings *config.InsightFindings) *string { return &findings.ApplianceNewDomains.Mode },
				limits: []insightLimitSetting{{
					key: "minimum_new_domains", label: "New domains in a day", help: "Ones it had never used before.",
					unit: "domains", minimum: 1, maximum: 1_000, whole: true,
					get: func(findings config.InsightFindings) float64 {
						return count(findings.ApplianceNewDomains.MinimumNewDomains)
					},
					set: func(findings *config.InsightFindings, value float64) {
						findings.ApplianceNewDomains.MinimumNewDomains = int(value)
					},
				}},
			},
		}},
		{id: "blocking", title: "Blocking", kinds: []insightKindSetting{
			{
				kind: blockinginsights.KindUpdateFailing, key: "update_failing", title: "Block list updates are failing",
				description: "A block list stops downloading.",
				mode:        func(findings *config.InsightFindings) *string { return &findings.UpdateFailing.Mode },
				limits: []insightLimitSetting{{
					key: "missed_updates", label: "Missed updates", help: "Scheduled updates in a row that failed.",
					unit: "missed updates", minimum: 1, maximum: 100, whole: true,
					get: func(findings config.InsightFindings) float64 { return count(findings.UpdateFailing.MissedUpdates) },
					set: func(findings *config.InsightFindings, value float64) {
						findings.UpdateFailing.MissedUpdates = int(value)
					},
				}},
			},
			{
				kind: blockinginsights.KindPastBlock, key: "past_block", title: "Possible past blocking issue",
				description: "A domain was blocked before you allowed it.",
				mode:        func(findings *config.InsightFindings) *string { return &findings.PastBlock.Mode },
			},
			{
				kind: blockinginsights.KindListUnreadable, key: "list_unreadable", title: "Block list left out of the comparison",
				description: "A block list could not be read to compare with the others.", note: neverNews,
				mode: func(findings *config.InsightFindings) *string { return &findings.ListUnreadable.Mode },
			},
			{
				kind: blockinginsights.KindLowUnique, key: "low_unique_coverage", title: "Little unique coverage",
				description: "A block list mostly repeats your other lists.", note: neverNews,
				mode: func(findings *config.InsightFindings) *string { return &findings.LowUniqueCoverage.Mode },
			},
			{
				kind: blockinginsights.KindUniqueCoverage, key: "unique_coverage", title: "Meaningful unique coverage",
				description: "A block list blocks many domains no other list does.", note: neverNews,
				mode: func(findings *config.InsightFindings) *string { return &findings.UniqueCoverage.Mode },
			},
		}},
	}
}

// insightKindSettings lists every kind of finding in the order Insights
// settings shows them.
func insightKindSettings() []insightKindSetting {
	var kinds []insightKindSetting
	for _, group := range insightSettingGroups() {
		kinds = append(kinds, group.kinds...)
	}
	return kinds
}

// insightModes is what Insights does with each kind of finding, by kind.
type insightModes map[string]string

func insightModesOf(findings config.InsightFindings) insightModes {
	modes := make(insightModes)
	for _, kind := range insightKindSettings() {
		if mode := *kind.mode(&findings); mode != "" {
			modes[kind.kind] = mode
		}
	}
	return modes
}

// shows reports whether findings of a kind appear in Insights. A kind with no
// settings, such as one a newer analyzer makes, shows.
func (modes insightModes) shows(kind string) bool { return modes[kind] != config.InsightModeOff }

// alerts reports whether findings of a kind go out as alerts. A kind with no
// settings alerts, as every kind with news did before there were settings.
func (modes insightModes) alerts(kind string) bool {
	mode, set := modes[kind]
	return !set || mode == config.InsightModeAlert
}

// off lists the kinds that are off, which the analyzers do not look for.
func (modes insightModes) off() map[string]bool {
	off := make(map[string]bool)
	for kind, mode := range modes {
		if mode == config.InsightModeOff {
			off[kind] = true
		}
	}
	return off
}

// shown keeps the findings of the kinds Insights shows. Every page of
// Insights filters through here, whichever analyzer made the finding.
func (modes insightModes) shown(findings []insights.Finding) []insights.Finding {
	return slices.DeleteFunc(findings, func(finding insights.Finding) bool { return !modes.shows(finding.Kind) })
}

// insightDeviceLimits are the device analyzer's limits from the settings. A
// limit the settings leave at zero takes the analyzer's default.
func insightDeviceLimits(findings config.InsightFindings) devices.Limits {
	whole := func(value int) uint64 { return uint64(max(value, 0)) }
	return devices.Limits{
		QuietDailyLookups:   whole(findings.WentQuiet.MinimumDailyLookups),
		SpikeFactor:         findings.TrafficSpike.Factor,
		SpikeLookups:        whole(findings.TrafficSpike.MinimumLookups),
		NewDomains:          whole(findings.NewDestinations.MinimumNewDomains),
		UnusualHourLookups:  whole(findings.UnusualHours.MinimumLookups),
		CheckInInterval:     findings.CheckIn.LongestInterval.Duration,
		CheckInSpan:         findings.CheckIn.ShortestSpan.Duration,
		ApplianceNewDomains: whole(findings.ApplianceNewDomains.MinimumNewDomains),
	}
}

// insightBlockingLimits are the blocking analyzer's limits from the settings.
func insightBlockingLimits(findings config.InsightFindings) blockinginsights.Limits {
	return blockinginsights.Limits{MissedUpdates: max(findings.UpdateFailing.MissedUpdates, 0)}
}
