package config

import (
	"math"
	"strconv"
	"strings"
	"time"
)

// Insights configures what Insights looks for and what it does with each kind
// of finding it makes.
type Insights struct {
	// Findings sets, for each kind of finding, whether Insights shows it and
	// sends it as an alert, only shows it, or leaves it out, and the limits
	// that make one.
	Findings InsightFindings `toml:"findings"`
	// Webhook is where older releases sent Insights alerts, before alerts got
	// their own [alerts] section. It is read only to move an older file's
	// setup into [[alerts.destinations]], and is never written back.
	Webhook InsightsWebhook `toml:"webhook,omitempty"`
}

// What Insights does with a kind of finding.
const (
	// InsightModeAlert shows findings of the kind in Insights and sends each
	// new one as an alert.
	InsightModeAlert = "alert"
	// InsightModeShow shows them in Insights without sending alerts.
	InsightModeShow = "show"
	// InsightModeOff leaves them out. Insights does not look for them at all.
	InsightModeOff = "off"
)

// The limits Insights has always used, and the range an operator may move
// each one within. Each default is conservative on purpose: a quiet page is
// better than one that cries wolf about normal variation.
const (
	defaultInsightQuietDailyLookups   = 50
	maximumInsightQuietDailyLookups   = 100_000
	defaultInsightSpikeFactor         = 3.0
	minimumInsightSpikeFactor         = 1.5
	maximumInsightSpikeFactor         = 100.0
	defaultInsightSpikeLookups        = 500
	maximumInsightSpikeLookups        = 1_000_000
	defaultInsightNewDomains          = 20
	maximumInsightNewDomains          = 10_000
	defaultInsightUnusualHourLookups  = 30
	maximumInsightUnusualHourLookups  = 100_000
	defaultInsightCheckInInterval     = 2 * time.Hour
	minimumInsightCheckInInterval     = 2 * time.Minute
	maximumInsightCheckInInterval     = 2 * time.Hour
	defaultInsightCheckInSpan         = 12 * time.Hour
	minimumInsightCheckInSpan         = time.Hour
	maximumInsightCheckInSpan         = 23 * time.Hour
	defaultInsightApplianceNewDomains = 3
	maximumInsightApplianceNewDomains = 1_000
	defaultInsightMissedUpdates       = 2
	maximumInsightMissedUpdates       = 100
)

// InsightFindings holds one table for each kind of finding, named for the
// kind without its area: went_quiet is devices.went-quiet. A limit left out
// or set to 0 takes its default.
type InsightFindings struct {
	NewDevice           InsightFinding             `toml:"new_device"`
	WentQuiet           InsightWentQuiet           `toml:"went_quiet"`
	TrafficSpike        InsightTrafficSpike        `toml:"traffic_spike"`
	NewDestinations     InsightNewDestinations     `toml:"new_destinations"`
	NewApp              InsightFinding             `toml:"new_app"`
	UnusualHours        InsightUnusualHours        `toml:"unusual_hours"`
	CheckIn             InsightCheckIn             `toml:"check_in"`
	ApplianceNewDomains InsightApplianceNewDomains `toml:"appliance_new_domains"`
	UpdateFailing       InsightUpdateFailing       `toml:"update_failing"`
	PastBlock           InsightFinding             `toml:"past_block"`
	// ListUnreadable, LowUniqueCoverage, and UniqueCoverage describe how the
	// block lists compare. That is never news, so they are shown or left out
	// but never sent as alerts.
	ListUnreadable    InsightFinding `toml:"list_unreadable"`
	LowUniqueCoverage InsightFinding `toml:"low_unique_coverage"`
	UniqueCoverage    InsightFinding `toml:"unique_coverage"`
}

// InsightFinding is a kind of finding with no limits of its own.
type InsightFinding struct {
	// Mode is "alert", "show", or "off".
	Mode string `toml:"mode"`
}

// InsightWentQuiet reports a device that was busy all week and then sent
// nothing for a whole day. The day of silence is fixed.
type InsightWentQuiet struct {
	Mode string `toml:"mode"`
	// MinimumDailyLookups is how many lookups a day the device must have
	// averaged over the week before, so a device that rarely speaks is not
	// reported for resting.
	MinimumDailyLookups int `toml:"minimum_daily_lookups"`
}

// InsightTrafficSpike reports a device far busier than its own week.
type InsightTrafficSpike struct {
	Mode string `toml:"mode"`
	// Factor is how many times its daily average the last day must reach, and
	// MinimumLookups the fewest lookups that day must have.
	Factor         float64 `toml:"factor"`
	MinimumLookups int     `toml:"minimum_lookups"`
}

// InsightNewDestinations reports a device that queried many domains it had
// never queried before.
type InsightNewDestinations struct {
	Mode string `toml:"mode"`
	// MinimumNewDomains is how many first-time domains in the selected period
	// make the device worth a look.
	MinimumNewDomains int `toml:"minimum_new_domains"`
}

// InsightUnusualHours reports a device busy at an hour of the day it had not
// used for two weeks.
type InsightUnusualHours struct {
	Mode string `toml:"mode"`
	// MinimumLookups is how many lookups in one such hour make it unusual,
	// so a stray lookup at an odd hour is not reported.
	MinimumLookups int `toml:"minimum_lookups"`
}

// InsightCheckIn reports a name one device looks up on a steady schedule.
type InsightCheckIn struct {
	Mode string `toml:"mode"`
	// LongestInterval is the most time a schedule may leave between lookups,
	// and ShortestSpan the least time it must keep that schedule up.
	LongestInterval Duration `toml:"longest_interval"`
	ShortestSpan    Duration `toml:"shortest_span"`
}

// InsightApplianceNewDomains reports an appliance, such as a camera or a TV,
// calling services it never used.
type InsightApplianceNewDomains struct {
	Mode string `toml:"mode"`
	// MinimumNewDomains is how many domains it never used, in one day, make
	// it worth a look.
	MinimumNewDomains int `toml:"minimum_new_domains"`
}

// InsightUpdateFailing reports a block list that stopped downloading.
type InsightUpdateFailing struct {
	Mode string `toml:"mode"`
	// MissedUpdates is how many update intervals the list must go without a
	// download. One failed attempt usually recovers on the next try.
	MissedUpdates int `toml:"missed_updates"`
}

// DefaultInsightFindings is what Insights does with each kind of finding
// unless an operator says otherwise: every kind that is news alerts, and the
// three that describe block list coverage are only shown.
func DefaultInsightFindings() InsightFindings {
	return InsightFindings{
		NewDevice:       InsightFinding{Mode: InsightModeAlert},
		WentQuiet:       InsightWentQuiet{Mode: InsightModeAlert, MinimumDailyLookups: defaultInsightQuietDailyLookups},
		TrafficSpike:    InsightTrafficSpike{Mode: InsightModeAlert, Factor: defaultInsightSpikeFactor, MinimumLookups: defaultInsightSpikeLookups},
		NewDestinations: InsightNewDestinations{Mode: InsightModeAlert, MinimumNewDomains: defaultInsightNewDomains},
		NewApp:          InsightFinding{Mode: InsightModeAlert},
		UnusualHours:    InsightUnusualHours{Mode: InsightModeAlert, MinimumLookups: defaultInsightUnusualHourLookups},
		CheckIn: InsightCheckIn{
			Mode:            InsightModeAlert,
			LongestInterval: Duration{Duration: defaultInsightCheckInInterval},
			ShortestSpan:    Duration{Duration: defaultInsightCheckInSpan},
		},
		ApplianceNewDomains: InsightApplianceNewDomains{Mode: InsightModeAlert, MinimumNewDomains: defaultInsightApplianceNewDomains},
		UpdateFailing:       InsightUpdateFailing{Mode: InsightModeAlert, MissedUpdates: defaultInsightMissedUpdates},
		PastBlock:           InsightFinding{Mode: InsightModeAlert},
		ListUnreadable:      InsightFinding{Mode: InsightModeShow},
		LowUniqueCoverage:   InsightFinding{Mode: InsightModeShow},
		UniqueCoverage:      InsightFinding{Mode: InsightModeShow},
	}
}

// normalizeInsights tidies modes as written by hand and gives every mode and
// limit left out its default, so a file from before these settings existed
// behaves exactly as it did.
func (configuration *Config) normalizeInsights() {
	findings := &configuration.Insights.Findings
	defaults := DefaultInsightFindings()
	for _, mode := range []struct {
		value    *string
		fallback string
	}{
		{&findings.NewDevice.Mode, defaults.NewDevice.Mode},
		{&findings.WentQuiet.Mode, defaults.WentQuiet.Mode},
		{&findings.TrafficSpike.Mode, defaults.TrafficSpike.Mode},
		{&findings.NewDestinations.Mode, defaults.NewDestinations.Mode},
		{&findings.NewApp.Mode, defaults.NewApp.Mode},
		{&findings.UnusualHours.Mode, defaults.UnusualHours.Mode},
		{&findings.CheckIn.Mode, defaults.CheckIn.Mode},
		{&findings.ApplianceNewDomains.Mode, defaults.ApplianceNewDomains.Mode},
		{&findings.UpdateFailing.Mode, defaults.UpdateFailing.Mode},
		{&findings.PastBlock.Mode, defaults.PastBlock.Mode},
		{&findings.ListUnreadable.Mode, defaults.ListUnreadable.Mode},
		{&findings.LowUniqueCoverage.Mode, defaults.LowUniqueCoverage.Mode},
		{&findings.UniqueCoverage.Mode, defaults.UniqueCoverage.Mode},
	} {
		*mode.value = strings.ToLower(strings.TrimSpace(*mode.value))
		if *mode.value == "" {
			*mode.value = mode.fallback
		}
	}
	for _, limit := range []struct {
		value    *int
		fallback int
	}{
		{&findings.WentQuiet.MinimumDailyLookups, defaults.WentQuiet.MinimumDailyLookups},
		{&findings.TrafficSpike.MinimumLookups, defaults.TrafficSpike.MinimumLookups},
		{&findings.NewDestinations.MinimumNewDomains, defaults.NewDestinations.MinimumNewDomains},
		{&findings.UnusualHours.MinimumLookups, defaults.UnusualHours.MinimumLookups},
		{&findings.ApplianceNewDomains.MinimumNewDomains, defaults.ApplianceNewDomains.MinimumNewDomains},
		{&findings.UpdateFailing.MissedUpdates, defaults.UpdateFailing.MissedUpdates},
	} {
		if *limit.value == 0 {
			*limit.value = limit.fallback
		}
	}
	if findings.TrafficSpike.Factor == 0 {
		findings.TrafficSpike.Factor = defaults.TrafficSpike.Factor
	}
	if findings.CheckIn.LongestInterval.Duration == 0 {
		findings.CheckIn.LongestInterval = defaults.CheckIn.LongestInterval
	}
	if findings.CheckIn.ShortestSpan.Duration == 0 {
		findings.CheckIn.ShortestSpan = defaults.CheckIn.ShortestSpan
	}
}

// InsightSettingProblem is one setting under [insights.findings] that
// Insights cannot use.
type InsightSettingProblem struct {
	// Setting is the setting's path under [insights.findings], such as
	// "went_quiet.minimum_daily_lookups". The console names its form fields
	// the same way, so it can point at the field that needs fixing.
	Setting string
	// Problem says what is wrong, such as "must be between 1 and 100,000".
	Problem string
}

func (problem InsightSettingProblem) Error() string {
	return "insights.findings." + problem.Setting + " " + problem.Problem
}

// Problems lists every setting Insights cannot use, in the order the settings
// are listed. The console checks a change with it before saving, and loading a
// file refuses any.
func (findings InsightFindings) Problems() []InsightSettingProblem {
	var problems []InsightSettingProblem
	add := func(setting, problem string) {
		problems = append(problems, InsightSettingProblem{Setting: setting, Problem: problem})
	}
	mode := func(setting, value string) {
		switch value {
		case InsightModeAlert, InsightModeShow, InsightModeOff:
		default:
			add(setting, `must be "alert", "show", or "off"`)
		}
	}
	// Coverage findings are never news, so there is nothing to alert about.
	shownMode := func(setting, value string) {
		if value != InsightModeShow && value != InsightModeOff {
			add(setting, `must be "show" or "off" because these findings are never news`)
		}
	}
	count := func(setting string, value, maximum int) {
		if value < 1 || value > maximum {
			add(setting, "must be between 1 and "+wholeNumber(maximum))
		}
	}
	mode("new_device.mode", findings.NewDevice.Mode)
	mode("went_quiet.mode", findings.WentQuiet.Mode)
	count("went_quiet.minimum_daily_lookups", findings.WentQuiet.MinimumDailyLookups, maximumInsightQuietDailyLookups)
	mode("traffic_spike.mode", findings.TrafficSpike.Mode)
	if factor := findings.TrafficSpike.Factor; math.IsNaN(factor) || factor < minimumInsightSpikeFactor || factor > maximumInsightSpikeFactor {
		add("traffic_spike.factor", "must be between 1.5 and 100")
	}
	count("traffic_spike.minimum_lookups", findings.TrafficSpike.MinimumLookups, maximumInsightSpikeLookups)
	mode("new_destinations.mode", findings.NewDestinations.Mode)
	count("new_destinations.minimum_new_domains", findings.NewDestinations.MinimumNewDomains, maximumInsightNewDomains)
	mode("new_app.mode", findings.NewApp.Mode)
	mode("unusual_hours.mode", findings.UnusualHours.Mode)
	count("unusual_hours.minimum_lookups", findings.UnusualHours.MinimumLookups, maximumInsightUnusualHourLookups)
	mode("check_in.mode", findings.CheckIn.Mode)
	if interval := findings.CheckIn.LongestInterval.Duration; interval < minimumInsightCheckInInterval || interval > maximumInsightCheckInInterval {
		// A schedule needs two dozen lookups in one day to count as steady,
		// so a longer interval could never be reported.
		add("check_in.longest_interval", "must be between 2 minutes and 2 hours")
	}
	if span := findings.CheckIn.ShortestSpan.Duration; span < minimumInsightCheckInSpan || span > maximumInsightCheckInSpan {
		add("check_in.shortest_span", "must be between 1 hour and 23 hours")
	}
	mode("appliance_new_domains.mode", findings.ApplianceNewDomains.Mode)
	count("appliance_new_domains.minimum_new_domains", findings.ApplianceNewDomains.MinimumNewDomains, maximumInsightApplianceNewDomains)
	mode("update_failing.mode", findings.UpdateFailing.Mode)
	count("update_failing.missed_updates", findings.UpdateFailing.MissedUpdates, maximumInsightMissedUpdates)
	mode("past_block.mode", findings.PastBlock.Mode)
	shownMode("list_unreadable.mode", findings.ListUnreadable.Mode)
	shownMode("low_unique_coverage.mode", findings.LowUniqueCoverage.Mode)
	shownMode("unique_coverage.mode", findings.UniqueCoverage.Mode)
	return problems
}

// wholeNumber writes a count with thousands separators, the way the console
// shows counts.
func wholeNumber(value int) string {
	digits := strconv.Itoa(value)
	var grouped strings.Builder
	for index, digit := range digits {
		if index > 0 && (len(digits)-index)%3 == 0 {
			grouped.WriteByte(',')
		}
		grouped.WriteRune(digit)
	}
	return grouped.String()
}

// InsightsWebhook is the one alert destination older releases kept under
// [insights.webhook]. An empty URL meant alerts were off.
type InsightsWebhook struct {
	URL           string        `toml:"url,omitempty"`
	Format        string        `toml:"format,omitempty"`
	Paused        bool          `toml:"paused,omitempty"`
	NtfyReceipt   bool          `toml:"ntfy_receipt,omitempty"`
	PushoverToken string        `toml:"pushover_token,omitempty"`
	PushoverUser  string        `toml:"pushover_user,omitempty"`
	Headers       []AlertHeader `toml:"headers,omitempty"`
}

// destination turns an older release's webhook into an alert destination. Its
// ID is the key the older release gave its record of what was sent: a hash of
// the URL, or "browser". found is false when the webhook sent nowhere.
func (webhook InsightsWebhook) destination() (AlertDestination, bool) {
	destination := AlertDestination{
		URL: strings.TrimSpace(webhook.URL), Format: webhook.Format, NtfyReceipt: webhook.NtfyReceipt,
		PushoverToken: strings.TrimSpace(webhook.PushoverToken), PushoverUser: strings.TrimSpace(webhook.PushoverUser),
		Headers: append([]AlertHeader(nil), webhook.Headers...),
	}
	destination.Normalize()
	switch destination.Format {
	case AlertFormatBrowser:
		destination.ID = AlertFormatBrowser
	case AlertFormatPushover:
		// An older release posted to Pushover's API unless the file named
		// another, and its keys, not a URL, said whether alerts were on.
		if destination.PushoverToken == "" && destination.PushoverUser == "" {
			return AlertDestination{}, false
		}
		if destination.URL == "" {
			destination.URL = PushoverMessagesURL
		}
		destination.ID = AlertTarget(destination.URL)
	default:
		if destination.URL == "" {
			return AlertDestination{}, false
		}
		destination.ID = AlertTarget(destination.URL)
	}
	return destination, true
}
