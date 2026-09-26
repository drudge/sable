package devices

import (
	"fmt"
	"strconv"
	"time"

	"github.com/drudge/sable/internal/insights"
)

// Limits are how far a device has to stray from its own history before a
// change is worth reporting. The console sets them from each kind of
// finding's settings, and a limit left at zero takes its default.
type Limits struct {
	// QuietDailyLookups is how many lookups a day a device must have averaged
	// over the week before for a silent day to count as going quiet, so a
	// device that rarely speaks is not reported for resting.
	QuietDailyLookups uint64
	// SpikeFactor is how many times its daily average a device's last day
	// must reach to count as a spike, and SpikeLookups the fewest lookups
	// that day must have.
	SpikeFactor  float64
	SpikeLookups uint64
	// NewDomains is how many first-time domains in the window show that a
	// device started talking to a meaningfully different set of places.
	NewDomains uint64
	// UnusualHourLookups is how many lookups in an hour a device never uses
	// make that hour unusual, so a stray lookup at an odd hour is ignored.
	UnusualHourLookups uint64
	// CheckInInterval is the longest a steady schedule may wait between
	// lookups, and CheckInSpan the least time it must keep that schedule up.
	CheckInInterval time.Duration
	CheckInSpan     time.Duration
	// ApplianceNewDomains is how many first-time domains in one day make an
	// appliance worth a look.
	ApplianceNewDomains uint64
}

// DefaultLimits are the limits Insights uses unless an operator sets others.
// Each is conservative on purpose: a quiet page is better than a page that
// cries wolf about normal variation.
func DefaultLimits() Limits {
	return Limits{
		QuietDailyLookups: 50, SpikeFactor: 3, SpikeLookups: 500, NewDomains: 20, UnusualHourLookups: 30,
		CheckInInterval: 2 * time.Hour, CheckInSpan: 12 * time.Hour, ApplianceNewDomains: 3,
	}
}

// withDefaults gives every limit left at zero its default.
func (limits Limits) withDefaults() Limits {
	defaults := DefaultLimits()
	for _, limit := range []struct{ value, fallback *uint64 }{
		{&limits.QuietDailyLookups, &defaults.QuietDailyLookups},
		{&limits.SpikeLookups, &defaults.SpikeLookups},
		{&limits.NewDomains, &defaults.NewDomains},
		{&limits.UnusualHourLookups, &defaults.UnusualHourLookups},
		{&limits.ApplianceNewDomains, &defaults.ApplianceNewDomains},
	} {
		if *limit.value == 0 {
			*limit.value = *limit.fallback
		}
	}
	if limits.SpikeFactor == 0 {
		limits.SpikeFactor = defaults.SpikeFactor
	}
	if limits.CheckInInterval == 0 {
		limits.CheckInInterval = defaults.CheckInInterval
	}
	if limits.CheckInSpan == 0 {
		limits.CheckInSpan = defaults.CheckInSpan
	}
	return limits
}

// countText writes a count the way a sentence reads it: a word up to ten, and
// digits past that.
func countText(count uint64) string {
	words := []string{"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"}
	if count < uint64(len(words)) {
		return words[count]
	}
	return insights.FormatCount(count)
}

// growthText says how much busier than usual a spike is, the way the rule
// reads: "at least tripled their usual volume".
func growthText(factor float64) string {
	switch factor {
	case 2:
		return "at least doubled their usual volume"
	case 3:
		return "at least tripled their usual volume"
	default:
		return "reached at least " + strconv.FormatFloat(factor, 'f', -1, 64) + "× their usual volume"
	}
}

// spanText writes how long a schedule must run, in whole hours when it is
// whole hours and in minutes otherwise, so it never rounds a limit down.
func spanText(span time.Duration) string {
	if span%time.Hour == 0 {
		return insights.FormatDuration(span)
	}
	minutes := int(span / time.Minute)
	return fmt.Sprintf("%d %s", minutes, insights.Plural(minutes, "minute", "minutes"))
}
