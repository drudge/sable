package config

import (
	"fmt"
	"slices"
	"strings"
	"time"
	// Schedules name IANA time zones, which must read on hosts without a
	// zone database too.
	_ "time/tzdata"
	"unicode"

	"github.com/drudge/sable/internal/insights/services"
)

// What a schedule blocks while it is on.
const (
	// ScheduleBlockEverything blocks everything for the rule set's devices,
	// the way a hold does, except the domains they are allowed.
	ScheduleBlockEverything = "everything"
	// ScheduleBlockApps blocks the schedule's apps, as if the rule set
	// blocked them, only while the schedule is on.
	ScheduleBlockApps = "apps"
)

// scheduleTimeLayout is how a schedule writes its start and end: a 24-hour
// clock.
const scheduleTimeLayout = "15:04"

// scheduleDays are the days a schedule can name, in the order they are kept.
var scheduleDays = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// Schedule turns blocking on for a rule set's devices at set times each
// week, such as a bedtime. It starts at Start on each of its Days, and ends at
// End: the same day, or the next morning when End comes before Start. Times
// are read in TimeZone, an IANA name, so a schedule follows daylight saving
// time where it is.
type Schedule struct {
	Name     string   `toml:"name"`
	Days     []string `toml:"days"`
	Start    string   `toml:"start"`
	End      string   `toml:"end"`
	TimeZone string   `toml:"time_zone"`
	// Block is ScheduleBlockEverything or ScheduleBlockApps.
	Block string   `toml:"block"`
	Apps  []string `toml:"apps,omitempty"`
}

// Weekdays returns the schedule's days.
func (schedule Schedule) Weekdays() []time.Weekday {
	days := make([]time.Weekday, 0, len(schedule.Days))
	for _, day := range schedule.Days {
		if index := slices.Index(scheduleDays, day); index >= 0 {
			days = append(days, time.Weekday(index))
		}
	}
	return days
}

// Minutes returns the schedule's start and end as minutes past midnight.
func (schedule Schedule) Minutes() (start, end int) {
	return scheduleMinutes(schedule.Start), scheduleMinutes(schedule.End)
}

func scheduleMinutes(value string) int {
	parsed, err := time.Parse(scheduleTimeLayout, value)
	if err != nil {
		return -1
	}
	return parsed.Hour()*60 + parsed.Minute()
}

func cloneSchedules(schedules []Schedule) []Schedule {
	if schedules == nil {
		return nil
	}
	cloned := make([]Schedule, len(schedules))
	for index, schedule := range schedules {
		cloned[index] = schedule
		cloned[index].Days = slices.Clone(schedule.Days)
		cloned[index].Apps = slices.Clone(schedule.Apps)
	}
	return cloned
}

func normalizeSchedules(schedules []Schedule) {
	for index := range schedules {
		schedule := &schedules[index]
		schedule.Name = strings.TrimSpace(schedule.Name)
		schedule.TimeZone = strings.TrimSpace(schedule.TimeZone)
		schedule.Block = strings.ToLower(strings.TrimSpace(schedule.Block))
		if schedule.Block == "" {
			schedule.Block = ScheduleBlockEverything
		}
		schedule.Start, schedule.End = normalizeScheduleTime(schedule.Start), normalizeScheduleTime(schedule.End)
		schedule.Days = normalizeScheduleDays(schedule.Days)
		schedule.Apps = sortedUnique(schedule.Apps)
	}
}

// normalizeScheduleTime writes a time as two-digit hours and minutes, so
// "9:00" is kept as "09:00". A time that doesn't read stays for validation
// to report.
func normalizeScheduleTime(value string) string {
	value = strings.TrimSpace(value)
	if parsed, err := time.Parse(scheduleTimeLayout, value); err == nil {
		return parsed.Format(scheduleTimeLayout)
	}
	return value
}

// normalizeScheduleDays lowercases the days and keeps them in week order,
// once each. A day Sable doesn't know stays, at the end, for validation to
// report.
func normalizeScheduleDays(days []string) []string {
	var known, unknown []string
	for _, day := range days {
		day = strings.ToLower(strings.TrimSpace(day))
		if slices.Contains(scheduleDays, day) {
			known = append(known, day)
		} else {
			unknown = append(unknown, day)
		}
	}
	slices.SortFunc(known, func(left, right string) int {
		return slices.Index(scheduleDays, left) - slices.Index(scheduleDays, right)
	})
	return append(slices.Compact(known), unknown...)
}

func validateSchedules(parent string, schedules []Schedule) []error {
	var validationErrors []error
	seen := make(map[string]int, len(schedules))
	for index, schedule := range schedules {
		field := fmt.Sprintf("%s.schedules[%d]", parent, index)
		if err := validateScheduleName(field, schedule.Name); err != nil {
			validationErrors = append(validationErrors, err)
		} else if previous, taken := seen[strings.ToLower(schedule.Name)]; taken {
			validationErrors = append(validationErrors, fmt.Errorf("%s.name %q is already used by %s.schedules[%d]", field, schedule.Name, parent, previous))
		} else {
			seen[strings.ToLower(schedule.Name)] = index
		}
		if len(schedule.Days) == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("%s.days must name at least one day", field))
		}
		for dayIndex, day := range schedule.Days {
			if !slices.Contains(scheduleDays, day) {
				validationErrors = append(validationErrors, fmt.Errorf("%s.days[%d] %q must be one of %s", field, dayIndex, day, strings.Join(scheduleDays, ", ")))
			}
		}
		start, end := schedule.Minutes()
		if start < 0 {
			validationErrors = append(validationErrors, fmt.Errorf("%s.start must be a time like 21:00", field))
		}
		if end < 0 {
			validationErrors = append(validationErrors, fmt.Errorf("%s.end must be a time like 07:00", field))
		}
		if start >= 0 && start == end {
			validationErrors = append(validationErrors, fmt.Errorf("%s.end must differ from its start", field))
		}
		if schedule.TimeZone == "" {
			validationErrors = append(validationErrors, fmt.Errorf("%s.time_zone is required, such as America/New_York", field))
		} else if _, err := time.LoadLocation(schedule.TimeZone); err != nil || strings.EqualFold(schedule.TimeZone, "Local") {
			validationErrors = append(validationErrors, fmt.Errorf("%s.time_zone %q is not a time zone Sable knows", field, schedule.TimeZone))
		}
		switch schedule.Block {
		case ScheduleBlockEverything:
			if len(schedule.Apps) > 0 {
				validationErrors = append(validationErrors, fmt.Errorf("%s.apps only applies when block is %q", field, ScheduleBlockApps))
			}
		case ScheduleBlockApps:
			if len(schedule.Apps) == 0 {
				validationErrors = append(validationErrors, fmt.Errorf("%s.apps must name at least one app when block is %q", field, ScheduleBlockApps))
			}
		default:
			validationErrors = append(validationErrors, fmt.Errorf("%s.block must be %q or %q", field, ScheduleBlockEverything, ScheduleBlockApps))
		}
		for appIndex, app := range schedule.Apps {
			if _, found := services.Find(app); !found {
				validationErrors = append(validationErrors, fmt.Errorf("%s.apps[%d] names no app called %q", field, appIndex, app))
			}
		}
	}
	return validationErrors
}

func validateScheduleName(field, name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%s.name is required", field)
	case len([]rune(name)) > maximumRuleSetNameLength:
		return fmt.Errorf("%s.name must be at most %d characters", field, maximumRuleSetNameLength)
	case strings.IndexFunc(name, unicode.IsControl) >= 0:
		return fmt.Errorf("%s.name must not contain control characters", field)
	}
	return nil
}
