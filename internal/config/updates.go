package config

import (
	"errors"
	"slices"
	"strings"
	"time"
)

// How often the lead looks for a newer Sable release on its own.
const (
	UpdateCheckHourly = "hourly"
	UpdateCheckDaily  = "daily"
	UpdateCheckWeekly = "weekly"

	defaultUpdateCheckAt  = "09:00"
	defaultUpdateCheckDay = "monday"
)

// updateCheckDays names the days a weekly update check can fall on, in
// time.Weekday order.
var updateCheckDays = []string{"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"}

// CheckWeekday is the day a weekly update check falls on.
func (updates Updates) CheckWeekday() time.Weekday {
	return time.Weekday(max(slices.Index(updateCheckDays, updates.CheckDay), 0))
}

// normalize fills in a schedule for a configuration from before schedules:
// hourly, and 09:00 on Monday for when it turns daily or weekly.
func (updates *Updates) normalize() {
	updates.CheckSchedule = strings.ToLower(strings.TrimSpace(updates.CheckSchedule))
	if updates.CheckSchedule == "" {
		updates.CheckSchedule = UpdateCheckHourly
	}
	updates.CheckAt = strings.TrimSpace(updates.CheckAt)
	if updates.CheckAt == "" {
		updates.CheckAt = defaultUpdateCheckAt
	}
	updates.CheckDay = strings.ToLower(strings.TrimSpace(updates.CheckDay))
	if updates.CheckDay == "" {
		updates.CheckDay = defaultUpdateCheckDay
	}
}

func (updates Updates) validate() []error {
	var problems []error
	switch updates.CheckSchedule {
	case UpdateCheckHourly, UpdateCheckDaily, UpdateCheckWeekly:
	default:
		problems = append(problems, errors.New("updates.check_schedule must be hourly, daily, or weekly"))
	}
	if _, err := time.Parse("15:04", updates.CheckAt); err != nil {
		problems = append(problems, errors.New("updates.check_at must use HH:MM local time"))
	}
	if !slices.Contains(updateCheckDays, updates.CheckDay) {
		problems = append(problems, errors.New("updates.check_day must be a day of the week, such as monday"))
	}
	return problems
}
