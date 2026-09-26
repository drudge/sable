package config

import (
	"strings"
	"testing"
	"time"
)

// A file that says nothing about a schedule checks hourly. Switched to daily
// or weekly, it checks at 09:00, on Monday for weekly.
func TestUpdateChecksDefaultToHourly(t *testing.T) {
	t.Parallel()
	loaded, err := Decode(strings.NewReader("[updates]\ncheck_on_login = true\n"))
	if err != nil {
		t.Fatal(err)
	}
	// A configuration built in code fills in the same once it is normalized.
	blank := Defaults()
	blank.Updates = Updates{CheckOnLogin: true}
	blank.normalize()
	want := Updates{CheckOnLogin: true, CheckSchedule: "hourly", CheckAt: "09:00", CheckDay: "monday"}
	for name, got := range map[string]Updates{"Defaults": Defaults().Updates, "an older file": loaded.Updates, "a normalized empty schedule": blank.Updates} {
		if got != want {
			t.Errorf("%s = %+v, want %+v", name, got, want)
		}
	}
	if day := want.CheckWeekday(); day != time.Monday {
		t.Fatalf("weekly checks fall on %s", day)
	}
}

// A schedule is read the way people type it, and one Sable cannot keep is
// refused with the setting to fix.
func TestUpdateCheckSchedulesAreChecked(t *testing.T) {
	t.Parallel()
	loaded, err := Decode(strings.NewReader("[updates]\ncheck_schedule = ' Weekly '\ncheck_at = '18:30'\ncheck_day = 'Friday'\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Updates; got.CheckSchedule != "weekly" || got.CheckAt != "18:30" || got.CheckDay != "friday" || got.CheckWeekday() != time.Friday {
		t.Fatalf("updates = %+v", got)
	}
	for setting, want := range map[string]string{
		"check_schedule = 'monthly'": "updates.check_schedule must be hourly, daily, or weekly",
		"check_at = '25:00'":         "updates.check_at must use HH:MM local time",
		"check_at = '9am'":           "updates.check_at must use HH:MM local time",
		"check_day = 'someday'":      "updates.check_day must be a day of the week, such as monday",
	} {
		if _, err := Decode(strings.NewReader("[updates]\n" + setting + "\n")); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error = %v, want %q", setting, err, want)
		}
	}
}
