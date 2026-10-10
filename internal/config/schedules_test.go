package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSchedulesValidateAndNormalize(t *testing.T) {
	t.Parallel()
	configuration := Defaults()
	configuration.Blocking.RuleSets = []RuleSet{{Name: "Kids", Schedules: []Schedule{
		{Name: " Bedtime ", Days: []string{"Thu", "sun", "mon", "sun"}, Start: "21:00", End: "7:00", TimeZone: "America/New_York"},
		{Name: "Homework", Days: []string{"mon"}, Start: "15:30", End: "17:30", TimeZone: "America/Chicago", Block: "Apps", Apps: []string{"youtube", " roblox"}},
	}}}
	configuration.normalize()
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
	bedtime, homework := configuration.Blocking.RuleSets[0].Schedules[0], configuration.Blocking.RuleSets[0].Schedules[1]
	if bedtime.Name != "Bedtime" || !slices.Equal(bedtime.Days, []string{"sun", "mon", "thu"}) || bedtime.End != "07:00" ||
		bedtime.Block != ScheduleBlockEverything || homework.Block != ScheduleBlockApps || !slices.Equal(homework.Apps, []string{"roblox", "youtube"}) {
		t.Fatalf("normalized schedules = %+v", configuration.Blocking.RuleSets[0].Schedules)
	}
	if window, err := bedtime.Window(); err != nil || window.Days != [7]bool{time.Sunday: true, time.Monday: true, time.Thursday: true} || window.Location.String() != "America/New_York" {
		t.Fatalf("Window() = %+v, %v", window, err)
	}
	if start, end := bedtime.Minutes(); start != 21*60 || end != 7*60 {
		t.Fatalf("Minutes() = %d, %d", start, end)
	}
	cloned := cloneConfig(configuration)
	cloned.Blocking.RuleSets[0].Schedules[0].Days[0] = "changed"
	cloned.Blocking.RuleSets[0].Schedules[1].Apps[0] = "changed"
	if configuration.Blocking.RuleSets[0].Schedules[0].Days[0] != "sun" || configuration.Blocking.RuleSets[0].Schedules[1].Apps[0] != "roblox" {
		t.Fatal("Clone shared a schedule's days or apps")
	}

	for _, test := range []struct {
		change func(*Schedule)
		want   string
	}{
		{func(s *Schedule) { s.Name = "" }, "rule_sets[0].schedules[0].name is required"},
		{func(s *Schedule) { s.Name = "homework" }, `schedules[1].name "Homework" is already used by blocking.rule_sets[0].schedules[0]`},
		{func(s *Schedule) { s.Days = nil }, "schedules[0].days must name at least one day"},
		{func(s *Schedule) { s.Days = []string{"funday"} }, `schedules[0].days[0] "funday" must be one of`},
		{func(s *Schedule) { s.Start = "9pm" }, "schedules[0].start must be a time"},
		{func(s *Schedule) { s.End = "25:00" }, "schedules[0].end must be a time"},
		{func(s *Schedule) { s.End = "21:00" }, "schedules[0].end must differ from its start"},
		{func(s *Schedule) { s.TimeZone = "" }, "schedules[0].time_zone is required"},
		{func(s *Schedule) { s.TimeZone = "Mars/Olympus" }, `time_zone "Mars/Olympus" is not a time zone`},
		{func(s *Schedule) { s.TimeZone = "Local" }, `time_zone "Local" is not a time zone`},
		{func(s *Schedule) { s.Block = "some" }, `schedules[0].block must be "everything" or "apps"`},
		{func(s *Schedule) { s.Apps = []string{"youtube"} }, `schedules[0].apps only applies when block is "apps"`},
		{func(s *Schedule) { s.Block = ScheduleBlockApps }, "schedules[0].apps must name at least one app"},
		{func(s *Schedule) { s.Block, s.Apps = ScheduleBlockApps, []string{"myspace"} }, `schedules[0].apps[0] names no app called "myspace"`},
	} {
		candidate := cloneConfig(configuration)
		test.change(&candidate.Blocking.RuleSets[0].Schedules[0])
		if err := candidate.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("Validate() error = %v, want %q", err, test.want)
		}
	}
}

func TestSchedulesSurviveTOMLAndRuleSetSaves(t *testing.T) {
	t.Parallel()
	configuration, err := Decode(strings.NewReader(`
[[blocking.rule_sets]]
name = "Kids"
lists = []

[[blocking.rule_sets.schedules]]
name = "Bedtime"
days = ["sun", "mon"]
start = "21:00"
end = "07:00"
time_zone = "America/New_York"
block = "everything"
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []Schedule{{Name: "Bedtime", Days: []string{"sun", "mon"}, Start: "21:00", End: "07:00", TimeZone: "America/New_York", Block: ScheduleBlockEverything}}
	if got := configuration.Blocking.RuleSets[0].Schedules; !slices.EqualFunc(got, want, equalSchedules) {
		t.Fatalf("decoded schedules = %+v", got)
	}
	encoded, err := Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(strings.NewReader(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.Blocking.RuleSets[0].Schedules; !slices.EqualFunc(got, want, equalSchedules) {
		t.Fatalf("schedules after a round trip = %+v\n%s", got, encoded)
	}
	set := decoded.Blocking.RuleSets[0]
	set.Name = "Kids and Teens"
	if err := decoded.SaveRuleSet("Kids", set); err != nil {
		t.Fatal(err)
	}
	decoded.Blocking.RuleSets[0].Schedules[0].Days[0] = "changed"
	if set.Schedules[0].Days[0] != "sun" {
		t.Fatal("SaveRuleSet kept the caller's schedules instead of a copy")
	}
}

func equalSchedules(left, right Schedule) bool {
	return left.Name == right.Name && slices.Equal(left.Days, right.Days) && left.Start == right.Start && left.End == right.End &&
		left.TimeZone == right.TimeZone && left.Block == right.Block && slices.Equal(left.Apps, right.Apps)
}

func TestSaveAndDeleteSchedules(t *testing.T) {
	t.Parallel()
	configuration := Config{Blocking: Blocking{RuleSets: []RuleSet{{Name: "Kids"}}}}
	bedtime := Schedule{Name: "Bedtime", Days: []string{"mon"}, Start: "21:00", End: "07:00", TimeZone: "UTC", Block: ScheduleBlockEverything}
	if err := configuration.SaveSchedule("Kids", "", bedtime); err != nil {
		t.Fatal(err)
	}
	before := configuration.Blocking.RuleSets
	if err := configuration.SaveSchedule("Kids", "", Schedule{Name: " bedtime "}); err == nil || !strings.Contains(err.Error(), "already has a schedule") {
		t.Fatalf("SaveSchedule(duplicate) = %v", err)
	}
	renamed := bedtime
	renamed.Name, renamed.Days = "School nights", []string{"sun", "mon"}
	if err := configuration.SaveSchedule("Kids", "Bedtime", renamed); err != nil {
		t.Fatal(err)
	}
	if schedules := configuration.Blocking.RuleSets[0].Schedules; len(schedules) != 1 || schedules[0].Name != "School nights" || len(before[0].Schedules[0].Days) != 1 {
		t.Fatalf("schedules = %+v, before = %+v", schedules, before[0].Schedules)
	}
	for _, err := range []error{
		configuration.SaveSchedule("Guests", "", bedtime),
		configuration.SaveSchedule("Kids", "Bedtime", bedtime),
		configuration.DeleteSchedule("Kids", "Bedtime"),
		configuration.DeleteSchedule("Guests", "School nights"),
	} {
		if err == nil {
			t.Fatal("a change to a missing rule set or schedule went through")
		}
	}
	if err := configuration.DeleteSchedule("Kids", "School nights"); err != nil || configuration.Blocking.RuleSets[0].Schedules != nil {
		t.Fatalf("DeleteSchedule() = %v, schedules %+v", err, configuration.Blocking.RuleSets[0].Schedules)
	}
}

func TestSetScheduleOff(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 12, 22, 0, 0, 0, time.UTC)
	bedtime := Schedule{Name: "Bedtime", Days: []string{"mon"}, Start: "21:00", End: "07:00", TimeZone: "UTC", Block: ScheduleBlockEverything}
	stale := bedtime
	stale.Name, stale.OffUntil = "Homework", now.Add(-time.Hour)
	configuration := Config{Blocking: Blocking{RuleSets: []RuleSet{{Name: "Kids", Schedules: []Schedule{bedtime, stale}}}}}
	before := configuration.Blocking.RuleSets
	until := now.Add(9 * time.Hour)
	if err := configuration.SetScheduleOff("Kids", "Bedtime", until, now); err != nil {
		t.Fatal(err)
	}
	schedules := configuration.Blocking.RuleSets[0].Schedules
	if !schedules[0].OffUntil.Equal(until) || !schedules[1].OffUntil.IsZero() || !before[0].Schedules[1].OffUntil.Equal(stale.OffUntil) {
		t.Fatalf("schedules = %+v, before = %+v", schedules, before[0].Schedules)
	}
	if window, err := schedules[0].Window(); err != nil || !window.OffUntil.Equal(until) {
		t.Fatalf("Window() = %+v, %v", window, err)
	}
	if err := configuration.SetScheduleOff("Kids", "Bedtime", time.Time{}, now); err != nil || !configuration.Blocking.RuleSets[0].Schedules[0].OffUntil.IsZero() {
		t.Fatalf("SetScheduleOff(zero) = %v, schedules %+v", err, configuration.Blocking.RuleSets[0].Schedules)
	}
	for _, err := range []error{
		configuration.SetScheduleOff("Guests", "Bedtime", until, now),
		configuration.SetScheduleOff("Kids", "Nap", until, now),
	} {
		if err == nil {
			t.Fatal("a change to a missing rule set or schedule went through")
		}
	}
}
