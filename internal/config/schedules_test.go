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
	if days := bedtime.Weekdays(); !slices.Equal(days, []time.Weekday{time.Sunday, time.Monday, time.Thursday}) {
		t.Fatalf("Weekdays() = %v", days)
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
