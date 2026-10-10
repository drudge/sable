package app

import (
	"slices"
	"testing"
	"time"

	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
)

func TestRuntimeRuleSetsJoinTheirDevices(t *testing.T) {
	t.Parallel()
	configuration := config.Defaults()
	configuration.Blocking.RuleSets = []config.RuleSet{{Name: "Kids", Lists: []string{"Strict"}}, {Name: "Work"}}
	configuration.Clients = []config.Client{
		{Name: "Emma's iPad", MAC: "da:a1:19:00:00:01", RuleSet: "Kids"},
		{Name: "Leo's Switch", Address: "192.0.2.20", RuleSet: "Kids"},
		{Name: "Guest Wi-Fi", Address: "10.20.40.0/24", RuleSet: "Kids"},
		{Name: "Printer", Address: "192.0.2.9"},
	}
	sets := runtimeRuleSets(configuration)
	if len(sets) != 2 || sets[0].Name != "Kids" || !slices.Equal(sets[0].Clients, []string{"da:a1:19:00:00:01", "192.0.2.20", "10.20.40.0/24"}) {
		t.Fatalf("runtime rule sets = %+v", sets)
	}
	if !slices.Equal(sets[0].Lists, []string{"Strict", blockcompiler.CustomSourceName}) ||
		!slices.Equal(sets[1].Lists, []string{blockcompiler.CustomSourceName}) || sets[1].Clients != nil {
		t.Fatalf("rule set lists = %v and %v, want the operator's domains in each", sets[0].Lists, sets[1].Lists)
	}
	configuration.Blocking.RuleSets[0].Domains, configuration.Blocking.RuleSets[0].Apps = []string{"games.example"}, []string{"tiktok"}
	domains := runtimeRuleSets(configuration)[0].Domains
	if !slices.Contains(domains, "games.example") || !slices.Contains(domains, "tiktok.com") || !slices.Contains(domains, "tiktokcdn.com") {
		t.Fatalf("Kids blocks %v, want its own domain and every TikTok domain", domains)
	}
	if !slices.Equal(configuration.Blocking.RuleSets[0].Domains, []string{"games.example"}) {
		t.Fatalf("runtimeRuleSets changed the config's domains to %v", configuration.Blocking.RuleSets[0].Domains)
	}
	until := time.Date(2026, 10, 8, 20, 0, 0, 0, time.UTC)
	holds := runtimeHolds([]config.Hold{{MAC: "da:a1:19:00:00:01", Until: until}, {Address: "192.0.2.20"}})
	if len(holds) != 2 || holds[0] != (dnsserver.HoldPolicy{Client: "da:a1:19:00:00:01", Until: until}) || holds[1] != (dnsserver.HoldPolicy{Client: "192.0.2.20"}) {
		t.Fatalf("runtimeHolds() = %+v", holds)
	}
	if got := defaultLists(nil); got != nil {
		t.Fatalf("defaultLists(nil) = %v, want every list", got)
	}
	if got := defaultLists([]string{"Ads"}); !slices.Equal(got, []string{"Ads", blockcompiler.CustomSourceName}) {
		t.Fatalf("defaultLists(Ads) = %v", got)
	}
}

func TestRuntimeSchedulesReadTheirTimes(t *testing.T) {
	t.Parallel()
	schedules := runtimeSchedules([]config.Schedule{
		{Name: "Bedtime", Days: []string{"sun", "thu"}, Start: "21:00", End: "07:00", TimeZone: "America/New_York", Block: config.ScheduleBlockEverything},
		{Name: "Homework", Days: []string{"mon"}, Start: "15:30", End: "17:30", TimeZone: "UTC", Block: config.ScheduleBlockApps, Apps: []string{"tiktok"}},
	})
	if len(schedules) != 2 {
		t.Fatalf("runtimeSchedules() = %+v", schedules)
	}
	bedtime, homework := schedules[0], schedules[1]
	if bedtime.Name != "Bedtime" || !slices.Equal(bedtime.Days, []time.Weekday{time.Sunday, time.Thursday}) || bedtime.Start != 21*60 || bedtime.End != 7*60 ||
		bedtime.Location.String() != "America/New_York" || !bedtime.Everything || bedtime.Domains != nil {
		t.Fatalf("Bedtime = %+v", bedtime)
	}
	if homework.Everything || homework.Start != 15*60+30 || !slices.Contains(homework.Domains, "tiktok.com") {
		t.Fatalf("Homework = %+v", homework)
	}
	if got := runtimeSchedules(nil); got != nil {
		t.Fatalf("runtimeSchedules(nil) = %+v, want nil", got)
	}
}
