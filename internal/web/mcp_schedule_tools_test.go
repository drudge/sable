package web

import (
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

// An assistant can see when a rule set's schedules run and skip, delay, end
// or resume one, the way the console's row buttons do.
func TestMCPScheduleTools(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	addMCPTools(configuration, "override_schedule")
	now := time.Now().UTC()
	start, end := now.Add(-time.Hour).Truncate(time.Minute), now.Add(2*time.Hour).Truncate(time.Minute)
	configuration.snapshot.Config.Blocking.RuleSets = []config.RuleSet{
		{Name: "Kids", Schedules: []config.Schedule{{
			Name: "Bedtime", Days: []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"},
			Start: start.Format("15:04"), End: end.Format("15:04"), TimeZone: "UTC", Block: config.ScheduleBlockEverything,
		}}},
		{Name: "Work"},
	}
	call := func(token, tool string, arguments map[string]any) (map[string]any, string) {
		t.Helper()
		return callMCPToolForTest(t, server, token, tool, arguments)
	}
	first := func(result map[string]any) map[string]any {
		t.Helper()
		schedules, _ := result["schedules"].([]any)
		if len(schedules) != 1 {
			t.Fatalf("schedules = %v", result)
		}
		return schedules[0].(map[string]any)
	}

	listed, failure := call("sable_pat_blocking", "list_schedules", map[string]any{})
	if failure != "" {
		t.Fatalf("list_schedules failed: %s", failure)
	}
	if schedule := first(listed); schedule["rule_set"] != "Kids" || schedule["name"] != "Bedtime" || schedule["on"] != true ||
		schedule["ends"] != end.Format(time.RFC3339) || schedule["paused_until"] != nil {
		t.Fatalf("list_schedules = %v", schedule)
	}
	if listed, failure = call("sable_pat_blocking", "list_schedules", map[string]any{"rule_set": "Work"}); failure != "" || len(listed["schedules"].([]any)) != 0 {
		t.Fatalf("Work's schedules = %v %q", listed, failure)
	}
	if _, failure = call("sable_pat_blocking", "list_schedules", map[string]any{"rule_set": "Teens"}); !strings.Contains(failure, "no rule set called Teens") {
		t.Fatalf("an unknown rule set = %q", failure)
	}

	ended, failure := call("sable_pat_blocking", "override_schedule", map[string]any{"rule_set": "Kids", "schedule": "Bedtime", "action": "end"})
	if failure != "" || ended["message"] != "Kids's Bedtime schedule ended early" {
		t.Fatalf("end = %v %q", ended, failure)
	}
	if schedule := ended["schedule"].(map[string]any); schedule["on"] != false || schedule["paused_until"] != end.Format(time.RFC3339) ||
		schedule["next_start"] != start.Add(24*time.Hour).Format(time.RFC3339) {
		t.Fatalf("ended schedule = %v", schedule)
	}
	if resumed, failure := call("sable_pat_blocking", "override_schedule", map[string]any{"rule_set": "Kids", "schedule": "Bedtime", "action": "resume"}); failure != "" ||
		resumed["schedule"].(map[string]any)["on"] != true || !configuration.snapshot.Config.Blocking.RuleSets[0].Schedules[0].OffUntil.IsZero() {
		t.Fatalf("resume = %v %q", resumed, failure)
	}

	if _, failure := call("sable_pat_blocking", "override_schedule", map[string]any{"rule_set": "Kids", "schedule": "Nap", "action": "skip"}); !strings.Contains(failure, "no schedule called Nap") {
		t.Fatalf("an unknown schedule = %q", failure)
	}
	if _, failure := call("sable_pat_reader", "override_schedule", map[string]any{"rule_set": "Kids", "schedule": "Bedtime", "action": "skip"}); !strings.Contains(failure, "blocking.write") {
		t.Fatalf("reader override = %q", failure)
	}
}
