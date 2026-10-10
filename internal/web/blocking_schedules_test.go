package web

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web/pages"
)

func TestRuleSetPanelAddsEditsAndDeletesSchedules(t *testing.T) {
	t.Parallel()
	server, configuration := newRuleSetTestServer(t)
	schedules := func() []config.Schedule { return configuration.Current().Config.Blocking.RuleSets[0].Schedules }

	panel := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-set?name=Kids", nil).Body.String()
	if !strings.Contains(panel, "No schedules.") || !strings.Contains(panel, `hx-get="/ui/blocking/rule-sets/schedules/form?name=Kids"`) {
		t.Fatalf("panel has no way to add a schedule:\n%s", panel)
	}
	form := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-sets/schedules/form?name=Kids", nil)
	if form.Code != http.StatusOK || !strings.Contains(form.Body.String(), `name="day" value="sun" checked`) || strings.Contains(form.Body.String(), `name="day" value="sat" checked`) ||
		!strings.Contains(form.Body.String(), `value="21:00"`) || !strings.Contains(form.Body.String(), `value="tiktok"`) {
		t.Fatalf("new schedule form = %d %s", form.Code, form.Body.String())
	}

	bedtime := url.Values{"name": {"Kids"}, "schedule": {"Bedtime"}, "day": {"thu", "sun"}, "start": {"21:00"}, "end": {"07:00"}, "time_zone": {"America/New_York"}, "block": {"everything"}, "app": {"tiktok"}}
	saved := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/schedules", bedtime)
	if saved.Code != http.StatusOK || !strings.Contains(saved.Body.String(), "Kids has a Bedtime schedule") || !strings.Contains(saved.Body.String(), `data-rule-set-schedule="Bedtime"`) ||
		!strings.Contains(saved.Body.String(), "1 schedule") {
		t.Fatalf("add = %d %s", saved.Code, saved.Body.String())
	}
	if got := schedules(); len(got) != 1 || !slices.Equal(got[0].Days, []string{"sun", "thu"}) || got[0].Block != config.ScheduleBlockEverything || len(got[0].Apps) != 0 {
		t.Fatalf("schedules = %+v", got)
	}

	for _, test := range []struct {
		change func(url.Values)
		want   string
	}{
		{func(form url.Values) { form.Set("schedule", " ") }, "Give the schedule a name"},
		{func(form url.Values) { form.Del("day") }, "Pick at least one day"},
		{func(form url.Values) { form.Set("end", "21:00") }, "end at a different time"},
		{func(form url.Values) { form.Set("start", "") }, "Set when the schedule starts"},
		{func(form url.Values) { form.Set("time_zone", "Mars/Olympus") }, "know a time zone called Mars/Olympus"},
		{func(form url.Values) { form.Set("block", "apps"); form.Del("app") }, "Pick at least one app"},
		{func(form url.Values) { form.Set("schedule", "bedtime") }, "already has a schedule"},
	} {
		form := url.Values{}
		for key, values := range bedtime {
			form[key] = slices.Clone(values)
		}
		form.Set("schedule", "Homework")
		test.change(form)
		response := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/schedules", form)
		if response.Code != http.StatusUnprocessableEntity || response.Header().Get("HX-Retarget") != "#rule-set-schedule-notice" || !strings.Contains(response.Body.String(), test.want) {
			t.Errorf("%s: = %d %s %s", test.want, response.Code, response.Header().Get("HX-Retarget"), response.Body.String())
		}
	}

	edit := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-sets/schedules/form?name=Kids&schedule=Bedtime", nil).Body.String()
	if !strings.Contains(edit, `name="original" value="Bedtime"`) || !strings.Contains(edit, `name="day" value="thu" checked`) || !strings.Contains(edit, "Save Schedule") {
		t.Fatalf("edit form:\n%s", edit)
	}
	homework := url.Values{"name": {"Kids"}, "original": {"Bedtime"}, "schedule": {"Homework"}, "day": {"mon"}, "start": {"15:30"}, "end": {"17:30"}, "time_zone": {"UTC"}, "block": {"apps"}, "app": {"youtube", "tiktok"}}
	if response := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/schedules", homework); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Kids&#39;s Homework schedule saved") {
		t.Fatalf("edit = %d %s", response.Code, response.Body.String())
	}
	if got := schedules(); len(got) != 1 || got[0].Name != "Homework" || !slices.Equal(got[0].Apps, []string{"tiktok", "youtube"}) {
		t.Fatalf("schedules after the edit = %+v", got)
	}
	// Editing the rule set in its dialog keeps its schedules.
	if response := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/save", url.Values{"original": {"Kids"}, "name": {"Kids"}, "lists": {"Ads"}}); response.Code != http.StatusOK || len(schedules()) != 1 {
		t.Fatalf("save the dialog = %d, schedules %+v", response.Code, schedules())
	}

	deleted := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/schedules/delete", url.Values{"name": {"Kids"}, "schedule": {"Homework"}})
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), "Homework schedule deleted") || schedules() != nil {
		t.Fatalf("delete = %d %s, schedules %+v", deleted.Code, deleted.Body.String(), schedules())
	}
	if again := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/schedules/delete", url.Values{"name": {"Kids"}, "schedule": {"Homework"}}); again.Code != http.StatusNotFound {
		t.Fatalf("delete twice = %d %s", again.Code, again.Body.String())
	}
	if missing := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-sets/schedules/form?name=Kids&schedule=Nope", nil); missing.Code != http.StatusNotFound {
		t.Fatalf("form for an unknown schedule = %d", missing.Code)
	}
}

func TestScheduleWithBlockingOffBlocksEverything(t *testing.T) {
	t.Parallel()
	server, configuration := newRuleSetTestServer(t)
	if response := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/save", url.Values{"original": {"Kids"}, "name": {"Kids"}, "blocking": {"off"}}); response.Code != http.StatusOK {
		t.Fatalf("turn blocking off = %d", response.Code)
	}
	form := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-sets/schedules/form?name=Kids", nil).Body.String()
	if strings.Contains(form, `value="tiktok"`) || !strings.Contains(form, "so its schedules block everything") {
		t.Fatalf("form for a rule set with blocking off offers apps:\n%s", form)
	}
	saved := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/schedules", url.Values{
		"name": {"Kids"}, "schedule": {"Lights out"}, "day": {"fri"}, "start": {"22:00"}, "end": {"06:00"}, "time_zone": {"UTC"}, "block": {"apps"}, "app": {"tiktok"},
	})
	if got := configuration.Current().Config.Blocking.RuleSets[0].Schedules; saved.Code != http.StatusOK || len(got) != 1 || got[0].Block != config.ScheduleBlockEverything || len(got[0].Apps) != 0 {
		t.Fatalf("save = %d, schedules %+v", saved.Code, got)
	}
	if !strings.Contains(saved.Body.String(), "Blocking off · 1 schedule") || !strings.Contains(saved.Body.String(), `data-rule-set-schedule="Lights out"`) {
		t.Fatalf("panel and tab after saving:\n%s", saved.Body.String())
	}
}

func TestRuleSetSchedulesDescribeThemselves(t *testing.T) {
	t.Parallel()
	newYork, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	set := config.RuleSet{Schedules: []config.Schedule{
		{Name: "Bedtime", Days: []string{"sun", "mon", "tue", "wed", "thu"}, Start: "21:00", End: "07:00", TimeZone: "America/New_York", Block: config.ScheduleBlockEverything},
		{Name: "Homework", Days: []string{"mon", "wed", "fri"}, Start: "15:30", End: "17:30", TimeZone: "America/Chicago", Block: config.ScheduleBlockApps, Apps: []string{"youtube", "tiktok"}},
	}}
	eastern := pages.TimeDisplay{Format: pages.TimeFormat12, Location: newYork}
	// Monday, October 12, 2026 at 10 PM in New York.
	monday := time.Date(2026, time.October, 12, 22, 0, 0, 0, newYork)
	views := ruleSetSchedules(set, eastern, monday)
	if got := views[0]; got.When != "Sun to Thu, 9:00 PM to 7:00 AM" || got.Blocks != "Everything" || !got.On || got.Next != "Ends Tue 7:00 AM" {
		t.Errorf("Bedtime = %+v", got)
	}
	if got := views[1]; got.When != "Mon, Wed, Fri, 3:30 PM to 5:30 PM CDT" || got.Blocks != "TikTok, YouTube" || got.On || got.Next != "Starts Wed 3:30 PM CDT" {
		t.Errorf("Homework = %+v", got)
	}
	if got := ruleSetSchedules(set, pages.TimeDisplay{Format: pages.TimeFormat24, Location: newYork}, monday.Add(-3*time.Hour))[0]; got.When != "Sun to Thu, 21:00 to 07:00" || got.Next != "Starts 21:00" {
		t.Errorf("Bedtime in 24-hour time = %+v", got)
	}

	for _, test := range []struct {
		days []string
		want string
	}{
		{[]string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}, "Every day"},
		{[]string{"mon", "tue", "wed", "thu", "fri"}, "Weekdays"},
		{[]string{"sun", "sat"}, "Weekends"},
		{[]string{"fri", "sat", "sun", "mon"}, "Fri to Mon"},
		{[]string{"mon", "tue"}, "Mon, Tue"},
		{[]string{"tue"}, "Tue"},
	} {
		window, err := config.Schedule{Days: test.days, TimeZone: "UTC"}.Window()
		if err != nil {
			t.Fatal(err)
		}
		if got := scheduleDays(window.Days); got != test.want {
			t.Errorf("scheduleDays(%v) = %q, want %q", test.days, got, test.want)
		}
	}
}
