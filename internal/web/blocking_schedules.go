package web

import (
	"cmp"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights/services"
	"github.com/drudge/sable/internal/web/pages"
)

// scheduleDayLabels name a schedule's days, Sunday first, as the form and
// its summary show them.
var scheduleDayLabels = []pages.ScheduleDay{
	{Value: "sun", Label: "Sun", Name: "Sunday"}, {Value: "mon", Label: "Mon", Name: "Monday"}, {Value: "tue", Label: "Tue", Name: "Tuesday"}, {Value: "wed", Label: "Wed", Name: "Wednesday"},
	{Value: "thu", Label: "Thu", Name: "Thursday"}, {Value: "fri", Label: "Fri", Name: "Friday"}, {Value: "sat", Label: "Sat", Name: "Saturday"},
}

// ruleSetSchedules describes a rule set's schedules for its panel: when each
// one runs, what it blocks, and whether it is on at now. Times read in the
// schedule's own zone, which is named when it isn't the viewer's.
func ruleSetSchedules(set config.RuleSet, display pages.TimeDisplay, now time.Time) []pages.RuleSetSchedule {
	views := make([]pages.RuleSetSchedule, 0, len(set.Schedules))
	for _, schedule := range set.Schedules {
		view := pages.RuleSetSchedule{Name: schedule.Name, Everything: schedule.Block == config.ScheduleBlockEverything, Blocks: scheduleBlocks(schedule)}
		window, err := schedule.Window()
		if err != nil {
			view.When = strings.Join(schedule.Days, ", ")
			views = append(views, view)
			continue
		}
		on, _, until := window.At(now)
		start, _ := window.Next(now)
		zone := ""
		if window.Location.String() != display.Zone() {
			zone = " " + cmp.Or(start, until).In(window.Location).Format("MST")
		}
		view.When = scheduleDays(window.Days) + ", " + scheduleClock(window.Start, display) + " to " + scheduleClock(window.End, display) + zone
		view.On, view.Paused = on, now.Before(schedule.OffUntil)
		switch {
		case on:
			view.Next = "Ends " + scheduleMoment(until.In(window.Location), now.In(window.Location), display) + zone
		case !start.IsZero():
			view.Next = "Starts " + scheduleMoment(start.In(window.Location), now.In(window.Location), display) + zone
		}
		view.Overrides = scheduleOverrides(on, view.Paused, start, now)
		views = append(views, view)
	}
	return views
}

// scheduleDays names a schedule's days the short way where there is one:
// every day, weekdays, weekends, a run such as "Sun to Thu", or a list.
func scheduleDays(days [7]bool) string {
	count := 0
	for _, on := range days {
		if on {
			count++
		}
	}
	switch {
	case count == 7:
		return "Every day"
	case days == [7]bool{false, true, true, true, true, true, false}:
		return "Weekdays"
	case days == [7]bool{true, false, false, false, false, false, true}:
		return "Weekends"
	}
	// A run of three or more days in a row, which may wrap past Saturday,
	// reads as its first and last day.
	for first := range 7 {
		if !days[first] || days[(first+6)%7] {
			continue
		}
		length := 0
		for length < 7 && days[(first+length)%7] {
			length++
		}
		if length == count && count >= 3 {
			return scheduleDayLabels[first].Label + " to " + scheduleDayLabels[(first+length-1)%7].Label
		}
	}
	labels := make([]string, 0, count)
	for index, on := range days {
		if on {
			labels = append(labels, scheduleDayLabels[index].Label)
		}
	}
	return strings.Join(labels, ", ")
}

// scheduleClock writes minutes past midnight in the viewer's 12 or 24-hour
// format.
func scheduleClock(minutes int, display pages.TimeDisplay) string {
	clock := time.Date(2000, time.January, 1, minutes/60, minutes%60, 0, 0, time.UTC)
	if display.TwentyFourHour() {
		return clock.Format("15:04")
	}
	return clock.Format("3:04 PM")
}

// scheduleMoment writes when a schedule next starts or ends, with the day
// when it isn't today.
func scheduleMoment(at, now time.Time, display pages.TimeDisplay) string {
	clock := scheduleClock(at.Hour()*60+at.Minute(), display)
	switch {
	case at.Year() == now.Year() && at.YearDay() == now.YearDay():
		return clock
	case at.Sub(now) < 7*24*time.Hour:
		return at.Format("Mon") + " " + clock
	default:
		return at.Format("Jan 2") + " " + clock
	}
}

// scheduleOverrideNotice is how soon a schedule has to start for its row to
// offer Skip and Delay 30 Minutes.
const scheduleOverrideNotice = 24 * time.Hour

// scheduleOverrides are the changes a schedule's row offers: Delay 30
// Minutes and End Now while it is on, Skip and Delay 30 Minutes when it
// starts within a day, and Resume once one of those has it off.
func scheduleOverrides(on, paused bool, start, now time.Time) []pages.ScheduleOverride {
	delay := pages.ScheduleOverride{Action: scheduleDelay, Label: "Delay 30 Minutes", Icon: "timer"}
	switch {
	case on:
		return []pages.ScheduleOverride{delay, {Action: scheduleEnd, Label: "End Now", Icon: "x"}}
	case paused:
		return []pages.ScheduleOverride{{Action: scheduleResume, Label: "Resume", Icon: "rotate-ccw"}}
	case !start.IsZero() && start.Sub(now) <= scheduleOverrideNotice:
		return []pages.ScheduleOverride{{Action: scheduleSkip, Label: "Skip", Icon: "chevrons-right"}, delay}
	}
	return nil
}

// scheduleBlocks says what a schedule blocks: everything, or its apps by
// name.
func scheduleBlocks(schedule config.Schedule) string {
	if schedule.Block == config.ScheduleBlockEverything {
		return "Everything"
	}
	names := make([]string, 0, len(schedule.Apps))
	for _, id := range schedule.Apps {
		service, _ := services.Find(id)
		names = append(names, cmp.Or(service.Name, id))
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// ruleSetScheduleForm swaps a rule set's panel for the schedule form: a new
// schedule, or the one named.
func (server *Server) ruleSetScheduleForm(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	query := request.URL.Query()
	name, original := query.Get("name"), query.Get("schedule")
	set, found := server.ruleSet(name)
	if !found {
		server.renderRuleSetChange(writer, request, name, "", refuse(http.StatusNotFound, "There is no rule set called %s.", name))
		return
	}
	schedule := config.Schedule{Days: []string{"sun", "mon", "tue", "wed", "thu"}, Start: "21:00", End: "07:00", TimeZone: browserTimeZone(request), Block: config.ScheduleBlockEverything}
	if original != "" {
		index := slices.IndexFunc(set.Schedules, func(existing config.Schedule) bool { return existing.Name == original })
		if index < 0 {
			server.renderRuleSetChange(writer, request, name, "", refuse(http.StatusNotFound, "%s has no schedule called %s. It may have been deleted.", name, original))
			return
		}
		schedule = set.Schedules[index]
	}
	server.render(writer, request, pages.RuleSetScheduleForm(ruleSetScheduleFormView(set, original, schedule)))
}

// browserTimeZone is the viewer's time zone, for a new schedule, or UTC when
// the browser hasn't said.
func browserTimeZone(request *http.Request) string {
	if zone := requestTimeLocation(request).String(); zone != "Local" {
		return zone
	}
	return "UTC"
}

func ruleSetScheduleFormView(set config.RuleSet, original string, schedule config.Schedule) pages.RuleSetScheduleFormView {
	view := pages.RuleSetScheduleFormView{
		Set: set.Name, Off: set.Off, Original: original, Name: schedule.Name, Start: schedule.Start, End: schedule.End,
		TimeZone: schedule.TimeZone, Apps: schedule.Block == config.ScheduleBlockApps, Days: slices.Clone(scheduleDayLabels),
	}
	for index := range view.Days {
		view.Days[index].Chosen = slices.Contains(schedule.Days, view.Days[index].Value)
	}
	if !set.Off {
		view.Groups = ruleSetAppGroups(schedule.Apps)
	}
	return view
}

// saveRuleSetSchedule adds a schedule to a rule set, or saves the one it
// edits, then shows the rule set's panel again. A problem shows above the
// form, leaving what was typed alone.
func (server *Server) saveRuleSetSchedule(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		server.renderFormProblem(writer, request, "#rule-set-schedule-notice", refuse(http.StatusBadRequest, "Sable could not read the form."))
		return
	}
	name, original := request.FormValue("name"), request.FormValue("original")
	schedule := config.Schedule{
		Name: strings.TrimSpace(request.FormValue("schedule")), Days: request.Form["day"],
		Start: request.FormValue("start"), End: request.FormValue("end"), TimeZone: strings.TrimSpace(request.FormValue("time_zone")),
		Block: cmp.Or(request.FormValue("block"), config.ScheduleBlockEverything),
	}
	// A rule set with blocking off has no apps to block, so its schedules
	// block everything.
	if set, found := server.ruleSet(name); found && set.Off {
		schedule.Block = config.ScheduleBlockEverything
	}
	if schedule.Block == config.ScheduleBlockApps {
		schedule.Apps = request.Form["app"]
	}
	if err := scheduleProblem(schedule); err != nil {
		server.renderFormProblem(writer, request, "#rule-set-schedule-notice", err)
		return
	}
	message, err := server.ruleSetService().SaveSchedule(request.Context(), requestActor(request, ""), name, original, schedule)
	if err != nil {
		server.renderFormProblem(writer, request, "#rule-set-schedule-notice", err)
		return
	}
	server.renderRuleSetChange(writer, request, name, message, nil)
}

// scheduleProblem says what a schedule from the form is missing, in the
// form's words, before the config's own checks see it.
func scheduleProblem(schedule config.Schedule) error {
	start, end := schedule.Minutes()
	switch {
	case schedule.Name == "":
		return refuse(http.StatusUnprocessableEntity, "Give the schedule a name, such as Bedtime.")
	case len(schedule.Days) == 0:
		return refuse(http.StatusUnprocessableEntity, "Pick at least one day.")
	case start < 0 || end < 0:
		return refuse(http.StatusUnprocessableEntity, "Set when the schedule starts and ends.")
	case start == end:
		return refuse(http.StatusUnprocessableEntity, "The schedule has to end at a different time than it starts.")
	case schedule.TimeZone == "":
		return refuse(http.StatusUnprocessableEntity, "Pick a time zone, such as America/New_York.")
	case !validZoneName(schedule.TimeZone):
		return refuse(http.StatusUnprocessableEntity, "Sable doesn't know a time zone called %s.", schedule.TimeZone)
	case schedule.Block == config.ScheduleBlockApps && len(schedule.Apps) == 0:
		return refuse(http.StatusUnprocessableEntity, "Pick at least one app to block.")
	}
	if _, err := time.LoadLocation(schedule.TimeZone); err != nil {
		return refuse(http.StatusUnprocessableEntity, "Sable doesn't know a time zone called %s.", schedule.TimeZone)
	}
	return nil
}

// deleteRuleSetSchedule removes one of a rule set's schedules.
func (server *Server) deleteRuleSetSchedule(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		server.renderRuleSetChange(writer, request, "", "", refuse(http.StatusBadRequest, "Sable could not read the form."))
		return
	}
	name := request.FormValue("name")
	message, err := server.ruleSetService().DeleteSchedule(request.Context(), requestActor(request, ""), name, request.FormValue("schedule"))
	server.renderRuleSetChange(writer, request, name, message, err)
}

// What a schedule's row can do to it.
const (
	scheduleSkip   = "skip"
	scheduleDelay  = "delay"
	scheduleEnd    = "end"
	scheduleResume = "resume"
)

// scheduleDelayStep is how much Delay 30 Minutes moves a schedule.
const scheduleDelayStep = 30 * time.Minute

// overrideRuleSetSchedule skips, delays, ends or resumes one of a rule
// set's schedules, then shows the rule set's panel again.
func (server *Server) overrideRuleSetSchedule(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		server.renderRuleSetChange(writer, request, "", "", refuse(http.StatusBadRequest, "Sable could not read the form."))
		return
	}
	name, scheduleName, action := request.FormValue("name"), request.FormValue("schedule"), request.FormValue("action")
	until, err := server.scheduleOffUntil(name, scheduleName, action, time.Now())
	message := ""
	if err == nil {
		message, err = server.ruleSetService().SetScheduleOff(request.Context(), requestActor(request, ""), name, scheduleName, action, until)
	}
	server.renderRuleSetChange(writer, request, name, message, err)
}

// scheduleOffUntil works out how long action keeps a schedule off: to the
// end of the window it is in or starts next for Skip and End Now, 30 minutes
// past now or the next start for Delay, and no longer for Resume.
func (server *Server) scheduleOffUntil(name, scheduleName, action string, now time.Time) (time.Time, error) {
	set, found := server.ruleSet(name)
	if !found {
		return time.Time{}, refuse(http.StatusNotFound, "There is no rule set called %s.", name)
	}
	index := slices.IndexFunc(set.Schedules, func(existing config.Schedule) bool { return existing.Name == scheduleName })
	if index < 0 {
		return time.Time{}, refuse(http.StatusNotFound, "%s has no schedule called %s. It may have been deleted.", name, scheduleName)
	}
	window, err := set.Schedules[index].Window()
	if err != nil {
		return time.Time{}, refuse(http.StatusConflict, "%s's %s schedule has a time zone Sable doesn't know.", name, scheduleName)
	}
	on, _, _ := window.At(now)
	start, end := window.Next(now)
	if start.IsZero() && action != scheduleResume {
		return time.Time{}, refuse(http.StatusConflict, "%s's %s schedule has no days to skip or delay.", name, scheduleName)
	}
	switch action {
	case scheduleSkip, scheduleEnd:
		return end, nil
	case scheduleDelay:
		if on {
			return now.Add(scheduleDelayStep), nil
		}
		return start.Add(scheduleDelayStep), nil
	case scheduleResume:
		return time.Time{}, nil
	default:
		return time.Time{}, refuse(http.StatusBadRequest, "Sable doesn't know how to %s a schedule.", action)
	}
}
