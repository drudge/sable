package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/weekly"
)

var mcpScheduleTools = []mcpTool{
	{
		Name:  "list_schedules",
		Title: "List rule set schedules",
		Description: "List each rule set's schedules: the days and times each one blocks everything or some apps for " +
			"the rule set's devices, whether it is on now, and when it next starts or ends. paused_until says a " +
			"schedule was skipped, delayed, or ended early and stays off until then.",
		InputSchema: mcpObjectSchema(map[string]any{
			"rule_set": mcpString("Optional rule set name, to list only its schedules."),
		}, nil),
		Annotations: mcpToolAnnotations{Title: "List rule set schedules", ReadOnlyHint: true, IdempotentHint: true},
		call:        (*Server).mcpListSchedules,
		section:     "blocking",
		grant:       "blocking.read",
	},
	{
		Name:  "override_schedule",
		Title: "Skip, delay, end, or resume a schedule",
		Description: "Change one rule set schedule for its current or next window only, the way the console's " +
			"buttons do. skip keeps the next window (or the current one) from blocking, delay moves its start 30 " +
			"minutes later (or gives 30 more minutes when it is on), end turns it off until the window would have " +
			"ended, and resume undoes any of those. The schedule's days and times stay as they are.",
		InputSchema: mcpObjectSchema(map[string]any{
			"rule_set": mcpString("The rule set the schedule belongs to, as list_schedules shows it."),
			"schedule": mcpString("The schedule's name, for example Bedtime."),
			"action": map[string]any{
				"type": "string", "enum": []string{scheduleSkip, scheduleDelay, scheduleEnd, scheduleResume},
				"description": "What to do: skip, delay, end, or resume.",
			},
		}, []string{"rule_set", "schedule", "action"}),
		Annotations: mcpToolAnnotations{Title: "Skip, delay, end, or resume a schedule", DestructiveHint: true},
		call:        (*Server).mcpOverrideSchedule,
		section:     "blocking",
		grant:       "blocking.write",
	},
}

type mcpSchedule struct {
	RuleSet  string     `json:"rule_set"`
	Name     string     `json:"name"`
	Days     []string   `json:"days"`
	Start    string     `json:"start"`
	End      string     `json:"end"`
	TimeZone string     `json:"time_zone"`
	Block    string     `json:"block"`
	Apps     []string   `json:"apps,omitempty"`
	On       bool       `json:"on"`
	Paused   *time.Time `json:"paused_until,omitempty"`
	Starts   *time.Time `json:"next_start,omitempty"`
	Ends     *time.Time `json:"ends,omitempty"`
}

func (server *Server) mcpListSchedules(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		RuleSet string `json:"rule_set"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	sets := server.config.Current().Config.Blocking.RuleSets
	if input.RuleSet != "" {
		set, found := server.ruleSet(input.RuleSet)
		if !found {
			return nil, refuse(http.StatusNotFound, "There is no rule set called %s.", input.RuleSet)
		}
		sets = []config.RuleSet{set}
	}
	now := time.Now()
	schedules := []mcpSchedule{}
	for _, set := range sets {
		for _, schedule := range set.Schedules {
			schedules = append(schedules, mcpScheduleAt(set.Name, schedule, now))
		}
	}
	return map[string]any{"schedules": schedules}, nil
}

// mcpScheduleAt describes a schedule at now, with its times in its own zone.
func mcpScheduleAt(ruleSet string, schedule config.Schedule, now time.Time) mcpSchedule {
	view := mcpSchedule{
		RuleSet: ruleSet, Name: schedule.Name, Days: schedule.Days, Start: schedule.Start, End: schedule.End,
		TimeZone: schedule.TimeZone, Block: schedule.Block, Apps: schedule.Apps,
	}
	window, err := schedule.Window()
	if err != nil {
		return view
	}
	if now.Before(schedule.OffUntil) {
		view.Paused = scheduleTime(schedule.OffUntil, window)
	}
	on, _, until := window.At(now)
	start, end := window.Next(now)
	view.On = on
	if on {
		view.Ends = scheduleTime(until, window)
	} else if !start.IsZero() {
		view.Starts, view.Ends = scheduleTime(start, window), scheduleTime(end, window)
	}
	return view
}

// scheduleTime is a moment in the schedule's own time zone, the way its
// start and end are written.
func scheduleTime(at time.Time, window weekly.Window) *time.Time {
	at = at.In(window.Location)
	return &at
}

func (server *Server) mcpOverrideSchedule(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		RuleSet  string `json:"rule_set"`
		Schedule string `json:"schedule"`
		Action   string `json:"action"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	now := time.Now()
	message, err := server.ruleSetService().OverrideSchedule(request.Context(), requestActor(request, "mcp"), input.RuleSet, input.Schedule, input.Action, now)
	if err != nil {
		return nil, err
	}
	set, _ := server.ruleSet(input.RuleSet)
	for _, schedule := range set.Schedules {
		if schedule.Name == input.Schedule {
			return map[string]any{"message": message, "schedule": mcpScheduleAt(set.Name, schedule, now)}, nil
		}
	}
	return map[string]any{"message": message}, nil
}
