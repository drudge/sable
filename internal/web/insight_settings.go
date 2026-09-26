package web

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/web/pages"
)

// insightAlertStatus says whether Insights alerts go anywhere: on when they
// are switched on and some destination takes them, paused when alerts are
// paused, and off otherwise.
func insightAlertStatus(settings config.Alerts, canOpenSettings bool) pages.InsightAlertStatusView {
	destinations := 0
	for _, destination := range settings.Destinations {
		if destination.Gets(config.AlertGroupInsights) {
			destinations++
		}
	}
	status := pages.InsightAlertStatusView{State: "on"}
	switch {
	case len(settings.Destinations) == 0:
		status.State, status.Detail = "off", "Nothing is set up to receive them yet."
	case !settings.Send.Insights:
		status.State, status.Detail = "off", "Insights alerts are turned off."
	case destinations == 0:
		status.State, status.Detail = "off", "None of the places alerts go takes Insights alerts."
	case settings.Paused:
		status.State, status.Detail = "paused", "Nothing is sent until alerts resume."
	default:
		status.Detail = fmt.Sprintf("Kinds set to Show and alert go to %d %s.", destinations, insights.Plural(destinations, "place", "places"))
	}
	if canOpenSettings {
		status.Link = "/settings?tab=alerts"
	}
	return status
}

// insightSettingsPageView is Insights settings for the page and its bell, or
// nil for an operator who may not read the query log.
func (server *Server) insightSettingsPageView(console pages.DashboardView) *pages.InsightSettingsView {
	if !console.CanLogs {
		return nil
	}
	view := server.insightSettingsView(console, server.config.Current().Config.Insights.Findings, nil, nil)
	return &view
}

// insightSettingsView lays Insights settings out. submitted holds what the
// operator typed, which a refused save shows back as typed, and invalid what
// is wrong with each setting, by its path.
func (server *Server) insightSettingsView(console pages.DashboardView, findings config.InsightFindings, submitted url.Values, invalid map[string]string) pages.InsightSettingsView {
	view := pages.InsightSettingsView{
		CanEdit: console.CanWriteSettings,
		Alerts:  insightAlertStatus(server.config.Current().Config.Alerts, console.CanSettings),
	}
	focused := false
	for _, group := range insightSettingGroups() {
		groupView := pages.InsightSettingGroupView{ID: group.id, Title: group.title}
		for _, kind := range group.kinds {
			kindView := pages.InsightKindSettingView{
				Key: kind.key, Title: kind.title, Description: kind.description, Icon: insightFindingIcon(kind.kind),
				Mode: *kind.mode(&findings), CanAlert: kind.note == "", Note: kind.note,
			}
			for _, limit := range kind.limits {
				name := kind.key + "." + limit.key
				limitView := pages.InsightLimitView{
					Name: name, Label: limit.label, Help: limit.help, Value: formatLimit(limit.get(findings)),
					Minimum: formatLimit(limit.minimum), Maximum: formatLimit(limit.maximum), Step: "any",
				}
				if limit.whole {
					limitView.Step = "1"
				}
				if typed, sent := submitted[name]; sent {
					limitView.Value = strings.TrimSpace(typed[0])
				}
				if problem, found := invalid[name]; found {
					limitView.Error = limit.label + " " + problem + "."
					limitView.Focus, focused = !focused, true
				}
				kindView.Limits = append(kindView.Limits, limitView)
			}
			groupView.Kinds = append(groupView.Kinds, kindView)
		}
		view.Groups = append(view.Groups, groupView)
	}
	return view
}

// formatLimit writes a limit the way its field shows it, without trailing
// zeros.
func formatLimit(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

// insightSettingsFromForm reads the settings a form sends over the saved
// ones. A setting the form leaves out keeps its saved value, and a limit that
// is not a number keeps it too and is reported by its path.
func insightSettingsFromForm(form url.Values, saved config.InsightFindings) (config.InsightFindings, map[string]string) {
	findings := saved
	invalid := make(map[string]string)
	for _, kind := range insightKindSettings() {
		if values, sent := form[kind.key+".mode"]; sent {
			*kind.mode(&findings) = strings.ToLower(strings.TrimSpace(values[0]))
		}
		for _, limit := range kind.limits {
			name := kind.key + "." + limit.key
			values, sent := form[name]
			if !sent {
				continue
			}
			value, err := strconv.ParseFloat(strings.ReplaceAll(strings.TrimSpace(values[0]), ",", ""), 64)
			switch {
			case err != nil || math.IsNaN(value) || math.IsInf(value, 0):
				invalid[name] = "must be a number"
			case limit.whole && value != math.Trunc(value):
				invalid[name] = "must be a whole number"
			case value < limit.minimum || value > limit.maximum:
				// Checked here as well as in the configuration, because a
				// number too large to hold would wrap around on the way.
				invalid[name] = "must be between " + formatRange(limit)
			default:
				limit.set(&findings, value)
			}
		}
	}
	return findings, invalid
}

// formatRange writes a limit's range the way the console writes counts.
func formatRange(limit insightLimitSetting) string {
	format := func(value float64) string {
		if value == math.Trunc(value) {
			return insights.FormatCount(uint64(value))
		}
		return formatLimit(value)
	}
	return format(limit.minimum) + " and " + format(limit.maximum)
}

// insightSettingChanges lists, for the audit log, every setting that differs
// between two sets of settings.
func insightSettingChanges(before, after config.InsightFindings) []string {
	var changes []string
	for _, kind := range insightKindSettings() {
		if was, now := *kind.mode(&before), *kind.mode(&after); was != now {
			changes = append(changes, kind.key+".mode "+now)
		}
		for _, limit := range kind.limits {
			if was, now := limit.get(before), limit.get(after); was != now {
				changes = append(changes, kind.key+"."+limit.key+" "+formatLimit(now)+" "+limit.unit)
			}
		}
	}
	return changes
}

// insightSettingsPanel shows Insights settings. Anyone who may read the query
// log may look at them.
func (server *Server) insightSettingsPanel(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanLogs {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	server.renderInsightSettings(writer, request, server.insightSettingsView(console, server.config.Current().Config.Insights.Findings, nil, nil))
}

// saveInsightSettings saves what the form sends, or shows it back with what
// needs fixing.
func (server *Server) saveInsightSettings(writer http.ResponseWriter, request *http.Request) {
	console, editor, ok := server.insightSettingsRequest(writer, request)
	if !ok {
		return
	}
	saved := server.config.Current().Config.Insights.Findings
	candidate, invalid := insightSettingsFromForm(request.PostForm, saved)
	for _, problem := range candidate.Problems() {
		if _, found := invalid[problem.Setting]; !found {
			invalid[problem.Setting] = problem.Problem
		}
	}
	if len(invalid) > 0 {
		view := server.insightSettingsView(console, candidate, request.PostForm, invalid)
		view.Error = insightSettingsProblem(invalid)
		writeFragmentStatus(writer, http.StatusUnprocessableEntity)
		server.renderInsightSettings(writer, request, view)
		return
	}
	var changes []string
	if err := editor.Update(request.Context(), func(configuration *config.Config) error {
		changes = insightSettingChanges(configuration.Insights.Findings, candidate)
		configuration.Insights.Findings = candidate
		return nil
	}); err != nil {
		server.logger.Warn("save insights settings", "client", requestClientIP(request), "error", err)
		view := server.insightSettingsView(console, candidate, request.PostForm, nil)
		view.Error = "Insights settings could not be saved: " + err.Error()
		writeFragmentStatus(writer, http.StatusUnprocessableEntity)
		server.renderInsightSettings(writer, request, view)
		return
	}
	summary := "saved Insights settings without changes"
	if len(changes) > 0 {
		summary = "changed Insights settings: " + strings.Join(changes, ", ")
	}
	server.recordControlPlaneAudit(request, "insights.settings", summary)
	server.insightSettingsSaved(writer, request, console, "Insights settings saved.")
}

// resetInsightSettings puts every kind of finding back to its default mode
// and limits.
func (server *Server) resetInsightSettings(writer http.ResponseWriter, request *http.Request) {
	console, editor, ok := server.insightSettingsRequest(writer, request)
	if !ok {
		return
	}
	if err := editor.Update(request.Context(), func(configuration *config.Config) error {
		configuration.Insights.Findings = config.DefaultInsightFindings()
		return nil
	}); err != nil {
		server.logger.Warn("reset insights settings", "client", requestClientIP(request), "error", err)
		view := server.insightSettingsView(console, server.config.Current().Config.Insights.Findings, nil, nil)
		view.Error = "Insights settings could not be reset: " + err.Error()
		writeFragmentStatus(writer, http.StatusUnprocessableEntity)
		server.renderInsightSettings(writer, request, view)
		return
	}
	server.recordControlPlaneAudit(request, "insights.settings", "reset Insights settings to their defaults")
	server.insightSettingsSaved(writer, request, console, "Insights settings are back to their defaults.")
}

// insightSettingsSaved shows the saved settings and has the page behind the
// dialog look again, since what it shows may have changed.
func (server *Server) insightSettingsSaved(writer http.ResponseWriter, request *http.Request, console pages.DashboardView, message string) {
	view := server.insightSettingsView(console, server.config.Current().Config.Insights.Findings, nil, nil)
	view.Message = message
	writer.Header().Set("HX-Trigger", "insightsChanged")
	server.renderInsightSettings(writer, request, view)
}

// insightSettingsRequest admits a change to Insights settings: the operator
// must be able to see them and to change settings.
func (server *Server) insightSettingsRequest(writer http.ResponseWriter, request *http.Request) (pages.DashboardView, settingsEditor, bool) {
	console := server.consoleView(request)
	if !console.CanLogs || !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return console, nil, false
	}
	editor, ok := server.config.(settingsEditor)
	if !ok {
		writeFragmentStatus(writer, http.StatusNotImplemented)
		view := server.insightSettingsView(console, server.config.Current().Config.Insights.Findings, nil, nil)
		view.Error = "Settings cannot be changed on this server."
		server.renderInsightSettings(writer, request, view)
		return console, nil, false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		writeFragmentStatus(writer, http.StatusBadRequest)
		return console, nil, false
	}
	return console, editor, true
}

// insightSettingsProblem sums up why a save was refused. A limit's field says
// what it needs itself, so a choice that cannot be saved is named here.
func insightSettingsProblem(invalid map[string]string) string {
	for _, kind := range insightKindSettings() {
		if problem, found := invalid[kind.key+".mode"]; found {
			return kind.title + " " + problem + "."
		}
	}
	if len(invalid) == 1 {
		return "One limit needs fixing before these settings can be saved."
	}
	return fmt.Sprintf("%d limits need fixing before these settings can be saved.", len(invalid))
}

func (server *Server) renderInsightSettings(writer http.ResponseWriter, request *http.Request, view pages.InsightSettingsView) {
	if err := pages.InsightSettings(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render insights settings", "error", err)
	}
}
