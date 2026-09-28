package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/web/pages"
)

// errInsightsOff is what a request for Insights gets while it is turned off.
var errInsightsOff = errors.New("this server has Insights turned off; turn it on in Settings > General")

// insightDataStore is the store's hold on what Insights collected.
type insightDataStore interface {
	InsightDataSummary(context.Context) (store.InsightData, error)
	DeleteInsightData(context.Context, time.Time) error
}

func (server *Server) insightsEnabled() bool {
	return server.config.Current().Config.Insights.Enabled
}

// whileInsightsOn serves an Insights route only while Insights is on. The
// page itself, and a link to a finding, device, or app on it, says Insights is
// off and where to turn it on; anything else, such as a panel a stale page
// asks for, is simply not there.
func (server *Server) whileInsightsOn(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if server.insightsEnabled() {
			next(writer, request)
			return
		}
		if strings.HasPrefix(request.URL.Path, "/ui/") {
			http.Error(writer, errInsightsOff.Error(), http.StatusNotFound)
			return
		}
		console := server.consoleView(request)
		if !console.CanBlocking && !console.CanLogs {
			server.authenticationFailure(writer, request, http.StatusForbidden, "")
			return
		}
		if err := pages.InsightsOffPage(console).Render(request.Context(), writer); err != nil {
			server.logger.Error("render insights off page", "error", err)
		}
	}
}

// settingsInsightsView lays out the Insights switch and what Insights holds.
func (server *Server) settingsInsightsView(ctx context.Context, console pages.DashboardView, message, errorMessage string) pages.SettingsInsightsView {
	view := pages.SettingsInsightsView{
		Enabled: server.insightsEnabled(),
		CanEdit: console.CanWriteSettings,
		Message: message, Error: errorMessage,
	}
	if data, ok := server.queries.(insightDataStore); ok {
		summary, err := data.InsightDataSummary(ctx)
		if err != nil {
			server.logger.Warn("count Insights data", "error", err)
		}
		view.Data = insightDataSummary(summary, console.TimeDisplay)
	} else {
		view.CanEdit = false
	}
	return view
}

// insightDataSummary says what Insights holds in a line, or nothing when it
// holds nothing. UniFi names gear that never queries Sable, so there can be
// more hardware addresses than client addresses.
func insightDataSummary(summary store.InsightData, display pages.TimeDisplay) string {
	if summary.Addresses == 0 && summary.Hardware == 0 {
		return ""
	}
	counted := func(count int, one, many string) string {
		return fmt.Sprintf("%d %s", count, ifThenString(count == 1, one, many))
	}
	text := counted(summary.Addresses, "address", "addresses") + " and " +
		counted(summary.Hardware, "hardware address", "hardware addresses")
	if !summary.Since.IsZero() {
		text += ", back to " + display.In(summary.Since).Format("Jan 2, 2006")
	}
	return text + "."
}

// saveInsightsSwitch turns Insights on or off, and on the way off deletes
// what it collected when asked to. The page reloads, since the sidebar and
// the command palette change with it.
func (server *Server) saveInsightsSwitch(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderSettingsInsights(writer, request, console, http.StatusBadRequest, "", "Sable could not read the form.")
		return
	}
	editor, editable := server.config.(settingsEditor)
	data, holds := server.queries.(insightDataStore)
	if !editable || !holds {
		server.renderSettingsInsights(writer, request, console, http.StatusNotImplemented, "", "Insights cannot be changed on this server.")
		return
	}
	enabled := request.FormValue("enabled") == "true"
	remove := !enabled && request.FormValue("delete") == "true"
	if err := editor.Update(request.Context(), func(candidate *config.Config) error {
		candidate.Insights.Enabled = enabled
		return nil
	}); err != nil {
		server.renderSettingsInsights(writer, request, console, http.StatusUnprocessableEntity, "", "Sable could not save the setting: "+err.Error())
		return
	}
	// Collection stopped with the setting, so nothing lands after the delete.
	if remove {
		if err := data.DeleteInsightData(request.Context(), time.Now()); err != nil {
			server.logger.Warn("delete Insights data", "error", err)
			server.recordControlPlaneAudit(request, "insights", "turned Insights off")
			server.renderSettingsInsights(writer, request, console, http.StatusInternalServerError, "",
				"Insights is off, but Sable could not delete what it collected. Try Delete Insights Data.")
			return
		}
	}
	server.forgetInsightCaches()
	switch {
	case enabled:
		server.recordControlPlaneAudit(request, "insights", "turned Insights on")
	case remove:
		server.recordControlPlaneAudit(request, "insights", "turned Insights off and deleted what it collected")
	default:
		server.recordControlPlaneAudit(request, "insights", "turned Insights off")
	}
	writer.Header().Set("HX-Refresh", "true")
	writer.WriteHeader(http.StatusOK)
}

// deleteInsightData deletes what Insights collected and keeps it as it is,
// on or off.
func (server *Server) deleteInsightData(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	data, holds := server.queries.(insightDataStore)
	if !holds {
		server.renderSettingsInsights(writer, request, console, http.StatusNotImplemented, "", "Insights data cannot be deleted on this server.")
		return
	}
	if err := data.DeleteInsightData(request.Context(), time.Now()); err != nil {
		server.logger.Warn("delete Insights data", "error", err)
		server.renderSettingsInsights(writer, request, console, http.StatusInternalServerError, "", "Sable could not delete what Insights collected.")
		return
	}
	server.forgetInsightCaches()
	server.recordControlPlaneAudit(request, "insights", "deleted what Insights collected")
	server.renderSettingsInsights(writer, request, console, http.StatusOK, "Deleted what Insights collected.", "")
}

func (server *Server) renderSettingsInsights(writer http.ResponseWriter, request *http.Request, console pages.DashboardView, status int, message, errorMessage string) {
	writer.WriteHeader(status)
	view := server.settingsInsightsView(request.Context(), console, message, errorMessage)
	if err := pages.SettingsInsights(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render Insights settings", "error", err)
	}
}

// forgetInsightCaches drops the device counts Insights keeps, so nothing
// counted from deleted data, or from before Insights was off, is shown again.
func (server *Server) forgetInsightCaches() {
	server.deviceActivityCache.forget()
	server.deviceSignalCache.forget()
	server.repeatedLookupCache.forget()
}
