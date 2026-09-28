package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/querylog"
)

func (server insightsTestServer) setInsights(t *testing.T, enabled bool) {
	t.Helper()
	if err := server.config.(settingsEditor).Update(context.Background(), func(candidate *config.Config) error {
		candidate.Insights.Enabled = enabled
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// withOperator adds the account the test sessions sign in as, so what they
// do is audited under it.
func (server insightsTestServer) withOperator(t *testing.T) insightsTestServer {
	t.Helper()
	if _, err := server.store.CreateUser(context.Background(), "operator", "Operator", "operator@example.com", "argon2id$hash",
		[]string{"Administrator"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return server
}

func (server insightsTestServer) auditDetails(t *testing.T) []string {
	t.Helper()
	records, err := server.store.ListAuditRecords(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	details := make([]string, 0, len(records))
	for _, record := range records {
		if record.Action == "insights" {
			details = append(details, record.Details)
		}
	}
	return details
}

// The switch sits in Settings > General, above Software Updates, with what
// Insights holds, and saves on its own rather than with Save Settings.
func TestSettingsGeneralHoldsTheInsightsSwitch(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	page := server.get(t, "everything", "/settings?tab=general", false).Body.String()
	card := strings.Index(page, `id="settings-insights"`)
	if card < strings.Index(page, "Persistent configuration and DNS data backend") || card > strings.Index(page, "Update preferences for this node") {
		t.Fatal("the Insights card is not between Storage and Software Updates")
	}
	for _, expected := range []string{
		`data-insights-off="insights-off-dialog"`,
		`id="insights-off-dialog"`,
		`<input type="checkbox" name="delete" value="true" checked>`,
		"Device data:</strong> 4 addresses and 1 hardware address, back to ",
		`data-dialog-open="insights-delete-dialog"`,
	} {
		if !strings.Contains(page, expected) {
			t.Errorf("Settings > General is missing %q", expected)
		}
	}
	// An operator who may only read settings sees the switch but cannot use it.
	readOnly := server.get(t, "logs-reader", "/settings?tab=general", false).Body.String()
	if !strings.Contains(readOnly, `data-insights-off="insights-off-dialog" disabled`) || strings.Contains(readOnly, `id="insights-off-dialog"`) {
		t.Error("a read-only operator can turn Insights off")
	}
}

func TestTurningInsightsOffHidesItAndDeletesWhenAsked(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t).withOperator(t)

	if response := server.post(t, "logs-reader", "/ui/settings/insights", url.Values{"enabled": {"false"}}); response.Code != http.StatusForbidden {
		t.Fatalf("turning Insights off without permission = %d", response.Code)
	}
	response := server.post(t, "everything", "/ui/settings/insights", url.Values{"enabled": {"false"}, "delete": {"true"}})
	if response.Code != http.StatusOK || response.Header().Get("HX-Refresh") != "true" {
		t.Fatalf("turning Insights off = %d, refresh %q", response.Code, response.Header().Get("HX-Refresh"))
	}
	if server.insightsEnabled() {
		t.Fatal("Insights is still on")
	}
	if summary, err := server.store.InsightDataSummary(context.Background()); err != nil || summary.Addresses != 0 || summary.Hardware != 0 {
		t.Fatalf("Insights data after turning off with delete = %+v, %v", summary, err)
	}
	if got := server.auditDetails(t); len(got) != 1 || got[0] != "turned Insights off and deleted what it collected" {
		t.Fatalf("audit = %q", got)
	}

	// Insights leaves the sidebar and the command palette, and its page says
	// it is off.
	page := server.get(t, "everything", "/insights", false)
	body := page.Body.String()
	if page.Code != http.StatusOK || !strings.Contains(body, "Insights Is Off") || !strings.Contains(body, `href="/settings?tab=general#settings-insights"`) {
		t.Fatalf("Insights page while off = %d", page.Code)
	}
	for _, gone := range []string{`href="/insights"`, `id="command-page-insights"`, `id="command-action-search-devices"`, "warmInsights"} {
		if strings.Contains(body, gone) {
			t.Errorf("Insights is off but the page still has %q", gone)
		}
	}
	for _, target := range []string{"/ui/insights/overview", "/ui/insights/settings"} {
		if response := server.get(t, "everything", target, true); response.Code != http.StatusNotFound {
			t.Errorf("GET %s while off = %d, want 404", target, response.Code)
		}
	}
	// The alerts group folds away.
	alerts := server.get(t, "everything", "/settings?tab=alerts", false).Body.String()
	if strings.Contains(alerts, `id="alerts-group-insights"`) {
		t.Error("the Insights alert group still shows while Insights is off")
	}

	// Back on, everything returns.
	if response := server.post(t, "everything", "/ui/settings/insights", url.Values{"enabled": {"true"}}); response.Code != http.StatusOK {
		t.Fatalf("turning Insights on = %d", response.Code)
	}
	if body := server.get(t, "everything", "/insights", false).Body.String(); strings.Contains(body, "Insights Is Off") || !strings.Contains(body, `href="/insights"`) {
		t.Fatal("Insights did not come back")
	}
	if got := server.auditDetails(t); len(got) != 2 || got[0] != "turned Insights on" {
		t.Fatalf("audit = %q", got)
	}
}

func TestTurningInsightsOffCanKeepItsData(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t).withOperator(t)
	if response := server.post(t, "everything", "/ui/settings/insights", url.Values{"enabled": {"false"}}); response.Code != http.StatusOK {
		t.Fatalf("turning Insights off = %d", response.Code)
	}
	if summary, err := server.store.InsightDataSummary(context.Background()); err != nil || summary.Addresses == 0 {
		t.Fatalf("Insights data after turning off without delete = %+v, %v", summary, err)
	}
	// What was kept can still be deleted while Insights is off.
	response := server.post(t, "everything", "/ui/settings/insights/delete", nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Deleted what Insights collected.") ||
		strings.Contains(response.Body.String(), "Device data:") {
		t.Fatalf("delete = %d %s", response.Code, response.Body.String())
	}
	if got := server.auditDetails(t); len(got) != 2 || got[0] != "deleted what Insights collected" || got[1] != "turned Insights off" {
		t.Fatalf("audit = %q", got)
	}
}

// With Insights off, nothing is analyzed for alerts, device names come only
// from the operator, and the choices under the folded alerts group survive a
// save of the other groups.
func TestInsightsOffStopsAlertsAndHardwareNames(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	if err := server.store.RecordClientIdentities(context.Background(), []querylog.ClientIdentity{
		{Address: "10.0.0.9", MAC: "f4:ab:5c:0b:47:8a", Source: "unifi", Hostname: "Office Camera", SeenAt: server.now},
	}); err != nil {
		t.Fatal(err)
	}
	if name := server.givenClientNames(context.Background(), server.now.Add(-time.Hour)).Address("10.0.0.9"); name != "Office Camera" {
		t.Fatalf("camera named %q with Insights on", name)
	}
	server.setInsights(t, false)
	if alerts, err := server.InsightAlerts().Alerts(context.Background(), time.Now()); err != nil || len(alerts) != 0 {
		t.Fatalf("Insights alerts while off = %v, %v", alerts, err)
	}
	if name := server.givenClientNames(context.Background(), server.now.Add(-time.Hour)).Address("10.0.0.9"); name != "" {
		t.Fatalf("camera named %q from UniFi with Insights off", name)
	}

	server.alerts = &alerts.Dispatcher{Config: func() config.Config { return server.config.Current().Config }}
	editor := server.config.(settingsEditor)
	if err := editor.Update(context.Background(), func(candidate *config.Config) error {
		candidate.Alerts.Send.Insights = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	response := server.post(t, "everything", "/ui/settings/alerts/groups", url.Values{
		"cluster": {"true"}, "backups": {"failures"}, "sign_ins_after": {"5"}, "sign_ins_within": {"10"},
	})
	if response.Code != http.StatusOK {
		t.Fatalf("save alert groups = %d", response.Code)
	}
	if !server.config.Current().Config.Alerts.Send.Insights {
		t.Fatal("saving alert groups while Insights is off turned its alerts off")
	}
}
