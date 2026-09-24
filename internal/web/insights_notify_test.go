package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

func TestInsightAlertsTakeStockThenSendEachNewFindingOnce(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	received := make([]insightAlert, 0)
	hook := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		var alert insightAlert
		if err := json.Unmarshal(body, &alert); err != nil {
			t.Errorf("alert body %q: %v", body, err)
		}
		mu.Lock()
		received = append(received, alert)
		mu.Unlock()
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(hook.Close)

	server := newInsightsTestServer(t)
	ctx := context.Background()
	if err := server.config.(settingsEditor).Update(ctx, func(configuration *config.Config) error {
		configuration.Insights.Webhook.URL = hook.URL
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// The first look only takes stock of what is already there.
	if err := server.sendInsightAlerts(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(received) != 0 {
		t.Fatalf("taking stock sent %d alerts", len(received))
	}
	news := server.insightNews(ctx, now)
	if len(news) == 0 {
		t.Fatal("the test network has no news to alert about")
	}
	// Pretend one finding is new since then.
	target := insightAlertTarget(hook.URL)
	if err := server.store.ForgetInsightsNotified(ctx, target, []string{news[0].ID}); err != nil {
		t.Fatal(err)
	}
	if err := server.sendInsightAlerts(ctx, now.Add(insightAlertInterval)); err != nil {
		t.Fatal(err)
	}
	if len(received) != 1 || received[0].ID != news[0].ID || received[0].Headline == "" || received[0].Text == "" || received[0].Source != "sable" {
		t.Fatalf("received = %+v", received)
	}
	// It is not sent twice.
	if err := server.sendInsightAlerts(ctx, now.Add(2*insightAlertInterval)); err != nil {
		t.Fatal(err)
	}
	if len(received) != 1 {
		t.Fatalf("a finding alerted %d times", len(received))
	}
}

func TestInsightAlertTargetsDoNotKeepTheURL(t *testing.T) {
	t.Parallel()
	target := insightAlertTarget("https://hooks.slack.com/services/T000/B000/secret-token")
	if len(target) != 32 || target == insightAlertTarget("https://hooks.slack.com/services/T000/B000/other") {
		t.Fatalf("target = %q", target)
	}
}

func TestInsightAlertsCanBeSetUpAndTestedFromTheOverview(t *testing.T) {
	t.Parallel()
	var tests sync.WaitGroup
	tests.Add(1)
	var title, contentType string
	hook := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		title, contentType = request.Header.Get("Title"), request.Header.Get("Content-Type")
		tests.Done()
	}))
	t.Cleanup(hook.Close)
	server := newInsightsTestServer(t)
	// The setup opens from a bell beside the range control, in a dialog that
	// stays outside the overview the range control swaps.
	if overview := server.get(t, "everything", "/ui/insights/overview?range=day", true).Body.String(); !strings.Contains(overview, `data-dialog-open="insight-alerts-dialog" aria-label="Alerts off"`) ||
		strings.Contains(overview, `id="insight-alerts"`) {
		t.Fatal("the overview does not offer the alert setup from its bell")
	}
	if page := server.get(t, "everything", "/insights?range=day", false).Body.String(); !strings.Contains(page, `id="insight-alerts-dialog"`) || !strings.Contains(page, `id="insight-alerts"`) {
		t.Fatal("the page has no alert setup dialog")
	}
	if overview := server.get(t, "logs-reader", "/ui/insights/overview?range=day", true).Body.String(); strings.Contains(overview, "insight-alerts-dialog") {
		t.Fatal("an operator without settings write sees the alert setup")
	}
	form := url.Values{"url": {hook.URL}, "format": {"text"}}
	if response := server.post(t, "logs-reader", "/ui/insights/alerts", form); response.Code != http.StatusForbidden {
		t.Fatalf("saving without settings write = %d", response.Code)
	}
	saved := server.post(t, "everything", "/ui/insights/alerts", form)
	if saved.Code != http.StatusOK || !strings.Contains(saved.Body.String(), "New findings will be sent") || saved.Header().Get("HX-Trigger") != "insightsChanged" {
		t.Fatalf("saving = %d %q %s", saved.Code, saved.Header().Get("HX-Trigger"), saved.Body.String())
	}
	if overview := server.get(t, "everything", "/ui/insights/overview?range=day", true).Body.String(); !strings.Contains(overview, `aria-label="Alerts on"`) {
		t.Fatal("the bell does not say alerts are on")
	}
	if webhook := server.config.Current().Config.Insights.Webhook; webhook != (config.InsightsWebhook{URL: hook.URL, Format: "text"}) {
		t.Fatalf("webhook = %+v", webhook)
	}
	if tested := server.post(t, "everything", "/ui/insights/alerts/test", url.Values{}); !strings.Contains(tested.Body.String(), "Test sent.") {
		t.Fatalf("testing = %s", tested.Body.String())
	}
	tests.Wait()
	if title != "Test alert: Sable" || !strings.HasPrefix(contentType, "text/plain") {
		t.Fatalf("test alert title %q, type %q", title, contentType)
	}
	if invalid := server.post(t, "everything", "/ui/insights/alerts", url.Values{"url": {"ftp://nope"}}); invalid.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an invalid URL = %d", invalid.Code)
	}
}
