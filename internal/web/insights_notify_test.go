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
	if webhook := server.config.Current().Config.Insights.Webhook; webhook.URL != hook.URL || webhook.Format != "text" || webhook.Paused || webhook.NtfyReceipt || len(webhook.Headers) != 0 {
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

func TestPausedInsightAlertsSendNothingAndResumeWithoutTheBacklog(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	sent := 0
	hook := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		sent++
		mu.Unlock()
	}))
	t.Cleanup(hook.Close)
	server := newInsightsTestServer(t)
	ctx := context.Background()
	saved := server.post(t, "everything", "/ui/insights/alerts", url.Values{"url": {hook.URL}, "format": {"text"}})
	if saved.Code != http.StatusOK {
		t.Fatalf("saving = %d", saved.Code)
	}
	now := time.Now()
	if err := server.sendInsightAlerts(ctx, now); err != nil {
		t.Fatal(err)
	}
	news := server.insightNews(ctx, now)
	if len(news) == 0 {
		t.Fatal("the test network has no news to alert about")
	}

	if response := server.post(t, "logs-reader", "/ui/insights/alerts/enabled", url.Values{"enabled": {"false"}}); response.Code != http.StatusForbidden {
		t.Fatalf("pausing without settings write = %d", response.Code)
	}
	paused := server.post(t, "everything", "/ui/insights/alerts/enabled", url.Values{"enabled": {"false"}})
	if !strings.Contains(paused.Body.String(), "Alerts paused.") || !strings.Contains(paused.Body.String(), "Resume") || paused.Header().Get("HX-Trigger") != "insightsChanged" {
		t.Fatalf("pausing = %s", paused.Body.String())
	}
	if overview := server.get(t, "everything", "/ui/insights/overview?range=day", true).Body.String(); !strings.Contains(overview, `aria-label="Alerts paused"`) {
		t.Fatal("the bell does not say alerts are paused")
	}
	// Saving the setup again leaves alerts paused.
	server.post(t, "everything", "/ui/insights/alerts", url.Values{"url": {hook.URL}, "format": {"text"}})
	if webhook := server.config.Current().Config.Insights.Webhook; !webhook.Paused || webhook.URL != hook.URL {
		t.Fatalf("webhook after saving while paused = %+v", webhook)
	}

	// A finding that turns up while paused is noted, not sent.
	target := insightAlertTarget(hook.URL)
	if err := server.store.ForgetInsightsNotified(ctx, target, []string{news[0].ID}); err != nil {
		t.Fatal(err)
	}
	if err := server.sendInsightAlerts(ctx, now.Add(insightAlertInterval)); err != nil {
		t.Fatal(err)
	}
	resumed := server.post(t, "everything", "/ui/insights/alerts/enabled", url.Values{"enabled": {"true"}})
	if !strings.Contains(resumed.Body.String(), "Alerts resumed.") || !strings.Contains(resumed.Body.String(), "Pause") {
		t.Fatalf("resuming = %s", resumed.Body.String())
	}
	if err := server.sendInsightAlerts(ctx, now.Add(2*insightAlertInterval)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if sent != 0 {
		t.Fatalf("sent %d alerts for findings from while alerts were paused", sent)
	}
}

func TestInsightAlertsSendHeadersAndCanRequireAnNtfyReceipt(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var authorization, priority string
	// ntfy answers with a receipt for what it published.
	ntfy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		authorization, priority = request.Header.Get("Authorization"), request.Header.Get("Priority")
		mu.Unlock()
		_, _ = io.WriteString(writer, `{"id":"kqsbW5IVYYUc","time":1790289679,"event":"message","topic":"sable","message":"hi"}`)
	}))
	t.Cleanup(ntfy.Close)
	// A parked domain answers anything with a page.
	parked := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "<html>This domain is for sale</html>")
	}))
	t.Cleanup(parked.Close)
	server := newInsightsTestServer(t)

	form := url.Values{
		"url": {ntfy.URL}, "format": {"text"}, "ntfy_receipt": {"true"},
		"header_name":  {"Authorization", " ", "Priority"},
		"header_value": {"Bearer tk_secret", "", "high"},
	}
	saved := server.post(t, "everything", "/ui/insights/alerts", form)
	if saved.Code != http.StatusOK {
		t.Fatalf("saving = %d %s", saved.Code, saved.Body.String())
	}
	webhook := server.config.Current().Config.Insights.Webhook
	if !webhook.NtfyReceipt || len(webhook.Headers) != 2 || webhook.Headers[0] != (config.InsightsWebhookHeader{Name: "Authorization", Value: "Bearer tk_secret"}) || webhook.Headers[1].Name != "Priority" {
		t.Fatalf("webhook = %+v", webhook)
	}
	if body := saved.Body.String(); !strings.Contains(body, `value="Bearer tk_secret"`) || !strings.Contains(body, `insight-alerts-advanced" data-alert-for="json text" open`) {
		t.Fatal("the saved setup does not show its headers in an open Advanced section")
	}
	tested := server.post(t, "everything", "/ui/insights/alerts/test", url.Values{})
	if !strings.Contains(tested.Body.String(), "ntfy published it as message kqsbW5IVYYUc") {
		t.Fatalf("testing ntfy = %s", tested.Body.String())
	}
	mu.Lock()
	if authorization != "Bearer tk_secret" || priority != "high" {
		t.Fatalf("headers sent: Authorization %q, Priority %q", authorization, priority)
	}
	mu.Unlock()

	form.Set("url", parked.URL)
	server.post(t, "everything", "/ui/insights/alerts", form)
	if tested := server.post(t, "everything", "/ui/insights/alerts/test", url.Values{}); !strings.Contains(tested.Body.String(), "not with an ntfy receipt") {
		t.Fatalf("testing a parked domain = %s", tested.Body.String())
	}
	// Without the check, any 200 counts.
	form.Del("ntfy_receipt")
	server.post(t, "everything", "/ui/insights/alerts", form)
	if tested := server.post(t, "everything", "/ui/insights/alerts/test", url.Values{}); !strings.Contains(tested.Body.String(), "Test sent.") {
		t.Fatalf("testing without the check = %s", tested.Body.String())
	}

	// JSON is not what ntfy takes, so it hides and drops the receipt check.
	json := server.post(t, "everything", "/ui/insights/alerts", url.Values{"url": {ntfy.URL}, "format": {"json"}, "ntfy_receipt": {"true"}})
	if server.config.Current().Config.Insights.Webhook.NtfyReceipt || !strings.Contains(json.Body.String(), `setting-switch-row" data-alert-for="text" hidden`) {
		t.Fatal("a JSON webhook kept or showed the ntfy receipt check")
	}

	bad := url.Values{"url": {ntfy.URL}, "header_name": {"Host"}, "header_value": {"example.com"}}
	if response := server.post(t, "everything", "/ui/insights/alerts", bad); response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "Sable sets Host itself") {
		t.Fatalf("saving a Host header = %d", response.Code)
	}
}

func TestInsightAlertsSendToPushoverAndSayWhatItRejected(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var form url.Values
	pushover := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		mu.Lock()
		form = request.PostForm
		mu.Unlock()
		if request.PostForm.Get("token") != "app-token" {
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(writer, `{"token":"invalid","errors":["application token is invalid"],"status":0,"request":"r-bad"}`)
			return
		}
		_, _ = io.WriteString(writer, `{"status":1,"request":"r-good"}`)
	}))
	t.Cleanup(pushover.Close)
	server := newInsightsTestServer(t)

	if missing := server.post(t, "everything", "/ui/insights/alerts", url.Values{"format": {"pushover"}, "pushover_token": {"app-token"}}); missing.Code != http.StatusUnprocessableEntity || !strings.Contains(missing.Body.String(), "application token and a user key") {
		t.Fatalf("saving Pushover with only a token = %d", missing.Code)
	}
	// The dialog asks for no URL: Pushover's own API is used, whatever the
	// form still carries from another kind.
	setup := url.Values{"url": {"https://ntfy.sh/left-over"}, "format": {"pushover"}, "pushover_token": {"app-token"}, "pushover_user": {"user-key"}}
	if saved := server.post(t, "everything", "/ui/insights/alerts", setup); saved.Code != http.StatusOK || !strings.Contains(saved.Body.String(), `value="user-key"`) {
		t.Fatalf("saving Pushover = %d", saved.Code)
	}
	if webhook := server.config.Current().Config.Insights.Webhook; webhook.URL != config.PushoverMessagesURL {
		t.Fatalf("Pushover URL = %q", webhook.URL)
	}
	// Blank keys turn Pushover alerts off.
	if off := server.post(t, "everything", "/ui/insights/alerts", url.Values{"format": {"pushover"}}); off.Code != http.StatusOK || server.config.Current().Config.Insights.Webhook.URL != "" {
		t.Fatalf("clearing Pushover keys = %d", off.Code)
	}
	// Point Pushover at the fake API the way a config file could.
	usePushover := func(token string) {
		t.Helper()
		if err := server.config.(settingsEditor).Update(context.Background(), func(configuration *config.Config) error {
			configuration.Insights.Webhook = config.InsightsWebhook{URL: pushover.URL, Format: "pushover", PushoverToken: token, PushoverUser: "user-key"}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	usePushover("app-token")
	if tested := server.post(t, "everything", "/ui/insights/alerts/test", url.Values{}); !strings.Contains(tested.Body.String(), "Pushover accepted it as request r-good") {
		t.Fatalf("testing Pushover = %s", tested.Body.String())
	}
	mu.Lock()
	if form.Get("user") != "user-key" || form.Get("title") != "Test alert: Sable" || form.Get("message") == "" || !strings.HasSuffix(form.Get("url"), "/insights") {
		t.Fatalf("Pushover got %v", form)
	}
	mu.Unlock()

	usePushover("wrong")
	if tested := server.post(t, "everything", "/ui/insights/alerts/test", url.Values{}); !strings.Contains(tested.Body.String(), "application token is invalid") {
		t.Fatalf("testing a wrong token = %s", tested.Body.String())
	}
	// Leaving Pushover drops its keys.
	server.post(t, "everything", "/ui/insights/alerts", url.Values{"url": {"https://hooks.example.com/x"}, "format": {"json"}, "pushover_token": {"app-token"}, "pushover_user": {"user-key"}})
	if webhook := server.config.Current().Config.Insights.Webhook; webhook.PushoverToken != "" || webhook.PushoverUser != "" {
		t.Fatalf("a JSON webhook kept Pushover keys: %+v", webhook)
	}
}

func TestInsightAlertPreviewShowsEachFormatWithoutSecrets(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	preview := func(form url.Values) string {
		t.Helper()
		response := server.post(t, "everything", "/ui/insights/alerts/preview", form)
		if response.Code != http.StatusOK {
			t.Fatalf("preview %v = %d", form, response.Code)
		}
		return response.Body.String()
	}
	if response := server.post(t, "logs-reader", "/ui/insights/alerts/preview", url.Values{}); response.Code != http.StatusForbidden {
		t.Fatalf("previewing without settings write = %d", response.Code)
	}
	json := preview(url.Values{"url": {"https://hooks.example.com/x"}, "format": {"json"}, "header_name": {"Authorization"}, "header_value": {"Bearer secret-token"}})
	for _, want := range []string{"POST https://hooks.example.com/x", "Content-Type: application/json", "Authorization: ••••oken", "\n  &#34;source&#34;: &#34;sable&#34;"} {
		if !strings.Contains(json, want) {
			t.Errorf("the JSON preview lacks %q:\n%s", want, json)
		}
	}
	if strings.Contains(json, "secret-token") {
		t.Error("the JSON preview shows the whole Authorization header")
	}
	text := preview(url.Values{"format": {"text"}})
	if !strings.Contains(text, "(no URL yet)") || !strings.Contains(text, "Title: Test alert: Sable") || !strings.Contains(text, "text/plain") {
		t.Errorf("the text preview:\n%s", text)
	}
	pushover := preview(url.Values{"url": {config.PushoverMessagesURL}, "format": {"pushover"}, "pushover_token": {"azGDORePK8gMaC0QOYAM"}, "pushover_user": {"uQiRzpo4DXghDmr9QzzfQu27"}})
	for _, want := range []string{"token=••••OYAM", "user=••••Qu27", "title=Test alert: Sable", "url_title=Open Insights", "application/x-www-form-urlencoded"} {
		if !strings.Contains(pushover, want) {
			t.Errorf("the Pushover preview lacks %q:\n%s", want, pushover)
		}
	}
}
