package web

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web/pages"
	"github.com/drudge/sable/internal/webpush"
)

// memoryAlertVault stands in for the encrypted vault destination secrets live
// in.
type memoryAlertVault struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (vault *memoryAlertVault) Put(_ context.Context, name string, value []byte) error {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	vault.values[name] = slices.Clone(value)
	return nil
}

func (vault *memoryAlertVault) Get(_ context.Context, name string) ([]byte, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	value, found := vault.values[name]
	if !found {
		return nil, errors.New("secret not found")
	}
	return slices.Clone(value), nil
}

func (vault *memoryAlertVault) Delete(_ context.Context, name string) error {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	delete(vault.values, name)
	return nil
}

// fixedPushKeys stands in for the vault-backed key browser pushes are signed
// with.
type fixedPushKeys struct{ key *ecdsa.PrivateKey }

func (keys fixedPushKeys) PushKey(context.Context) (*ecdsa.PrivateKey, error) { return keys.key, nil }

// alertsTestServer is the Insights test server with alerts wired the way the
// application wires them, over an in-memory vault.
type alertsTestServer struct {
	insightsTestServer
	key *ecdsa.PrivateKey
}

func newAlertsTestServer(t *testing.T) alertsTestServer {
	t.Helper()
	server := newInsightsTestServer(t)
	// Audit entries name the operator who made them, so the test sessions'
	// operator has to exist.
	if _, err := server.store.CreateUser(context.Background(), "operator", "Operator", "", "unused", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	key, err := webpush.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	secrets := alerts.NewSecretStore(&memoryAlertVault{values: make(map[string][]byte)})
	server.SetPushKeys(fixedPushKeys{key})
	server.SetAlerts(&alerts.Dispatcher{
		Config:   func() config.Config { return server.config.Current().Config },
		Secrets:  secrets,
		Sent:     server.store,
		Browsers: &alerts.Browsers{Keys: fixedPushKeys{key}, Store: server.store, Logger: logger},
		Logger:   logger,
	}, secrets)
	return alertsTestServer{insightsTestServer: server, key: key}
}

func (server alertsTestServer) alertsConfig() config.Alerts {
	return server.config.Current().Config.Alerts
}

// saveDestination posts the Add or Edit Destination form.
func (server alertsTestServer) saveDestination(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return server.post(t, "everything", "/ui/settings/alerts/destinations/save", form)
}

// onlyDestination is the one destination sable.toml holds.
func (server alertsTestServer) onlyDestination(t *testing.T) config.AlertDestination {
	t.Helper()
	destinations := server.alertsConfig().Destinations
	if len(destinations) != 1 {
		t.Fatalf("destinations = %+v, want one", destinations)
	}
	return destinations[0]
}

// savedSecrets are the secrets the vault holds for a destination.
func (server alertsTestServer) savedSecrets(t *testing.T, id string) alerts.Secrets {
	t.Helper()
	secrets, found := server.alertSecrets.Secrets(context.Background(), id)
	if !found {
		t.Fatalf("the vault holds no secrets for %q", id)
	}
	return secrets
}

// lastAudit is the newest audit entry.
func (server alertsTestServer) lastAudit(t *testing.T) (string, string) {
	t.Helper()
	records, err := server.store.ListAuditRecords(context.Background(), 1)
	if err != nil || len(records) == 0 {
		t.Fatalf("audit records = %v, %v", records, err)
	}
	return records[0].Action, records[0].Details
}

// subscribeBrowser posts what a browser's PushManager hands the page after it
// subscribes, the way the Alerts tab's script does.
func (server alertsTestServer) subscribeBrowser(t *testing.T, session, endpoint string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/ui/settings/alerts/browsers",
		strings.NewReader(url.Values{"push_subscription": {browserSubscription(t, endpoint)}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	request.Header.Set("X-CSRF-Token", "csrf-token")
	request.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0 Safari/537.36")
	request.AddCookie(&http.Cookie{Name: server.sessionCookieName(), Value: session})
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

// browserSubscription is what a browser's PushManager hands the page.
func browserSubscription(t *testing.T, endpoint string) string {
	t.Helper()
	browser, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(map[string]any{
		"endpoint": endpoint,
		"keys": map[string]string{
			"p256dh": base64.RawURLEncoding.EncodeToString(browser.PublicKey().Bytes()),
			"auth":   base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// fakePushService is a browser's push service: it records each push and can
// be told the subscription is gone.
type fakePushService struct {
	*httptest.Server
	mu     sync.Mutex
	pushes []*http.Request
	gone   bool
}

func newFakePushService(t *testing.T) *fakePushService {
	t.Helper()
	service := &fakePushService{}
	service.Server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		service.mu.Lock()
		defer service.mu.Unlock()
		service.pushes = append(service.pushes, request)
		if service.gone {
			writer.WriteHeader(http.StatusGone)
			return
		}
		writer.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(service.Close)
	return service
}

func (service *fakePushService) count() int {
	service.mu.Lock()
	defer service.mu.Unlock()
	return len(service.pushes)
}

func (service *fakePushService) goAway() {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.gone = true
}

// fakeWebhook answers each alert the way a service does, and keeps what it
// was sent.
type fakeWebhook struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
	bodies   [][]byte
}

func newFakeWebhook(t *testing.T, answer func(writer http.ResponseWriter, request *http.Request)) *fakeWebhook {
	t.Helper()
	hook := &fakeWebhook{}
	hook.Server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		request.Body = io.NopCloser(bytes.NewReader(body))
		hook.mu.Lock()
		hook.requests = append(hook.requests, request)
		hook.bodies = append(hook.bodies, body)
		hook.mu.Unlock()
		answer(writer, request)
	}))
	t.Cleanup(hook.Close)
	return hook
}

// last is the newest request the webhook got, and its body.
func (hook *fakeWebhook) last(t *testing.T) (*http.Request, []byte) {
	t.Helper()
	hook.mu.Lock()
	defer hook.mu.Unlock()
	if len(hook.requests) == 0 {
		t.Fatal("the webhook got nothing")
	}
	return hook.requests[len(hook.requests)-1], hook.bodies[len(hook.bodies)-1]
}

func TestSettingsHasAnAlertsTab(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	page := server.get(t, "everything", "/settings?tab=alerts", false).Body.String()
	for _, want := range []string{
		`<title>Alerts · Settings · Sable</title>`, `data-active-tab="alerts"`, `data-isotope-tab="alerts"`,
		`data-isotope-panel="alerts"`, `id="alerts-panel"`, `id="alert-destination-dialog"`, `id="alert-destination-add"`,
		"No destinations yet", `<span class="status-badge">Off</span>`, "Add a destination to start getting alerts.",
		`id="alerts-group-sign_ins"`, `name="sign_ins_after" min="1" max="1000" value="5"`, `name="sign_ins_within" min="1" max="1440" value="10"`,
		`id="command-settings-alerts"`, `data-command-href="/settings?tab=alerts"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the Alerts tab lacks %q", want)
		}
	}
	// The tab lives outside the settings form, so Save Settings never sends
	// its fields.
	form := page[strings.Index(page, `<form id="settings-form"`):]
	if strings.Contains(form[:strings.Index(form, "</form>")], `id="alerts-panel"`) {
		t.Fatal("the Alerts tab sits inside the settings form")
	}

	// Anyone who can read settings sees the tab; only those who can change
	// them get its buttons.
	readOnly := server.get(t, "logs-reader", "/settings?tab=alerts", false).Body.String()
	if !strings.Contains(readOnly, `id="alerts-panel"`) || strings.Contains(readOnly, `id="alert-destination-add"`) ||
		strings.Contains(readOnly, `id="alert-destination-dialog"`) || strings.Contains(readOnly, "Save Groups") ||
		!regexp.MustCompile(`name="insights" value="true" checked disabled`).MatchString(readOnly) {
		t.Fatal("an operator who cannot change settings gets the Alerts tab's buttons")
	}
	if response := server.get(t, "zones-only", "/settings?tab=alerts", false); response.Code != http.StatusForbidden {
		t.Fatalf("an operator who cannot read settings = %d", response.Code)
	}
}

func TestAddingAnAlertDestinationKeepsItsSecretsInTheVault(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	saved := server.saveDestination(t, url.Values{
		"name": {"Phone"}, "format": {"text"}, "url": {"https://ntfy.sh/sable-alerts"}, "ntfy_receipt": {"true"},
		"header_name":  {"Authorization", " ", "Priority"},
		"header_value": {"Bearer tk_secret", "", "high"},
		"sends_all":    {"true"},
	})
	body := saved.Body.String()
	if saved.Code != http.StatusOK || !strings.Contains(body, "Added Phone. Send a test to make sure it arrives.") {
		t.Fatalf("adding = %d %s", saved.Code, body)
	}
	destination := server.onlyDestination(t)
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(destination.ID) || destination.Name != "Phone" || destination.Format != config.AlertFormatText ||
		!destination.NtfyReceipt || destination.HasSecrets() || destination.Sends != nil {
		t.Fatalf("sable.toml holds %+v", destination)
	}
	secrets := server.savedSecrets(t, destination.ID)
	if secrets.URL != "https://ntfy.sh/sable-alerts" ||
		!slices.Equal(secrets.Headers, []config.AlertHeader{{Name: "Authorization", Value: "Bearer tk_secret"}, {Name: "Priority", Value: "high"}}) {
		t.Fatalf("the vault holds %+v", secrets)
	}
	// The list shows where it sends with the topic cut short, and no secret.
	for _, want := range []string{
		`id="alert-destination-` + destination.ID + `"`, "<strong>Phone</strong>", "https://ntfy.sh/••••erts",
		`<span class="alert-group-tag">Everything</span>`, `<span class="status-badge success">On</span>`,
		`hx-vals="{&#34;id&#34;:&#34;` + destination.ID + `&#34;}"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the list lacks %q", want)
		}
	}
	for _, secret := range []string{"sable-alerts", "tk_secret"} {
		if strings.Contains(body, secret) {
			t.Errorf("the panel shows the secret %q", secret)
		}
	}
	if action, details := server.lastAudit(t); action != "alerts" || details != "added alert destination Phone (ntfy)" {
		t.Fatalf("audit = %q %q", action, details)
	}

	// A second destination gets its own name, and can pick its groups.
	server.saveDestination(t, url.Values{
		"format": {"slack"}, "url": {"https://hooks.slack.com/services/T0/B0/token"},
		"sends_all": {"false"}, "sends": {"cluster", "sign_ins"},
	})
	destinations := server.alertsConfig().Destinations
	if len(destinations) != 2 || destinations[1].ID == destination.ID || !slices.Equal(destinations[1].Sends, []string{"cluster", "sign_ins"}) {
		t.Fatalf("destinations = %+v", destinations)
	}
	page := server.get(t, "everything", "/settings?tab=alerts", false).Body.String()
	if !strings.Contains(page, `<span class="alert-group-tag">Cluster</span> <span class="alert-group-tag">Failed Sign-Ins</span>`) {
		t.Fatal("the list does not name the groups a destination picked")
	}
}

func TestEditingAnAlertDestinationKeepsSecretsLeftBlank(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	server.saveDestination(t, url.Values{
		"name": {"Phone"}, "format": {"text"}, "url": {"https://ntfy.sh/sable-alerts"},
		"header_name": {"Authorization", "Priority"}, "header_value": {"Bearer tk_secret", "high"},
		"sends_all": {"false"}, "sends": {"cluster"},
	})
	id := server.onlyDestination(t).ID

	// The form shows each saved secret cut short, never the secret itself.
	form := server.get(t, "everything", "/ui/settings/alerts/destinations/form?id="+id, true)
	body := form.Body.String()
	for _, want := range []string{
		"Edit Destination", `name="id" value="` + id + `"`, `name="name" value="Phone"`,
		`placeholder="Saved: https://ntfy.sh/••••erts"`, `value="Authorization"`, `placeholder="Saved: ••••cret"`,
		`value="Priority"`, `placeholder="Saved: ••••"`, `name="sends_all" value="false" checked`, `name="sends" value="cluster" checked`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the edit form lacks %q", want)
		}
	}
	for _, secret := range []string{"sable-alerts", "tk_secret", "high"} {
		if strings.Contains(body, secret) {
			t.Errorf("the edit form shows the secret %q", secret)
		}
	}

	// Saving with every secret left blank keeps them all, whatever case the
	// header's name is typed in.
	saved := server.saveDestination(t, url.Values{
		"id": {id}, "name": {"Pocket"}, "format": {"text"},
		"header_name": {"authorization", "Priority"}, "header_value": {"", ""},
	})
	if saved.Code != http.StatusOK || !strings.Contains(saved.Body.String(), "Saved Pocket.") {
		t.Fatalf("saving = %d %s", saved.Code, saved.Body.String())
	}
	if destination := server.onlyDestination(t); destination.ID != id || destination.Name != "Pocket" || destination.Sends != nil {
		t.Fatalf("after renaming, sable.toml holds %+v", destination)
	}
	secrets := server.savedSecrets(t, id)
	if secrets.URL != "https://ntfy.sh/sable-alerts" ||
		!slices.Equal(secrets.Headers, []config.AlertHeader{{Name: "authorization", Value: "Bearer tk_secret"}, {Name: "Priority", Value: "high"}}) {
		t.Fatalf("secrets left blank were not kept: %+v", secrets)
	}
	if action, details := server.lastAudit(t); action != "alerts" || details != "changed alert destination Pocket (ntfy)" {
		t.Fatalf("audit = %q %q", action, details)
	}

	// Typing a secret replaces it, and a header left out is dropped.
	server.saveDestination(t, url.Values{
		"id": {id}, "format": {"text"}, "url": {"https://ntfy.example/new-topic"},
		"header_name": {"Priority"}, "header_value": {"urgent"},
	})
	secrets = server.savedSecrets(t, id)
	if secrets.URL != "https://ntfy.example/new-topic" || !slices.Equal(secrets.Headers, []config.AlertHeader{{Name: "Priority", Value: "urgent"}}) {
		t.Fatalf("typed secrets were not saved: %+v", secrets)
	}

	// Moving to Pushover keeps no URL or headers, and moving back needs a URL.
	server.saveDestination(t, url.Values{
		"id": {id}, "format": {"pushover"}, "pushover_token": {"app-token"}, "pushover_user": {"user-key"},
		"header_name": {"Priority"}, "header_value": {""},
	})
	secrets = server.savedSecrets(t, id)
	if secrets.URL != "" || secrets.PushoverToken != "app-token" || secrets.PushoverUser != "user-key" || len(secrets.Headers) != 0 {
		t.Fatalf("after moving to Pushover, the vault holds %+v", secrets)
	}
	if back := server.saveDestination(t, url.Values{"id": {id}, "format": {"slack"}}); back.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(back.Body.String(), "Slack needs a URL.") {
		t.Fatalf("moving to Slack without a URL = %d %s", back.Code, back.Body.String())
	}
	if gone := server.get(t, "everything", "/ui/settings/alerts/destinations/form?id=missing", true); gone.Code != http.StatusNotFound ||
		gone.Header().Get("HX-Retarget") != "#alerts-panel" || !strings.Contains(gone.Body.String(), "That destination no longer exists.") {
		t.Fatalf("editing a destination that is gone = %d %v", gone.Code, gone.Header())
	}
}

func TestAPushoverDestinationKeepsNoURLForAnotherFormat(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	// An older release saved Pushover's own API as the URL it posted to.
	destination := config.AlertDestination{ID: config.AlertTarget(config.PushoverMessagesURL), Format: config.AlertFormatPushover}
	if err := server.config.(settingsEditor).Update(context.Background(), func(candidate *config.Config) error {
		candidate.Alerts.Destinations = []config.AlertDestination{destination}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := server.alertSecrets.Put(context.Background(), destination.ID, alerts.Secrets{
		URL: config.PushoverMessagesURL, PushoverToken: "app-token", PushoverUser: "user-key",
	}); err != nil {
		t.Fatal(err)
	}
	form := server.get(t, "everything", "/ui/settings/alerts/destinations/form?id="+destination.ID, true).Body.String()
	if strings.Contains(form, "api.pushover.net") || !strings.Contains(form, `placeholder="Saved: ••••oken"`) || !strings.Contains(form, `placeholder="Saved: ••••-key"`) {
		t.Fatalf("the Pushover form offers its API as a saved URL:\n%s", form)
	}
	moved := server.saveDestination(t, url.Values{"id": {destination.ID}, "format": {"text"}})
	if moved.Code != http.StatusUnprocessableEntity || !strings.Contains(moved.Body.String(), "ntfy needs a URL.") {
		t.Fatalf("moving Pushover to ntfy without a URL = %d %s", moved.Code, moved.Body.String())
	}
	// Saving it as Pushover keeps its keys and posts to Pushover's API.
	if saved := server.saveDestination(t, url.Values{"id": {destination.ID}, "format": {"pushover"}, "name": {"Pocket"}}); saved.Code != http.StatusOK {
		t.Fatalf("saving Pushover = %d %s", saved.Code, saved.Body.String())
	}
	if secrets := server.savedSecrets(t, destination.ID); secrets.URL != "" || secrets.PushoverToken != "app-token" || secrets.PushoverUser != "user-key" {
		t.Fatalf("the vault holds %+v", secrets)
	}
}

func TestAlertDestinationProblemsShowInTheDialog(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	for _, test := range []struct {
		name string
		form url.Values
		want string
	}{
		{"a URL that is not http", url.Values{"format": {"json"}, "url": {"ftp://hooks.example.com/x"}}, "Enter a URL that starts with https:// or http://."},
		{"no URL", url.Values{"format": {"discord"}}, "Discord needs a URL."},
		{"a header Sable sets itself", url.Values{"format": {"json"}, "url": {"https://hooks.example.com/x"}, "header_name": {"Host"}, "header_value": {"example.com"}}, "Sable sets Host itself."},
		{"a header value on two lines", url.Values{"format": {"text"}, "url": {"https://ntfy.sh/x"}, "header_name": {"X-Note"}, "header_value": {"one\ntwo"}}, "The value for X-Note cannot contain line breaks."},
		{"Pushover with only a token", url.Values{"format": {"pushover"}, "pushover_token": {"app-token"}}, "Pushover needs an application token and a user key."},
		{"only some groups, but none picked", url.Values{"format": {"text"}, "url": {"https://ntfy.sh/x"}, "sends_all": {"false"}}, "Pick at least one group, or choose Everything."},
		{"a group that does not exist", url.Values{"format": {"text"}, "url": {"https://ntfy.sh/x"}, "sends_all": {"false"}, "sends": {"weather"}}, `&#34;weather&#34; is not an alert group`},
		{"a long name", url.Values{"format": {"text"}, "url": {"https://ntfy.sh/x"}, "name": {strings.Repeat("n", 65)}}, "Keep the name to 64 characters."},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := server.saveDestination(t, test.form)
			if response.Code != http.StatusUnprocessableEntity || response.Header().Get("HX-Retarget") != "#alert-destination-notice" ||
				response.Header().Get(consoleFragmentHeader) != "true" || !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("saving = %d %v %s", response.Code, response.Header(), response.Body.String())
			}
		})
	}
	if destinations := server.alertsConfig().Destinations; len(destinations) != 0 {
		t.Fatalf("a destination with a problem was saved: %+v", destinations)
	}
	if gone := server.saveDestination(t, url.Values{"id": {"missing"}, "format": {"text"}, "url": {"https://ntfy.sh/x"}}); gone.Code != http.StatusNotFound ||
		!strings.Contains(gone.Body.String(), "That destination no longer exists.") {
		t.Fatalf("saving a destination that is gone = %d %s", gone.Code, gone.Body.String())
	}
}

func TestRemovingAnAlertDestinationForgetsItsSecrets(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	server.saveDestination(t, url.Values{"format": {"slack"}, "url": {"https://hooks.slack.com/services/T0/B0/token"}})
	id := server.onlyDestination(t).ID
	server.post(t, "everything", "/ui/settings/alerts/paused", url.Values{"paused": {"true"}})

	removed := server.post(t, "everything", "/ui/settings/alerts/destinations/remove", url.Values{"id": {id}})
	if removed.Code != http.StatusOK || !strings.Contains(removed.Body.String(), "Removed Slack.") || !strings.Contains(removed.Body.String(), "No destinations yet") {
		t.Fatalf("removing = %d %s", removed.Code, removed.Body.String())
	}
	// With nowhere to send, nothing is left paused.
	if configuration := server.alertsConfig(); len(configuration.Destinations) != 0 || configuration.Paused {
		t.Fatalf("after removing, alerts = %+v", configuration)
	}
	if _, found := server.alertSecrets.Secrets(context.Background(), id); found {
		t.Fatal("the vault kept the removed destination's secrets")
	}
	if action, details := server.lastAudit(t); action != "alerts" || details != "removed alert destination Slack" {
		t.Fatalf("audit = %q %q", action, details)
	}
	if again := server.post(t, "everything", "/ui/settings/alerts/destinations/remove", url.Values{"id": {id}}); again.Code != http.StatusNotFound ||
		!strings.Contains(again.Body.String(), "That destination was already removed.") {
		t.Fatalf("removing again = %d %s", again.Code, again.Body.String())
	}
}

func TestAlertTestsSayWhatNtfyAnswered(t *testing.T) {
	t.Parallel()
	// ntfy answers with a receipt for what it published.
	ntfy := newFakeWebhook(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"id":"kqsbW5IVYYUc","time":1790289679,"event":"message","topic":"sable","message":"hi"}`)
	})
	// A parked domain answers anything with a page.
	parked := newFakeWebhook(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "<html>This domain is for sale</html>")
	})
	server := newAlertsTestServer(t)
	server.saveDestination(t, url.Values{
		"format": {"text"}, "url": {ntfy.URL + "/sable"}, "ntfy_receipt": {"true"},
		"header_name": {"Authorization", "Priority"}, "header_value": {"Bearer tk_secret", "high"},
	})
	id := server.onlyDestination(t).ID
	test := func() string {
		t.Helper()
		return server.post(t, "everything", "/ui/settings/alerts/destinations/test", url.Values{"id": {id}}).Body.String()
	}

	if body := test(); !strings.Contains(body, "Test sent. ntfy published it as message kqsbW5IVYYUc.") || !strings.Contains(body, "Last sent") ||
		!strings.Contains(body, "Test alert: Sable") {
		t.Fatalf("testing ntfy = %s", body)
	}
	request, sent := ntfy.last(t)
	if request.Header.Get("Title") != "Test alert: Sable" || request.Header.Get("Authorization") != "Bearer tk_secret" ||
		request.Header.Get("Priority") != "high" || !strings.HasPrefix(request.Header.Get("Content-Type"), "text/plain") ||
		!strings.HasSuffix(strings.TrimSpace(string(sent)), "/settings?tab=alerts") {
		t.Fatalf("ntfy got %v %q", request.Header, sent)
	}

	server.saveDestination(t, url.Values{"id": {id}, "format": {"text"}, "url": {parked.URL + "/sable"}, "ntfy_receipt": {"true"}})
	body := test()
	if !strings.Contains(body, "The webhook answered, but not with an ntfy receipt; check the URL.") || !strings.Contains(body, "Last send failed") {
		t.Fatalf("testing a parked domain = %s", body)
	}
	// Without the check, any answer counts.
	server.saveDestination(t, url.Values{"id": {id}, "format": {"text"}})
	if body := test(); !strings.Contains(body, "Test sent.") || strings.Contains(body, "Last send failed") {
		t.Fatalf("testing without the receipt check = %s", body)
	}
	if missing := server.post(t, "everything", "/ui/settings/alerts/destinations/test", url.Values{"id": {"missing"}}); missing.Code != http.StatusNotFound ||
		!strings.Contains(missing.Body.String(), "That alert destination no longer exists.") {
		t.Fatalf("testing a destination that is gone = %d %s", missing.Code, missing.Body.String())
	}
}

func TestAlertTestsSayWhetherSlackAndDiscordPostedThem(t *testing.T) {
	t.Parallel()
	// Each fake answers the way the real service does, or refuses when the
	// path carries a bad token.
	slack := newFakeWebhook(t, func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/bad") {
			writer.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(writer, "invalid_token")
			return
		}
		_, _ = io.WriteString(writer, "ok")
	})
	discord := newFakeWebhook(t, func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/bad") {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(writer, `{"message": "Invalid Webhook Token", "code": 50027}`)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	parked := newFakeWebhook(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "<html>This domain is for sale</html>")
	})
	server := newAlertsTestServer(t)
	for _, test := range []struct {
		format, address, want string
	}{
		{"slack", slack.URL + "/services/good", "Test sent. Slack posted it."},
		{"slack", slack.URL + "/services/bad", "Slack did not post it: invalid_token."},
		{"slack", parked.URL + "/hook", "but not like Slack; check the URL."},
		{"discord", discord.URL + "/api/webhooks/good", "Test sent. Discord posted it."},
		{"discord", discord.URL + "/api/webhooks/bad", "Discord did not post it: Invalid Webhook Token."},
		{"discord", parked.URL + "/hook", "but not like Discord; check the URL."},
	} {
		// Headers are only for a plain webhook and ntfy, so these are dropped.
		saved := server.saveDestination(t, url.Values{"format": {test.format}, "url": {test.address}, "header_name": {"X-Extra"}, "header_value": {"1"}})
		if saved.Code != http.StatusOK {
			t.Fatalf("adding %s = %d %s", test.address, saved.Code, saved.Body.String())
		}
		destinations := server.alertsConfig().Destinations
		id := destinations[len(destinations)-1].ID
		if headers := server.savedSecrets(t, id).Headers; len(headers) != 0 {
			t.Fatalf("%s kept headers %v", test.format, headers)
		}
		if body := server.post(t, "everything", "/ui/settings/alerts/destinations/test", url.Values{"id": {id}}).Body.String(); !strings.Contains(body, test.want) {
			t.Errorf("testing %s = %s", test.address, body)
		}
	}
	_, posted := slack.last(t)
	var message struct {
		Attachments []struct {
			Blocks []struct {
				Type     string `json:"type"`
				Elements []struct {
					URL string `json:"url"`
				} `json:"elements"`
			} `json:"blocks"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(posted, &message); err != nil || len(message.Attachments) != 1 {
		t.Fatalf("Slack got %s: %v", posted, err)
	}
	blocks := message.Attachments[0].Blocks
	if last := blocks[len(blocks)-1]; last.Type != "actions" || !strings.HasSuffix(last.Elements[0].URL, "/settings?tab=alerts") {
		t.Fatalf("Slack's button leads to %+v", last)
	}
}

func TestAlertTestsSayWhatPushoverAccepted(t *testing.T) {
	t.Parallel()
	pushover := newFakeWebhook(t, func(writer http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		if request.PostForm.Get("token") != "app-token" {
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(writer, `{"token":"invalid","errors":["application token is invalid"],"status":0,"request":"r-bad"}`)
			return
		}
		_, _ = io.WriteString(writer, `{"status":1,"request":"r-good"}`)
	})
	server := newAlertsTestServer(t)
	// Point Pushover at the fake API the way sable.toml could; the dialog
	// always uses Pushover's own.
	usePushover := func(token string) string {
		t.Helper()
		destination := config.AlertDestination{ID: "phone", Format: config.AlertFormatPushover}
		if err := server.config.(settingsEditor).Update(context.Background(), func(candidate *config.Config) error {
			candidate.Alerts.Destinations = []config.AlertDestination{destination}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := server.alertSecrets.Put(context.Background(), destination.ID, alerts.Secrets{URL: pushover.URL, PushoverToken: token, PushoverUser: "user-key"}); err != nil {
			t.Fatal(err)
		}
		return server.post(t, "everything", "/ui/settings/alerts/destinations/test", url.Values{"id": {destination.ID}}).Body.String()
	}
	if body := usePushover("app-token"); !strings.Contains(body, "Test sent. Pushover accepted it as request r-good.") || !strings.Contains(body, "user key ••••-key") {
		t.Fatalf("testing Pushover = %s", body)
	}
	request, _ := pushover.last(t)
	if request.PostForm.Get("user") != "user-key" || request.PostForm.Get("title") != "Test alert: Sable" || request.PostForm.Get("url_title") != "Open Alerts" {
		t.Fatalf("Pushover got %v", request.PostForm)
	}
	if body := usePushover("wrong"); !strings.Contains(body, "Pushover did not send it: application token is invalid.") {
		t.Fatalf("testing a wrong token = %s", body)
	}
}

func TestAlertPreviewShowsEachFormatWithoutSecrets(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	preview := func(form url.Values) string {
		t.Helper()
		response := server.post(t, "everything", "/ui/settings/alerts/destinations/preview", form)
		if response.Code != http.StatusOK {
			t.Fatalf("preview %v = %d", form, response.Code)
		}
		return response.Body.String()
	}
	for _, test := range []struct {
		name    string
		form    url.Values
		want    []string
		secrets []string
	}{
		{
			"a JSON webhook with a typed Authorization header",
			url.Values{"url": {"https://hooks.example.com/hooks/private-token"}, "format": {"json"}, "header_name": {"Authorization"}, "header_value": {"Bearer secret-token"}},
			[]string{"POST https://hooks.example.com/hooks/••••oken", "Content-Type: application/json", "Authorization: ••••oken", "\n  &#34;source&#34;: &#34;sable&#34;"},
			[]string{"private-token", "secret-token"},
		},
		{
			"Discord",
			url.Values{"url": {"https://discord.com/api/webhooks/123/secret-token"}, "format": {"discord"}},
			[]string{"POST https://discord.com/api/webhooks/123/••••oken", "&#34;title&#34;: &#34;Test alert: Sable&#34;"},
			[]string{"secret-token"},
		},
		{
			"ntfy with no URL yet",
			url.Values{"format": {"text"}},
			[]string{"POST (no URL yet)", "Title: Test alert: Sable", "Content-Type: text/plain"},
			nil,
		},
		{
			"Pushover",
			url.Values{"format": {"pushover"}, "pushover_token": {"azGDORePK8gMaC0QOYAM"}, "pushover_user": {"uQiRzpo4DXghDmr9QzzfQu27"}},
			[]string{"POST https://api.pushover.net/1/messages.json", "token=••••OYAM", "user=••••Qu27", "title=Test alert: Sable", "url_title=Open Alerts", "application/x-www-form-urlencoded"},
			[]string{"azGDORePK8gMaC0QOYAM", "uQiRzpo4DXghDmr9QzzfQu27"},
		},
		{
			"browsers",
			url.Values{"format": {"browser"}},
			[]string{"POST (each browser&#39;s push service)", "encrypted for each browser", "&#34;url&#34;: &#34;/settings?tab=alerts&#34;"},
			nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := preview(test.form)
			for _, want := range test.want {
				if !strings.Contains(body, want) {
					t.Errorf("the preview lacks %q:\n%s", want, body)
				}
			}
			for _, secret := range test.secrets {
				if strings.Contains(body, secret) {
					t.Errorf("the preview shows %q", secret)
				}
			}
		})
	}

	// A saved destination previews with what is saved, and a saved header's
	// value stays hidden however harmless its name.
	server.saveDestination(t, url.Values{
		"format": {"json"}, "url": {"https://hooks.example.com/hooks/private-token"},
		"header_name": {"X-Api-Key"}, "header_value": {"key-from-vault"},
	})
	id := server.onlyDestination(t).ID
	body := preview(url.Values{"id": {id}, "format": {"json"}, "header_name": {"X-Api-Key", "X-Typed"}, "header_value": {"", "typed-value"}})
	for _, want := range []string{"POST https://hooks.example.com/hooks/••••oken", "X-Api-Key: ••••ault", "X-Typed: typed-value"} {
		if !strings.Contains(body, want) {
			t.Errorf("the saved destination's preview lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "key-from-vault") || strings.Contains(body, "private-token") {
		t.Errorf("the saved destination's preview shows a saved secret:\n%s", body)
	}
}

func TestPausingAlertsKeepsEveryDestination(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	if response := server.post(t, "everything", "/ui/settings/alerts/paused", url.Values{"paused": {"true"}}); response.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(response.Body.String(), "Add a destination first.") {
		t.Fatalf("pausing with no destination = %d %s", response.Code, response.Body.String())
	}
	server.saveDestination(t, url.Values{"format": {"text"}, "url": {"https://ntfy.sh/sable-alerts"}})
	id := server.onlyDestination(t).ID

	paused := server.post(t, "everything", "/ui/settings/alerts/paused", url.Values{"paused": {"true"}})
	body := paused.Body.String()
	if paused.Code != http.StatusOK || !strings.Contains(body, "Alerts paused.") || !strings.Contains(body, `<span class="status-badge warning">Paused</span>`) ||
		!strings.Contains(body, "<span>Resume</span>") || !server.alertsConfig().Paused {
		t.Fatalf("pausing = %d %s", paused.Code, body)
	}
	if action, details := server.lastAudit(t); action != "alerts" || details != "paused alerts" {
		t.Fatalf("audit = %q %q", action, details)
	}
	// Changing a destination leaves alerts paused, and says so.
	edited := server.saveDestination(t, url.Values{"id": {id}, "name": {"Phone"}, "format": {"text"}})
	if !strings.Contains(edited.Body.String(), "Saved Phone. Alerts are paused.") || !server.alertsConfig().Paused {
		t.Fatalf("saving while paused = %s", edited.Body.String())
	}
	resumed := server.post(t, "everything", "/ui/settings/alerts/paused", url.Values{"paused": {"false"}})
	if body := resumed.Body.String(); !strings.Contains(body, "Alerts resumed. Only alerts from now on will be sent.") || !strings.Contains(body, "<span>Pause</span>") ||
		server.alertsConfig().Paused {
		t.Fatalf("resuming = %s", body)
	}
}

// Each kind of Insights finding has its own switch under Insights Findings,
// so new devices, say, can stop alerting without leaving Settings. The switch
// changes the same setting Insights settings does: off keeps the kind in
// Insights without alerts, and on shows a hidden kind again.
func TestEachKindOfInsightFindingHasItsOwnAlertSwitch(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	if err := server.config.(settingsEditor).Update(context.Background(), func(candidate *config.Config) error {
		candidate.Insights.Findings.CheckIn.Mode = config.InsightModeOff
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	page := server.get(t, "everything", "/settings?tab=alerts", false).Body.String()
	for _, want := range []string{
		`name="insight_alert_new_device" value="true" checked`, `name="insight_alert_went_quiet" value="true" checked`,
		"Hidden in Insights.", `href="/insights?sable-command=command-page-insights-settings"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the Insights Findings group lacks %q", want)
		}
	}
	if strings.Contains(page, `name="insight_alert_check_in" value="true" checked`) || strings.Contains(page, "insight_alert_unique_coverage") {
		t.Error("a hidden kind shows as alerting, or a kind that never alerts has a switch")
	}
	form := url.Values{
		"insights": {"true"}, "backups": {"failures"}, "sign_ins_after": {"5"}, "sign_ins_within": {"10"}, "insight_kinds": {"true"},
		"insight_alert_went_quiet": {"true"}, "insight_alert_check_in": {"true"},
	}
	if saved := server.post(t, "everything", "/ui/settings/alerts/groups", form); saved.Code != http.StatusOK {
		t.Fatalf("saving = %d %s", saved.Code, saved.Body.String())
	}
	findings := server.config.Current().Config.Insights.Findings
	if findings.NewDevice.Mode != config.InsightModeShow || findings.WentQuiet.Mode != config.InsightModeAlert ||
		findings.CheckIn.Mode != config.InsightModeAlert || findings.UniqueCoverage.Mode != config.InsightModeShow {
		t.Fatalf("findings = %+v", findings)
	}
	// A kind switched off stays off rather than coming back to show.
	if err := server.config.(settingsEditor).Update(context.Background(), func(candidate *config.Config) error {
		candidate.Insights.Findings.NewApp.Mode = config.InsightModeOff
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	server.post(t, "everything", "/ui/settings/alerts/groups", form)
	if mode := server.config.Current().Config.Insights.Findings.NewApp.Mode; mode != config.InsightModeOff {
		t.Fatalf("a hidden kind switched off became %q", mode)
	}
	// A form from before the switches existed leaves the kinds alone.
	delete(form, "insight_kinds")
	delete(form, "insight_alert_went_quiet")
	server.post(t, "everything", "/ui/settings/alerts/groups", form)
	if mode := server.config.Current().Config.Insights.Findings.WentQuiet.Mode; mode != config.InsightModeAlert {
		t.Fatalf("a form without the switches changed went quiet to %q", mode)
	}
	if readOnly := server.get(t, "logs-reader", "/settings?tab=alerts", false).Body.String(); !strings.Contains(readOnly, `name="insight_alert_new_device" value="true" disabled`) {
		t.Error("an operator who cannot change settings can flip a kind's switch")
	}
}

func TestAlertGroupsAndTheFailedSignInLimitSave(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	page := server.get(t, "everything", "/settings?tab=alerts", false).Body.String()
	for group, on := range map[string]bool{"insights": true, "cluster": true, "updates": true, "integrations": true, "server": true, "sign_ins": false} {
		checked := regexp.MustCompile(`name="` + group + `" value="true" checked`).MatchString(page)
		if checked != on {
			t.Errorf("%s is switched on = %t, want %t", group, checked, on)
		}
	}
	if !strings.Contains(page, `name="backups" value="failures" checked`) {
		t.Error("backup alerts do not start with failures only")
	}

	saved := server.post(t, "everything", "/ui/settings/alerts/groups", url.Values{
		"cluster": {"true"}, "updates": {"true"}, "server": {"true"}, "sign_ins": {"true"},
		"backups": {"all"}, "sign_ins_after": {"3"}, "sign_ins_within": {"15"},
	})
	if saved.Code != http.StatusOK || !strings.Contains(saved.Body.String(), "Saved which alerts Sable sends.") {
		t.Fatalf("saving groups = %d %s", saved.Code, saved.Body.String())
	}
	want := config.Alerts{
		Send:    config.AlertSwitches{Cluster: true, Updates: true, Backups: config.AlertBackupsAll, Server: true, SignIns: true},
		SignIns: config.AlertSignIns{After: 3, Within: config.Duration{Duration: 15 * time.Minute}},
	}
	if configuration := server.alertsConfig(); configuration.Send != want.Send || configuration.SignIns != want.SignIns {
		t.Fatalf("alerts = %+v, want %+v", configuration, want)
	}
	if action, details := server.lastAudit(t); action != "alerts" || details != "changed which alerts are sent" {
		t.Fatalf("audit = %q %q", action, details)
	}
	for _, test := range []struct {
		name  string
		value url.Values
		want  string
	}{
		{"a backup choice that does not exist", url.Values{"backups": {"sometimes"}}, "Choose which backups send alerts."},
		{"no failures", url.Values{"sign_ins_after": {"0"}}, "Failed sign-ins must be a number from 1 to 1000."},
		{"a word for failures", url.Values{"sign_ins_after": {"five"}}, "Failed sign-ins must be a number from 1 to 1000."},
		{"no minutes", url.Values{"sign_ins_within": {"0"}}, "Minutes must be a number from 1 to 1440, which is a day."},
		{"more than a day", url.Values{"sign_ins_within": {"1441"}}, "Minutes must be a number from 1 to 1440, which is a day."},
	} {
		t.Run(test.name, func(t *testing.T) {
			form := url.Values{"backups": {"failures"}, "sign_ins_after": {"5"}, "sign_ins_within": {"10"}}
			for name, values := range test.value {
				form[name] = values
			}
			response := server.post(t, "everything", "/ui/settings/alerts/groups", form)
			if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("saving = %d %s", response.Code, response.Body.String())
			}
		})
	}
	if configuration := server.alertsConfig(); configuration.Send != want.Send || configuration.SignIns != want.SignIns {
		t.Fatalf("a rejected form changed alerts to %+v", configuration)
	}
}

func TestChangingAlertsNeedsSettingsWrite(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	server.saveDestination(t, url.Values{"format": {"text"}, "url": {"https://ntfy.sh/sable-alerts"}})
	id := server.onlyDestination(t).ID
	for _, route := range []struct {
		method, path string
		form         url.Values
	}{
		{http.MethodGet, "/ui/settings/alerts/destinations/form", nil},
		{http.MethodGet, "/ui/settings/alerts/destinations/form?id=" + id, nil},
		{http.MethodGet, "/ui/settings/alerts/browsers/key", nil},
		{http.MethodPost, "/ui/settings/alerts/destinations/save", url.Values{"format": {"text"}, "url": {"https://ntfy.sh/x"}}},
		{http.MethodPost, "/ui/settings/alerts/destinations/remove", url.Values{"id": {id}}},
		{http.MethodPost, "/ui/settings/alerts/destinations/test", url.Values{"id": {id}}},
		{http.MethodPost, "/ui/settings/alerts/destinations/preview", url.Values{"id": {id}}},
		{http.MethodPost, "/ui/settings/alerts/paused", url.Values{"paused": {"true"}}},
		{http.MethodPost, "/ui/settings/alerts/groups", url.Values{"backups": {"off"}, "sign_ins_after": {"5"}, "sign_ins_within": {"10"}}},
		{http.MethodPost, "/ui/settings/alerts/browsers", url.Values{"push_subscription": {"{}"}}},
		{http.MethodPost, "/ui/settings/alerts/browsers/remove", url.Values{"browser": {"x"}}},
	} {
		for _, session := range []string{"logs-reader", "zones-only"} {
			var response *httptest.ResponseRecorder
			if route.method == http.MethodGet {
				response = server.get(t, session, route.path, true)
			} else {
				response = server.post(t, session, route.path, route.form)
			}
			if response.Code != http.StatusForbidden {
				t.Errorf("%s %s %s = %d, want %d", session, route.method, route.path, response.Code, http.StatusForbidden)
			}
		}
	}
	if configuration := server.alertsConfig(); len(configuration.Destinations) != 1 || configuration.Paused || configuration.Send.Backups != config.AlertBackupsFailures {
		t.Fatalf("an operator without settings write changed alerts to %+v", configuration)
	}
}

func TestAlertBrowsersTurnOnAndGetTests(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	service := newFakePushService(t)
	server.alerts.Browsers.Client = service.Client()

	// Browsers subscribe with the push key, which only operators who can
	// change settings may read.
	answer := server.get(t, "everything", "/ui/settings/alerts/browsers/key", false)
	var body struct{ Key string }
	if err := json.Unmarshal(answer.Body.Bytes(), &body); err != nil || answer.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("push key = %s %v", answer.Body.String(), answer.Header())
	}
	if want, _ := webpush.PublicKey(server.key); body.Key != want {
		t.Fatalf("push key = %q, want %q", body.Key, want)
	}

	// With no destination sending to browsers, turning one on adds it.
	added := server.subscribeBrowser(t, "everything", service.URL+"/push/one")
	if body := added.Body.String(); added.Code != http.StatusOK || !strings.Contains(body, "This browser will get alerts. Browsers is now one of your destinations.") ||
		!strings.Contains(body, "Chrome on macOS") || !strings.Contains(body, "by operator") {
		t.Fatalf("turning on a browser = %d %s", added.Code, body)
	}
	if destination := server.onlyDestination(t); destination.ID != "browser" || destination.Format != config.AlertFormatBrowser {
		t.Fatalf("turning on a browser added %+v", destination)
	}
	if action, details := server.lastAudit(t); action != "alerts" || details != "turned on alerts in Chrome on macOS, adding Browsers to the destinations" {
		t.Fatalf("audit = %q %q", action, details)
	}
	if bad := server.subscribeBrowser(t, "everything", "http://not-https.example/push"); bad.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(bad.Body.String(), "Push endpoint must be an https URL.") {
		t.Fatalf("turning on a browser with an http endpoint = %d %s", bad.Code, bad.Body.String())
	}
	// A second browser joins the same destination.
	if second := server.subscribeBrowser(t, "everything", service.URL+"/push/two"); strings.Contains(second.Body.String(), "Browsers is now one of your destinations.") {
		t.Fatal("a second browser added a second destination")
	}
	if destinations := server.alertsConfig().Destinations; len(destinations) != 1 {
		t.Fatalf("destinations = %+v", destinations)
	}
	panel := server.get(t, "everything", "/settings?tab=alerts", false).Body.String()
	if !strings.Contains(panel, "Browsers getting alerts") || !strings.Contains(panel, "2 browsers") || !strings.Contains(panel, `<span class="status-badge success">On</span>`) {
		t.Fatal("the tab does not list the browsers that turned alerts on")
	}

	tested := server.post(t, "everything", "/ui/settings/alerts/destinations/test", url.Values{"id": {"browser"}})
	if !strings.Contains(tested.Body.String(), "Test sent to 2 browsers.") || service.count() != 2 {
		t.Fatalf("testing browsers = %s", tested.Body.String())
	}
	push := service.pushes[0]
	if push.Header.Get("Content-Encoding") != "aes128gcm" || !strings.HasPrefix(push.Header.Get("Authorization"), "vapid t=") || push.Header.Get("TTL") != "86400" {
		t.Fatalf("push headers = %v", push.Header)
	}

	// Browsers their push service calls gone are forgotten.
	service.goAway()
	gone := server.post(t, "everything", "/ui/settings/alerts/destinations/test", url.Values{"id": {"browser"}}).Body.String()
	if !strings.Contains(gone, "No browser has turned alerts on yet; use Turn On in This Browser first.") {
		t.Fatalf("testing gone browsers = %s", gone)
	}
	if subscriptions, _ := server.store.PushSubscriptions(context.Background()); len(subscriptions) != 0 {
		t.Fatalf("gone browsers were kept: %+v", subscriptions)
	}
}

func TestAlertBrowsersCanBeRemoved(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	subscription := webpush.Subscription{Endpoint: "https://push.example/one", P256DH: "k", Auth: "a", Label: "Safari on iPhone", CreatedAt: time.Now()}
	if err := server.store.SavePushSubscription(context.Background(), subscription); err != nil {
		t.Fatal(err)
	}
	removed := server.post(t, "everything", "/ui/settings/alerts/browsers/remove", url.Values{"browser": {subscription.ID()}})
	if removed.Code != http.StatusOK || !strings.Contains(removed.Body.String(), "Safari on iPhone will no longer get alerts.") {
		t.Fatalf("removing = %d %s", removed.Code, removed.Body.String())
	}
	if subscriptions, _ := server.store.PushSubscriptions(context.Background()); len(subscriptions) != 0 {
		t.Fatalf("after removing = %+v", subscriptions)
	}
	if action, details := server.lastAudit(t); action != "alerts" || details != "stopped alerts in Safari on iPhone" {
		t.Fatalf("audit = %q %q", action, details)
	}
	if again := server.post(t, "everything", "/ui/settings/alerts/browsers/remove", url.Values{"browser": {subscription.ID()}}); again.Code != http.StatusNotFound ||
		!strings.Contains(again.Body.String(), "That browser was already removed.") {
		t.Fatalf("removing again = %d %s", again.Code, again.Body.String())
	}
}

// Browsers get alerts only through the Browsers destination, so removing it
// forgets them too instead of leaving them subscribed to nothing.
func TestRemovingBrowsersForgetsItsBrowsers(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	server.saveDestination(t, url.Values{"format": {"browser"}})
	subscription := webpush.Subscription{Endpoint: "https://push.example/one", P256DH: "k", Auth: "a", Label: "Safari on iPhone", CreatedAt: time.Now()}
	if err := server.store.SavePushSubscription(context.Background(), subscription); err != nil {
		t.Fatal(err)
	}
	panel := server.get(t, "everything", "/settings?tab=alerts", false).Body.String()
	row := panel[strings.Index(panel, `id="alert-destination-browser"`):]
	if row = row[:strings.Index(row, "</article>")]; !strings.Contains(row, "Safari on iPhone") || !strings.Contains(row, "Turn On in This Browser") {
		t.Fatal("the Browsers row does not hold its browsers and the button that adds this one")
	}
	if removed := server.post(t, "everything", "/ui/settings/alerts/destinations/remove", url.Values{"id": {"browser"}}); removed.Code != http.StatusOK {
		t.Fatalf("removing Browsers = %d %s", removed.Code, removed.Body.String())
	}
	if subscriptions, _ := server.store.PushSubscriptions(context.Background()); len(subscriptions) != 0 {
		t.Fatalf("browsers kept after removing Browsers: %+v", subscriptions)
	}
}

func TestOnlyOneAlertDestinationPushesToBrowsers(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	added := server.saveDestination(t, url.Values{"format": {"browser"}})
	if added.Code != http.StatusOK || !strings.Contains(added.Body.String(), "Added Browsers. Turn on alerts in this browser to start getting them.") {
		t.Fatalf("adding browsers = %d %s", added.Code, added.Body.String())
	}
	if destination := server.onlyDestination(t); destination.ID != "browser" || destination.Format != config.AlertFormatBrowser {
		t.Fatalf("added %+v", destination)
	}
	if again := server.saveDestination(t, url.Values{"format": {"browser"}}); again.Code != http.StatusConflict ||
		!strings.Contains(again.Body.String(), "Another destination already sends to your browsers.") {
		t.Fatalf("adding a second browser destination = %d %s", again.Code, again.Body.String())
	}
	form := server.get(t, "everything", "/ui/settings/alerts/destinations/form", true).Body.String()
	if !strings.Contains(form, `value="browser" disabled`) || !strings.Contains(form, "Another destination already sends to your browsers.") {
		t.Fatal("the Add Destination form offers Browsers twice")
	}
	if own := server.get(t, "everything", "/ui/settings/alerts/destinations/form?id=browser", true).Body.String(); strings.Contains(own, `value="browser" disabled`) {
		t.Fatal("the browser destination cannot keep its own format")
	}
}

// The Insights bell opens Insights settings, and says whether Insights
// findings go out as alerts.
func TestInsightsBellSaysWhetherAlertsAreOn(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	overview := func(session string) string {
		t.Helper()
		return server.get(t, session, "/ui/insights/overview?range=day", true).Body.String()
	}
	const bell = `data-dialog-open="insight-settings-dialog" aria-label="Insights settings, alerts `
	if body := overview("everything"); !strings.Contains(body, bell+`off"`) {
		t.Fatal("the bell does not say alerts are off")
	}
	if page := server.get(t, "everything", "/insights?range=day", false).Body.String(); strings.Contains(page, "insight-alerts-dialog") {
		t.Fatal("the Insights page still carries the old alert dialog")
	}
	server.saveDestination(t, url.Values{"format": {"text"}, "url": {"https://ntfy.sh/sable-alerts"}})
	if body := overview("everything"); !strings.Contains(body, bell+`on"`) {
		t.Fatal("the bell does not say alerts are on")
	}
	server.post(t, "everything", "/ui/settings/alerts/paused", url.Values{"paused": {"true"}})
	if body := overview("logs-reader"); !strings.Contains(body, bell+`paused"`) {
		t.Fatal("the bell does not say alerts are paused")
	}
}

func TestAlertsStateSaysWhetherAnyDestinationCanSend(t *testing.T) {
	t.Parallel()
	ntfy := config.AlertDestination{ID: "phone", Format: config.AlertFormatText, URL: "https://ntfy.sh/x"}
	unsaved := config.AlertDestination{ID: "chat", Format: config.AlertFormatSlack}
	pushover := config.AlertDestination{ID: "pocket", Format: config.AlertFormatPushover, PushoverToken: "token"}
	browsers := config.AlertDestination{ID: "browser", Format: config.AlertFormatBrowser}
	for _, test := range []struct {
		name         string
		paused       bool
		destinations []config.AlertDestination
		browsers     int
		push         bool
		want         pages.AlertsState
	}{
		{"nowhere to send", false, nil, 0, true, pages.AlertsOff},
		{"a destination that can send", false, []config.AlertDestination{unsaved, ntfy}, 0, true, pages.AlertsOn},
		{"paused", true, []config.AlertDestination{ntfy}, 0, true, pages.AlertsPaused},
		{"a URL never saved", false, []config.AlertDestination{unsaved}, 0, true, pages.AlertsOff},
		{"Pushover with no user key", false, []config.AlertDestination{pushover}, 0, true, pages.AlertsOff},
		{"browsers none of which turned alerts on", false, []config.AlertDestination{browsers}, 0, true, pages.AlertsOff},
		{"browsers that turned alerts on", false, []config.AlertDestination{browsers}, 2, true, pages.AlertsOn},
		{"browsers on a server that cannot push", false, []config.AlertDestination{browsers}, 2, false, pages.AlertsOff},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := alertsState(config.Alerts{Paused: test.paused}, test.destinations, test.browsers, test.push); got != test.want {
				t.Fatalf("alertsState = %q, want %q", got, test.want)
			}
		})
	}
}

func TestNewAlertDestinationsGetAnIDNoOtherHas(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool)
	for range 100 {
		id := newAlertDestinationID(nil, config.AlertFormatText)
		if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(id) || seen[id] {
			t.Fatalf("id %q repeats or is not sixteen hex characters", id)
		}
		seen[id] = true
	}
	if id := newAlertDestinationID(nil, config.AlertFormatBrowser); id != "browser" {
		t.Fatalf("the browser destination is called %q", id)
	}
	taken := []config.AlertDestination{{ID: "browser", Format: config.AlertFormatJSON}}
	if id := newAlertDestinationID(taken, config.AlertFormatBrowser); id == "browser" || len(id) != 16 {
		t.Fatalf("with browser taken, the browser destination is called %q", id)
	}
}
