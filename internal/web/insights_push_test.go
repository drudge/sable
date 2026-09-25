package web

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/webpush"
)

// fixedPushKeys stands in for the vault-backed key store.
type fixedPushKeys struct{ key *ecdsa.PrivateKey }

func (keys fixedPushKeys) PushKey(context.Context) (*ecdsa.PrivateKey, error) { return keys.key, nil }

// fakePushService is a browser's push service: it records each push and can
// be told the subscription is gone.
type fakePushService struct {
	*httptest.Server
	mu     sync.Mutex
	pushes []*http.Request
	gone   bool
}

func newFakePushService(t *testing.T) *fakePushService {
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

// browserSubscription is what a browser's PushManager hands the page.
func browserSubscription(t *testing.T, endpoint string) string {
	t.Helper()
	browser, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(map[string]any{
		"endpoint": endpoint,
		"keys": map[string]string{
			"p256dh": base64.RawURLEncoding.EncodeToString(browser.PublicKey().Bytes()),
			"auth":   base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")),
		},
	})
	return string(encoded)
}

func TestInsightAlertsPushToBrowsersThatTurnThemOn(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	key, err := webpush.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	service := newFakePushService(t)
	server.SetPushKeys(fixedPushKeys{key})
	server.pushClient = service.Client()
	ctx := context.Background()

	// Browser alerts count as off until a browser turns them on.
	server.post(t, "everything", "/ui/insights/alerts", url.Values{"format": {"browser"}})
	if overview := server.get(t, "everything", "/ui/insights/overview?range=day", true).Body.String(); !strings.Contains(overview, `aria-label="Alerts off"`) {
		t.Fatal("browser alerts with no browsers count as on")
	}
	if tested := server.post(t, "everything", "/ui/insights/alerts/test", url.Values{}); !strings.Contains(tested.Body.String(), "no browser has turned alerts on") {
		t.Fatalf("testing with no browsers = %s", tested.Body.String())
	}

	answer := server.get(t, "everything", "/ui/insights/alerts/browsers/key", false)
	var body struct{ Key string }
	if err := json.Unmarshal(answer.Body.Bytes(), &body); err != nil || body.Key == "" {
		t.Fatalf("push key = %s", answer.Body.String())
	}
	if want, _ := webpush.PublicKey(key); body.Key != want {
		t.Fatalf("push key = %q, want %q", body.Key, want)
	}
	if response := server.get(t, "logs-reader", "/ui/insights/alerts/browsers/key", false); response.Code != http.StatusForbidden {
		t.Fatalf("reading the push key without settings write = %d", response.Code)
	}

	// Turning a browser on from another kind switches alerts to browsers.
	server.post(t, "everything", "/ui/insights/alerts", url.Values{"url": {"https://ntfy.sh/topic"}, "format": {"text"}})
	subscribe := func(endpoint string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/ui/insights/alerts/browsers",
			strings.NewReader(url.Values{"push_subscription": {browserSubscription(t, endpoint)}}.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		request.Header.Set("X-CSRF-Token", "csrf-token")
		request.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0 Safari/537.36")
		request.AddCookie(&http.Cookie{Name: server.sessionCookieName(), Value: "everything"})
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response
	}
	added := subscribe(service.URL + "/push/one")
	if added.Code != http.StatusOK || !strings.Contains(added.Body.String(), "This browser will get alerts.") || !strings.Contains(added.Body.String(), "Chrome on macOS") {
		t.Fatalf("subscribing = %d %s", added.Code, added.Body.String())
	}
	if webhook := server.config.Current().Config.Insights.Webhook; webhook.Format != config.InsightsWebhookBrowser || webhook.URL != "" {
		t.Fatalf("webhook after subscribing = %+v", webhook)
	}
	if bad := subscribe("http://not-https.example/push"); bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("subscribing with an http endpoint = %d", bad.Code)
	}
	if overview := server.get(t, "everything", "/ui/insights/overview?range=day", true).Body.String(); !strings.Contains(overview, `aria-label="Alerts on"`) {
		t.Fatal("the bell does not say browser alerts are on")
	}

	tested := server.post(t, "everything", "/ui/insights/alerts/test", url.Values{})
	if !strings.Contains(tested.Body.String(), "Test sent to 1 browser.") || service.count() != 1 {
		t.Fatalf("testing = %s", tested.Body.String())
	}
	push := service.pushes[0]
	if push.Header.Get("Content-Encoding") != "aes128gcm" || !strings.HasPrefix(push.Header.Get("Authorization"), "vapid t=") || push.Header.Get("TTL") != "86400" {
		t.Fatalf("push headers = %v", push.Header)
	}

	// New findings go to the browser like any other destination.
	now := time.Now()
	if err := server.sendInsightAlerts(ctx, now); err != nil {
		t.Fatal(err)
	}
	news := server.insightNews(ctx, now)
	if len(news) == 0 {
		t.Fatal("the test network has no news to alert about")
	}
	if err := server.store.ForgetInsightsNotified(ctx, insightAlertTarget("browser"), []string{news[0].ID}); err != nil {
		t.Fatal(err)
	}
	before := service.count()
	if err := server.sendInsightAlerts(ctx, now.Add(insightAlertInterval)); err != nil {
		t.Fatal(err)
	}
	if service.count() != before+1 {
		t.Fatalf("a new finding made %d pushes", service.count()-before)
	}

	// A browser its push service calls gone is forgotten.
	service.mu.Lock()
	service.gone = true
	service.mu.Unlock()
	if tested := server.post(t, "everything", "/ui/insights/alerts/test", url.Values{}); !strings.Contains(tested.Body.String(), "no browser has turned alerts on") {
		t.Fatalf("testing a gone browser = %s", tested.Body.String())
	}
	if subscriptions, _ := server.store.PushSubscriptions(ctx); len(subscriptions) != 0 {
		t.Fatalf("a gone browser was kept: %+v", subscriptions)
	}
}

func TestInsightAlertBrowsersCanBeRemoved(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	key, _ := webpush.GenerateKey()
	server.SetPushKeys(fixedPushKeys{key})
	subscription := webpush.Subscription{Endpoint: "https://push.example/one", P256DH: "k", Auth: "a", Label: "Safari on iPhone", CreatedAt: time.Now()}
	if err := server.store.SavePushSubscription(context.Background(), subscription); err != nil {
		t.Fatal(err)
	}
	if response := server.post(t, "logs-reader", "/ui/insights/alerts/browsers/remove", url.Values{"browser": {subscription.ID()}}); response.Code != http.StatusForbidden {
		t.Fatalf("removing without settings write = %d", response.Code)
	}
	removed := server.post(t, "everything", "/ui/insights/alerts/browsers/remove", url.Values{"browser": {subscription.ID()}})
	if !strings.Contains(removed.Body.String(), "Safari on iPhone will no longer get alerts.") {
		t.Fatalf("removing = %s", removed.Body.String())
	}
	if subscriptions, _ := server.store.PushSubscriptions(context.Background()); len(subscriptions) != 0 {
		t.Fatalf("after removing = %+v", subscriptions)
	}
}

func TestServiceWorkerAndManifestAreServedWithoutSigningIn(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	worker := server.get(t, "", "/sw.js", false)
	if worker.Code != http.StatusOK || !strings.Contains(worker.Body.String(), `addEventListener("push"`) ||
		!strings.HasPrefix(worker.Header().Get("Content-Type"), "text/javascript") || worker.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("service worker = %d %v", worker.Code, worker.Header())
	}
	manifest := server.get(t, "", "/manifest.webmanifest", false)
	var described struct {
		Display string `json:"display"`
		Icons   []struct {
			Source string `json:"src"`
		} `json:"icons"`
	}
	if err := json.Unmarshal(manifest.Body.Bytes(), &described); err != nil || described.Display != "standalone" || len(described.Icons) == 0 {
		t.Fatalf("manifest = %d %s", manifest.Code, manifest.Body.String())
	}
}

func TestBrowserLabelsNameTheBrowserAndSystem(t *testing.T) {
	t.Parallel()
	for userAgent, want := range map[string]string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1": "Safari on iPhone",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0 Safari/537.36 Edg/152.0":                   "Edge on Windows",
		"Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0":                                                                  "Firefox on Linux",
		"Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0 Mobile Safari/537.36":                                "Chrome on Android",
		"curl/8.7.1": "A browser",
	} {
		if got := browserLabel(userAgent); got != want {
			t.Errorf("browserLabel(%q) = %q, want %q", userAgent, got, want)
		}
	}
}
