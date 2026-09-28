//go:build browser

package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

// TestBrowserAlertsTab drives Settings > Alerts in a real browser against the
// console with alerts wired: it adds an ntfy destination, previews it, sees it
// listed, sends it a test, and saves the groups.
func TestBrowserAlertsTab(t *testing.T) {
	var published atomic.Int32
	ntfy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		published.Add(1)
		_, _ = io.WriteString(writer, `{"id":"browserTest01","time":1790289679,"event":"message","topic":"sable-alerts"}`)
	}))
	defer ntfy.Close()
	app := newAlertsTestServer(t)
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/alerts.cjs", server.URL, app.sessionCookieName(), ntfy.URL)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser alerts tab: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}

	destination := app.onlyDestination(t)
	if destination.Name != "Phone" || destination.Format != config.AlertFormatText || !destination.NtfyReceipt || destination.HasSecrets() {
		t.Fatalf("the browser saved %+v", destination)
	}
	if secrets := app.savedSecrets(t, destination.ID); secrets.URL != ntfy.URL+"/sable-alerts" {
		t.Fatalf("the vault holds %+v", secrets)
	}
	if published.Load() != 1 {
		t.Fatalf("ntfy got %d alerts, want the one test", published.Load())
	}
	if alerts := app.alertsConfig(); !alerts.Send.SignIns || alerts.SignIns.After != 3 || alerts.SignIns.Within.Duration != 15*time.Minute {
		t.Fatalf("the browser saved groups %+v", alerts)
	}
}
