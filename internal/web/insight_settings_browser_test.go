//go:build browser

package web

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"

	"github.com/drudge/sable/internal/config"
)

// Open Insights settings from the bell, switch a kind to Show only with the
// mouse and another with the keyboard, and save.
func TestBrowserInsightSettings(t *testing.T) {
	app := newInsightsTestServer(t)
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/insight-settings.cjs", server.URL, app.sessionCookieName())
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser insight settings: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
	findings := app.config.Current().Config.Insights.Findings
	if findings.WentQuiet.Mode != config.InsightModeShow || findings.NewApp.Mode != config.InsightModeOff {
		t.Fatalf("saved settings = %+v", findings)
	}
	if findings.UnusualHours.MinimumLookups != 45 {
		t.Fatalf("unusual hours limit = %d, want 45", findings.UnusualHours.MinimumLookups)
	}
}
