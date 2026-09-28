//go:build browser

package web

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

// Turn Insights off from Settings > General, cancel once, then turn it off
// with its data deleted and back on.
func TestBrowserInsightsSwitch(t *testing.T) {
	app := newInsightsTestServer(t)
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/insights-switch.cjs", server.URL, app.sessionCookieName())
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser insights switch: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
	if !app.insightsEnabled() {
		t.Fatal("Insights did not end up back on")
	}
	if summary, err := app.store.InsightDataSummary(context.Background()); err != nil || summary.Addresses != 0 {
		t.Fatalf("Insights data = %+v, %v; want it deleted", summary, err)
	}
}
