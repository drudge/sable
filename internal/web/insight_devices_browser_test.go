//go:build browser

package web

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

// Narrow the Insights Devices list by search and filters, and keep them
// through a range change and a reload.
func TestBrowserInsightDeviceFilters(t *testing.T) {
	app := newInsightsTestServer(t)
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/insight-devices.cjs", server.URL, app.sessionCookieName())
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser insight device filters: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
