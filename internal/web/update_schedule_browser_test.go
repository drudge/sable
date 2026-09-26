//go:build browser

package web

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

// Pick a weekly update check on Friday evening in Settings > General, seeing
// the day and time come and go with the schedule, and save it.
func TestBrowserUpdateSchedule(t *testing.T) {
	app := newInsightsTestServer(t)
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/update-schedule.cjs", server.URL, app.sessionCookieName())
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser update schedule: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
	if preferences := app.config.Current().Config.Updates; !preferences.CheckOnLogin || preferences.CheckSchedule != "weekly" ||
		preferences.CheckDay != "friday" || preferences.CheckAt != "18:30" {
		t.Fatalf("saved update preferences = %+v", preferences)
	}
}
