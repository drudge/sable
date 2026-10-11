//go:build browser

package web

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/insights"
)

// Open a finding's hide menu, back out of it with Escape, mark the finding
// normal, and hide another from its row.
func TestBrowserInsightHideMenu(t *testing.T) {
	app := newInsightsTestServer(t)
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/insight-hide.cjs", server.URL, app.sessionCookieName())
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser insight hide: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
	feedback, err := app.store.InsightFeedback(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	normal, snoozed := 0, 0
	for _, entry := range feedback {
		switch {
		case entry.Action == insights.FeedbackNormal && strings.HasPrefix(entry.FindingID, "blocking.past-block/"):
			normal++
		case entry.Action == insights.FeedbackSnooze:
			snoozed++
		}
	}
	if len(feedback) != 2 || normal != 1 || snoozed != 1 {
		t.Fatalf("stored feedback = %+v", feedback)
	}
}
