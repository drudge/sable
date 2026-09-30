//go:build browser

package web

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
	"github.com/miekg/dns"
)

// Narrow the Insights Apps list by search, category, and failures, and open a
// failing app's drawer.
func TestBrowserInsightAppFilters(t *testing.T) {
	app := newInsightsTestServer(t)
	var events []querylog.Event
	lookup := func(offset time.Duration, client, name string, source querylog.Source) {
		events = append(events, querylog.Event{
			OccurredAt: app.now.Add(-offset), ClientIP: client, Name: name, RecordType: dns.TypeA,
			Class: dns.ClassINET, ResponseCode: dns.RcodeRefused, Source: source, Protocol: "UDP",
		})
	}
	for index := range 5 {
		lookup(time.Duration(30+index)*time.Minute, "10.0.0.5", "www.netflix.com.", querylog.SourceUpstream)
	}
	lookup(20*time.Minute, "10.0.0.9", "eu.tectonic.remarkable.com.", querylog.SourceError)
	if err := app.store.WriteQueryEvents(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/insight-apps.cjs", server.URL, app.sessionCookieName())
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser insight app filters: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
