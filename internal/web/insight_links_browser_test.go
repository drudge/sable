//go:build browser

package web

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

// Open findings, devices, and apps at their own addresses: from a click, from
// Back and Forward, and from a link opened fresh.
func TestBrowserInsightLinks(t *testing.T) {
	app := newInsightsTestServer(t)
	var events []querylog.Event
	for index, name := range []string{"api-global.netflix.com.", "api-global.netflix.com.", "www.netflix.com."} {
		events = append(events, querylog.Event{
			OccurredAt: app.now.Add(-time.Duration(30+index) * time.Minute), ClientIP: "10.0.0.5", Name: name, RecordType: dns.TypeA,
			Class: dns.ClassINET, ResponseCode: dns.RcodeSuccess, Source: querylog.SourceUpstream, Protocol: "UDP",
		})
	}
	if err := app.store.WriteQueryEvents(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/insight-links.cjs", server.URL, app.sessionCookieName())
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser insight links: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
