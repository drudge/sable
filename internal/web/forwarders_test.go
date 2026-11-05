package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
)

// forwarderTestStats is a DNS handler that also reports on its forwarders.
type forwarderTestStats struct {
	testStats
	tested *bool
}

func (forwarderTestStats) ForwarderStats() []dnsserver.ForwarderStats {
	now := time.Now()
	return []dnsserver.ForwarderStats{
		{Forwarder: "https://cloudflare-dns.com/dns-query (1.1.1.1)", Attempts: 1210, Answers: 1204, Timeouts: 6,
			Median: 23400 * time.Microsecond, P95: 61 * time.Millisecond, Samples: 128, LastUsed: now},
		{Forwarder: "tls://dns.quad9.net (9.9.9.9)", Attempts: 4, Errors: 4, CoolingUntil: now.Add(5 * time.Second),
			LastError: "tls: failed to verify certificate", LastErrorAt: now.Add(-time.Minute)},
		{Forwarder: "udp://192.0.2.53:53", Route: "corp.example"},
	}
}

func (stats forwarderTestStats) TestForwarders(context.Context) []dnsserver.ForwarderTest {
	*stats.tested = true
	return []dnsserver.ForwarderTest{
		{Forwarder: "https://cloudflare-dns.com/dns-query (1.1.1.1)", OK: true, ResponseTime: 8200 * time.Microsecond,
			ResponseCode: "NOERROR", AuthenticatedData: true, Validates: "yes"},
		{Forwarder: "tls://dns.quad9.net (9.9.9.9)", Error: "no answer in time"},
	}
}

func newForwarderTestServer(t *testing.T, tested *bool) *Server {
	t.Helper()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		forwarderTestStats{testStats: testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}}, tested: tested},
		configuration, configuration.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestSettingsShowForwarderActivity(t *testing.T) {
	t.Parallel()
	var tested bool
	server := newForwarderTestServer(t, &tested)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/settings?tab=recursion", nil))
	body := response.Body.String()
	for _, want := range []string{
		`name="forwarder_order"`, `<option value="round_robin" selected>`,
		"On This Node", `<th scope="col" class="right-cell">95th pct</th>`, `<td class="right-cell">1,204</td>`, `<td class="right-cell">23 ms</td>`,
		`<td class="right-cell">61 ms</td>`, `title="6 timeouts, 0 errors">6</td>`, "Answering",
		"Tried last", "tls: failed to verify certificate", "No traffic yet", "Cached answers and tests don't count", "For corp.example",
		"1,204 answered · 23 ms median · 61 ms 95th pct · 6 failed",
		`hx-post="/ui/settings/forwarders/test"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page lacks %q", want)
		}
	}
	if tested {
		t.Fatal("rendering the page ran a forwarder test")
	}
}

func TestForwarderTestRoute(t *testing.T) {
	t.Parallel()
	var tested bool
	server := newForwarderTestServer(t, &tested)
	request := httptest.NewRequest(http.MethodPost, "/ui/settings/forwarders/test", strings.NewReader(url.Values{}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK || !tested {
		t.Fatalf("test route = %d, tested %v: %s", response.Code, tested, body)
	}
	// The test redraws the same table with each result in its Test column,
	// rather than listing the forwarders a second time.
	for _, want := range []string{`id="forwarder-activity-list"`, "Tested just now", "<span>8.2 ms</span>", "Validates DNSSEC",
		"<span>Failed</span>", "no answer in time", "Test: 8.2 ms · Validates DNSSEC", `<td class="right-cell">1,204</td>`} {
		if !strings.Contains(body, want) {
			t.Errorf("test results lack %q: %s", want, body)
		}
	}
	if rows := strings.Count(body, "<tr><td"); rows != 3 {
		t.Errorf("test drew %d table rows, want the 3 forwarders once each", rows)
	}
	if strings.Count(body, `class="forwarder-test passed"`)+strings.Count(body, `class="forwarder-test failed"`) != 4 {
		t.Errorf("want the two tested forwarders marked once in the table and once in the phone list: %s", body)
	}
}

func TestForwarderTestRouteIsReplicaLocal(t *testing.T) {
	t.Parallel()
	for _, route := range routeTable() {
		if route.pattern == "POST /ui/settings/forwarders/test" {
			if !route.replicaLocal {
				t.Fatal("each node tests its own forwarders, so a replica must be able to run the test")
			}
			return
		}
	}
	t.Fatal("forwarder test route is not registered")
}
