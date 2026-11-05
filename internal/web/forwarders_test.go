package web

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
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

// forwarderTestConfig saves the two forwarders forwarderTestStats reports
// on, plus one it has no numbers for yet.
func forwarderTestConfig() config.Config {
	configuration := config.Defaults()
	configuration.Resolver.Forwarders = []string{"https://cloudflare-dns.com/dns-query (1.1.1.1)", "tls://dns.quad9.net (9.9.9.9)", "8.8.8.8"}
	return configuration
}

func newForwarderTestServer(t *testing.T, tested *bool) *Server {
	t.Helper()
	server, _ := newForwarderTestServerWithConfig(t, tested)
	return server
}

func newForwarderTestServerWithConfig(t *testing.T, tested *bool) (*Server, *editableTestConfiguration) {
	t.Helper()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: forwarderTestConfig(), Revision: 1}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		forwarderTestStats{testStats: testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}}, tested: tested},
		configuration, configuration.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	return server, configuration
}

func TestSettingsShowForwarderEditor(t *testing.T) {
	t.Parallel()
	var tested bool
	server := newForwarderTestServer(t, &tested)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/settings?tab=recursion", nil))
	body := response.Body.String()
	for _, want := range []string{
		`name="forwarder_order"`, `<option value="round_robin" selected>`, "data-forwarder-editor", "Add Forwarder", "Edit as Text",
		`<th scope="col" class="right-cell">95th pct</th>`, `<td class="right-cell" data-label="Answered">1,204</td>`,
		`<td class="right-cell" data-label="Median">23 ms</td>`, `title="6 timeouts, 0 errors">6</td>`, "Answering",
		"Tried last", "tls: failed to verify certificate", "No traffic yet", "Cached answers and tests don't count",
		"DNS over HTTPS", "DNS over TLS", "Routes and forwarder zones", "Plain DNS · for corp.example",
		`hx-post="/ui/settings/forwarders/test"`, `id="add-forwarder-dialog"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page lacks %q", want)
		}
	}
	// Each saved forwarder is one form field, in saved order; the route's
	// forwarder is shown but isn't a resolver forwarder, and the text editor
	// starts disabled so it isn't sent twice.
	// The row template is inert, so it sends nothing.
	rendered := regexp.MustCompile(`(?s)<template data-forwarder-row-template>.*?</template>`).ReplaceAllString(body, "")
	fields := regexp.MustCompile(`<input type="hidden" name="forwarders" value="([^"]*)"`).FindAllStringSubmatch(rendered, -1)
	var values []string
	for _, field := range fields {
		values = append(values, html.UnescapeString(field[1]))
	}
	if want := forwarderTestConfig().Resolver.Forwarders; !slices.Equal(values, want) {
		t.Errorf("forwarder fields = %q, want %q", values, want)
	}
	if !regexp.MustCompile(`<textarea[^>]*name="forwarders"[^>]*disabled`).MatchString(body) {
		t.Error("the Edit as Text field must start disabled")
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
	for _, want := range []string{`id="forwarder-editor-body"`, "Tested just now", "<span>8.2 ms</span>", "Validates DNSSEC",
		"<span>Failed</span>", "no answer in time", `data-label="Answered">1,204</td>`} {
		if !strings.Contains(body, want) {
			t.Errorf("test results lack %q: %s", want, body)
		}
	}
	if rows := strings.Count(body, "data-forwarder-row draggable"); rows != 3 {
		t.Errorf("test drew %d editable rows, want the 3 saved forwarders once each", rows)
	}
	if strings.Count(body, `class="forwarder-test passed"`)+strings.Count(body, `class="forwarder-test failed"`) != 2 {
		t.Errorf("want the two tested forwarders marked once each: %s", body)
	}
}

func TestCheckForwarders(t *testing.T) {
	t.Parallel()
	server := newForwarderTestServer(t, new(bool))
	check := func(lines string) forwarderCheck {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/ui/settings/forwarders/check", strings.NewReader(url.Values{"forwarders": {lines}}.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		var result forwarderCheck
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil {
			t.Fatalf("check = %d %s", response.Code, response.Body.String())
		}
		return result
	}
	if result := check("1.1.1.1\n tls://dns.google (8.8.8.8)\n1.1.1.1\n"); result.Error != "" || !slices.Equal(result.Forwarders, []string{"1.1.1.1", "tls://dns.google (8.8.8.8)"}) {
		t.Errorf("good list = %+v, want both kept once, in order", result)
	}
	for _, bad := range []string{"https://dns.quad9.net/dns-query", "tls://dns.google", "this-server", "http://dns.example (192.0.2.1)"} {
		if result := check(bad); result.Error == "" || !strings.HasPrefix(result.Error, bad+": ") {
			t.Errorf("check(%q) = %+v, want it refused and named", bad, result)
		}
	}
	if result := check("https://dns.quad9.net/dns-query"); !strings.Contains(result.Error, "parentheses") {
		t.Errorf("a DoH forwarder by host name should ask for its IP address: %q", result.Error)
	}
}

// Rows send one field each and Edit as Text sends one field of lines; both
// save the same list, in the order sent.
func TestSettingsSaveForwarderRows(t *testing.T) {
	t.Parallel()
	server, configuration := newForwarderTestServerWithConfig(t, new(bool))
	base := url.Values{
		"dns_listen": {"127.0.0.1:5353"}, "resolver_mode": {"forward"}, "resolver_timeout": {"2s"}, "resolver_retries": {"2"},
		"resolver_retry_timeout": {"1s"}, "cache_size": {"1024"}, "settings_tab": {"recursion"},
		"cache_minimum_ttl": {"0"}, "cache_maximum_ttl": {"604800"}, "cache_negative_ttl": {"300"}, "cache_failure_ttl": {"10"},
		"cache_stale_ttl": {"259200"}, "cache_stale_answer_ttl": {"30"}, "cache_stale_reset_ttl": {"30"}, "cache_stale_max_wait_ms": {"1800"},
		"cache_prefetch_minimum_ttl": {"2"}, "cache_prefetch_trigger_ttl": {"9"}, "cache_prefetch_sample_interval": {"5m"}, "cache_prefetch_hits_per_hour": {"30"},
		"blocking_update_hours": {"24"}, "blocking_response_type": {"zero"}, "blocking_response_ttl": {"60"},
		"query_log_retention": {"30d"}, "server_log_level": {"info"}, "server_log_retention": {"30d"}, "statistics_retention": {"1y"},
	}
	for _, test := range []struct {
		name   string
		fields []string
		want   []string
	}{
		{"rows", []string{"8.8.8.8", "tls://dns.quad9.net (9.9.9.9)"}, []string{"8.8.8.8", "tls://dns.quad9.net (9.9.9.9)"}},
		{"text", []string{"9.9.9.9\n1.1.1.1"}, []string{"9.9.9.9", "1.1.1.1"}},
	} {
		form := url.Values{}
		for key, value := range base {
			form[key] = value
		}
		form["forwarders"] = test.fields
		request := httptest.NewRequest(http.MethodPost, "/ui/settings", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		if got := configuration.Current().Config.Resolver.Forwarders; !slices.Equal(got, test.want) {
			t.Fatalf("%s: saved forwarders = %q, want %q (%d %s)", test.name, got, test.want, response.Code, response.Body.String())
		}
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
