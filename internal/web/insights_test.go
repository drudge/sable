package web

import (
	"context"
	"database/sql"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/store"
)

// permissionAuthenticator signs each test session in with its own permissions.
type permissionAuthenticator struct {
	testAuthenticator
	sessions map[string][]string
}

func (authenticator permissionAuthenticator) AuthenticateSession(_ context.Context, token string) (auth.Principal, error) {
	permissions, found := authenticator.sessions[token]
	if !found {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	return auth.Principal{UserID: 1, Username: "operator", CSRFToken: "csrf-token", Permissions: permissions}, nil
}

var insightsTestSessions = map[string][]string{
	"everything":    {auth.PermissionAll},
	"blocking-only": {auth.PermissionBlockingRead},
	"logs-only":     {auth.PermissionLogsRead},
	"zones-only":    {auth.PermissionZonesRead},
}

type insightsTestServer struct {
	*Server
	store *store.Store
	now   time.Time
}

func newInsightsTestServer(t *testing.T) insightsTestServer {
	t.Helper()
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "lists"), 0o755); err != nil {
		t.Fatal(err)
	}
	var alpha, beta strings.Builder
	for index := range 300 {
		name := "tracker" + strconv.Itoa(index) + ".example\n"
		alpha.WriteString(name)
		if index < 150 {
			beta.WriteString("0.0.0.0 " + name)
		}
	}
	for name, contents := range map[string]string{"alpha.txt": alpha.String(), "beta.txt": beta.String()} {
		if err := os.WriteFile(filepath.Join(directory, "lists", name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now().UTC().Truncate(time.Second)
	opened, err := store.Open(context.Background(), "sqlite", filepath.Join(directory, "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { opened.Close() })
	// A server that has been recording block sources for longer than the
	// backdated history below.
	metadata, err := sql.Open("sqlite", filepath.Join(directory, "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := metadata.Exec("UPDATE sable_metadata SET value = ? WHERE key LIKE 'query_log_rollup_%_since'",
		now.Add(-7*24*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	metadata.Close()
	event := func(offset time.Duration, client, name string, source querylog.Source) querylog.Event {
		return querylog.Event{
			OccurredAt: now.Add(offset), ClientIP: client, Name: name, RecordType: dns.TypeA,
			Class: dns.ClassINET, ResponseCode: dns.RcodeNameError, Source: source, Protocol: "UDP",
		}
	}
	blockedBy := func(event querylog.Event, rule string, sources ...string) querylog.Event {
		event.Decision = querylog.Decision{Policy: querylog.PolicyBlocked, PolicyRule: rule, PolicySources: sources}
		return event
	}
	if err := opened.WriteQueryEvents(context.Background(), []querylog.Event{
		event(-5*time.Hour, "10.0.0.5", "telemetry.example.com.", querylog.SourceBlocked),
		event(-4*time.Hour, "10.0.0.5", "telemetry.example.com.", querylog.SourceBlocked),
		event(-3*time.Hour, "10.0.0.9", "telemetry.example.com.", querylog.SourceBlocked),
		blockedBy(event(-2*time.Hour, "10.0.0.5", "ads.example.", querylog.SourceBlocked), "ads.example", "Alpha", "Beta"),
		blockedBy(event(-90*time.Minute, "10.0.0.50", "ads.example.", querylog.SourceBlocked), "ads.example", "Alpha"),
		event(-time.Hour, "10.0.0.5", "www.example.org.", querylog.SourceUpstream),
		// Outside the day window.
		event(-72*time.Hour, "10.0.0.5", "telemetry.example.com.", querylog.SourceBlocked),
	}); err != nil {
		t.Fatal(err)
	}

	configuration := config.Defaults()
	configuration.Cluster.DataDirectory = t.TempDir()
	configuration.Blocking.Enabled = true
	configuration.Blocking.AllowedDomains = []string{"telemetry.example.com"}
	configuration.Blocking.Lists = []config.BlockList{
		{Name: "Alpha", Path: "lists/alpha.txt", Format: "auto"},
		{Name: "Beta", Path: "lists/beta.txt", Format: "auto"},
	}
	configuration.Resolver.Hosts = []config.HostOverride{{Name: "george-laptop.corp.example", Addresses: []string{"10.0.0.5"}}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: now.Add(-time.Hour)}},
		&editableTestConfiguration{snapshot: config.Snapshot{Config: configuration, Revision: 1}, baseDirectory: directory},
		testZones{},
		"sqlite",
		testQueryLog{},
		opened,
		func(context.Context) error { return nil },
		permissionAuthenticator{sessions: insightsTestSessions},
		true,
		false,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	return insightsTestServer{Server: server, store: opened, now: now}
}

func (server insightsTestServer) get(t *testing.T, session, target string, htmx bool) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.AddCookie(&http.Cookie{Name: server.sessionCookieName(), Value: session})
	if htmx {
		request.Header.Set("HX-Request", "true")
	}
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

func TestInsightsOpensWithEitherBlockingOrLogsRead(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	for session, want := range map[string]int{
		"everything": http.StatusOK, "blocking-only": http.StatusOK, "logs-only": http.StatusOK, "zones-only": http.StatusForbidden,
	} {
		for _, target := range []string{"/insights", "/ui/insights/overview?range=day"} {
			if response := server.get(t, session, target, false); response.Code != want {
				t.Errorf("%s GET %s = %d, want %d", session, target, response.Code, want)
			}
		}
	}

	blockingOnly := server.get(t, "blocking-only", "/ui/insights/overview?range=day", true).Body.String()
	if !strings.Contains(blockingOnly, "Block List Contribution") || strings.Contains(blockingOnly, "Clients With Most Blocks") {
		t.Fatal("a blocking-only operator should see list contribution and no query activity")
	}
	if strings.Contains(blockingOnly, "telemetry.example.com") {
		t.Fatal("a blocking-only operator saw query history in a past-block finding")
	}
	if !strings.Contains(blockingOnly, "Query activity is hidden because your account cannot read logs.") {
		t.Fatal("the page did not explain why query activity is missing")
	}

	logsOnly := server.get(t, "logs-only", "/ui/insights/overview?range=day", true).Body.String()
	if !strings.Contains(logsOnly, "Clients With Most Blocks") || strings.Contains(logsOnly, "Block List Contribution") {
		t.Fatal("a logs-only operator should see query activity and no list contribution")
	}
	// A past block pairs history with the allow list, which is blocking
	// configuration this operator may not read.
	if strings.Contains(logsOnly, "Possible past blocking issue") {
		t.Fatal("a logs-only operator saw an allow-list finding")
	}
}

func TestInsightsNavigationAndCommandPaletteFollowPermissions(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	for session, want := range map[string]bool{"everything": true, "logs-only": true, "blocking-only": true, "zones-only": false} {
		body := server.get(t, session, "/", false).Body.String()
		if strings.Contains(body, `href="/insights"`) != want || strings.Contains(body, `id="command-page-insights"`) != want {
			t.Errorf("%s: Insights navigation present = %t, want %t", session, strings.Contains(body, `href="/insights"`), want)
		}
	}
	body := server.get(t, "everything", "/", false).Body.String()
	dashboard := strings.Index(body, `data-tooltip="Dashboard"`)
	insights := strings.Index(body, `data-tooltip="Insights"`)
	zones := strings.Index(body, `data-tooltip="Zones"`)
	if dashboard < 0 || !(dashboard < insights && insights < zones) {
		t.Fatalf("Insights is not directly below Dashboard (dashboard %d, insights %d, zones %d)", dashboard, insights, zones)
	}

	page := server.get(t, "everything", "/insights?range=week", false).Body.String()
	for _, expected := range []string{
		`<title>Insights · Sable</title>`,
		`aria-current="page"`,
		`hx-get="/ui/insights/overview?range=week"`, `hx-trigger="load"`,
		`id="insights-range-week" class="active" aria-pressed="true"`,
		`id="insights-range-select"`, `id="insights-update-indicator"`,
		`class="insights-skeleton"`, "Analyzing your network…",
	} {
		if !strings.Contains(page, expected) {
			t.Errorf("Insights page is missing %q", expected)
		}
	}
	if strings.Contains(page, `id="insights-range-hour"`) {
		t.Error("Insights offered an hour range")
	}
}

func TestInsightsOverviewShowsEvidenceThatReproducesInTheQueryLog(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	response := server.get(t, "everything", "/ui/insights/overview?range=day", true)
	if response.Code != http.StatusOK {
		t.Fatalf("overview = %d", response.Code)
	}
	if got := response.Header().Get("HX-Replace-Url"); got != "/insights?range=day" {
		t.Fatalf("HX-Replace-Url = %q", got)
	}
	body := response.Body.String()
	for _, expected := range []string{
		"Possible past blocking issue", "Blocked 3 times during the selected period and is now explicitly allowed.",
		"Little unique coverage", "100% of this list&#39;s domains are also covered by Alpha.",
		`class="admin-mobile-list insight-list-mobile"`, `class="admin-desktop-table"`,
		`data-dialog-open="insight-finding-1"`, `id="insight-finding-1"`, "How Sable found this",
		"george-laptop.corp.example",
		`<th scope="col" class="right-cell">Queries blocked</th>`,
		// Alpha matched both blocked ads.example queries; Beta shared one.
		`<span class="numeric-cell">2</span> <small>1 alone</small>`,
		`<span class="numeric-cell">1</span> <small>0 alone</small>`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("overview is missing %q", expected)
		}
	}
	for _, advice := range []string{"remove this list", "Remove list", "should remove"} {
		if strings.Contains(body, advice) {
			t.Errorf("overview advises %q", advice)
		}
	}

	// Every query log link on the page has to reproduce the number shown next
	// to it: the same whole value, over the same window.
	for _, test := range []struct {
		pattern string
		want    int
	}{
		{`href="(/logs\?name=telemetry\.example\.com&amp;source=blocked&amp;tab=queries[^"]*)"`, 3},
		{`href="(/logs\?client_ip=10\.0\.0\.5&amp;name=telemetry\.example\.com&amp;source=blocked[^"]*)"`, 2},
		{`href="(/logs\?tab=queries&amp;client_ip=10\.0\.0\.5&amp;source=blocked[^"]*)"`, 3},
		{`href="(/logs\?tab=queries&amp;name=ads\.example&amp;source=blocked[^"]*)"`, 2},
	} {
		match := regexp.MustCompile(test.pattern).FindStringSubmatch(body)
		if match == nil {
			t.Errorf("no link matching %s", test.pattern)
			continue
		}
		link := html.UnescapeString(match[1])
		if !strings.Contains(link, "match=exact") || !strings.Contains(link, "start=") || !strings.Contains(link, "end=") {
			t.Errorf("link %s does not carry an exact window", link)
		}
		filter, _ := queryLogFilter(httptest.NewRequest(http.MethodGet, link, nil))
		page, err := server.store.QueryEvents(context.Background(), filter)
		if err != nil {
			t.Fatal(err)
		}
		if page.TotalEntries != test.want {
			t.Errorf("%s reports %d entries, want %d", link, page.TotalEntries, test.want)
		}
	}
}

func TestRequiredAnyPermissionCoversInsightsRoutes(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/insights", "/ui/insights/overview"} {
		permissions := requiredAnyPermission(httptest.NewRequest(http.MethodGet, path, nil))
		if len(permissions) != 2 || permissions[0] != auth.PermissionBlockingRead || permissions[1] != auth.PermissionLogsRead {
			t.Errorf("%s permissions = %v", path, permissions)
		}
	}
	if permissions := requiredAnyPermission(httptest.NewRequest(http.MethodGet, "/insightsx", nil)); permissions != nil {
		t.Errorf("unrelated path permissions = %v", permissions)
	}
}
