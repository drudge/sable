package web

import (
	"context"
	"database/sql"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"logs-reader":   {auth.PermissionLogsRead, auth.PermissionSettingsRead},
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
	if _, err := metadata.Exec("UPDATE sable_metadata SET value = ? WHERE key LIKE 'query_log_%_since'",
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
		event(-50*time.Minute, "fd00::5", "www.example.org.", querylog.SourceUpstream),
		// The laptop has been around for days, so it is not new.
		event(-6*24*time.Hour, "10.0.0.5", "www.example.org.", querylog.SourceUpstream),
		// Outside the day window.
		event(-72*time.Hour, "10.0.0.5", "telemetry.example.com.", querylog.SourceBlocked),
	}); err != nil {
		t.Fatal(err)
	}

	if err := opened.RecordClientIdentities(context.Background(), []querylog.ClientIdentity{
		{Address: "10.0.0.5", MAC: "3c:22:fb:01:02:03", Source: "neighbor", SeenAt: now.Add(-time.Minute)},
		{Address: "fd00::5", MAC: "3c:22:fb:01:02:03", Source: "neighbor", SeenAt: now.Add(-time.Minute)},
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
		`<title>Overview · Insights · Sable</title>`,
		`data-isotope-tabs`, `data-active-tab="overview"`, `data-isotope-tab="devices"`, `id="insight-device-dialog"`,
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
		`data-dialog-open="insight-finding-1"`, `id="insight-finding-1"`, "How Sable decides", `class="insight-cause"`, "Could be ",
		"Why Sable surfaced this", "Blocked 3 times during the selected period",
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
	// DNS data in a reason is set in monospace after its text.
	if !regexp.MustCompile(`Now allowed by\s+<code>telemetry\.example\.com</code>`).MatchString(body) {
		t.Error("the allow rule in a reason is not set as code")
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

func (server insightsTestServer) post(t *testing.T, session, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	request.Header.Set("X-CSRF-Token", "csrf-token")
	request.AddCookie(&http.Cookie{Name: server.sessionCookieName(), Value: session})
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

const insightsTestLaptop = "mac:3c:22:fb:01:02:03"

func TestInsightsDevicesGroupAddressesAndReportNewOnes(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	body := server.get(t, "everything", "/ui/insights/overview?range=day&tab=devices", true).Body.String()
	for _, expected := range []string{
		`data-active-tab="devices"`, `id="insight-devices-title"`,
		// The laptop's IPv4 and IPv6 addresses are one device, named from its
		// local host entry and tied together by the neighbor table.
		"george-laptop.corp.example", `<span class="status-badge">Local host</span>`, `<span class="insight-device-ids"><code>3c:22:fb:01:02:03</code><code>10.0.0.5 +1 more</code></span>`,
		`hx-get="/ui/insights/device?key=mac%3A3c%3A22%3Afb%3A01%3A02%3A03&amp;range=day"`,
		// 10.0.0.50 first appeared today while tracking was already running,
		// and nothing ties it to hardware, so it is a new address.
		"New address on the network", `<span class="status-badge active">New</span>`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("devices tab is missing %q", expected)
		}
	}
	if strings.Contains(body, "New device on the network") {
		t.Error("an address with no hardware identity was reported as a new device")
	}
	if got := server.get(t, "everything", "/ui/insights/overview?range=week", true).Header().Get("HX-Replace-Url"); got != "/insights?range=week" {
		t.Errorf("overview HX-Replace-Url = %q", got)
	}
	// A range change keeps the tab the operator is on.
	request := httptest.NewRequest(http.MethodGet, "/ui/insights/overview?range=week", nil)
	request.Header.Set("HX-Request", "true")
	request.Header.Set("HX-Current-URL", "https://sable.example/insights?range=day&tab=devices")
	request.AddCookie(&http.Cookie{Name: server.sessionCookieName(), Value: "everything"})
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if got := response.Header().Get("HX-Replace-Url"); got != "/insights?range=week&tab=devices" {
		t.Errorf("range change HX-Replace-Url = %q, want the devices tab kept", got)
	}
	if blockingOnly := server.get(t, "blocking-only", "/ui/insights/overview?range=day", true).Body.String(); strings.Contains(blockingOnly, `data-isotope-tab="devices"`) {
		t.Error("an operator without logs access saw the Devices tab")
	}
}

func TestInsightsDeviceDrawerLinksReproduceTheirCounts(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	if response := server.get(t, "blocking-only", "/ui/insights/device?range=day&key="+url.QueryEscape(insightsTestLaptop), true); response.Code != http.StatusForbidden {
		t.Fatalf("device drawer without logs access = %d", response.Code)
	}
	body := server.get(t, "everything", "/ui/insights/device?range=day&key="+url.QueryEscape(insightsTestLaptop), true).Body.String()
	for _, expected := range []string{
		"george-laptop.corp.example", "Most queried domains", "telemetry.example.com",
		`aria-label="Rename george-laptop.corp.example"`, `hx-get="/ui/insights/device?key=mac%3A3c%3A22%3Afb%3A01%3A02%3A03&amp;range=day&amp;edit=1"`,
		// Useful values carry a copy button labeled with what it copies.
		`<code id="insight-device-mac">3c:22:fb:01:02:03</code>`, `data-copy-target="insight-device-mac" aria-label="Copy hardware address"`,
		`data-copy-target="insight-device-address-0" aria-label="Copy address"`, `aria-label="Copy domain"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("device drawer is missing %q", expected)
		}
	}
	match := regexp.MustCompile(`class="insight-list-link" href="(/logs\?client_ip=10\.0\.0\.5&amp;tab=queries[^"]*)" aria-label="View ([\d,]+) queries for 10\.0\.0\.5 in Query Logs">([\d,]+)</a>`).FindStringSubmatch(body)
	if match == nil {
		t.Fatal("device drawer has no query log link for 10.0.0.5")
	}
	filter, _ := queryLogFilter(httptest.NewRequest(http.MethodGet, html.UnescapeString(match[1]), nil))
	page, err := server.store.QueryEvents(context.Background(), filter)
	if err != nil {
		t.Fatal(err)
	}
	if strconv.Itoa(page.TotalEntries) != match[3] {
		t.Fatalf("link reports %d queries, drawer %s", page.TotalEntries, match[3])
	}
	// A multi-address device's domain counts cover every address, which no
	// single query log link can reproduce, so those rows are not links.
	if strings.Contains(body, "name=telemetry.example.com") {
		t.Fatal("a multi-address device linked a domain count to a single address")
	}
	if strings.Contains(body, `name="name"`) {
		t.Fatal("the name field showed before the operator chose to rename")
	}
	editing := server.get(t, "everything", "/ui/insights/device?range=day&edit=1&key="+url.QueryEscape(insightsTestLaptop), true).Body.String()
	for _, expected := range []string{`class="insight-name-editor"`, `name="name"`, "autofocus", `data-escape-click="#insight-device-content [data-name-cancel]"`, "Follows the hardware address", "data-name-cancel", `value="george-laptop.corp.example"`} {
		if !strings.Contains(editing, expected) {
			t.Errorf("rename editor is missing %q", expected)
		}
	}
	if readOnly := server.get(t, "logs-reader", "/ui/insights/device?range=day&edit=1&key="+url.QueryEscape(insightsTestLaptop), true).Body.String(); strings.Contains(readOnly, "Rename ") || strings.Contains(readOnly, `name="name"`) {
		t.Fatal("an operator without settings write could rename a device")
	}
	if missing := server.get(t, "everything", "/ui/insights/device?range=day&key=mac:00:00:00:00:00:01", true).Body.String(); !strings.Contains(missing, "sent no queries in the selected period") {
		t.Fatal("an unknown device did not explain itself")
	}
}

func TestInsightsDeviceNamingFollowsTheHardwareAddress(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	form := url.Values{"key": {insightsTestLaptop}, "name": {"George's MacBook"}, "range": {"day"}}
	if response := server.post(t, "logs-reader", "/ui/insights/devices/name", form); response.Code != http.StatusForbidden {
		t.Fatalf("naming without settings write = %d", response.Code)
	}
	response := server.post(t, "everything", "/ui/insights/devices/name", form)
	if response.Code != http.StatusOK || response.Header().Get("HX-Trigger") != "insightsChanged" || !strings.Contains(response.Body.String(), "Name saved.") {
		t.Fatalf("naming = %d %q %s", response.Code, response.Header().Get("HX-Trigger"), response.Body.String())
	}
	clients := server.config.Current().Config.Clients
	if len(clients) != 1 || clients[0] != (config.Client{Name: "George's MacBook", MAC: "3c:22:fb:01:02:03"}) {
		t.Fatalf("configured clients = %+v", clients)
	}
	devicesTab := server.get(t, "everything", "/ui/insights/overview?range=day&tab=devices", true).Body.String()
	if !strings.Contains(devicesTab, "George&#39;s MacBook") || !strings.Contains(devicesTab, `<span class="status-badge">Your name</span>`) {
		t.Fatal("the devices tab did not use the operator's name")
	}
	removed := server.post(t, "everything", "/ui/insights/devices/name", url.Values{"key": {insightsTestLaptop}, "name": {"George's MacBook"}, "remove": {"1"}, "range": {"day"}})
	if removed.Code != http.StatusOK || len(server.config.Current().Config.Clients) != 0 || !strings.Contains(removed.Body.String(), "Name removed.") {
		t.Fatalf("removing = %d, clients %+v", removed.Code, server.config.Current().Config.Clients)
	}
	if invalid := server.post(t, "everything", "/ui/insights/devices/name", url.Values{"key": {"nonsense"}, "name": {"x"}}); invalid.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an unknown device key = %d", invalid.Code)
	}
}

// The neighbor table is sampled more often than UniFi, so the newest sighting
// of the laptop carries no name. Its UniFi name has to hold anyway, ahead of
// its host override, on the devices tab and in every client ranking; the
// operator's own name then outranks it everywhere.
func TestInsightsNamesHoldWhateverSightingIsNewest(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	if err := server.store.RecordClientIdentities(context.Background(), []querylog.ClientIdentity{
		{Address: "10.0.0.5", MAC: "3c:22:fb:01:02:03", Source: "unifi", Hostname: "George's MacBook", SeenAt: server.now.Add(-3 * time.Minute)},
	}); err != nil {
		t.Fatal(err)
	}
	pages := map[string]string{
		"devices tab": "/ui/insights/overview?range=day&tab=devices",
		"dashboard":   "/ui/stats/insights?range=day",
	}
	for page, target := range pages {
		body := server.get(t, "everything", target, true).Body.String()
		if !strings.Contains(body, "George&#39;s MacBook") || strings.Contains(body, "george-laptop.corp.example") {
			t.Errorf("the %s did not name the laptop from UniFi", page)
		}
	}
	if body := server.get(t, "everything", pages["devices tab"], true).Body.String(); !strings.Contains(body, `<span class="status-badge">UniFi</span>`) {
		t.Error("the devices tab did not credit UniFi for the name")
	}

	form := url.Values{"key": {insightsTestLaptop}, "name": {"Work Laptop"}, "range": {"day"}}
	if response := server.post(t, "everything", "/ui/insights/devices/name", form); response.Code != http.StatusOK {
		t.Fatalf("naming = %d", response.Code)
	}
	for page, target := range pages {
		body := server.get(t, "everything", target, true).Body.String()
		if !strings.Contains(body, "Work Laptop") || strings.Contains(body, "George&#39;s MacBook") {
			t.Errorf("the %s did not put the operator's name first", page)
		}
	}
}

// Sable's own dynamic DNS updates look like a check-in, so the server leaves
// the lookups it makes itself out and marks itself in the device list, while a
// device's real heartbeat is still reported.
func TestInsightsKnowsTheLookupsSableMakesItself(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	if err := server.config.(settingsEditor).Update(context.Background(), func(configuration *config.Config) error {
		configuration.DynamicDNS.Enabled = true
		configuration.DynamicDNS.Publishers = []config.DynamicDNSPublisher{{
			Provider: "cloudflare", Records: []config.DynamicDNSRecord{{Zone: "example.net", Name: "home.example.net", IPv4: true, TTL: 300}},
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var events []querylog.Event
	for index := range 280 {
		at := server.now.Add(-23*time.Hour + time.Duration(index)*5*time.Minute)
		for client, name := range map[string]string{"127.0.0.1": "api.cloudflare.com.", "10.0.0.9": "heartbeat.vendor.example."} {
			events = append(events, querylog.Event{
				OccurredAt: at, ClientIP: client, Name: name, RecordType: dns.TypeA, Class: dns.ClassINET,
				ResponseCode: dns.RcodeSuccess, Source: querylog.SourceUpstream, Protocol: "UDP",
			})
		}
	}
	if err := server.store.WriteQueryEvents(context.Background(), events); err != nil {
		t.Fatal(err)
	}

	body := server.get(t, "everything", "/ui/insights/overview?range=day&tab=devices", true).Body.String()
	if !strings.Contains(body, "Looked up heartbeat.vendor.example every 5 minutes") {
		t.Error("a device's own heartbeat was not reported")
	}
	if strings.Contains(body, "Looked up api.cloudflare.com") {
		t.Error("Sable's own dynamic DNS updates were reported as a check-in")
	}
	if !strings.Contains(body, `<span class="status-badge">This server</span>`) {
		t.Error("the devices tab did not mark this server")
	}
	drawer := server.get(t, "everything", "/ui/insights/device?range=day&key="+url.QueryEscape("ip:127.0.0.1"), true).Body.String()
	if !strings.Contains(drawer, `<span class="status-badge">This server</span>`) || !strings.Contains(drawer, "Runs Sable") {
		t.Error("the device drawer did not say this server runs Sable")
	}
}

func TestOwnLookupsFollowTheFeaturesThatRun(t *testing.T) {
	t.Parallel()
	configuration := config.Defaults()
	configuration.Blocking.Lists = []config.BlockList{{Name: "Hosts", URL: "https://lists.example.net/hosts.txt"}}
	if names := ownLookups(configuration); !names["lists.example.net"] || names["api.ipify.org"] || names["api.cloudflare.com"] {
		t.Fatalf("lookups with only a block list = %v", names)
	}
	configuration.DynamicDNS.Enabled = true
	configuration.DynamicDNS.Publishers = []config.DynamicDNSPublisher{{
		Provider: "cloudflare", Records: []config.DynamicDNSRecord{{Zone: "example.net", Name: "home.example.net", IPv4: true}},
	}}
	configuration.UniFi.Enabled = true
	configuration.UniFi.ControllerURL = "https://UniFi.home.arpa:8443"
	names := ownLookups(configuration)
	for _, name := range []string{"api.ipify.org", "api6.ipify.org", "api.cloudflare.com", "unifi.home.arpa", "lists.example.net"} {
		if !names[name] {
			t.Errorf("own lookups are missing %s: %v", name, names)
		}
	}
}

// A device named or typed while Sable only knew its address keeps that entry
// after Sable ties the address to hardware. Removing the name or type by
// hardware address has to clear it too, or the drawer says it is gone while
// the device keeps it.
func TestInsightsRemovingANameClearsWhatWasKeptOnTheAddress(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	setting := func(path string, values url.Values) string {
		t.Helper()
		values.Set("range", "day")
		response := server.post(t, "everything", path, values)
		if response.Code != http.StatusOK {
			t.Fatalf("%s %v = %d %s", path, values, response.Code, response.Body.String())
		}
		return response.Body.String()
	}
	devicesTab := func() string {
		return server.get(t, "everything", "/ui/insights/overview?range=day&tab=devices", true).Body.String()
	}

	setting("/ui/insights/devices/name", url.Values{"key": {"ip:10.0.0.5"}, "name": {"Old Name"}})
	if drawer := server.get(t, "everything", "/ui/insights/device?range=day&key="+url.QueryEscape(insightsTestLaptop), true).Body.String(); !strings.Contains(drawer, "Old Name") {
		t.Fatal("the laptop did not take the name kept on its address")
	}
	if removed := setting("/ui/insights/devices/name", url.Values{"key": {insightsTestLaptop}, "remove": {"1"}}); !strings.Contains(removed, "Name removed.") {
		t.Fatal("removing the name was not confirmed")
	}
	if clients := server.config.Current().Config.Clients; len(clients) != 0 || strings.Contains(devicesTab(), "Old Name") {
		t.Fatalf("the name kept on the address survived its removal: %+v", clients)
	}

	// Renaming moves the name onto the hardware address, so removing the new
	// name does not bring the old one back.
	setting("/ui/insights/devices/name", url.Values{"key": {"ip:10.0.0.5"}, "name": {"Old Name"}})
	setting("/ui/insights/devices/name", url.Values{"key": {insightsTestLaptop}, "name": {"Work Laptop"}})
	if clients := server.config.Current().Config.Clients; len(clients) != 1 || clients[0] != (config.Client{Name: "Work Laptop", MAC: "3c:22:fb:01:02:03"}) {
		t.Fatalf("renaming left %+v", clients)
	}
	setting("/ui/insights/devices/name", url.Values{"key": {insightsTestLaptop}, "remove": {"1"}})
	if body := devicesTab(); strings.Contains(body, "Old Name") || strings.Contains(body, "Work Laptop") {
		t.Fatal("an old name came back after the new one was removed")
	}

	// A type works the same way.
	setting("/ui/insights/devices/type", url.Values{"key": {"ip:10.0.0.5"}, "type": {"printer"}})
	if cleared := setting("/ui/insights/devices/type", url.Values{"key": {insightsTestLaptop}, "type": {""}}); !strings.Contains(cleared, "Sable will guess this device&#39;s type again.") || strings.Contains(cleared, "You set this type") {
		t.Fatalf("the type kept on the address survived: %+v", server.config.Current().Config.Clients)
	}
}

// A name or type the operator set for a whole network covers every device on
// it, so the drawer cannot remove it from one device. The drawer says where it
// comes from instead of offering to remove it, and a type handed back from a
// device goes to the network's rather than to Sable's guess.
func TestInsightsNetworkNamesAreNotTheDrawersToRemove(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	if err := server.config.(settingsEditor).Update(context.Background(), func(configuration *config.Config) error {
		configuration.Clients = []config.Client{{Name: "Office", Address: "10.0.0.0/24", Type: "computer"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	drawer := "/ui/insights/device?range=day&key=" + url.QueryEscape("ip:10.0.0.50")
	setting := func(path string, values url.Values) string {
		t.Helper()
		values.Set("key", "ip:10.0.0.50")
		values.Set("range", "day")
		response := server.post(t, "everything", path, values)
		if response.Code != http.StatusOK {
			t.Fatalf("%s %v = %d", path, values, response.Code)
		}
		return response.Body.String()
	}

	if editor := server.get(t, "everything", drawer+"&edit=1", true).Body.String(); strings.Contains(editor, "Remove Name") || !strings.Contains(editor, "Its name comes from 10.0.0.0/24.") {
		t.Fatal("the drawer offered to remove the name set for the whole network")
	}
	if body := server.get(t, "everything", drawer, true).Body.String(); !strings.Contains(body, "Named for 10.0.0.0/24") || !strings.Contains(body, "You set this type for") {
		t.Fatal("the drawer did not say the name and type come from the network")
	}
	if picker := server.get(t, "everything", drawer+"&edit=type", true).Body.String(); !strings.Contains(picker, `<option value="" selected>Computer (set for 10.0.0.0/24)</option>`) {
		t.Fatal("the type picker did not offer the network's type as the device's own default")
	}

	// A name of the device's own takes the network's place until it is removed.
	setting("/ui/insights/devices/name", url.Values{"name": {"Front Desk"}})
	if editor := server.get(t, "everything", drawer+"&edit=1", true).Body.String(); !strings.Contains(editor, "Remove Name") {
		t.Fatal("the device's own name could not be removed")
	}
	if removed := setting("/ui/insights/devices/name", url.Values{"remove": {"1"}}); !strings.Contains(removed, "Name removed.") || !strings.Contains(removed, "Office") {
		t.Fatal("removing the device's own name did not return it to the network's")
	}

	setting("/ui/insights/devices/type", url.Values{"type": {"printer"}})
	if cleared := setting("/ui/insights/devices/type", url.Values{"type": {""}}); !strings.Contains(cleared, "It takes the type you set for 10.0.0.0/24 again.") {
		t.Fatal("handing the type back claimed Sable would guess it")
	}
}

func TestInsightsDeviceTypeCorrectionFollowsTheHardwareAddress(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	drawer := "/ui/insights/device?range=day&key=" + url.QueryEscape(insightsTestLaptop)
	if closed := server.get(t, "everything", drawer, true).Body.String(); strings.Contains(closed, `name="type"`) || !strings.Contains(closed, `title="Change type"`) {
		t.Fatal("the type picker is not tucked behind its pencil")
	}
	open := server.get(t, "everything", drawer+"&edit=type", true).Body.String()
	if !strings.Contains(open, `name="type"`) || strings.Contains(open, `title="Change type"`) {
		t.Fatal("the pencil does not open the type picker")
	}
	if !strings.Contains(open, "Computer (detected)") {
		t.Fatal("the picker does not say what Sable detected")
	}
	form := url.Values{"key": {insightsTestLaptop}, "type": {"computer"}, "range": {"day"}}
	if response := server.post(t, "logs-reader", "/ui/insights/devices/type", form); response.Code != http.StatusForbidden {
		t.Fatalf("correcting without settings write = %d", response.Code)
	}
	response := server.post(t, "everything", "/ui/insights/devices/type", form)
	if response.Code != http.StatusOK || response.Header().Get("HX-Trigger") != "insightsChanged" || !strings.Contains(response.Body.String(), "Type saved.") {
		t.Fatalf("correcting = %d %q %s", response.Code, response.Header().Get("HX-Trigger"), response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Set by you") {
		t.Fatal("the drawer does not show the operator's type")
	}
	clients := server.config.Current().Config.Clients
	if len(clients) != 1 || clients[0] != (config.Client{MAC: "3c:22:fb:01:02:03", Type: "computer"}) {
		t.Fatalf("configured clients = %+v", clients)
	}
	cleared := server.post(t, "everything", "/ui/insights/devices/type", url.Values{"key": {insightsTestLaptop}, "type": {""}, "range": {"day"}})
	if cleared.Code != http.StatusOK || len(server.config.Current().Config.Clients) != 0 {
		t.Fatalf("clearing = %d, clients %+v", cleared.Code, server.config.Current().Config.Clients)
	}
	if invalid := server.post(t, "everything", "/ui/insights/devices/type", url.Values{"key": {insightsTestLaptop}, "type": {"toaster"}}); invalid.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an unknown type = %d", invalid.Code)
	}
}

func TestInsightFindingsCanBeHiddenAndShownAgain(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	body := server.get(t, "everything", "/ui/insights/overview?range=day", true).Body.String()
	match := regexp.MustCompile(`name="id" value="(blocking\.past-block/[^"]+)"`).FindStringSubmatch(body)
	if match == nil {
		t.Fatal("the past-block finding offers no way to hide it")
	}
	id := html.UnescapeString(match[1])
	form := url.Values{"id": {id}, "label": {"Possible past blocking issue: telemetry.example.com"}, "action": {"normal"}}
	if response := server.post(t, "logs-reader", "/ui/insights/feedback", form); response.Code != http.StatusForbidden {
		t.Fatalf("hiding without settings write = %d", response.Code)
	}
	if strings.Contains(server.get(t, "logs-reader", "/ui/insights/overview?range=day", true).Body.String(), "Seen it?") {
		t.Fatal("an operator without settings write is offered hiding")
	}
	response := server.post(t, "everything", "/ui/insights/feedback", form)
	if response.Code != http.StatusNoContent || response.Header().Get("HX-Trigger") != "insightsChanged" {
		t.Fatalf("hiding = %d %q", response.Code, response.Header().Get("HX-Trigger"))
	}
	hidden := server.get(t, "everything", "/ui/insights/overview?range=day", true).Body.String()
	if strings.Contains(hidden, `<span class="insight-finding-title">Possible past blocking issue</span>`) {
		t.Fatal("a finding marked normal is still listed")
	}
	if !strings.Contains(hidden, "1 hidden finding") || !strings.Contains(hidden, "Marked normal") {
		t.Fatal("the hidden finding is not listed with its status")
	}
	if invalid := server.post(t, "everything", "/ui/insights/feedback", url.Values{"id": {id}, "action": {"forever"}}); invalid.Code != http.StatusBadRequest {
		t.Fatalf("an unknown action = %d", invalid.Code)
	}
	if shown := server.post(t, "everything", "/ui/insights/feedback/remove", url.Values{"id": {id}}); shown.Code != http.StatusNoContent {
		t.Fatalf("showing again = %d", shown.Code)
	}
	if !strings.Contains(server.get(t, "everything", "/ui/insights/overview?range=day", true).Body.String(), `<span class="insight-finding-title">Possible past blocking issue</span>`) {
		t.Fatal("a finding shown again is still hidden")
	}
}
