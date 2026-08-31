package web

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a-h/templ"
	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/certificates"
	clusterstate "github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	dnssecstate "github.com/drudge/sable/internal/dnssec"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/update"
	webassets "github.com/drudge/sable/internal/web/assets"
	"github.com/drudge/sable/internal/web/pages"
	zonemodel "github.com/drudge/sable/internal/zone"
)

func TestZoneOperationLogsFailuresAndSuccesses(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	server := &Server{logger: slog.New(slog.NewTextHandler(&output, nil))}
	request := httptest.NewRequest(http.MethodPost, "http://sable.test/ui/zones/import", nil)
	request.RemoteAddr = "192.0.2.20:53000"

	server.logZoneOperation(request, "example.test", errors.New("database unavailable"))
	server.logZoneOperation(request, "example.test", nil)

	logged := output.String()
	for _, expected := range []string{
		"level=WARN", "msg=\"zone operation failed\"", "operation=zone.import",
		"zone=example.test", "client=192.0.2.20", "error=\"database unavailable\"",
		"level=INFO", "msg=\"zone operation completed\"",
	} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("zone operation log does not contain %q:\n%s", expected, logged)
		}
	}
}

func TestBlockingOperationLogsFailuresAndSuccesses(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	server := &Server{logger: slog.New(slog.NewTextHandler(&output, nil))}
	request := httptest.NewRequest(http.MethodPost, "http://sable.test/ui/blocking/pause", strings.NewReader("minutes=15"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.RemoteAddr = "192.0.2.21:53000"
	if err := request.ParseForm(); err != nil {
		t.Fatalf("ParseForm() error = %v", err)
	}

	server.logBlockingOperation(request, errors.New("pause unavailable"), "minutes", 15)
	server.logBlockingOperation(request, nil, "minutes", 15)

	logged := output.String()
	for _, expected := range []string{
		"level=WARN", "msg=\"blocking operation failed\"", "operation=blocking.pause",
		"client=192.0.2.21", "minutes=15", "error=\"pause unavailable\"",
		"level=INFO", "msg=\"blocking operation completed\"",
	} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("blocking operation log does not contain %q:\n%s", expected, logged)
		}
	}
}

type testStats struct{ snapshot dnsserver.Stats }

type testResolverStats struct{ testStats }

func (testResolverStats) ServeDNS(writer dns.ResponseWriter, request *dns.Msg) {
	response := new(dns.Msg)
	response.SetReply(request)
	if len(request.Question) == 1 && request.Question[0].Qtype == dns.TypeA {
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.53"),
		})
	}
	_ = writer.WriteMsg(response)
}

type testDNSSECController struct {
	status    dnssecstate.Status
	requested string
}

func (controller *testDNSSECController) KeyStatus(context.Context, zonemodel.Zone) (dnssecstate.Status, error) {
	return controller.status, nil
}

func (controller *testDNSSECController) RequestRollover(_ context.Context, _ zonemodel.Zone, role string) error {
	controller.requested = role
	return nil
}

func (stats testStats) Stats() dnsserver.Stats { return stats.snapshot }
func (testStats) PurgeCache() int              { return 3 }
func (testStats) CachedResponses() []dnsserver.CachedResponse {
	return []dnsserver.CachedResponse{{
		Name: "example.com.", RecordType: "A", RemainingTTL: 293,
		Records: []dnsserver.CachedRecord{{Section: "Answer", Value: "example.com.\t293\tIN\tA\t192.0.2.1", TTL: 293}},
	}}
}

type synchronizingTestStats struct {
	testStats
	serial uint32
	calls  []string
}

func (stats *synchronizingTestStats) FetchZone(
	_ context.Context,
	zoneName, zoneType string,
	primaries []string,
	protocol, _ string,
) ([]dnsserver.ZoneRecord, error) {
	stats.serial++
	stats.calls = append(stats.calls, strings.Join([]string{zoneName, zoneType, strings.Join(primaries, ","), protocol}, "|"))
	return []dnsserver.ZoneRecord{
		{Name: "@", Type: "SOA", TTL: 300, Value: fmt.Sprintf("ns1.%s. hostmaster.%s. %d 3600 600 1209600 300", zoneName, zoneName, stats.serial)},
		{Name: "@", Type: "NS", TTL: 300, Value: "ns1." + zoneName + "."},
		{Name: "ns1", Type: "A", TTL: 300, Value: "192.0.2.53"},
	}, nil
}

func (stats *synchronizingTestStats) RefreshZone(
	ctx context.Context,
	zoneName, zoneType string,
	primaries []string,
	protocol, tsigKey string,
	_ []dnsserver.ZoneRecord,
) ([]dnsserver.ZoneRecord, bool, error) {
	records, err := stats.FetchZone(ctx, zoneName, zoneType, primaries, protocol, tsigKey)
	return records, err == nil, err
}

type testQueryLog struct{}

func (testQueryLog) Stats() querylog.Stats { return querylog.Stats{Persisted: 1} }

func (testQueryLog) RecentQueryEvents(context.Context, int) ([]querylog.Entry, error) {
	return []querylog.Entry{{
		ID: 1,
		Event: querylog.Event{
			OccurredAt: time.Now(), ClientIP: "192.0.2.1", Name: "example.com",
			RecordType: 1, Class: 1, ResponseCode: 0, Source: querylog.SourceCache,
			Duration: 25 * time.Microsecond,
			Decision: querylog.Decision{Policy: querylog.PolicyNoMatch, Cache: querylog.CacheHit, Resolver: querylog.ResolverCache},
		},
	}}, nil
}

func (log testQueryLog) QueryLogInsights(ctx context.Context, _, _ time.Time) (querylog.Insights, error) {
	entries, err := log.RecentQueryEvents(ctx, 1_000)
	if err != nil {
		return querylog.Insights{}, err
	}
	return insightsFrom(entries), nil
}

func (log testQueryLog) QueryEvents(ctx context.Context, filter querylog.Filter) (querylog.Page, error) {
	entries, err := log.RecentQueryEvents(ctx, filter.PageSize)
	if err != nil {
		return querylog.Page{}, err
	}
	return querylog.Page{Entries: entries, Page: 1, PageSize: filter.PageSize, TotalEntries: len(entries), TotalPages: 1}, nil
}

func TestQueryDecisionViewExplainsPolicyAndRoute(t *testing.T) {
	t.Parallel()

	view := queryDecisionView(querylog.Decision{
		Policy: querylog.PolicyAllowed, PolicyRule: "internal.example.", Cache: querylog.CacheMiss,
		Resolver: querylog.ResolverForwarded, Route: "corp.example.", DNSSEC: querylog.DNSSECSecure,
	})
	if !view.Available || view.Policy != "Allowed by policy" || view.PolicyDetail != "Matched internal.example." {
		t.Fatalf("policy explanation = %+v", view)
	}
	if view.Cache != "Cache miss" || view.Resolver != "Forwarded upstream" || view.ResolverDetail != "Conditional route: corp.example." {
		t.Fatalf("resolution explanation = %+v", view)
	}
	if view.DNSSEC != "DNSSEC secure" || !strings.Contains(view.Summary, "conditional route") {
		t.Fatalf("DNSSEC/summary explanation = %+v", view)
	}
}

func TestDNSQueryResultIncludesIsotopeActionsAndCopyTargets(t *testing.T) {
	t.Parallel()

	view := pages.QueryView{
		Success: true, Question: "example.com.", RecordType: "A", Server: "127.0.0.1:53",
		Protocol: "UDP", Elapsed: "1ms", Size: "64 bytes", RCode: "NOERROR",
		Flags: []string{"RA"}, JSON: `{"question":"example.com."}`,
		Answers: []pages.RecordView{{Name: "example.com.", Type: "A", Data: "192.0.2.1", TTL: 300}},
	}
	response := httptest.NewRecorder()
	if err := pages.QueryResult(view).Render(context.Background(), response); err != nil {
		t.Fatalf("render QueryResult: %v", err)
	}
	markup := response.Body.String()
	for _, expected := range []string{
		"NoError", "Copy JSON", `data-copy-target="dns-query-json"`,
		`data-copy-target="record-answer-0-name"`, `data-copy-target="record-answer-0-data"`,
		">Answer<", "check-circle", "hard-drive", "timer", "flag",
	} {
		if !strings.Contains(markup, expected) {
			t.Errorf("query result does not contain %q", expected)
		}
	}
	encoded := queryResultJSON(view)
	for _, expected := range []string{`"question":"example.com."`, `"record_type":"A"`, `"answers"`} {
		if !strings.Contains(encoded, expected) {
			t.Errorf("query result JSON does not contain %q: %s", expected, encoded)
		}
	}
}

type testConfiguration struct{ snapshot config.Snapshot }

func (configuration testConfiguration) Current() config.Snapshot { return configuration.snapshot }

type testZones struct{ snapshot zonemodel.Snapshot }

func (zones testZones) Current() zonemodel.Snapshot { return zones.snapshot }

type editableTestConfiguration struct {
	snapshot      config.Snapshot
	zoneSnapshot  zonemodel.Snapshot
	baseDirectory string
}

type testCertificateVault struct{}

func (testCertificateVault) Put(context.Context, string, []byte) error { return nil }
func (testCertificateVault) Get(context.Context, string) ([]byte, error) {
	return nil, errors.New("secret not found")
}

func (configuration *editableTestConfiguration) Current() config.Snapshot {
	return configuration.snapshot
}

func (configuration *editableTestConfiguration) BaseDirectory() string {
	return configuration.baseDirectory
}

func (configuration *editableTestConfiguration) UpdateBlocking(_ context.Context, mutate func(*config.Blocking) error) error {
	candidate := configuration.snapshot.Config
	candidate.Blocking.Domains = append([]string(nil), candidate.Blocking.Domains...)
	candidate.Blocking.AllowedDomains = append([]string(nil), candidate.Blocking.AllowedDomains...)
	candidate.Blocking.Lists = append([]config.BlockList(nil), candidate.Blocking.Lists...)
	candidate.Blocking.CustomAddresses = append([]string(nil), candidate.Blocking.CustomAddresses...)
	candidate.Blocking.BypassClients = append([]string(nil), candidate.Blocking.BypassClients...)
	if err := mutate(&candidate.Blocking); err != nil {
		return err
	}
	configuration.snapshot.Config = candidate
	configuration.snapshot.Revision++
	return nil
}

func (configuration *editableTestConfiguration) Update(_ context.Context, mutate func(*config.Config) error) error {
	candidate := configuration.snapshot.Config
	candidate.Server.DNSListen = append([]string(nil), candidate.Server.DNSListen...)
	candidate.Resolver.Forwarders = append([]string(nil), candidate.Resolver.Forwarders...)
	candidate.Resolver.RootHints = append([]string(nil), candidate.Resolver.RootHints...)
	candidate.EncryptedDNS.DoTListen = append([]string(nil), candidate.EncryptedDNS.DoTListen...)
	candidate.EncryptedDNS.DoHListen = append([]string(nil), candidate.EncryptedDNS.DoHListen...)
	if err := mutate(&candidate); err != nil {
		return err
	}
	configuration.snapshot.Config = candidate
	configuration.snapshot.Revision++
	return nil
}

type editableTestZoneStore struct{ configuration *editableTestConfiguration }

func (configuration *editableTestConfiguration) zoneStore() *editableTestZoneStore {
	return &editableTestZoneStore{configuration: configuration}
}

func (store *editableTestZoneStore) Current() zonemodel.Snapshot {
	return store.configuration.zoneSnapshot
}

func (store *editableTestZoneStore) UpdateZones(_ context.Context, mutate func(*[]zonemodel.Zone) error) error {
	candidate := zonemodel.Clone(store.configuration.zoneSnapshot.Zones)
	if err := mutate(&candidate); err != nil {
		return err
	}
	store.configuration.zoneSnapshot.Zones = candidate
	store.configuration.zoneSnapshot.Revision++
	return nil
}

type testAuthenticator struct{}

func (testAuthenticator) SetupRequired(context.Context) (bool, error) { return false, nil }
func (testAuthenticator) Setup(context.Context, string, string, string, string) (auth.Credentials, error) {
	return auth.Credentials{
		SessionToken: "session-token", CSRFToken: "csrf-token", Expires: time.Now().Add(time.Hour),
	}, nil
}
func (testAuthenticator) Login(context.Context, string, string, string, string) (auth.Credentials, error) {
	return auth.Credentials{
		SessionToken: "session-token", CSRFToken: "csrf-token", Expires: time.Now().Add(time.Hour),
	}, nil
}
func (testAuthenticator) AuthenticateSession(_ context.Context, token string) (auth.Principal, error) {
	if token != "session-token" {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	return auth.Principal{UserID: 1, Username: "admin", CSRFToken: "csrf-token", Permissions: []string{auth.PermissionAll}}, nil
}
func (testAuthenticator) AuthenticateToken(_ context.Context, token string) (auth.Principal, error) {
	if token != "sable_pat_test" {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	return auth.Principal{UserID: 1, Username: "admin", AuthenticatedByToken: true, Permissions: []string{auth.PermissionAll}}, nil
}
func (testAuthenticator) ValidateCSRF(principal auth.Principal, token string) bool {
	return principal.AuthenticatedByToken || token == principal.CSRFToken
}
func (testAuthenticator) Logout(context.Context, auth.Principal, string, string) error { return nil }
func (testAuthenticator) CreateAPIToken(
	context.Context, auth.Principal, int64, string, []string, auth.APITokenExpiration, string, string,
) (string, time.Time, error) {
	return "sable_pat_created", time.Now().Add(24 * time.Hour), nil
}
func (testAuthenticator) Avatar(context.Context, auth.Principal) (auth.Avatar, error) {
	return auth.Avatar{}, auth.ErrNotFound
}

func (testAuthenticator) Profile(context.Context, auth.Principal) (auth.ProfileSnapshot, error) {
	return auth.ProfileSnapshot{
		User:  auth.ManagedUser{ID: 1, Username: "admin", DisplayName: "Administrator", Email: "admin@example.test", Roles: []string{"Administrator"}},
		Roles: []auth.Role{{Name: "Administrator", Grants: []auth.Grant{{Surface: auth.SurfaceAPI, Permission: auth.PermissionAll}}}},
	}, nil
}
func (testAuthenticator) UpdateOwnProfile(context.Context, auth.Principal, string, string, string, string) error {
	return nil
}
func (testAuthenticator) ChangeOwnPassword(context.Context, auth.Principal, string, string, string, string) error {
	return nil
}
func (testAuthenticator) RevokeOwnAPIToken(context.Context, auth.Principal, int64, string, string) error {
	return nil
}

func TestDashboardAndHealthAreServedFromEmbeddedApplication(t *testing.T) {
	t.Parallel()

	configuration := config.Defaults()
	clusterDirectory := t.TempDir()
	configuration.Cluster.DataDirectory = clusterDirectory
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{
			Queries: 42, LocalAnswers: 5, LocalHosts: 2, CacheEntries: 1, CacheHits: 12,
			StartedAt: time.Now().Add(-time.Minute),
			Latency: []dnsserver.DNSLatencyHistogram{{
				Source: "cache", Protocol: "udp", Cache: "hit", ResponseCode: "NOERROR",
				Count: 2, SumNanoseconds: uint64(1500 * time.Microsecond),
				Buckets: []dnsserver.DNSLatencyBucket{{UpperBoundNanoseconds: uint64(time.Millisecond), Count: 1}},
			}},
		}},
		testConfiguration{snapshot: config.Snapshot{Config: configuration, Revision: 7}},
		testZones{},
		"sqlite",
		testQueryLog{},
		testQueryLog{},
		func(context.Context) error { return nil },
		nil,
		false,
		false,
		false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if server.httpServer.ReadHeaderTimeout != webReadHeaderTimeout ||
		server.httpServer.ReadTimeout != webReadTimeout ||
		server.httpServer.WriteTimeout != webWriteTimeout ||
		server.httpServer.IdleTimeout != webIdleTimeout ||
		server.httpServer.MaxHeaderBytes != webMaximumHeaderBytes {
		t.Fatalf("HTTP server limits are not fully configured: %+v", server.httpServer)
	}
	clusterService, err := clusterstate.Open(clusterstate.Options{DataDirectory: clusterDirectory, NodeName: "dns-1", Version: "dev", StartedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	server.SetClusterController(clusterService)
	server.SetUpdateController(&testUpdateController{status: update.Status{Phase: update.PhaseIdle, CurrentVersion: "dev"}})
	dashboardResponse := serveRequest(server, "GET", "/")
	dashboard := dashboardResponse.Body.String()
	if server.auth != nil || server.administrator != nil {
		t.Fatal("security-disabled server retained authentication capabilities")
	}
	if strings.Contains(dashboard, `href="/administration"`) {
		t.Fatal("security-disabled dashboard advertises unavailable administration")
	}
	if response := serveRequest(server, http.MethodGet, "/administration"); response.Code != http.StatusNotFound {
		t.Fatalf("security-disabled administration status = %d, want 404", response.Code)
	}
	for _, expected := range []string{"Sable", "DNS Client", "Revision 7", configuration.Server.DNSListen[0]} {
		if !strings.Contains(dashboard, expected) {
			t.Errorf("dashboard does not contain %q", expected)
		}
	}
	if !strings.Contains(dashboard, `<h1 class="sr-only">Dashboard</h1>`) {
		t.Error("dashboard does not contain its accessible page heading")
	}
	for _, expected := range []string{`includeIndicatorCSS`, `defaultTimeout`, `hx-headers:inherited=`} {
		if !strings.Contains(dashboard, expected) {
			t.Errorf("dashboard htmx 4 configuration does not contain %q", expected)
		}
	}
	for _, name := range []string{"bootstrap.js", "app.css", "app.js", "htmx.min.js", "sable-mark.svg", "sable-icon-180.png"} {
		if path := webassets.URL(name); !strings.Contains(dashboard, path) {
			t.Errorf("dashboard does not contain fingerprinted asset %q", path)
		}
	}
	appScript := `<script src="` + webassets.URL("app.js") + `" defer></script>`
	htmxScript := `<script src="` + webassets.URL("htmx.min.js") + `" defer></script>`
	if !strings.Contains(dashboard, appScript) || !strings.Contains(dashboard, htmxScript) || strings.Index(dashboard, appScript) > strings.Index(dashboard, htmxScript) {
		t.Error("deferred application script must register before htmx initializes")
	}
	for _, expected := range []string{"sidebar-rail", `data-account-menu`, `data-theme-value="system"`, `data-theme-value="light"`, `data-theme-value="dark"`, `aria-label="Collapse sidebar"`, `aria-label="Expand sidebar"`, `hx-get="/ui/stats/chart?insights=1&amp;range=day"`, `data-range="year"`, `data-range-popover`, `data-calendar-grid`, `data-range-start-time`, `hx-get="/ui/stats/insights?range=hour"`, `hx-trigger="load"`, "Loading query insights…", `id="runtime-stats"`, `id="stats-overview-title"`, `data-stats-scope="all"`, "Chart range", `id="dashboard-update-indicator"`, `hx-indicator="#dashboard-update-indicator"`, "Updating dashboard…", `data-stat-label="Total Queries"`, `data-stat-number="value"`, `data-stat-number="detail"`} {
		if !strings.Contains(dashboard, expected) {
			t.Errorf("dashboard interaction markup does not contain %q", expected)
		}
	}
	if cards := strings.Count(dashboard, `class="stat-card `); cards != 12 {
		t.Errorf("dashboard stat card count = %d, want all 12 metrics", cards)
	}
	if values := strings.Count(dashboard, `data-stat-number="value"`); values != 12 {
		t.Errorf("dashboard morphing value count = %d, want 12", values)
	}
	chartResponse := serveRequest(server, http.MethodGet, "/ui/stats/chart?range=day")
	if chartResponse.Code != http.StatusOK || !strings.Contains(chartResponse.Body.String(), `data-range="day"`) {
		t.Fatalf("day chart response = %d %s", chartResponse.Code, chartResponse.Body.String())
	}
	for _, expected := range []string{`id="runtime-stats"`, `hx-swap-oob="outerHTML"`, `data-stats-scope="all"`, "All time"} {
		if !strings.Contains(chartResponse.Body.String(), expected) {
			t.Errorf("day chart response does not contain %q", expected)
		}
	}
	rangedChartResponse := serveRequest(server, http.MethodGet, "/ui/stats/chart?range=day&stats_scope=range")
	rangedChart := rangedChartResponse.Body.String()
	for _, expected := range []string{`data-stats-scope="range"`, "Last 24 hours", "Chart range", "· all time", "Recent sample · not ranged"} {
		if rangedChartResponse.Code != http.StatusOK || !strings.Contains(rangedChart, expected) {
			t.Errorf("ranged day chart response does not contain %q", expected)
		}
	}
	if cards := strings.Count(rangedChart, `class="stat-card `); cards != 12 {
		t.Errorf("ranged dashboard stat card count = %d, want all 12 metrics", cards)
	}
	now := time.Now().Truncate(time.Minute)
	customChartPath := "/ui/stats/chart?range=custom&start=" + now.Add(-time.Hour).Format("2006-01-02T15:04") + "&end=" + now.Format("2006-01-02T15:04")
	customChartResponse := serveRequest(server, http.MethodGet, customChartPath)
	if customChartResponse.Code != http.StatusOK || !strings.Contains(customChartResponse.Body.String(), "Custom range") {
		t.Fatalf("custom chart response = %d %s", customChartResponse.Code, customChartResponse.Body.String())
	}
	invalidCustomResponse := serveRequest(server, http.MethodGet, "/ui/stats/chart?range=custom&start=nope&end=still-nope")
	if invalidCustomResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid custom chart status = %d, want 400", invalidCustomResponse.Code)
	}
	futureStart := now.Add(24 * time.Hour)
	futureChartPath := "/ui/stats/chart?range=custom&start=" + futureStart.Format("2006-01-02T15:04") + "&end=" + futureStart.Add(time.Hour).Format("2006-01-02T15:04")
	if response := serveRequest(server, http.MethodGet, futureChartPath); response.Code != http.StatusOK {
		t.Fatalf("future custom chart status = %d, want 200", response.Code)
	}
	invalidChartResponse := serveRequest(server, http.MethodGet, "/ui/stats/chart?range=forever")
	if invalidChartResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid chart range status = %d, want 400", invalidChartResponse.Code)
	}
	insightsResponse := serveRequest(server, http.MethodGet, "/ui/stats/insights?range=hour")
	if insightsResponse.Code != http.StatusOK || !strings.Contains(insightsResponse.Body.String(), `id="dashboard-insights"`) {
		t.Fatalf("hour insights response = %d %s", insightsResponse.Code, insightsResponse.Body.String())
	}
	for _, expected := range []string{`data-dialog-open="top-stats-clients-dialog"`, `data-top-stats-search`, `data-top-stats-limit`, `hx-get="/ui/stats/insights?range=hour"`, `hx-trigger="every 60s"`, `/logs?tab=queries&amp;`, "Last hour"} {
		if !strings.Contains(insightsResponse.Body.String(), expected) {
			t.Errorf("loaded insights markup does not contain %q", expected)
		}
	}
	if strings.Contains(insightsResponse.Body.String(), "hx-swap-oob") {
		t.Error("polled insights should replace themselves rather than swap out of band")
	}
	weekInsights := serveRequest(server, http.MethodGet, "/ui/stats/insights?range=week")
	if weekInsights.Code != http.StatusOK || !strings.Contains(weekInsights.Body.String(), "Last 7 days") {
		t.Fatalf("week insights response = %d %s", weekInsights.Code, weekInsights.Body.String())
	}
	if strings.Contains(weekInsights.Body.String(), `hx-trigger="every 60s"`) {
		t.Error("week insights should load on demand rather than poll")
	}
	customInsightsPath := "/ui/stats/insights?range=custom&start=" + url.QueryEscape(now.Add(-time.Hour).UTC().Format(time.RFC3339Nano)) + "&end=" + url.QueryEscape(now.UTC().Format(time.RFC3339Nano))
	customInsights := serveRequest(server, http.MethodGet, customInsightsPath)
	if customInsights.Code != http.StatusOK || !strings.Contains(customInsights.Body.String(), "Custom range") {
		t.Fatalf("custom insights response = %d %s", customInsights.Code, customInsights.Body.String())
	}
	if response := serveRequest(server, http.MethodGet, "/ui/stats/insights?range=custom&start=nope&end=still-nope"); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid custom insights status = %d, want 400", response.Code)
	}
	if response := serveRequest(server, http.MethodGet, "/ui/stats/insights?range=forever"); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid insights range status = %d, want 400", response.Code)
	}
	dnsClientResponse := serveRequest(server, http.MethodGet, "/dns-client")
	if dnsClientResponse.Code != http.StatusOK {
		t.Fatalf("DNS client page status = %d", dnsClientResponse.Code)
	}
	for _, expected := range []string{
		"Resolve DNS records and diagnose name resolution issues",
		"This Server",
		"Public Resolvers",
		"Cloudflare (1.1.1.1)",
		"Google (8.8.8.8)",
		"Quad9 (9.9.9.9)",
		"Root Servers",
		"Search servers...",
		"Custom...",
		"Custom DNS Server",
		"Use Server",
		"EDNS subnet",
		"DNSSEC",
		"Quick Queries",
		"Understanding Results",
	} {
		if !strings.Contains(dnsClientResponse.Body.String(), expected) {
			t.Errorf("DNS client page does not contain %q", expected)
		}
	}
	if strings.Contains(dnsClientResponse.Body.String(), `name="name" placeholder="Domain name" value=`) {
		t.Error("DNS client page pre-populates the domain input")
	}
	cacheResponse := serveRequest(server, http.MethodGet, "/cache")
	if cacheResponse.Code != http.StatusOK {
		t.Fatalf("cache page status = %d", cacheResponse.Code)
	}
	aboutResponse := serveRequest(server, http.MethodGet, "/about")
	if aboutResponse.Code != http.StatusOK {
		t.Fatalf("about page status = %d", aboutResponse.Code)
	}
	for _, expected := range []string{"About", "Sable DNS Server", "Prometheus Metrics", "Installed version", "Check for Updates", "MIT License", `class="nav-item active" href="/about"`, `job_name: &#34;sable-dns&#34;`} {
		if !strings.Contains(aboutResponse.Body.String(), expected) {
			t.Errorf("about page does not contain %q", expected)
		}
	}
	if strings.Contains(aboutResponse.Body.String(), "@Icon(") {
		t.Error("about page contains unrendered icon component syntax")
	}
	for _, expected := range []string{
		"DNS Cache", "Cache Status", "Cached Entries", "Cache Hits (Last Hour)",
		`class="operational-metric blue"`, `class="operational-metric amber"`,
		"Open Cache Browser", "Flush DNS Cache", "Cache Browser", "example.com", `href="/settings?tab=cache"`, `aria-label="Cache settings"`,
		"Clear DNS Cache?", `data-dialog-open="cache-browser-dialog"`,
	} {
		if !strings.Contains(cacheResponse.Body.String(), expected) {
			t.Errorf("cache page does not contain %q", expected)
		}
	}
	flushResponse := serveRequest(server, http.MethodPost, "/ui/cache/flush")
	if flushResponse.Code != http.StatusOK || !strings.Contains(flushResponse.Body.String(), "Cleared 3 cached DNS records") {
		t.Fatalf("cache flush response = %d %s", flushResponse.Code, flushResponse.Body.String())
	}
	for _, expected := range []string{`class="toast toast-success"`, `data-toast`, `data-toast-close`, `role="status"`} {
		if !strings.Contains(flushResponse.Body.String(), expected) {
			t.Errorf("cache flush toast does not contain %q", expected)
		}
	}
	blockingResponse := serveRequest(server, http.MethodGet, "/blocked")
	if blockingResponse.Code != http.StatusOK {
		t.Fatalf("blocking page status = %d", blockingResponse.Code)
	}
	settingsResponse := serveRequest(server, http.MethodGet, "/settings")
	for _, expected := range []string{"Settings", "General", "Protocols", "Recursion", "DNS Forwarders", "Logging", "Blocking Response", "Block List Updates", "Bypass Clients", "Manage Block Lists and Domains", "Display Preferences", `data-time-format-preference`, "12-hour (9:30 PM)"} {
		if !strings.Contains(settingsResponse.Body.String(), expected) {
			t.Errorf("settings page does not contain %q", expected)
		}
	}
	for _, expected := range []string{
		"DNS Blocking", "Block Lists", "Custom Blocked Domains", "Allowed Domains", "Settings → Blocking", `href="/settings?tab=blocking"`, `aria-label="Blocking settings"`,
		`class="operational-metric red"`, `class="operational-metric purple"`,
		`data-blocking-tab="lists"`, `data-domain-search`, "Add Block List", "Add Blocked Domain", "Pause Blocking",
		`blocking-update-button`, `hx-disable="this"`,
		"Import", "Export", "Clear All", `data-domain-import`,
		`pause-menu`,
	} {
		if !strings.Contains(blockingResponse.Body.String(), expected) {
			t.Errorf("blocking page does not contain %q", expected)
		}
	}
	if strings.Contains(blockingResponse.Body.String(), `data-blocking-tab="settings"`) || strings.Contains(blockingResponse.Body.String(), `hx-post="/ui/blocking/settings"`) {
		t.Error("blocking page still contains its old settings tab or mutation form")
	}
	clusterResponse := serveRequest(server, http.MethodGet, "/cluster")
	for _, expected := range []string{"Cluster Status", "No Cluster Configured", "Initialize Primary", "Configure Node", "One Primary", "Manual Promotion", clusterService.Snapshot().NodeID} {
		if !strings.Contains(clusterResponse.Body.String(), expected) {
			t.Errorf("cluster page does not contain %q", expected)
		}
	}
	unconfiguredLive := serveRequest(server, http.MethodGet, "/ui/cluster/status")
	if unconfiguredLive.Code != http.StatusOK || unconfiguredLive.Header().Get("HX-Retarget") != "#cluster-content" || unconfiguredLive.Header().Get("HX-Reswap") != "outerHTML" || !strings.Contains(unconfiguredLive.Body.String(), "No Cluster Configured") {
		t.Fatalf("unconfigured live cluster transition = %d headers=%v body=%s", unconfiguredLive.Code, unconfiguredLive.Header(), unconfiguredLive.Body.String())
	}
	clusterForm := url.Values{"domain": {"cluster.example"}, "addresses": {"192.0.2.10\n2001:db8::10"}}
	clusterRequest := httptest.NewRequest(http.MethodPost, "/ui/cluster/initialize", strings.NewReader(clusterForm.Encode()))
	clusterRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	clusterMutation := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(clusterMutation, clusterRequest)
	if clusterMutation.Code != http.StatusUnprocessableEntity || !strings.Contains(clusterMutation.Body.String(), "HTTPS Console / API URL") {
		t.Fatalf("insecure cluster initialization = %d %s", clusterMutation.Code, clusterMutation.Body.String())
	}
	insecureAPIInitialize := httptest.NewRequest(http.MethodPost, "/api/v1/cluster", strings.NewReader(`{"domain":"cluster.example","addresses":["192.0.2.10"]}`))
	insecureAPIInitialize.Header.Set("Content-Type", "application/json")
	insecureAPIResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(insecureAPIResponse, insecureAPIInitialize)
	if insecureAPIResponse.Code != http.StatusUnprocessableEntity || !strings.Contains(insecureAPIResponse.Body.String(), "HTTPS advertised URL") {
		t.Fatalf("insecure API cluster initialization = %d %s", insecureAPIResponse.Code, insecureAPIResponse.Body.String())
	}
	if err := clusterService.Initialize(context.Background(), "cluster.example", []string{"192.0.2.10", "2001:db8::10"}); err != nil {
		t.Fatal(err)
	}
	clusterDNSClient := serveRequest(server, http.MethodGet, "/dns-client")
	if clusterDNSClient.Code != http.StatusOK {
		t.Fatalf("cluster DNS client status = %d", clusterDNSClient.Code)
	}
	for _, duplicate := range []string{"Cluster Nodes", "dns-1 (This node)", "cluster-node:" + clusterService.Snapshot().NodeID} {
		if strings.Contains(clusterDNSClient.Body.String(), duplicate) {
			t.Errorf("single-node DNS client unexpectedly contains %q", duplicate)
		}
	}
	configuredClusterPage := serveRequest(server, http.MethodGet, "/cluster")
	if !strings.Contains(configuredClusterPage.Body.String(), `data-dialog-open="cluster-settings-dialog"`) ||
		!strings.Contains(configuredClusterPage.Body.String(), `id="cluster-settings-dialog"`) ||
		strings.Contains(configuredClusterPage.Body.String(), `data-dialog-open="cluster-settings-dialog" disabled`) {
		t.Fatalf("configured cluster node settings control is unavailable: %s", configuredClusterPage.Body.String())
	}
	clusterAPI := serveRequest(server, http.MethodGet, "/api/v1/cluster")
	if clusterAPI.Code != http.StatusOK || !strings.Contains(clusterAPI.Body.String(), `"initialized":true`) || !strings.Contains(clusterAPI.Body.String(), `"mode":"primary-replica"`) || !strings.Contains(clusterAPI.Body.String(), `"local_role":"primary"`) || !strings.Contains(clusterAPI.Body.String(), `"sync_state":"current"`) {
		t.Fatalf("cluster API = %d %s", clusterAPI.Code, clusterAPI.Body.String())
	}
	liveCluster := serveRequest(server, http.MethodGet, "/ui/cluster/status")
	for _, expected := range []string{`hx-trigger="every 2s"`, `class="operational-metric green"`, `class="operational-metric cyan"`, "Node Sync Status", "Primary", "Generation", "Applied / Current", "Generation Lag", "Last Successful Sync", "Fully synchronized", "Just now"} {
		if liveCluster.Code != http.StatusOK || !strings.Contains(liveCluster.Body.String(), expected) {
			t.Errorf("live cluster status does not contain %q: %d %s", expected, liveCluster.Code, liveCluster.Body.String())
		}
	}
	nodeAPI := serveRequest(server, http.MethodGet, "/api/v1/cluster/nodes/"+clusterService.Snapshot().NodeID)
	if nodeAPI.Code != http.StatusOK || !strings.Contains(nodeAPI.Body.String(), `"sync_state":"current"`) || !strings.Contains(nodeAPI.Body.String(), `"lag":0`) {
		t.Fatalf("cluster node API = %d %s", nodeAPI.Code, nodeAPI.Body.String())
	}
	clusterDelete := serveRequest(server, http.MethodPost, "/ui/cluster/delete")
	if clusterDelete.Code != http.StatusOK || !strings.Contains(clusterDelete.Body.String(), "Cluster configuration deleted") || clusterService.Snapshot().Initialized {
		t.Fatalf("cluster delete = %d %s", clusterDelete.Code, clusterDelete.Body.String())
	}
	if err := clusterService.Initialize(context.Background(), "metrics.cluster.example", []string{"192.0.2.10"}); err != nil {
		t.Fatal(err)
	}

	healthResponse := serveRequest(server, "GET", "/api/v1/health")
	if healthResponse.Code != 200 {
		t.Fatalf("health status = %d, want 200: %s", healthResponse.Code, healthResponse.Body.String())
	}
	if healthResponse.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("Content-Security-Policy header is empty")
	}
	queryLogResponse := serveRequest(server, "GET", "/ui/query-log")
	for _, expected := range []string{"example.com", "192.0.2.1", "cache"} {
		if !strings.Contains(queryLogResponse.Body.String(), expected) {
			t.Errorf("query log does not contain %q", expected)
		}
	}
	logsResponse := serveRequest(server, "GET", "/logs?tab=queries")
	for _, expected := range []string{"Server Logs", "DNS Query Log", "example.com", "Filters", "Search in results", "Protocol", "Answer", `href="/settings?tab=logging"`} {
		if !strings.Contains(logsResponse.Body.String(), expected) {
			t.Errorf("logs page does not contain %q", expected)
		}
	}
	queryLogAPIResponse := serveRequest(server, "GET", "/api/v1/query-log?limit=1")
	if queryLogAPIResponse.Code != 200 || !strings.Contains(queryLogAPIResponse.Body.String(), "example.com") || !strings.Contains(queryLogAPIResponse.Body.String(), `"decision":{"policy":"no_match","cache":"hit","resolver":"cache"}`) {
		t.Fatalf("query log API response = %d %s", queryLogAPIResponse.Code, queryLogAPIResponse.Body.String())
	}
	invalidLimitResponse := serveRequest(server, "GET", "/api/v1/query-log?limit=invalid")
	if invalidLimitResponse.Code != 400 {
		t.Fatalf("invalid query log limit status = %d, want 400", invalidLimitResponse.Code)
	}
	purgeResponse := serveRequest(server, "POST", "/api/v1/cache/purge")
	if purgeResponse.Code != 200 || !strings.Contains(purgeResponse.Body.String(), `"removed":3`) {
		t.Fatalf("cache purge response = %d %s", purgeResponse.Code, purgeResponse.Body.String())
	}
	policyResponse := serveRequest(server, "GET", "/api/v1/policy")
	if policyResponse.Code != 200 || !strings.Contains(policyResponse.Body.String(), `"config_revision":7`) {
		t.Fatalf("policy response = %d %s", policyResponse.Code, policyResponse.Body.String())
	}
	purgeUIResponse := serveRequest(server, "POST", "/ui/cache/purge")
	if purgeUIResponse.Code != 200 || !strings.Contains(purgeUIResponse.Body.String(), "Purged 3 cache entries") {
		t.Fatalf("cache purge UI response = %d %s", purgeUIResponse.Code, purgeUIResponse.Body.String())
	}
	metricsResponse := serveRequest(server, "GET", "/metrics")
	if metricsResponse.Code != 200 || metricsResponse.Header().Get("Content-Type") != prometheusContentType {
		t.Fatalf("metrics response = %d, %q", metricsResponse.Code, metricsResponse.Header().Get("Content-Type"))
	}
	clusterMetricsState := clusterService.Snapshot()
	for _, expected := range []string{
		"sable_dns_queries_total 42",
		"sable_dns_local_answers_total 5",
		"sable_dnssec_secure_total 0",
		"sable_dnssec_insecure_total 0",
		"sable_dnssec_bogus_total 0",
		"sable_dnssec_trust_anchor_updates_enabled 0",
		"sable_dnssec_trust_anchors 0",
		"sable_dnssec_trust_anchors_pending 0",
		"sable_dnssec_trust_anchors_missing 0",
		"sable_dnssec_trust_anchors_revoked 0",
		"sable_local_hosts 2",
		"sable_query_log_persisted_total 1",
		"sable_cluster_initialized 1",
		"sable_cluster_nodes 1",
		"sable_cluster_nodes_connected 1",
		"sable_cluster_nodes_synchronized 1",
		fmt.Sprintf("sable_cluster_generation %d", clusterMetricsState.Generation),
		`sable_cluster_is_primary 1`,
		`sable_cluster_node_connected{node_id="` + clusterMetricsState.NodeID + `",node="dns-1",role="primary"} 1`,
		`sable_cluster_node_synchronized{node_id="` + clusterMetricsState.NodeID + `",node="dns-1",role="primary"} 1`,
		`sable_cluster_node_replication_lag_generations{node_id="` + clusterMetricsState.NodeID + `",node="dns-1",role="primary"} 0`,
		`sable_dns_response_duration_seconds_bucket{source="cache",protocol="udp",cache="hit",rcode="NOERROR",le="0.001"} 1`,
		`sable_dns_response_duration_seconds_bucket{source="cache",protocol="udp",cache="hit",rcode="NOERROR",le="+Inf"} 2`,
		`sable_dns_response_duration_seconds_sum{source="cache",protocol="udp",cache="hit",rcode="NOERROR"} 0.0015`,
		`sable_dns_response_duration_seconds_count{source="cache",protocol="udp",cache="hit",rcode="NOERROR"} 2`,
	} {
		if !strings.Contains(metricsResponse.Body.String(), expected) {
			t.Errorf("metrics do not contain %q", expected)
		}
	}
}

func TestRequestBodyTimeoutReservesTheLongWindowForBoundedUploads(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/ui/backup/restore",
		"/ui/zones/import",
		"/ui/zones/import-new",
		"/ui/blocking/domains/import",
		"/ui/blocking/allowed/import",
	} {
		if timeout := requestBodyTimeout(path); timeout != webReadTimeout {
			t.Errorf("requestBodyTimeout(%q) = %s, want %s", path, timeout, webReadTimeout)
		}
	}
	for _, path := range []string{"/setup", "/login", "/api/v1/cluster/enroll", "/dns-query"} {
		if timeout := requestBodyTimeout(path); timeout != webRequestBodyTimeout {
			t.Errorf("requestBodyTimeout(%q) = %s, want %s", path, timeout, webRequestBodyTimeout)
		}
	}
}

func TestSharedHTTPSListenerServesUnauthenticatedDoHOnlyOverTLS(t *testing.T) {
	t.Parallel()

	configuration := config.Defaults()
	configuration.Server.HTTPSListen = "0.0.0.0:443"
	configuration.EncryptedDNS.DoHListen = []string{"0.0.0.0:443"}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testResolverStats{testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}}},
		testConfiguration{snapshot: config.Snapshot{Config: configuration}}, testZones{}, "sqlite",
		testQueryLog{}, testQueryLog{}, func(context.Context) error { return nil }, nil, false, false, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeA)
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://sable.test/dns-query", bytes.NewReader(wire))
	request.Header.Set("Content-Type", "application/dns-message")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/dns-message" {
		t.Fatalf("HTTPS DoH response = %d %q: %s", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(response.Body.Bytes()); err != nil || len(answer.Answer) != 1 {
		t.Fatalf("HTTPS DoH answer = %v, %v", answer.Answer, err)
	}

	request = httptest.NewRequest(http.MethodPost, "http://sable.test/dns-query", bytes.NewReader(wire))
	request.Header.Set("Content-Type", "application/dns-message")
	response = httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("plain HTTP DoH response = %d, want 404", response.Code)
	}
}

func TestSettingsEditorValidatesPersistsAndRendersRuntimeSettings(t *testing.T) {
	t.Parallel()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 4}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration, configuration.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"dns_listen": {"127.0.0.1:5353\n[::1]:5353"}, "forwarders": {"1.1.1.1:53\n9.9.9.9:53"},
		"resolver_mode": {"recursive"}, "root_hints": {"192.0.2.1:53\n192.0.2.2:53"},
		"resolver_timeout": {"2s"}, "resolver_retries": {"3"}, "resolver_retry_timeout": {"800ms"},
		"cache_size": {"2048"}, "dnssec_validation": {"true"},
		"trust_anchor_updates": {"true"}, "dot_listen": {"127.0.0.1:853"}, "doh_listen": {"127.0.0.1:8443"},
		"certificate_file": {"tls/cert.pem"}, "private_key_file": {"tls/key.pem"},
		"minimum_tls_version": {"1.3"}, "query_log_enabled": {"true"},
		"cache_minimum_ttl": {"10"}, "cache_maximum_ttl": {"604800"}, "cache_negative_ttl": {"300"}, "cache_failure_ttl": {"10"},
		"serve_stale": {"true"}, "cache_stale_ttl": {"259200"}, "cache_stale_answer_ttl": {"30"},
		"save_cache":            {"true"},
		"cache_stale_reset_ttl": {"30"}, "cache_prefetch_minimum_ttl": {"2"},
		"cache_stale_max_wait_ms":    {"1800"},
		"cache_prefetch_trigger_ttl": {"9"}, "cache_prefetch_sample_interval": {"5m"},
		"cache_prefetch_hits_per_hour": {"30"},
		"blocking_update_hours":        {"12"}, "blocking_response_type": {"zero"}, "blocking_response_ttl": {"45"},
		"blocking_bypass_clients": {"192.0.2.10\n10.0.0.0/8"}, "blocking_allow_txt_report": {"true"},
		"settings_tab": {"blocking"},
	}
	request := httptest.NewRequest(http.MethodPost, "/ui/settings", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Settings saved and applied") || !strings.Contains(response.Body.String(), `data-active-tab="blocking"`) {
		t.Fatalf("settings update = %d %s", response.Code, response.Body.String())
	}
	updated := configuration.Current()
	if updated.Revision != 5 || updated.Config.Resolver.CacheSize != 2048 || updated.Config.Resolver.Timeout.Duration != 2*time.Second ||
		updated.Config.Resolver.Retries != 3 || updated.Config.Resolver.RetryTimeout.Duration != 800*time.Millisecond ||
		updated.Config.Resolver.Mode != "recursive" || len(updated.Config.Resolver.RootHints) != 2 ||
		!updated.Config.Resolver.SaveCache || updated.Config.Resolver.CacheStaleResetTTL != 30 ||
		updated.Config.Resolver.CacheStaleMaxWait.Duration != 1800*time.Millisecond ||
		updated.Config.Resolver.CachePrefetchSample.Duration != 5*time.Minute || updated.Config.Resolver.CachePrefetchHitsPerHour != 30 ||
		updated.Config.EncryptedDNS.MinimumVersion != "1.3" || len(updated.Config.Server.DNSListen) != 2 ||
		updated.Config.Blocking.UpdateInterval.Duration != 12*time.Hour || updated.Config.Blocking.ResponseType != "zero" ||
		updated.Config.Blocking.ResponseTTL != 45 || len(updated.Config.Blocking.BypassClients) != 2 || !updated.Config.Blocking.AllowTXTReport {
		t.Fatalf("updated settings = %+v revision=%d", updated.Config, updated.Revision)
	}

	invalid := httptest.NewRequest(http.MethodPost, "/ui/settings", strings.NewReader(url.Values{
		"dns_listen": {"127.0.0.1:5353"}, "forwarders": {"1.1.1.1:53"},
		"resolver_timeout": {"invalid"}, "cache_size": {"2048"},
	}.Encode()))
	invalid.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	invalidResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusUnprocessableEntity || configuration.Current().Revision != 5 {
		t.Fatalf("invalid settings update = %d revision=%d", invalidResponse.Code, configuration.Current().Revision)
	}
	// The client admits marked error fragments into the target while keeping
	// unrendered server errors out of the page.
	if invalidResponse.Header().Get("X-Sable-Console-Fragment") != "true" {
		t.Fatalf("rejected settings response was not marked as a console fragment: %v", invalidResponse.Header())
	}
	if !strings.Contains(invalidResponse.Body.String(), "Block-list update interval must be between 1 and 8760 hours.") {
		t.Fatalf("rejected settings response did not carry the reason: %s", invalidResponse.Body.String())
	}
}

func TestRequiredPermissionCoversControlPlaneRoutes(t *testing.T) {
	t.Parallel()
	tests := []struct{ method, path, permission string }{
		{http.MethodGet, "/settings", auth.PermissionSettingsRead},
		{http.MethodPost, "/ui/settings", auth.PermissionSettingsWrite},
		{http.MethodPost, "/ui/settings/tsig/save", auth.PermissionSettingsWrite},
		{http.MethodPost, "/ui/settings/tsig/delete", auth.PermissionSettingsWrite},
		{http.MethodPost, "/ui/certificates/renew", auth.PermissionSettingsWrite},
		{http.MethodPost, "/ui/certificates/generate", auth.PermissionSettingsWrite},
		{http.MethodPost, "/ui/certificates/import", auth.PermissionSettingsWrite},
		{http.MethodPost, "/api/v1/cache/purge", auth.PermissionSettingsWrite},
		{http.MethodGet, "/zones/example.test", auth.PermissionZonesRead},
		{http.MethodPost, "/ui/zones/add", ""},
		{http.MethodGet, "/blocked", auth.PermissionBlockingRead},
		{http.MethodPost, "/ui/blocking/toggle", auth.PermissionBlockingWrite},
		{http.MethodGet, "/administration", auth.PermissionUsersRead},
		{http.MethodGet, "/profile", ""},
		{http.MethodPost, "/ui/profile", ""},
		{http.MethodGet, "/cluster", auth.PermissionClusterRead},
		{http.MethodGet, "/api/v1/cluster", auth.PermissionClusterRead},
		{http.MethodGet, "/api/v1/cluster/nodes/node-1", auth.PermissionClusterRead},
		{http.MethodGet, "/ui/cluster/status", auth.PermissionClusterRead},
		{http.MethodPost, "/ui/cluster/initialize", auth.PermissionClusterWrite},
		{http.MethodPost, "/ui/cluster/settings", auth.PermissionClusterWrite},
		{http.MethodPost, "/ui/cluster/restart", auth.PermissionClusterWrite},
		{http.MethodPost, "/ui/cluster/leave", auth.PermissionClusterWrite},
		{http.MethodPost, "/api/v1/cluster", auth.PermissionClusterWrite},
		{http.MethodDelete, "/api/v1/cluster/membership", auth.PermissionClusterWrite},
		{http.MethodDelete, "/api/v1/cluster", auth.PermissionClusterWrite},
		{http.MethodGet, "/ui/administration/tokens", auth.PermissionUsersRead},
		{http.MethodPost, "/ui/administration/users", auth.PermissionUsersWrite},
		{http.MethodPost, "/ui/administration/users/profile", auth.PermissionUsersWrite},
		{http.MethodGet, "/api/v1/query-log?limit=1", auth.PermissionLogsRead},
		{http.MethodGet, "/ui/updates", auth.PermissionUpdatesRead},
		{http.MethodPost, "/ui/updates/check", auth.PermissionUpdatesRead},
		{http.MethodPost, "/ui/updates/command-check", auth.PermissionUpdatesRead},
		{http.MethodPost, "/ui/updates/install", auth.PermissionUpdatesApply},
		{http.MethodPost, "/ui/updates/restart", auth.PermissionUpdatesApply},
	}
	for _, test := range tests {
		request := httptest.NewRequest(test.method, test.path, nil)
		if permission := requiredPermission(request); permission != test.permission {
			t.Errorf("%s %s permission = %q, want %q", test.method, test.path, permission, test.permission)
		}
	}
}

func TestManualCertificateGenerationConfiguresGeneratedKeyPair(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}, baseDirectory: directory}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration, configuration.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	server.SetCertificateController(certificates.New(testCertificateVault{}, slog.New(slog.NewTextHandler(io.Discard, nil)), directory))
	form := url.Values{
		"manual_certificate_names":       {"dns.example.test\n192.0.2.10"},
		"manual_certificate_valid_days":  {"365"},
		"manual_certificate_storage_dir": {"data/tls/manual"},
		"settings_tab":                   {"protocols"},
	}
	request := httptest.NewRequest(http.MethodPost, "/ui/certificates/generate", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Self-signed certificate generated and activated") {
		t.Fatalf("certificate generation = %d %s", response.Code, response.Body.String())
	}
	updated := configuration.Current()
	if updated.Config.EncryptedDNS.CertificateMode != "manual" || updated.Config.EncryptedDNS.CertificateFile != filepath.Join("data", "tls", "manual", "certificate.pem") {
		t.Fatalf("certificate configuration = %+v", updated.Config.EncryptedDNS)
	}
	certificate, privateKey := updated.Config.EncryptedDNSCertificatePaths(directory)
	if _, err := os.Stat(certificate); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(privateKey); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %v", info.Mode().Perm())
	}
}

func TestClusterSettingsAreStagedBeforeInitialization(t *testing.T) {
	t.Parallel()
	configuration := config.Defaults()
	configuration.Cluster.NodeName = "dns-old"
	configuration.Cluster.AdvertiseURL = "http://127.0.0.1:5380"
	editor := &editableTestConfiguration{snapshot: config.Snapshot{Config: configuration, Revision: 1}, baseDirectory: t.TempDir()}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		editor, editor.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	clusterService, err := clusterstate.Open(clusterstate.Options{
		DataDirectory: configuration.ClusterDataPath(editor.baseDirectory), NodeName: configuration.Cluster.NodeName,
		AdvertiseURL: configuration.Cluster.AdvertiseURL, Version: "dev", StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	server.SetClusterController(clusterService)
	if server.clusterView(httptest.NewRequest(http.MethodGet, "/cluster", nil), "", "").RestartRequired {
		t.Fatal("matching active and persisted cluster settings were reported as pending")
	}

	form := url.Values{
		"data_dir":  {"data/cluster-new"},
		"node_name": {"dns-1"}, "advertise_url": {"https://dns-1.example.test:5380"},
	}
	request := httptest.NewRequest(http.MethodPost, "/ui/cluster/settings", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Restart Sable") || !strings.Contains(response.Body.String(), "Restart required") {
		t.Fatalf("cluster settings response = %d %s", response.Code, response.Body.String())
	}
	updated := editor.Current()
	if updated.Revision != 2 || updated.Config.Cluster.DataDirectory != "data/cluster-new" || updated.Config.Cluster.NodeName != "dns-1" || updated.Config.Cluster.AdvertiseURL != "https://dns-1.example.test:5380" {
		t.Fatalf("updated cluster settings = %+v revision=%d", updated.Config.Cluster, updated.Revision)
	}
	if clusterService.Snapshot().NetworkReady {
		t.Fatal("staged settings changed the active cluster transport before restart")
	}

	initialize := httptest.NewRequest(http.MethodPost, "/ui/cluster/initialize", strings.NewReader(url.Values{"domain": {"cluster.example.test"}, "addresses": {"192.0.2.10"}}.Encode()))
	initialize.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	initializeResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(initializeResponse, initialize)
	if initializeResponse.Code != http.StatusConflict || clusterService.Snapshot().Initialized {
		t.Fatalf("initialize with pending restart = %d initialized=%t", initializeResponse.Code, clusterService.Snapshot().Initialized)
	}
	apiInitialize := httptest.NewRequest(http.MethodPost, "/api/v1/cluster", strings.NewReader(`{"domain":"cluster.example.test","addresses":["192.0.2.10"]}`))
	apiInitialize.Header.Set("Content-Type", "application/json")
	apiInitializeResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(apiInitializeResponse, apiInitialize)
	if apiInitializeResponse.Code != http.StatusConflict || !strings.Contains(apiInitializeResponse.Body.String(), "restart Sable") {
		t.Fatalf("API initialize with pending restart = %d %s", apiInitializeResponse.Code, apiInitializeResponse.Body.String())
	}
}

func TestClusterSettingsCanBeStagedWhileInitialized(t *testing.T) {
	t.Parallel()
	configuration := config.Defaults()
	configuration.Cluster.DataDirectory = "data/cluster"
	configuration.Cluster.NodeName = "dns-1"
	configuration.Cluster.AdvertiseURL = "https://dns-1.example.test:5380"
	directory := t.TempDir()
	editor := &editableTestConfiguration{snapshot: config.Snapshot{Config: configuration, Revision: 1}, baseDirectory: directory}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		editor, editor.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	clusterService, err := clusterstate.Open(clusterstate.Options{
		DataDirectory: configuration.ClusterDataPath(directory), NodeName: configuration.Cluster.NodeName,
		AdvertiseURL: configuration.Cluster.AdvertiseURL, Version: "dev", StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := clusterService.Initialize(context.Background(), "cluster.example.test", []string{"192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	server.SetClusterController(clusterService)
	form := url.Values{
		"data_dir": {"data/must-not-move"}, "node_name": {"core-dns"},
		"advertise_url": {"https://core-dns.example.test:5443"},
	}
	request := httptest.NewRequest(http.MethodPost, "/ui/cluster/settings", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Restart required") {
		t.Fatalf("initialized cluster settings response = %d %s", response.Code, response.Body.String())
	}
	updated := editor.Current().Config.Cluster
	if updated.DataDirectory != "data/cluster" || updated.NodeName != "core-dns" || updated.AdvertiseURL != "https://core-dns.example.test:5443" {
		t.Fatalf("initialized cluster settings = %+v", updated)
	}
}

func TestClusterOnboardingStaysInWizardAcrossRestart(t *testing.T) {
	t.Parallel()
	configuration := config.Defaults()
	configuration.Cluster.NodeName = "home-office.example.test"
	configuration.Cluster.AdvertiseURL = "http://127.0.0.1:5380"
	editor := &editableTestConfiguration{snapshot: config.Snapshot{Config: configuration, Revision: 1}, baseDirectory: t.TempDir()}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		editor, editor.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	clusterService, err := clusterstate.Open(clusterstate.Options{
		DataDirectory: configuration.ClusterDataPath(editor.baseDirectory), NodeName: configuration.Cluster.NodeName,
		AdvertiseURL: configuration.Cluster.AdvertiseURL, Version: "dev", StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	server.SetClusterController(clusterService)
	initial := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(initial, httptest.NewRequest(http.MethodGet, "/cluster", nil))
	initialBody := initial.Body.String()
	for _, expected := range []string{`data-cluster-onboarding`, `data-cluster-wizard-panel="1"`, `data-cluster-wizard-panel="2" hidden`, `data-cluster-wizard-next`, "Existing HTTPS", "Let's Encrypt", "Import PEM", "Advanced certificate options", `value="home-office"`, `name="advertise_url" value="" type="url" pattern="https://.*" data-https-url`, `icon-globe`} {
		if !strings.Contains(initialBody, expected) {
			t.Fatalf("initial onboarding missing %q: %s", expected, initialBody)
		}
	}

	invalidForm := url.Values{
		"workflow": {"primary"}, "wizard_step": {"https"}, "certificate_source": {"external"},
		"data_dir": {"data/cluster"}, "node_name": {"dns-1"}, "advertise_url": {"http://dns-1.example.test"},
	}
	invalidRequest := httptest.NewRequest(http.MethodPost, "/ui/cluster/onboarding", strings.NewReader(invalidForm.Encode()))
	invalidRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	invalidResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(invalidResponse, invalidRequest)
	if invalidResponse.Code != http.StatusUnprocessableEntity || !strings.Contains(invalidResponse.Body.String(), "absolute HTTPS URL") {
		t.Fatalf("HTTP onboarding URL response = %d %s", invalidResponse.Code, invalidResponse.Body.String())
	}
	if current := editor.Current(); current.Revision != 1 || current.Config.Cluster.NodeName != "home-office.example.test" {
		t.Fatalf("invalid onboarding staged configuration: revision=%d cluster=%+v", current.Revision, current.Config.Cluster)
	}

	form := url.Values{
		"workflow": {"primary"}, "certificate_source": {"external"},
		"data_dir": {"data/cluster"}, "node_name": {"dns-1"}, "advertise_url": {"https://dns-1.example.test"},
	}
	request := httptest.NewRequest(http.MethodPost, "/ui/cluster/onboarding", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("onboarding response = %d %s", response.Code, response.Body.String())
	}
	if response.Header().Get("HX-Replace-Url") != "/cluster?onboarding=primary" {
		t.Fatalf("onboarding URL = %q", response.Header().Get("HX-Replace-Url"))
	}
	body := response.Body.String()
	for _, expected := range []string{"Restart Sable to continue", "Restart &amp; Continue", `data-sable-restart`, `data-dialog-auto-open="true"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("onboarding response missing %q: %s", expected, body)
		}
	}
	updated := editor.Current().Config
	if updated.Cluster.NodeName != "dns-1" || updated.Cluster.AdvertiseURL != "https://dns-1.example.test" {
		t.Fatalf("onboarding settings = %+v", updated.Cluster)
	}
	restartedService, err := clusterstate.Open(clusterstate.Options{
		DataDirectory: updated.ClusterDataPath(editor.baseDirectory), NodeName: updated.Cluster.NodeName,
		AdvertiseURL: updated.Cluster.AdvertiseURL, Version: "dev", StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	server.SetClusterController(restartedService)
	continued := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(continued, httptest.NewRequest(http.MethodGet, "/cluster?onboarding=primary", nil))
	continuedBody := continued.Body.String()
	for _, expected := range []string{"Cluster Domain", "Initialize Primary", `data-dialog-auto-open="true"`, `/cluster?onboarding=primary&amp;configure=https`, `>Back</a>`} {
		if !strings.Contains(continuedBody, expected) {
			t.Fatalf("continued onboarding missing %q: %s", expected, continuedBody)
		}
	}

	joinForm := url.Values{
		"workflow": {"join"}, "primary_url": {"https://127.0.0.1:1"},
		"token": {"test-enrollment-token"}, "addresses": {"192.0.2.11"},
	}
	joinRequest := httptest.NewRequest(http.MethodPost, "/ui/cluster/join", strings.NewReader(joinForm.Encode()))
	joinRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	joinRequest.Header.Set("HX-Request", "true")
	joinResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(joinResponse, joinRequest)
	joinBody := joinResponse.Body.String()
	if joinResponse.Code != http.StatusUnprocessableEntity {
		t.Fatalf("failed join status = %d body=%s", joinResponse.Code, joinBody)
	}
	if joinResponse.Header().Get(consoleFragmentHeader) != "true" {
		t.Fatalf("failed join %s = %q, want true", consoleFragmentHeader, joinResponse.Header().Get(consoleFragmentHeader))
	}
	if cacheControl := joinResponse.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("failed join Cache-Control = %q", cacheControl)
	}
	directJoinRequest := httptest.NewRequest(http.MethodPost, "/ui/cluster/join", strings.NewReader(joinForm.Encode()))
	directJoinRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	directJoinResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(directJoinResponse, directJoinRequest)
	if directJoinResponse.Code != http.StatusUnprocessableEntity {
		t.Fatalf("direct failed join status = %d body=%s", directJoinResponse.Code, directJoinResponse.Body.String())
	}
	for _, expected := range []string{
		`data-dialog-auto-open="true"`, `data-cluster-join-form`, `class="cluster-join-error"`,
		"Could not join the cluster", `value="https://127.0.0.1:1"`, `value="test-enrollment-token"`,
		`>192.0.2.11</textarea>`, `class="cluster-join-submit-pending"`, "Joining &amp; syncing…",
	} {
		if !strings.Contains(joinBody, expected) {
			t.Fatalf("failed join response missing %q: %s", expected, joinBody)
		}
	}

	edit := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(edit, httptest.NewRequest(http.MethodGet, "/cluster?onboarding=primary&configure=https", nil))
	editBody := edit.Body.String()
	for _, expected := range []string{`data-initial-step="2"`, `data-cluster-wizard-panel="1" hidden`, `data-cluster-wizard-panel="2"`, `name="advertise_url" value="https://dns-1.example.test"`, `data-cluster-wizard-back`} {
		if !strings.Contains(editBody, expected) {
			t.Fatalf("editable onboarding missing %q: %s", expected, editBody)
		}
	}

	unchangedForm := url.Values{
		"workflow": {"primary"}, "wizard_step": {"https"}, "certificate_source": {"external"},
		"data_dir": {"data/cluster"}, "node_name": {"dns-1"}, "advertise_url": {"https://dns-1.example.test"},
	}
	unchangedRequest := httptest.NewRequest(http.MethodPost, "/ui/cluster/onboarding", strings.NewReader(unchangedForm.Encode()))
	unchangedRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	unchangedResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(unchangedResponse, unchangedRequest)
	if unchangedResponse.Code != http.StatusOK || !strings.Contains(unchangedResponse.Body.String(), "Cluster Domain") || strings.Contains(unchangedResponse.Body.String(), "Restart Sable to continue") {
		t.Fatalf("unchanged onboarding did not return to initialization = %d %s", unchangedResponse.Code, unchangedResponse.Body.String())
	}
}

func TestClusterJoinErrorExplainsDNSFailure(t *testing.T) {
	t.Parallel()
	err := fmt.Errorf("contact cluster primary: %w", &net.DNSError{Name: "localhoist", IsNotFound: true})
	if message := clusterJoinError(err); message != `Could not resolve primary host "localhoist". Check the Primary URL and try again.` {
		t.Fatalf("DNS join error = %q", message)
	}
}

func TestClusterOnboardingPrivateCAConfiguresBundledReplicaTrust(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	configuration := config.Defaults()
	editor := &editableTestConfiguration{snapshot: config.Snapshot{Config: configuration, Revision: 1}, baseDirectory: directory}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		editor, editor.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	server.SetCertificateController(certificates.New(testCertificateVault{}, slog.New(slog.NewTextHandler(io.Discard, nil)), directory))
	clusterService, err := clusterstate.Open(clusterstate.Options{
		DataDirectory: configuration.ClusterDataPath(directory), NodeName: "dns-1", AdvertiseURL: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	server.SetClusterController(clusterService)

	form := url.Values{
		"workflow": {"primary"}, "certificate_source": {"generated"},
		"data_dir": {"data/cluster"}, "node_name": {"dns-1"}, "advertise_url": {"https://127.0.0.1:5443"},
		"generated_https_listen": {"127.0.0.1:5443"}, "generated_valid_days": {"365"},
		"generated_storage_dir": {"data/cluster/pki"},
	}
	request := httptest.NewRequest(http.MethodPost, "/ui/cluster/onboarding", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("private CA onboarding = %d %s", response.Code, response.Body.String())
	}
	updated := editor.Current().Config
	if updated.Cluster.TrustAnchorFile != filepath.Join("data", "cluster", "pki", "cluster-ca.pem") ||
		updated.EncryptedDNS.CertificateFile != filepath.Join("data", "cluster", "pki", "node-certificate.pem") {
		t.Fatalf("private CA configuration: cluster=%+v encrypted_dns=%+v", updated.Cluster, updated.EncryptedDNS)
	}
	trustAnchor := updated.ClusterTrustAnchorPath(directory)
	if info, err := os.Stat(trustAnchor); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private CA trust anchor: info=%v error=%v", info, err)
	}

	restarted, err := clusterstate.Open(clusterstate.Options{
		DataDirectory: updated.ClusterDataPath(directory), NodeName: updated.Cluster.NodeName,
		AdvertiseURL: updated.Cluster.AdvertiseURL, HTTPSListen: updated.Server.HTTPSListen,
		TrustAnchorFile: trustAnchor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	token, err := restarted.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token.Token, "sable-enroll-v1.") {
		t.Fatalf("private CA enrollment token = %q", token.Token)
	}
}

func TestClusterManagedRestartIsSingleShotAndHealthIdentifiesNewProcess(t *testing.T) {
	t.Parallel()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}, baseDirectory: t.TempDir()}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration, configuration.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	restarts := make(chan struct{}, 2)
	server.SetRestartController(func() { restarts <- struct{}{} })

	for attempt := 0; attempt < 2; attempt++ {
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/ui/cluster/restart", nil))
		if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), server.instanceID) {
			t.Fatalf("restart response %d = %d %s", attempt, response.Code, response.Body.String())
		}
	}
	select {
	case <-restarts:
	default:
		t.Fatal("restart callback was not invoked")
	}
	select {
	case <-restarts:
		t.Fatal("restart callback was invoked more than once")
	default:
	}

	health := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"instance_id":"`+server.instanceID+`"`) {
		t.Fatalf("health response = %d %s", health.Code, health.Body.String())
	}
}

func TestEnrollmentTokenDismissalClearsRenderedSecret(t *testing.T) {
	t.Parallel()
	configuration := config.Defaults()
	configuration.Cluster.NodeName = "dns-1"
	configuration.Cluster.AdvertiseURL = "https://dns-1.example.test"
	editor := &editableTestConfiguration{snapshot: config.Snapshot{Config: configuration, Revision: 1}, baseDirectory: t.TempDir()}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		editor, editor.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	clusterService, err := clusterstate.Open(clusterstate.Options{
		DataDirectory: configuration.ClusterDataPath(editor.baseDirectory), NodeName: configuration.Cluster.NodeName,
		AdvertiseURL: configuration.Cluster.AdvertiseURL, Version: "dev", StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := clusterService.Initialize(context.Background(), "cluster.example.test", []string{"192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	server.SetClusterController(clusterService)

	request := httptest.NewRequest(http.MethodPost, "/ui/cluster/enrollment-tokens", strings.NewReader(url.Values{"ttl": {"15m"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create enrollment token = %d cache=%q body=%s", response.Code, response.Header().Get("Cache-Control"), response.Body.String())
	}
	if count := strings.Count(response.Body.String(), "data-enrollment-token-dismiss"); count != 2 {
		t.Fatalf("token result has %d dismissal controls, want 2: %s", count, response.Body.String())
	}
	for _, expected := range []string{`hx-get="/cluster"`, `hx-select="#cluster-content"`, `hx-target="#cluster-content"`} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("token result missing %q: %s", expected, response.Body.String())
		}
	}
	for _, expected := range []string{`class="button outline compact cluster-copy-token"`, `data-copy-target="cluster-enrollment-token"`, `data-copy-label>Copy token</span>`} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("token result missing compact copy control %q: %s", expected, response.Body.String())
		}
	}

	cleared := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(cleared, httptest.NewRequest(http.MethodGet, "/cluster", nil))
	if cleared.Code != http.StatusOK || strings.Contains(cleared.Body.String(), "data-enrollment-token-dismiss") || !strings.Contains(cleared.Body.String(), "Create Token") {
		t.Fatalf("cleared token view = %d %s", cleared.Code, cleared.Body.String())
	}
}

func TestAdministrationPageRendersIsotopeAdministrationControls(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	view := pages.AdministrationPageView{
		Console: pages.DashboardView{Version: "dev", Username: "admin", CanAdministration: true, ControlPlaneReadOnly: true, PrimaryURL: "https://dns-1.example.test"}, CurrentUserID: 1, CanManageUsers: true, ActiveTab: "users",
		Users: []auth.ManagedUser{{ID: 1, Username: "admin", DisplayName: "Administrator", Email: "admin@example.test", Roles: []string{"Administrator"}}},
		Roles: []auth.Role{{ID: 1, Name: "Administrator", Description: "Full control", BuiltIn: true,
			Permissions: []string{auth.PermissionAll}, Grants: []auth.Grant{{Permission: auth.PermissionAll, Surface: auth.SurfaceWeb}, {Permission: auth.PermissionAll, Surface: auth.SurfaceAPI}}, Users: 1},
			{ID: 2, Name: "API Administrator", Description: "API only", BuiltIn: true,
				Permissions: []string{auth.PermissionAll}, Grants: []auth.Grant{{Permission: auth.PermissionAll, Surface: auth.SurfaceAPI}}}},
		Sessions:    []auth.Session{{HashPrefix: "0123456789ab", UserID: 1, Username: "admin", CreatedAt: now, ExpiresAt: now.Add(time.Hour), Current: true}},
		Tokens:      []auth.APIToken{{ID: 7, UserID: 1, Username: "admin", Name: "automation", Groups: []string{"Metrics Readers"}, ExpiresAt: now.Add(time.Hour)}},
		Audit:       []auth.AuditRecord{{ID: 1, OccurredAt: now, Username: "admin", Action: "user.create", ClientIP: "192.0.2.1", Details: "username=operator"}},
		Permissions: auth.AllPermissions,
		Zones:       []pages.AuthorizationZone{{ID: "zone_example", Name: "example.test"}},
	}
	response := httptest.NewRecorder()
	if err := pages.AdministrationPage(view).Render(context.Background(), response); err != nil {
		t.Fatal(err)
	}
	markup := response.Body.String()
	for _, expected := range []string{
		"Administration", "Manage users, groups, permissions, sessions, and API tokens", "Add User", "Groups", "Permissions", "Sessions", "API Tokens",
		`hx-post="/ui/administration/users"`, `hx-post="/ui/administration/users/profile"`, `hx-post="/ui/administration/users/roles"`,
		`hx-post="/ui/administration/users/password"`, `hx-post="/ui/administration/users/delete"`,
		`hx-post="/ui/administration/sessions/revoke"`, `hx-post="/ui/administration/tokens/revoke"`,
		"API Token", "(current)", "Built in", `data-isotope-tab="users"`, `data-isotope-tab="tokens"`, `data-dialog-tab="info"`,
		`data-dialog-tab="groups"`, `data-dialog-save="info"`, `data-dialog-save="groups"`,
		"Save User Info", "Save Groups", "Cancel", "admin@example.test", "Confirm Password", `data-confirm-title="Sign out session?"`,
		`data-confirm-title="Revoke API token?"`, `class="nav-icon icon-log-out"`, `id="create-token-dialog"`, `name="groups"`, "Metrics Readers",
		`name="web_permissions"`, `name="api_permissions"`, `value="zone_example"`, "Selected zones",
		`aria-label="Web UI permission selection"`, `aria-label="API permission selection"`,
		`data-permission-select="all"`, `data-permission-select="none"`, "Select all", "Select none",
		`value="API Administrator"`, `data-token-group-row`, `data-token-fields`, `data-token-submit`, `data-token-close`,
		`id="create-user-dialog" data-dialog-tabs`, "Create a user or API-only identity", `data-web-access-passwords`, `data-role-web="true"`,
		`data-create-user-form`, `pattern="[a-z0-9._-]+"`, `data-username-error`, `data-group-error`, `data-group-access-status`,
		"Choose at least one group", "Password requirements depend on the selected group permissions",
		`name="user_id"`, `data-token-owner`, "Owner", `data-token-group-users="1"`,
		`id="api-tokens-panel"`, `hx-get="/ui/administration/tokens"`, `hx-trigger="apiTokensChanged from:body"`,
		`id="administration-tab-count-tokens"`, `name="expiration"`, `value="default"`, `value="never"`,
		"Non-expiring tokens remain valid until revoked",
		`data-control-plane-read-only="true"`, `data-cluster-primary-url="https://dns-1.example.test"`,
		`Replica · Read-only`, `View and troubleshoot here. Make configuration changes on the primary.`,
		`class="replica-primary-link"`, `href="https://dns-1.example.test"`, `Open Primary`,
		`type="submit" disabled>Add User`, `type="submit" disabled>Add Group`,
		`data-dialog-save="info" disabled>Save User Info`, `data-dialog-save="groups" disabled hidden>Save Groups`,
		`data-token-submit disabled>Create Token`,
		`data-dialog-tab="tokens"`, `data-dialog-panel="tokens"`, `hx-get="/ui/administration/tokens?user_id=1"`,
		`hx-trigger="dialogTabShown"`, `id="edit-user-1-token-count"`, "Tokens owned by admin", "Never used",
	} {
		if !strings.Contains(markup, expected) {
			t.Errorf("administration page does not contain %q", expected)
		}
	}
	if strings.Contains(markup, `button class="button destructive" type="submit" disabled>Disable User`) {
		t.Error("disable user action uses destructive styling")
	}
}

func TestAPITokenExpirationSelection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value   string
		want    auth.APITokenExpiration
		wantErr bool
	}{
		{value: "", want: auth.APITokenExpiration{}},
		{value: "default", want: auth.APITokenExpiration{}},
		{value: "never", want: auth.APITokenExpiration{Never: true}},
		{value: "720h", want: auth.APITokenExpiration{Lifetime: 30 * 24 * time.Hour}},
		{value: "0h", wantErr: true},
		{value: "later", wantErr: true},
	}
	for _, test := range tests {
		got, err := apiTokenExpiration(test.value)
		if (err != nil) != test.wantErr {
			t.Errorf("apiTokenExpiration(%q) error = %v, wantErr %t", test.value, err, test.wantErr)
		}
		if got != test.want {
			t.Errorf("apiTokenExpiration(%q) = %+v, want %+v", test.value, got, test.want)
		}
	}
}

func TestDisabledUserTokenPanelWarnsThatTokensAreInactive(t *testing.T) {
	t.Parallel()
	render := func(component templ.Component) string {
		response := httptest.NewRecorder()
		if err := component.Render(context.Background(), response); err != nil {
			t.Fatal(err)
		}
		return response.Body.String()
	}
	view := pages.AdministrationPageView{
		CanManageUsers: true,
		Tokens:         []auth.APIToken{{ID: 7, UserID: 2, Username: "automation", Name: "deployment"}},
	}
	disabled := render(pages.UserTokensContent(view, auth.ManagedUser{ID: 2, Username: "automation", Disabled: true}))
	for _, expected := range []string{"Tokens are currently inactive", "Authentication rejects every token", "will work again if the user is re-enabled", `role="note"`, `icon-alert-triangle`} {
		if !strings.Contains(disabled, expected) {
			t.Errorf("disabled user token panel does not contain %q", expected)
		}
	}
	active := render(pages.UserTokensContent(view, auth.ManagedUser{ID: 2, Username: "automation"}))
	if strings.Contains(active, "Tokens are currently inactive") {
		t.Error("active user token panel contains disabled-user warning")
	}
}

func TestAdministrationSeparatesSessionsFromAPITokens(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	view := pages.AdministrationPageView{
		Sessions: []auth.Session{{HashPrefix: "0123456789ab", Username: "admin", ExpiresAt: now.Add(time.Hour)}},
		Tokens:   []auth.APIToken{{ID: 7, Username: "admin", Name: "automation", Groups: []string{"Metrics Readers"}, ExpiresAt: now.Add(time.Hour)}},
	}
	render := func(component templ.Component) string {
		response := httptest.NewRecorder()
		if err := component.Render(context.Background(), response); err != nil {
			t.Fatal(err)
		}
		return response.Body.String()
	}
	sessions := render(pages.SessionsPanel(view))
	if strings.Contains(sessions, "Create Token") || strings.Contains(sessions, "API Token") || strings.Contains(sessions, `icon-trash`) {
		t.Fatalf("sessions panel mixes token or delete controls: %s", sessions)
	}
	if !strings.Contains(sessions, "Sign out session?") || !strings.Contains(sessions, `icon-log-out`) {
		t.Fatalf("sessions panel is missing sign-out confirmation: %s", sessions)
	}
	tokens := render(pages.TokensPanel(view))
	if !strings.Contains(tokens, "Create Token") || !strings.Contains(tokens, "Revoke API token?") {
		t.Fatalf("tokens panel is missing token controls: %s", tokens)
	}
}

func TestProfilePageProvidesSelfServiceAccountAndTokenControls(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	var response bytes.Buffer
	if err := pages.ProfilePage(pages.ProfilePageView{
		Console:   pages.DashboardView{Version: "dev", Username: "admin", DisplayName: "Administrator", SecurityEnabled: true},
		User:      auth.ManagedUser{ID: 1, Username: "admin", DisplayName: "Administrator", Email: "admin@example.test", Roles: []string{"Administrator"}},
		Roles:     []auth.Role{{Name: "Administrator", Grants: []auth.Grant{{Surface: auth.SurfaceAPI, Permission: auth.PermissionAll}}}},
		Tokens:    []auth.APIToken{{ID: 7, UserID: 1, Username: "admin", Name: "automation", Groups: []string{"Administrator"}, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}},
		ActiveTab: "tokens", DefaultTokenTTL: 90 * 24 * time.Hour,
	}).Render(context.Background(), &response); err != nil {
		t.Fatal(err)
	}
	markup := response.String()
	for _, expected := range []string{
		"Manage your account, password, and API tokens", `href="/profile?tab=profile"`, `href="/profile?tab=tokens"`,
		`hx-post="/ui/api-tokens"`, `hx-post="/ui/profile/tokens/revoke"`, "Administrator", "automation",
	} {
		if !strings.Contains(markup, expected) {
			t.Fatalf("profile page missing %q: %s", expected, markup)
		}
	}
}

func TestClusterUnverifiedSynchronizationUsesIndeterminateProgress(t *testing.T) {
	t.Parallel()
	var response bytes.Buffer
	view := pages.ClusterPageView{
		Initialized: true,
		LocalRole:   "Replica",
		Nodes: []pages.ClusterNodeView{
			{Name: "ns1", Role: "Primary", State: "unreachable", SyncState: "unknown", CurrentGeneration: 16},
			{Name: "ns2", Role: "Replica", State: "online", SyncState: "unverified", CurrentGeneration: 16, AppliedGeneration: 16, Local: true},
		},
	}
	if err := pages.ClusterLiveStatus(view).Render(context.Background(), &response); err != nil {
		t.Fatal(err)
	}
	markup := response.String()
	for _, expected := range []string{`class="cluster-sync-indeterminate"`, `aria-valuetext="Awaiting primary verification"`, "Uptime unavailable"} {
		if !strings.Contains(markup, expected) {
			t.Fatalf("cluster status missing %q: %s", expected, markup)
		}
	}
	if strings.Contains(markup, "Up unknown") {
		t.Fatalf("cluster status contains malformed unknown uptime: %s", markup)
	}
}

func TestClusterNodesLinkToAdvertisedPortals(t *testing.T) {
	t.Parallel()
	var response bytes.Buffer
	view := pages.ClusterPageView{
		Initialized: true,
		LocalRole:   "Primary",
		Nodes: []pages.ClusterNodeView{
			{ID: "node-primary", Name: "ns1", AdvertiseURL: "https://ns1.example.test:5380", Role: "Primary"},
			{ID: "node-replica", Name: "ns2", AdvertiseURL: "https://ns2.example.test:5380", Role: "Replica"},
		},
	}
	if err := pages.ClusterLiveStatus(view).Render(context.Background(), &response); err != nil {
		t.Fatal(err)
	}
	markup := response.String()
	for _, expected := range []string{
		`href="https://ns1.example.test:5380"`, `aria-label="Open ns1 portal"`,
		`href="https://ns2.example.test:5380"`, `aria-label="Open ns2 portal"`,
		`target="_blank"`, `rel="noopener noreferrer"`, `icon-external-link`,
	} {
		if !strings.Contains(markup, expected) {
			t.Fatalf("cluster status missing %q: %s", expected, markup)
		}
	}
	if links := strings.Count(markup, `class="cluster-node-portal"`); links != len(view.Nodes) {
		t.Fatalf("cluster portal link count = %d, want %d: %s", links, len(view.Nodes), markup)
	}
	if strings.Contains(markup, ">Open portal<") {
		t.Fatalf("cluster status renders a separate portal action instead of linking the endpoint: %s", markup)
	}
}

func serveRequest(server *Server, method, target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

func TestZoneEditorCreatesZoneAndRecords(t *testing.T) {
	t.Parallel()

	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration,
		configuration.zoneStore(),
		"sqlite",
		testQueryLog{},
		testQueryLog{},
		func(context.Context) error { return nil },
		nil,
		false,
		false,
		false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	page := serveRequest(server, http.MethodGet, "/zones")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "No zones found. Create your first zone to get started.") ||
		!strings.Contains(page.Body.String(), `data-dialog-open="import-new-zone-dialog"`) ||
		!strings.Contains(page.Body.String(), `hx-post="/ui/zones/import-new"`) ||
		!strings.Contains(page.Body.String(), `aria-label="Search zones"`) {
		t.Fatalf("empty zones page = %d %s", page.Code, page.Body.String())
	}
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response
	}
	created := post("/ui/zones/add", url.Values{
		"name": {"Example.Test."}, "primary_ns": {"ns1.example.test"},
		"responsible": {"hostmaster@example.test"}, "default_ttl": {"300"},
	})
	if created.Code != http.StatusOK || !strings.Contains(created.Body.String(), "Authoritative zone created") ||
		!strings.Contains(created.Body.String(), "example.test") || len(configuration.zoneSnapshot.Zones) != 1 {
		t.Fatalf("create zone response = %d %s", created.Code, created.Body.String())
	}
	if created.Header().Get("HX-Push-Url") != "/zones/example.test" {
		t.Fatalf("create zone HX-Push-Url = %q", created.Header().Get("HX-Push-Url"))
	}
	direct := serveRequest(server, http.MethodGet, "/zones/example.test")
	if direct.Code != http.StatusOK || !strings.Contains(direct.Body.String(), "Add Record") ||
		!strings.Contains(direct.Body.String(), `data-dialog-open="settings-selected-zone-dialog"`) ||
		!strings.Contains(direct.Body.String(), `hx-post="/ui/zones/clone"`) ||
		!strings.Contains(direct.Body.String(), `aria-label="Filter zone records"`) {
		t.Fatalf("direct zone page = %d %s", direct.Code, direct.Body.String())
	}
	if strings.Contains(direct.Body.String(), `data-dialog-url="/zones/example.test/example.test/SOA/`) {
		t.Fatal("zone page still embeds record contents in edit URLs")
	}
	for _, expected := range []string{
		"Maps a domain to an IPv4 address", "IPv4 Address", "IPv6 Address", "Target Host",
		"Name Server", "Glue Addresses (optional)", "Mail Server", "Text Value",
		"Certificate Association Data", "Service Parameters", "Advanced Options", "icon-settings-2", "record-advanced-chevron",
		"Zone Settings", "General", "Transfers &amp; Updates", `data-dialog-tab="general"`, `data-dialog-panel="transfers"`, "Zone Transfer", "AXFR or IXFR", "Transfer Policy", "Allowed Networks", "Secondary Servers",
		"Dynamic DNS Updates", "Allow Dynamic Updates",
		"DNSSEC", "Sign this zone", "Ed25519 (recommended)", "Authenticated Denial", "NSEC3 Iterations", "NSEC3 Salt", "Save DNSSEC", "Export Zone File", "Clone Zone", "Disable Zone", "Delete Zone",
		`class="record-advanced-grid"><label class="record-field"><span>TTL (seconds)</span>`,
	} {
		if !strings.Contains(direct.Body.String(), expected) {
			t.Errorf("zone record editor does not contain %q", expected)
		}
	}
	if strings.Contains(direct.Body.String(), `href="/administration?tab=groups"`) {
		t.Error("security-disabled zone editor links to unavailable permission administration")
	}
	dnssecSettings := post("/ui/zones/dnssec", url.Values{
		"zone": {"example.test"}, "enabled": {"true"}, "algorithm": {"ecdsa-p256-sha256"},
		"denial": {"nsec3"}, "nsec3_iterations": {"0"}, "nsec3_salt": {"a1b2c3d4"},
		"zsk_lifetime": {"720h"}, "ksk_lifetime": {"8760h"}, "key_prepublish": {"24h"}, "key_retire_after": {"168h"},
	})
	if dnssecSettings.Code != http.StatusOK || !strings.Contains(dnssecSettings.Body.String(), "DNSSEC settings updated") ||
		!configuration.zoneSnapshot.Zones[0].DNSSEC || configuration.zoneSnapshot.Zones[0].DNSSECAlgorithm != "ecdsa-p256-sha256" ||
		configuration.zoneSnapshot.Zones[0].DNSSECDenial != "nsec3" || configuration.zoneSnapshot.Zones[0].NSEC3Iterations != 0 ||
		configuration.zoneSnapshot.Zones[0].NSEC3Salt != "A1B2C3D4" ||
		!strings.Contains(dnssecSettings.Body.String(), "DNSSEC: Signed") {
		t.Fatalf("DNSSEC settings response = %d %s zone=%#v", dnssecSettings.Code, dnssecSettings.Body.String(), configuration.zoneSnapshot.Zones[0])
	}
	soaIndex := slices.IndexFunc(configuration.zoneSnapshot.Zones[0].Records, func(record zonemodel.Record) bool {
		return record.Type == "SOA"
	})
	if soaIndex < 0 {
		t.Fatal("created zone does not contain an SOA record")
	}
	soa := configuration.zoneSnapshot.Zones[0].Records[soaIndex]
	updatedSOA := post("/ui/zones/records/update", url.Values{
		"zone": {"example.test"}, "name": {soa.Name}, "type": {"SOA"}, "value": {soa.Value}, "ttl": {strconv.FormatUint(uint64(soa.TTL), 10)},
		"new_name": {"example.test"}, "new_primary_ns": {"ns2.example.test"}, "new_responsible": {"dns@example.test"},
		"new_serial": {"2026080809"}, "new_refresh": {"7200"}, "new_retry": {"900"}, "new_expire": {"1209600"}, "new_minimum": {"600"},
		"new_ttl": {"600"}, "new_expiry_ttl": {"0"}, "enabled": {"true"},
	})
	if updatedSOA.Code != http.StatusOK || !strings.Contains(updatedSOA.Body.String(), "Record updated") {
		t.Fatalf("update SOA response = %d %s", updatedSOA.Code, updatedSOA.Body.String())
	}
	soaIndex = slices.IndexFunc(configuration.zoneSnapshot.Zones[0].Records, func(record zonemodel.Record) bool { return record.Type == "SOA" })
	if got := configuration.zoneSnapshot.Zones[0].Records[soaIndex].Value; got != "ns2.example.test. dns.example.test. 2026080809 7200 900 1209600 600" {
		t.Fatalf("updated SOA value = %q", got)
	}
	initialSOA := configuration.zoneSnapshot.Zones[0].Records[0].Value
	added := post("/ui/zones/records/add", url.Values{
		"zone": {"example.test"}, "name": {"www"}, "type": {"A"},
		"value": {"192.0.2.10"}, "ttl": {"120"},
	})
	if added.Code != http.StatusOK || !strings.Contains(added.Body.String(), "192.0.2.10") ||
		len(configuration.zoneSnapshot.Zones[0].Records) != 3 {
		t.Fatalf("add record response = %d %s", added.Code, added.Body.String())
	}
	recordEditPath := "/zones/example.test/records/" + zonemodel.RecordID(zonemodel.Record{Name: "www", Type: "A", Value: "192.0.2.10", TTL: 120}) + "/edit"
	if !strings.Contains(added.Body.String(), `data-dialog-url="`+recordEditPath+`"`) {
		t.Fatalf("add record response does not contain edit URL %q", recordEditPath)
	}
	linkedRecord := serveRequest(server, http.MethodGet, recordEditPath)
	if linkedRecord.Code != http.StatusOK || !strings.Contains(linkedRecord.Body.String(), `data-dialog-url="`+recordEditPath+`"`) {
		t.Fatalf("linked record editor = %d %s", linkedRecord.Code, linkedRecord.Body.String())
	}
	if !strings.Contains(linkedRecord.Body.String(), `data-replica-primary-control`) {
		t.Fatalf("linked record editor is missing the replica read-only marker: %s", linkedRecord.Body.String())
	}
	legacyRecord := serveRequest(server, http.MethodGet, "/zones/example.test/www.example.test/A/192.0.2.10/edit")
	if legacyRecord.Code != http.StatusNotFound {
		t.Fatalf("legacy record URL status = %d, want 404", legacyRecord.Code)
	}
	if configuration.zoneSnapshot.Zones[0].Records[0].Value == initialSOA {
		t.Fatal("adding a record did not advance the SOA serial")
	}
	updated := post("/ui/zones/records/update", url.Values{
		"zone": {"example.test"}, "name": {"www"}, "type": {"A"},
		"value": {"192.0.2.10"}, "ttl": {"120"}, "new_name": {"www"},
		"new_value": {"192.0.2.20"}, "new_ttl": {"180"}, "enabled": {"true"},
		"new_comments": {"web endpoint"}, "new_expiry_ttl": {"3600"},
	})
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), "192.0.2.20") ||
		configuration.zoneSnapshot.Zones[0].Records[2].Value != "192.0.2.20" ||
		configuration.zoneSnapshot.Zones[0].Records[2].Comments != "web endpoint" ||
		configuration.zoneSnapshot.Zones[0].Records[2].ExpiresAt.IsZero() {
		t.Fatalf("update record response = %d %s", updated.Code, updated.Body.String())
	}
	api := serveRequest(server, http.MethodGet, "/api/v1/zones")
	if api.Code != http.StatusOK || !strings.Contains(api.Body.String(), `"name":"example.test"`) {
		t.Fatalf("zones API response = %d %s", api.Code, api.Body.String())
	}
	exported := serveRequest(server, http.MethodGet, "/api/v1/zones/export?zone=example.test")
	if exported.Code != http.StatusOK || !strings.Contains(exported.Body.String(), "$ORIGIN example.test.") ||
		!strings.Contains(exported.Body.String(), "192.0.2.20") {
		t.Fatalf("zone export response = %d %s", exported.Code, exported.Body.String())
	}
	importFile := func(endpoint, contents string, fields map[string]string) *httptest.ResponseRecorder {
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		for name, value := range fields {
			if err := form.WriteField(name, value); err != nil {
				t.Fatalf("write import field %q: %v", name, err)
			}
		}
		part, err := form.CreateFormFile("file", "example.test.zone")
		if err != nil {
			t.Fatalf("create zone file part: %v", err)
		}
		if _, err := io.WriteString(part, contents); err != nil {
			t.Fatalf("write zone file: %v", err)
		}
		if err := form.Close(); err != nil {
			t.Fatalf("close zone import form: %v", err)
		}
		request := httptest.NewRequest(http.MethodPost, endpoint, &body)
		request.Header.Set("Content-Type", form.FormDataContentType())
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response
	}
	zoneFile := `$ORIGIN example.test.
$TTL 300
@ IN SOA ns2.example.test. hostmaster.example.test. 2000010101 3600 600 1209600 300
@ IN NS ns2.example.test.
api 60 IN A 192.0.2.44
dynamic 60 IN APP "Wild IP" "WildIp.App" -
`
	imported := importFile("/ui/zones/import", zoneFile, map[string]string{"zone": "example.test", "overwrite": "true"})
	if imported.Code != http.StatusOK || imported.Header().Get("HX-Push-Url") != "/zones/example.test" ||
		!strings.Contains(imported.Body.String(), "Records imported into example.test") ||
		!strings.Contains(imported.Body.String(), "skipped 1 unsupported Technitium APP record (dynamic)") ||
		!strings.Contains(imported.Body.String(), "192.0.2.44") {
		t.Fatalf("zone import response = %d %s", imported.Code, imported.Body.String())
	}
	zone := configuration.zoneSnapshot.Zones[0]
	if len(zone.Records) != 4 || !slices.ContainsFunc(zone.Records, func(record zonemodel.Record) bool {
		return record.Name == "api" && record.Type == "A" && record.Value == "192.0.2.44" && record.TTL == 60
	}) {
		t.Fatalf("records after zone import = %#v", zone.Records)
	}
	revision := configuration.zoneSnapshot.Revision
	invalidWipe := importFile("/ui/zones/import", "api 60 IN A 192.0.2.45\n", map[string]string{
		"zone": "example.test", "overwrite_zone": "true",
	})
	if invalidWipe.Code != http.StatusOK || !strings.Contains(invalidWipe.Body.String(), "requires an apex SOA record") {
		t.Fatalf("invalid zone wipe response = %d %s", invalidWipe.Code, invalidWipe.Body.String())
	}
	if configuration.zoneSnapshot.Revision != revision || len(configuration.zoneSnapshot.Zones[0].Records) != 4 {
		t.Fatal("failed zone import changed the active configuration")
	}
	newZoneFile := `$ORIGIN imported.test.
@ 900 IN SOA ns1.imported.test. hostmaster.imported.test. 42 3600 600 1209600 900
@ 900 IN NS ns1.imported.test.
www 300 IN A 192.0.2.55
ip 300 IN APP "What Is My Dns" "WhatIsMyDns.App" -
`
	createdFromFile := importFile("/ui/zones/import-new", newZoneFile, nil)
	if createdFromFile.Code != http.StatusOK || createdFromFile.Header().Get("HX-Push-Url") != "/zones/imported.test" ||
		!strings.Contains(createdFromFile.Body.String(), "Zone imported.test imported") ||
		!strings.Contains(createdFromFile.Body.String(), "skipped 1 unsupported Technitium APP record (ip)") {
		t.Fatalf("new zone import response = %d %s", createdFromFile.Code, createdFromFile.Body.String())
	}
	importedZone := findZone(configuration.zoneSnapshot.Zones, "imported.test")
	if importedZone == nil || importedZone.DefaultTTL != 900 || !slices.ContainsFunc(importedZone.Records, func(record zonemodel.Record) bool {
		return record.Name == "www" && record.Type == "A" && record.Value == "192.0.2.55"
	}) {
		t.Fatalf("new zone imported from file = %#v", importedZone)
	}
	settings := post("/ui/zones/settings", url.Values{
		"zone": {"imported.test"}, "default_ttl": {"1200"}, "zone_transfer": {"acl"},
		"transfer_acl": {"192.0.2.0/24\n2001:db8::53"}, "notify": {"192.0.2.53\nsecondary.example:5353"},
		"tsig_key": {"update-key"}, "dynamic_updates": {"true"},
	})
	importedZone = findZone(configuration.zoneSnapshot.Zones, "imported.test")
	if settings.Code != http.StatusOK || !strings.Contains(settings.Body.String(), "Zone settings updated") || importedZone.DefaultTTL != 1200 ||
		importedZone.ZoneTransfer != "acl" || !slices.Equal(importedZone.TransferACL, []string{"192.0.2.0/24", "2001:db8::53"}) ||
		!slices.Equal(importedZone.Notify, []string{"192.0.2.53:53", "secondary.example:5353"}) || !importedZone.DynamicUpdates || importedZone.TSIGKey != "update-key" {
		t.Fatalf("zone settings response = %d %s zone=%#v", settings.Code, settings.Body.String(), importedZone)
	}
	toggled := post("/ui/zones/toggle", url.Values{"zone": {"imported.test"}, "action": {"disable"}})
	importedZone = findZone(configuration.zoneSnapshot.Zones, "imported.test")
	if toggled.Code != http.StatusOK || !strings.Contains(toggled.Body.String(), "Zone disabled") || !importedZone.Disabled ||
		!strings.Contains(toggled.Body.String(), "Enable Zone") {
		t.Fatalf("toggle zone response = %d %s zone=%#v", toggled.Code, toggled.Body.String(), importedZone)
	}
	cloned := post("/ui/zones/clone", url.Values{"zone": {"imported.test"}, "name": {"cloned.test"}})
	clonedZone := findZone(configuration.zoneSnapshot.Zones, "cloned.test")
	if cloned.Code != http.StatusOK || cloned.Header().Get("HX-Push-Url") != "/zones/cloned.test" ||
		!strings.Contains(cloned.Body.String(), "Zone cloned") || clonedZone == nil || clonedZone.Disabled || clonedZone.DefaultTTL != 1200 ||
		len(clonedZone.Records) != len(importedZone.Records) {
		t.Fatalf("clone zone response = %d %s zone=%#v", cloned.Code, cloned.Body.String(), clonedZone)
	}
}

func TestSignedZoneRendersAndExportsDSRecord(t *testing.T) {
	t.Parallel()
	key := &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: "signed.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519,
	}
	privateValue, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := privateValue.(crypto.Signer)
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: "signed.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.signed.test.", Mbox: "hostmaster.signed.test.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 1209600, Minttl: 300}
	signature := &dns.RRSIG{
		Hdr:       dns.RR_Header{Name: "signed.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		Algorithm: key.Algorithm, Expiration: uint32(time.Now().Add(24 * time.Hour).Unix()), Inception: uint32(time.Now().Add(-time.Minute).Unix()),
		KeyTag: key.KeyTag(), SignerName: "signed.test.",
	}
	if err := signature.Sign(privateKey, []dns.RR{soa}); err != nil {
		t.Fatal(err)
	}
	value := strings.TrimSpace(strings.TrimPrefix(key.String(), key.Hdr.String()))
	signatureValue := strings.TrimSpace(strings.TrimPrefix(signature.String(), signature.Hdr.String()))
	configuration := config.Defaults()
	zones := []zonemodel.Zone{{
		Name: "signed.test", Type: "primary", DefaultTTL: 300, DNSSEC: true, DNSSECAlgorithm: "ed25519",
		Records: []zonemodel.Record{
			{Name: "@", Type: "DNSKEY", TTL: 300, Value: value, Comments: "sable:dnssec-managed"},
			{Name: "@", Type: "RRSIG", TTL: 300, Value: signatureValue, Comments: "sable:dnssec-managed"},
		},
	}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{},
		testConfiguration{snapshot: config.Snapshot{Config: configuration}}, testZones{snapshot: zonemodel.Snapshot{Zones: zones}}, "sqlite",
		testQueryLog{}, testQueryLog{}, func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	page := serveRequest(server, http.MethodGet, "/zones/signed.test")
	for _, expected := range []string{"DNSSEC: Signed", "Zone Signed", "DS Record (SHA-256)", "DNSKEY Record", "Download DS Record", fmt.Sprint(key.KeyTag())} {
		if !strings.Contains(page.Body.String(), expected) {
			t.Errorf("signed zone page does not contain %q", expected)
		}
	}
	ds := serveRequest(server, http.MethodGet, "/api/v1/zones/ds?zone=signed.test")
	want := key.ToDS(dns.SHA256).String()
	if ds.Code != http.StatusOK || strings.TrimSpace(ds.Body.String()) != want || !strings.Contains(ds.Header().Get("Content-Disposition"), "signed.test.ds") {
		t.Fatalf("DS export = %d %q headers=%v, want %q", ds.Code, ds.Body.String(), ds.Header(), want)
	}
}

func TestManagedDNSSECKeyLifecycleUIAndActions(t *testing.T) {
	t.Parallel()
	configuration := config.Defaults()
	zones := []zonemodel.Zone{{
		Name: "managed.test", Type: "primary", DefaultTTL: 300, DNSSEC: true, DNSSECAlgorithm: "ed25519",
		ZSKLifetime: zonemodel.Duration{Duration: 30 * 24 * time.Hour}, KSKLifetime: zonemodel.Duration{Duration: 365 * 24 * time.Hour},
		KeyPrepublish: zonemodel.Duration{Duration: 24 * time.Hour}, KeyRetireAfter: zonemodel.Duration{Duration: 7 * 24 * time.Hour},
	}}
	editable := &editableTestConfiguration{
		snapshot:     config.Snapshot{Config: configuration, Revision: 1},
		zoneSnapshot: zonemodel.Snapshot{Zones: zones, Revision: 1},
	}
	controller := &testDNSSECController{status: dnssecstate.Status{
		ParentDSKeyTag: 111,
		NextAction:     "Publish the pending KSK DS record at the parent, then confirm its key tag.",
		Keys: []dnssecstate.KeyStatus{
			{Role: "ksk", State: "active", KeyTag: 111, DNSKEY: "active dnskey", DS: "managed.test. DS 111 15 2 AAA"},
			{Role: "ksk", State: "ready", KeyTag: 222, DNSKEY: "ready dnskey", DS: "managed.test. DS 222 15 2 BBB"},
			{Role: "zsk", State: "active", KeyTag: 333, DNSKEY: "zsk dnskey"},
		},
	}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{}, editable, editable.zoneStore(), "sqlite",
		testQueryLog{}, testQueryLog{}, func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	server.SetDNSSECController(controller)
	page := serveRequest(server, http.MethodGet, "/zones/managed.test")
	for _, expected := range []string{"Managed KSK/ZSK Signing", "ZSK Lifetime", "Roll ZSK", "Roll KSK", "Confirm Parent DS", "Key tag 222", "ready"} {
		if !strings.Contains(page.Body.String(), expected) {
			t.Errorf("managed DNSSEC page does not contain %q", expected)
		}
	}
	statusResponse := serveRequest(server, http.MethodGet, "/api/v1/zones/dnssec?zone=managed.test")
	if statusResponse.Code != http.StatusOK || !strings.Contains(statusResponse.Body.String(), `"parent_ds_key_tag":111`) || !strings.Contains(statusResponse.Body.String(), `"key_tag":222`) {
		t.Fatalf("DNSSEC status API = %d %s", statusResponse.Code, statusResponse.Body.String())
	}

	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response
	}
	rollover := post("/ui/zones/dnssec/rollover", url.Values{"zone": {"managed.test"}, "role": {"zsk"}})
	if rollover.Code != http.StatusOK || controller.requested != "zsk" {
		t.Fatalf("ZSK rollover = %d requested=%q body=%s", rollover.Code, controller.requested, rollover.Body.String())
	}
	confirmed := post("/ui/zones/dnssec/confirm-ds", url.Values{"zone": {"managed.test"}, "key_tag": {"222"}})
	if confirmed.Code != http.StatusOK || editable.zoneSnapshot.Zones[0].ParentDSKeyTag != 222 {
		t.Fatalf("DS confirmation = %d tag=%d body=%s", confirmed.Code, editable.zoneSnapshot.Zones[0].ParentDSKeyTag, confirmed.Body.String())
	}
}

func TestZoneEditorCreatesAndResyncsSecondaryStubAndForwarderZones(t *testing.T) {
	t.Parallel()

	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	stats := &synchronizingTestStats{testStats: testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), stats, configuration, configuration.zoneStore(), "sqlite",
		testQueryLog{}, testQueryLog{}, func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response
	}

	secondary := post("/ui/zones/add", url.Values{
		"name": {"secondary.test"}, "type": {"secondary"}, "primary_servers": {"192.0.2.53"}, "primary_protocol": {"tcp"},
	})
	stub := post("/ui/zones/add", url.Values{
		"name": {"stub.test"}, "type": {"stub"}, "primary_servers": {"192.0.2.54"}, "primary_protocol": {"udp"},
	})
	forwarder := post("/ui/zones/add", url.Values{
		"name": {"forward.test"}, "type": {"forwarder"}, "forwarder_address": {"dns.example"},
		"forwarder_protocol": {"tls"}, "forwarder_priority": {"5"},
	})
	if secondary.Code != http.StatusOK || stub.Code != http.StatusOK || forwarder.Code != http.StatusOK {
		t.Fatalf("create zone responses = secondary %d %s stub %d %s forwarder %d %s", secondary.Code, secondary.Body.String(), stub.Code, stub.Body.String(), forwarder.Code, forwarder.Body.String())
	}
	secondaryZone := findZone(configuration.zoneSnapshot.Zones, "secondary.test")
	stubZone := findZone(configuration.zoneSnapshot.Zones, "stub.test")
	forwarderZone := findZone(configuration.zoneSnapshot.Zones, "forward.test")
	if secondaryZone == nil || secondaryZone.Type != "secondary" || secondaryZone.PrimaryServers[0] != "192.0.2.53:53" || len(secondaryZone.Records) != 3 {
		t.Fatalf("secondary zone = %#v", secondaryZone)
	}
	if stubZone == nil || stubZone.Type != "stub" || stubZone.PrimaryProtocol != "udp" || len(stubZone.Records) != 3 {
		t.Fatalf("stub zone = %#v", stubZone)
	}
	if forwarderZone == nil || forwarderZone.Type != "forwarder" || !slices.ContainsFunc(forwarderZone.Records, func(record zonemodel.Record) bool {
		return record.Type == "FWD" && record.Value == "tls 5 dns.example:853"
	}) {
		t.Fatalf("forwarder zone = %#v", forwarderZone)
	}

	previousSOA := secondaryZone.Records[0].Value
	resynced := post("/ui/zones/resync", url.Values{"zone": {"secondary.test"}})
	secondaryZone = findZone(configuration.zoneSnapshot.Zones, "secondary.test")
	if resynced.Code != http.StatusOK || !strings.Contains(resynced.Body.String(), "Zone synchronized") || secondaryZone.Records[0].Value == previousSOA {
		t.Fatalf("secondary resync = %d %s zone=%#v", resynced.Code, resynced.Body.String(), secondaryZone)
	}
	readOnly := post("/ui/zones/records/add", url.Values{
		"zone": {"secondary.test"}, "type": {"A"}, "name": {"blocked"}, "value": {"192.0.2.9"}, "ttl": {"300"},
	})
	if readOnly.Code != http.StatusOK || !strings.Contains(readOnly.Body.String(), "read-only") {
		t.Fatalf("secondary record mutation = %d %s", readOnly.Code, readOnly.Body.String())
	}

	page := serveRequest(server, http.MethodGet, "/zones")
	for _, expected := range []string{"Secondary", "Stub", "Forwarder", "data-zone-create-options=\"transfer\"", "data-zone-create-options=\"forwarder\""} {
		if !strings.Contains(page.Body.String(), expected) {
			t.Errorf("zones UI does not contain %q", expected)
		}
	}
	detail := serveRequest(server, http.MethodGet, "/zones/secondary.test")
	if !strings.Contains(detail.Body.String(), "Resync") || strings.Contains(detail.Body.String(), ">Add Record<") || strings.Contains(detail.Body.String(), "Edit A record") {
		t.Fatalf("secondary detail actions are not read-only: %s", detail.Body.String())
	}
}

func TestZoneRecordWritesEnforceCNAMEExclusivity(t *testing.T) {
	t.Parallel()

	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration, configuration.zoneStore(), "sqlite",
		testQueryLog{}, testQueryLog{}, func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response
	}
	created := post("/ui/zones/add", url.Values{
		"name": {"example.test"}, "primary_ns": {"ns1.example.test"},
		"responsible": {"hostmaster@example.test"}, "default_ttl": {"300"},
	})
	if created.Code != http.StatusOK || len(configuration.zoneSnapshot.Zones) != 1 {
		t.Fatalf("create zone response = %d %s", created.Code, created.Body.String())
	}
	for _, seed := range []url.Values{
		{"zone": {"example.test"}, "name": {"www"}, "type": {"A"}, "value": {"192.0.2.10"}, "ttl": {"300"}},
		{"zone": {"example.test"}, "name": {"alias"}, "type": {"CNAME"}, "value": {"target.example.test."}, "ttl": {"300"}},
	} {
		if seeded := post("/ui/zones/records/add", seed); seeded.Code != http.StatusOK || !strings.Contains(seeded.Body.String(), "Record added") {
			t.Fatalf("seed record response = %d %s", seeded.Code, seeded.Body.String())
		}
	}

	tests := []struct {
		name    string
		path    string
		form    url.Values
		wantErr string
	}{
		{
			name: "cname rejected where an address exists",
			path: "/ui/zones/records/add",
			form: url.Values{
				"zone": {"example.test"}, "name": {"www"}, "type": {"CNAME"},
				"value": {"target.example.test."}, "ttl": {"300"},
			},
			wantErr: "cannot share the name",
		},
		{
			name: "address rejected where a cname exists",
			path: "/ui/zones/records/add",
			form: url.Values{
				"zone": {"example.test"}, "name": {"alias"}, "type": {"AAAA"},
				"value": {"2001:db8::1"}, "ttl": {"300"},
			},
			wantErr: "cannot share the name",
		},
		{
			name: "second cname rejected at the same name",
			path: "/ui/zones/records/add",
			form: url.Values{
				"zone": {"example.test"}, "name": {"alias"}, "type": {"CNAME"},
				"value": {"other.example.test."}, "ttl": {"300"},
			},
			wantErr: "a name can hold only one",
		},
		{
			name: "rename rejected onto a cname name",
			path: "/ui/zones/records/update",
			form: url.Values{
				"zone": {"example.test"}, "name": {"www"}, "type": {"A"},
				"value": {"192.0.2.10"}, "ttl": {"300"},
				"new_name": {"alias"}, "new_value": {"192.0.2.10"}, "new_ttl": {"300"},
				"enabled": {"true"}, "new_expiry_ttl": {"0"},
			},
			wantErr: "cannot share the name",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := zonemodel.Clone(configuration.zoneSnapshot.Zones)
			response := post(test.path, test.form)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), test.wantErr) {
				t.Fatalf("record write response = %d %s, want error %q", response.Code, response.Body.String(), test.wantErr)
			}
			if !reflect.DeepEqual(before, configuration.zoneSnapshot.Zones) {
				t.Fatalf("rejected write still changed the zone: %+v", configuration.zoneSnapshot.Zones[0].Records)
			}
		})
	}

	edited := post("/ui/zones/records/update", url.Values{
		"zone": {"example.test"}, "name": {"alias"}, "type": {"CNAME"},
		"value": {"target.example.test."}, "ttl": {"300"},
		"new_name": {"alias"}, "new_value": {"other.example.test."}, "new_ttl": {"300"},
		"enabled": {"true"}, "new_expiry_ttl": {"0"},
	})
	if edited.Code != http.StatusOK || !strings.Contains(edited.Body.String(), "Record updated") {
		t.Fatalf("editing the CNAME itself = %d %s", edited.Code, edited.Body.String())
	}
}

func TestZoneEditorCreatesAliasZonesAndKeepsTheirRecordsReadOnly(t *testing.T) {
	t.Parallel()

	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{}, configuration, configuration.zoneStore(), "sqlite",
		testQueryLog{}, testQueryLog{}, func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response
	}

	source := post("/ui/zones/add", url.Values{"name": {"example.test"}, "type": {"primary"}})
	if source.Code != http.StatusOK {
		t.Fatalf("create source zone = %d %s", source.Code, source.Body.String())
	}
	alias := post("/ui/zones/add", url.Values{
		"name": {"Example.Lan."}, "type": {"alias"}, "alias_zone": {"example.test"},
	})
	if alias.Code != http.StatusOK || !strings.Contains(alias.Body.String(), "Authoritative zone created") {
		t.Fatalf("create alias zone = %d %s", alias.Code, alias.Body.String())
	}
	aliasZone := findZone(configuration.zoneSnapshot.Zones, "example.lan")
	if aliasZone == nil || aliasZone.Type != "alias" || aliasZone.AliasZone != "example.test" {
		t.Fatalf("alias zone = %#v", aliasZone)
	}

	for name, form := range map[string]url.Values{
		"unknown source": {"name": {"missing.lan"}, "type": {"alias"}, "alias_zone": {"absent.test"}},
		"self reference": {"name": {"loop.lan"}, "type": {"alias"}, "alias_zone": {"loop.lan"}},
		"chained alias":  {"name": {"chain.lan"}, "type": {"alias"}, "alias_zone": {"example.lan"}},
		"empty source":   {"name": {"blank.lan"}, "type": {"alias"}, "alias_zone": {""}},
	} {
		rejected := post("/ui/zones/add", form)
		if findZone(configuration.zoneSnapshot.Zones, form.Get("name")) != nil {
			t.Errorf("%s created a zone: %s", name, rejected.Body.String())
		}
	}

	readOnly := post("/ui/zones/records/add", url.Values{
		"zone": {"example.lan"}, "type": {"A"}, "name": {"blocked"}, "value": {"192.0.2.9"}, "ttl": {"300"},
	})
	if readOnly.Code != http.StatusOK || !strings.Contains(readOnly.Body.String(), "read-only") {
		t.Fatalf("alias record mutation = %d %s", readOnly.Code, readOnly.Body.String())
	}

	page := serveRequest(server, http.MethodGet, "/zones")
	for _, expected := range []string{">Alias<", `data-zone-create-options="alias"`, `name="alias_zone"`} {
		if !strings.Contains(page.Body.String(), expected) {
			t.Errorf("zones UI does not contain %q", expected)
		}
	}
	// The zone manager's prepare hook mirrors the source in the real server. The
	// test catalog has no hook, so run the same pass here to get the records the
	// detail page has to render.
	if err := zonemodel.MaterializeAliases(&configuration.zoneSnapshot.Zones, time.Now()); err != nil {
		t.Fatal(err)
	}
	detail := serveRequest(server, http.MethodGet, "/zones/example.lan")
	if !strings.Contains(detail.Body.String(), "mirrored from") || strings.Contains(detail.Body.String(), ">Add Record<") {
		t.Fatalf("alias detail page = %s", detail.Body.String())
	}
	if strings.Contains(detail.Body.String(), ">Resync<") {
		t.Fatal("alias detail page offers a resync action it cannot perform")
	}
	// Mirrored records still open, read-only, the same way integration-owned
	// records in an editable zone do.
	for _, expected := range []string{
		`aria-label="View NS record"`, "record-open-button", "record-readonly-footer",
		"Mirrored from example.test.", "Sable maintains this record for the alias zone.",
		// The source badge carries the zone type's own class so it is tinted to
		// match the Alias zone badge rather than the generic integration blue.
		`class="record-source-badge alias"`,
	} {
		if !strings.Contains(detail.Body.String(), expected) {
			t.Errorf("alias record dialog does not contain %q", expected)
		}
	}
	for _, forbidden := range []string{">Update Record<", ">Delete Record<", `aria-label="Edit NS record"`} {
		if strings.Contains(detail.Body.String(), forbidden) {
			t.Errorf("alias record dialog offers %q", forbidden)
		}
	}
}

func TestParseZoneFileRejectsRecordsOutsideTheSelectedZone(t *testing.T) {
	t.Parallel()

	zone := zonemodel.Zone{Name: "example.test", Type: "primary", DefaultTTL: 300}
	contents := `$ORIGIN example.test.
$TTL 900
@ IN SOA ns1.example.test. hostmaster.example.test. 2026080801 3600 600 1209600 300
@ IN NS ns1.example.test.
www 60 IN A 192.0.2.10
mail IN MX 10 mail.example.test.
label IN TXT "hello world" ; imported note
alias 300 CNAME APP
`
	records, skipped, err := parseZoneFile(zone, strings.NewReader(contents))
	if err != nil {
		t.Fatalf("parseZoneFile() error = %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("parseZoneFile() skipped = %v", skipped)
	}
	if len(records) != 6 {
		t.Fatalf("parseZoneFile() records = %#v", records)
	}
	for _, expected := range []zonemodel.Record{
		{Name: "www", Type: "A", Value: "192.0.2.10", TTL: 60},
		{Name: "mail", Type: "MX", Value: "10 mail.example.test.", TTL: 900},
		{Name: "label", Type: "TXT", Value: `"hello world"`, TTL: 900, Comments: "imported note"},
		{Name: "alias", Type: "CNAME", Value: "APP.example.test.", TTL: 300},
	} {
		if !slices.Contains(records, expected) {
			t.Errorf("parsed records do not contain %#v: %#v", expected, records)
		}
	}
	outside := "outside.invalid. 300 IN A 192.0.2.1\n"
	if _, _, err := parseZoneFile(zone, strings.NewReader(outside)); err == nil || !strings.Contains(err.Error(), "outside zone") {
		t.Fatalf("outside-zone parse error = %v", err)
	}
	include := "$INCLUDE other.zone\n"
	if _, _, err := parseZoneFile(zone, strings.NewReader(include)); err == nil {
		t.Fatal("zone import accepted an $INCLUDE directive")
	}
	technitium := "ip 3600 IN APP \"What Is My Dns\" \"WhatIsMyDns.App\" -\nserve 3600 IN APP \"Wild IP\" \"WildIp.App\" -\nwww 300 IN A 192.0.2.20\n"
	records, skipped, err = parseZoneFile(zone, strings.NewReader(technitium))
	if err != nil || len(records) != 1 || !slices.Equal(skipped, []string{"ip", "serve"}) {
		t.Fatalf("Technitium APP import records=%#v skipped=%v error=%v", records, skipped, err)
	}
}

func TestParseZoneFileImportsSableForwarderRecords(t *testing.T) {
	t.Parallel()

	zone := zonemodel.Zone{Name: "forward.test", Type: "forwarder", DefaultTTL: 300}
	records, skipped, err := parseZoneFile(zone, strings.NewReader(`$ORIGIN forward.test.
@ 300 IN SOA ns1.forward.test. hostmaster.forward.test. 1 3600 600 1209600 300
@ 120 IN FWD tls 5 dns.example:853 ; primary forwarding policy
`))
	if err != nil || len(skipped) != 0 || !slices.ContainsFunc(records, func(record zonemodel.Record) bool {
		return record.Name == "@" && record.Type == "FWD" && record.Value == "tls 5 dns.example:853" && record.TTL == 120
	}) {
		t.Fatalf("parseZoneFile() = records %#v skipped %v error %v", records, skipped, err)
	}
}

func TestZoneRecordValueFromTypeSpecificFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		recordType string
		values     url.Values
		want       string
	}{
		{recordType: "A", values: url.Values{"value": {"192.0.2.10"}}, want: "192.0.2.10"},
		{recordType: "ANAME", values: url.Values{"value": {"origin.example.test."}}, want: "origin.example.test."},
		{recordType: "MX", values: url.Values{"preference": {"20"}, "exchange": {"mail.example.test."}}, want: "20 mail.example.test."},
		{recordType: "TXT", values: url.Values{"text": {`v=spf1 include:_spf.example ~all`}}, want: `"v=spf1 include:_spf.example ~all"`},
		{recordType: "SRV", values: url.Values{"priority": {"1"}, "weight": {"5"}, "port": {"443"}, "target": {"service.example.test."}}, want: "1 5 443 service.example.test."},
		{recordType: "CAA", values: url.Values{"flags": {"0"}, "tag": {"issue"}, "ca_domain": {"letsencrypt.org"}}, want: `0 issue "letsencrypt.org"`},
		{recordType: "DS", values: url.Values{"key_tag": {"12345"}, "algorithm": {"13"}, "digest_type": {"2"}, "digest": {"ABCDEF"}}, want: "12345 13 2 ABCDEF"},
		{recordType: "TLSA", values: url.Values{"certificate_usage": {"3"}, "selector": {"1"}, "matching_type": {"1"}, "certificate": {"ABCDEF"}}, want: "3 1 1 ABCDEF"},
		{recordType: "SVCB", values: url.Values{"svc_priority": {"1"}, "svc_target": {"svc.example.test."}, "svc_params": {"alpn|h2,h3|port|443"}}, want: `1 svc.example.test. alpn="h2,h3" port=443`},
		{recordType: "URI", values: url.Values{"uri_priority": {"10"}, "uri_weight": {"1"}, "uri": {"https://example.test/"}}, want: `10 1 "https://example.test/"`},
		{recordType: "NAPTR", values: url.Values{"naptr_order": {"10"}, "naptr_preference": {"20"}, "naptr_flags": {"S"}, "naptr_services": {"SIP+D2U"}, "naptr_replacement": {"_sip._udp.example.test."}}, want: `10 20 "S" "SIP+D2U" "" _sip._udp.example.test.`},
		{recordType: "SOA", values: url.Values{"primary_ns": {"ns1.example.test"}, "responsible": {"hostmaster@example.test"}, "serial": {"2026080801"}, "refresh": {"3600"}, "retry": {"600"}, "expire": {"1209600"}, "minimum": {"300"}}, want: "ns1.example.test. hostmaster.example.test. 2026080801 3600 600 1209600 300"},
		{recordType: "FWD", values: url.Values{"fwd_protocol": {"tls"}, "fwd_priority": {"10"}, "fwd_address": {"dns.example.test"}}, want: "tls 10 dns.example.test:853"},
	}
	for _, test := range tests {
		t.Run(test.recordType, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.values.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := request.ParseForm(); err != nil {
				t.Fatalf("ParseForm() error = %v", err)
			}
			got, err := zoneRecordValueFromForm(request, test.recordType, "")
			if err != nil || got != test.want {
				t.Fatalf("zoneRecordValueFromForm() = %q, %v; want %q", got, err, test.want)
			}
			if test.recordType != "ANAME" && test.recordType != "FWD" {
				if _, err := dns.NewRR("record.example.test. 300 IN " + test.recordType + " " + got); err != nil {
					t.Fatalf("composed %s record is invalid: %v", test.recordType, err)
				}
			}
		})
	}
	invalid := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("value=not-an-address"))
	invalid.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = invalid.ParseForm()
	if _, err := zoneRecordValueFromForm(invalid, "A", ""); err == nil {
		t.Fatal("zoneRecordValueFromForm() accepted an invalid IPv4 address")
	}
}

func TestSyncZoneNSGlueCreatesAddressRecords(t *testing.T) {
	t.Parallel()

	zone := zonemodel.Zone{
		Name: "example.test", Type: "primary", DefaultTTL: 300,
		Records: []zonemodel.Record{
			{Name: "@", Type: "NS", Value: "ns1.example.test.", TTL: 300},
			{Name: "ns1", Type: "A", Value: "192.0.2.1", TTL: 300},
		},
	}
	if err := syncZoneNSGlue(&zone, "ns1.example.test.", "ns2.example.test.", "192.0.2.2, 2001:db8::2"); err != nil {
		t.Fatalf("syncZoneNSGlue() error = %v", err)
	}
	if slices.ContainsFunc(zone.Records, func(record zonemodel.Record) bool { return record.Name == "ns1" && record.Type == "A" }) {
		t.Fatal("syncZoneNSGlue() retained the old glue record")
	}
	for _, expected := range []zonemodel.Record{
		{Name: "ns2", Type: "A", Value: "192.0.2.2", TTL: 300, Comments: "Glue record for ns2.example.test"},
		{Name: "ns2", Type: "AAAA", Value: "2001:db8::2", TTL: 300, Comments: "Glue record for ns2.example.test"},
	} {
		if !slices.Contains(zone.Records, expected) {
			t.Errorf("glue records do not contain %#v: %#v", expected, zone.Records)
		}
	}
	before := slices.Clone(zone.Records)
	if err := syncZoneNSGlue(&zone, "ns2.example.test.", "ns.external.test.", "192.0.2.3"); err == nil {
		t.Fatal("syncZoneNSGlue() accepted glue for an external name server")
	}
	if !slices.Equal(zone.Records, before) {
		t.Fatal("failed glue update changed the zone records")
	}
}

func TestBlockingEditorUpdatesTheRenderedPolicy(t *testing.T) {
	t.Parallel()

	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration,
		configuration.zoneStore(),
		"sqlite",
		testQueryLog{},
		testQueryLog{},
		func(context.Context) error { return nil },
		nil,
		false,
		false,
		false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	postDomain := func(htmx bool) *httptest.ResponseRecorder {
		form := url.Values{"domain": {"Telemetry.Example."}}
		request := httptest.NewRequest(http.MethodPost, "/ui/blocking/domains/add", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if htmx {
			request.Header.Set("HX-Request", "true")
		}
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response
	}
	response := postDomain(true)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Blocked domain added") ||
		!strings.Contains(response.Body.String(), "telemetry.example") {
		t.Fatalf("add blocked domain response = %d %s", response.Code, response.Body.String())
	}
	for _, expected := range []string{`class="toast toast-success"`, `data-toast`, `data-toast-close`, `role="status"`} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("blocking success toast does not contain %q", expected)
		}
	}
	if got := configuration.Current().Config.Blocking.Domains; len(got) != 1 || got[0] != "telemetry.example" {
		t.Fatalf("blocked domains = %v", got)
	}
	if duplicate := postDomain(true); duplicate.Code != http.StatusOK || !strings.Contains(duplicate.Body.String(), "already blocked") ||
		!strings.Contains(duplicate.Body.String(), `class="toast toast-error"`) || !strings.Contains(duplicate.Body.String(), `role="alert"`) {
		t.Fatalf("HTMX duplicate toast response = %d %s", duplicate.Code, duplicate.Body.String())
	}
	if duplicate := postDomain(false); duplicate.Code != http.StatusUnprocessableEntity {
		t.Fatalf("direct duplicate status = %d, want 422", duplicate.Code)
	}
}

func TestBlockingEditorAddsRemoteListBeforeActivatingPolicy(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64
	remote := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = writer.Write([]byte("0.0.0.0 telemetry.example\n"))
	}))
	defer remote.Close()

	configuration := &editableTestConfiguration{
		snapshot:      config.Snapshot{Config: config.Defaults(), Revision: 1},
		baseDirectory: t.TempDir(),
	}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration,
		configuration.zoneStore(),
		"sqlite",
		testQueryLog{},
		testQueryLog{},
		func(context.Context) error { return nil },
		nil,
		false,
		false,
		false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	post := func() *httptest.ResponseRecorder {
		form := url.Values{"name": {"Test Feed"}, "url": {remote.URL + "/hosts"}, "format": {"auto"}}
		request := httptest.NewRequest(http.MethodPost, "/ui/blocking/lists/add", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response
	}
	response := post()
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Block list added and compiled") {
		t.Fatalf("add list response = %d %s", response.Code, response.Body.String())
	}
	lists := configuration.Current().Config.Blocking.Lists
	if len(lists) != 1 || lists[0].Name != "Test Feed" || lists[0].URL != remote.URL+"/hosts" {
		t.Fatalf("configured lists = %+v", lists)
	}
	contents, err := os.ReadFile(filepath.Join(configuration.baseDirectory, lists[0].Path))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(contents) != "0.0.0.0 telemetry.example\n" {
		t.Fatalf("cached list contents = %q", contents)
	}
	if duplicate := post(); duplicate.Code != http.StatusOK || !strings.Contains(duplicate.Body.String(), "already added") {
		t.Fatalf("duplicate list response = %d %s", duplicate.Code, duplicate.Body.String())
	}
	if requests.Load() != 1 {
		t.Fatalf("remote requests = %d, want duplicate rejected before download", requests.Load())
	}
}

func TestBlockingEditorImportsAndExportsPolicyDomains(t *testing.T) {
	t.Parallel()

	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	configuration.snapshot.Config.Blocking.Domains = []string{"existing.example"}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration,
		configuration.zoneStore(),
		"sqlite",
		testQueryLog{},
		testQueryLog{},
		func(context.Context) error { return nil },
		nil,
		false,
		false,
		false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	var body bytes.Buffer
	multipartWriter := multipart.NewWriter(&body)
	file, err := multipartWriter.CreateFormFile("file", "domains.hosts")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(file, "# policy export\n0.0.0.0 Ads.Example tracker.example\n*.wild.example\ninvalid domain\nexisting.example\n")
	if err := multipartWriter.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/ui/blocking/domains/import", &body)
	request.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Imported 3 domains") || !strings.Contains(response.Body.String(), "invalid lines skipped") {
		t.Fatalf("import response = %d %s", response.Code, response.Body.String())
	}
	want := "*.wild.example,ads.example,existing.example,tracker.example"
	if got := strings.Join(configuration.Current().Config.Blocking.Domains, ","); got != want {
		t.Fatalf("imported domains = %q, want %q", got, want)
	}
	export := serveRequest(server, http.MethodGet, "/ui/blocking/domains/export")
	if export.Code != http.StatusOK || export.Header().Get("Content-Disposition") != `attachment; filename="blocked-domains.txt"` {
		t.Fatalf("export response = %d headers=%v", export.Code, export.Header())
	}
	if got := strings.TrimSpace(export.Body.String()); got != strings.ReplaceAll(want, ",", "\n") {
		t.Fatalf("export body = %q", got)
	}
}

func TestPrometheusLabelEscapesSpecialCharacters(t *testing.T) {
	t.Parallel()

	if got, want := prometheusLabel("a\\b\n\"c"), "a\\\\b\\n\\\"c"; got != want {
		t.Fatalf("prometheusLabel() = %q, want %q", got, want)
	}
}

func TestExpiredSessionRedirectsThroughLoginToRequestedPage(t *testing.T) {
	t.Parallel()

	configuration := config.Defaults()
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		testConfiguration{snapshot: config.Snapshot{Config: configuration}},
		testZones{},
		"sqlite",
		testQueryLog{},
		testQueryLog{},
		func(context.Context) error { return nil },
		testAuthenticator{},
		true,
		false,
		false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	directRequest := httptest.NewRequest(http.MethodGet, "http://example.test/zones/penree.net?type=A", nil)
	directResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(directResponse, directRequest)
	wantLogin := "/login?return_to=%2Fzones%2Fpenree.net%3Ftype%3DA"
	if directResponse.Code != http.StatusSeeOther || directResponse.Header().Get("Location") != wantLogin {
		t.Fatalf("direct response = %d Location=%q, want %q", directResponse.Code, directResponse.Header().Get("Location"), wantLogin)
	}

	htmxRequest := httptest.NewRequest(http.MethodPost, "http://example.test/ui/zones/records/update", nil)
	htmxRequest.Header.Set("HX-Request", "true")
	htmxRequest.Header.Set("HX-Current-URL", "http://example.test/zones/penree.net/records/XmK9a2Pq7vL3nR5s/edit")
	htmxResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(htmxResponse, htmxRequest)
	wantHTMXLogin := "/login?return_to=%2Fzones%2Fpenree.net%2Frecords%2FXmK9a2Pq7vL3nR5s%2Fedit"
	if htmxResponse.Code != http.StatusNoContent || htmxResponse.Header().Get("HX-Redirect") != wantHTMXLogin {
		t.Fatalf("HTMX response = %d HX-Redirect=%q, want %q", htmxResponse.Code, htmxResponse.Header().Get("HX-Redirect"), wantHTMXLogin)
	}
	if htmxResponse.Body.Len() != 0 {
		t.Fatalf("HTMX authentication response unexpectedly contains a partial page: %q", htmxResponse.Body.String())
	}

	loginPage := serveRequest(server, http.MethodGet, wantLogin)
	if loginPage.Code != http.StatusOK || !strings.Contains(loginPage.Body.String(), `name="return_to" value="/zones/penree.net?type=A"`) {
		t.Fatalf("login page did not preserve return target: %d %s", loginPage.Code, loginPage.Body.String())
	}
	loginForm := url.Values{
		"username":   {"admin"},
		"password":   {"correct horse battery staple"},
		"csrf_token": {authenticationFormToken(t, loginPage.Body.String())},
		"return_to":  {"/zones/penree.net?type=A"},
	}
	loginRequest := httptest.NewRequest(http.MethodPost, "http://example.test/login", strings.NewReader(loginForm.Encode()))
	loginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusSeeOther || loginResponse.Header().Get("Location") != "/zones/penree.net?type=A" {
		t.Fatalf("login response = %d Location=%q", loginResponse.Code, loginResponse.Header().Get("Location"))
	}

	externalLoginPage := serveRequest(server, http.MethodGet, "/login?return_to=https%3A%2F%2Fevil.example%2Fsteal")
	if !strings.Contains(externalLoginPage.Body.String(), `name="return_to" value="/"`) {
		t.Fatalf("external return target was not rejected: %s", externalLoginPage.Body.String())
	}
}

func TestFirstRunSetupProtectsConsoleAndEnforcesCSRF(t *testing.T) {
	t.Parallel()

	configuration := config.Defaults()
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		testConfiguration{snapshot: config.Snapshot{Config: configuration}},
		testZones{},
		"sqlite",
		testQueryLog{},
		testQueryLog{},
		func(context.Context) error { return nil },
		testAuthenticator{},
		true,
		true,
		false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	root := serveRequest(server, http.MethodGet, "/")
	if root.Code != http.StatusSeeOther || root.Header().Get("Location") != "/setup" {
		t.Fatalf("initial root response = %d Location=%q", root.Code, root.Header().Get("Location"))
	}
	setupPage := serveRequest(server, http.MethodGet, "/setup")
	if setupPage.Code != http.StatusOK || !strings.Contains(setupPage.Body.String(), "Create your administrator") {
		t.Fatalf("setup page = %d %s", setupPage.Code, setupPage.Body.String())
	}
	setupToken := authenticationFormToken(t, setupPage.Body.String())

	form := url.Values{
		"username": {"admin"}, "password": {"correct horse battery staple"},
		"confirm_password": {"correct horse battery staple"},
		"csrf_token":       {setupToken},
	}
	crossOriginRequest := httptest.NewRequest(http.MethodPost, "http://example.test/setup", strings.NewReader(form.Encode()))
	crossOriginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crossOriginRequest.Header.Set("Origin", "https://attacker.example")
	crossOriginResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(crossOriginResponse, crossOriginRequest)
	if crossOriginResponse.Code != http.StatusForbidden ||
		!strings.Contains(crossOriginResponse.Body.String(), "origin does not match") {
		t.Fatalf("cross-origin setup response = %d %s", crossOriginResponse.Code, crossOriginResponse.Body.String())
	}

	setupPage = serveRequest(server, http.MethodGet, "/setup")
	form.Set("csrf_token", authenticationFormToken(t, setupPage.Body.String()))
	sameHostRequest := httptest.NewRequest(http.MethodPost, "http://example.test/setup", strings.NewReader(form.Encode()))
	sameHostRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sameHostRequest.Header.Set("Origin", "https://example.test")
	sameHostRequest.Header.Set("Sec-Fetch-Site", "same-origin")
	if !server.requestOriginAllowed(sameHostRequest) {
		t.Fatal("standard same-origin browser request was rejected")
	}
	missingTokenForm := url.Values{
		"username": {"admin"}, "password": {"correct horse battery staple"},
		"confirm_password": {"correct horse battery staple"},
	}
	missingTokenRequest := httptest.NewRequest(
		http.MethodPost, "http://example.test/setup", strings.NewReader(missingTokenForm.Encode()),
	)
	missingTokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	missingTokenResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(missingTokenResponse, missingTokenRequest)
	if missingTokenResponse.Code != http.StatusForbidden ||
		!strings.Contains(missingTokenResponse.Body.String(), "form is no longer valid") {
		t.Fatalf("missing-token setup response = %d %s", missingTokenResponse.Code, missingTokenResponse.Body.String())
	}

	setupRequest := httptest.NewRequest(http.MethodPost, "http://example.test/setup", strings.NewReader(form.Encode()))
	setupRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setupResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(setupResponse, setupRequest)
	if setupResponse.Code != http.StatusSeeOther || setupResponse.Header().Get("Location") != "/" {
		t.Fatalf("setup response = %d %s", setupResponse.Code, setupResponse.Body.String())
	}
	cookies := setupResponse.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookies = %+v", cookies)
	}

	dashboardRequest := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	dashboardRequest.AddCookie(cookies[0])
	dashboardResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(dashboardResponse, dashboardRequest)
	if dashboardResponse.Code != http.StatusOK || !strings.Contains(dashboardResponse.Body.String(), "admin") {
		t.Fatalf("authenticated dashboard = %d %s", dashboardResponse.Code, dashboardResponse.Body.String())
	}

	purgeRequest := httptest.NewRequest(http.MethodPost, "http://example.test/api/v1/cache/purge", nil)
	purgeRequest.AddCookie(cookies[0])
	purgeResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(purgeResponse, purgeRequest)
	if purgeResponse.Code != http.StatusForbidden {
		t.Fatalf("purge without CSRF status = %d, want 403", purgeResponse.Code)
	}
	purgeRequest = httptest.NewRequest(http.MethodPost, "http://example.test/api/v1/cache/purge", nil)
	purgeRequest.AddCookie(cookies[0])
	purgeRequest.Header.Set("X-CSRF-Token", "csrf-token")
	purgeResponse = httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(purgeResponse, purgeRequest)
	if purgeResponse.Code != http.StatusOK {
		t.Fatalf("purge with CSRF status = %d", purgeResponse.Code)
	}
	tokenForm := url.Values{"name": {"monitoring"}, "user_id": {"1"}, "groups": {"Administrator"}}
	tokenRequest := httptest.NewRequest(
		http.MethodPost, "http://example.test/ui/api-tokens", strings.NewReader(tokenForm.Encode()),
	)
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRequest.Header.Set("X-CSRF-Token", "csrf-token")
	tokenRequest.AddCookie(cookies[0])
	tokenResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(tokenResponse, tokenRequest)
	if tokenResponse.Code != http.StatusOK || !strings.Contains(tokenResponse.Body.String(), "sable_pat_created") {
		t.Fatalf("token response = %d %s", tokenResponse.Code, tokenResponse.Body.String())
	}
	if trigger := tokenResponse.Header().Get("HX-Trigger"); trigger != "apiTokensChanged" {
		t.Fatalf("token response HX-Trigger = %q, want apiTokensChanged", trigger)
	}

	metricsRequest := httptest.NewRequest(http.MethodGet, "http://example.test/metrics", nil)
	metricsRequest.Header.Set("Authorization", "Bearer sable_pat_test")
	metricsResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(metricsResponse, metricsRequest)
	if metricsResponse.Code != http.StatusOK {
		t.Fatalf("token-authenticated metrics status = %d", metricsResponse.Code)
	}
}

func authenticationFormToken(t *testing.T, body string) string {
	t.Helper()
	const marker = `name="csrf_token" value="`
	_, after, found := strings.Cut(body, marker)
	if !found {
		t.Fatalf("authentication form does not contain a CSRF token: %s", body)
	}
	token, _, found := strings.Cut(after, `"`)
	if !found || token == "" {
		t.Fatalf("authentication form contains an invalid CSRF token: %s", body)
	}
	return token
}

func TestZoneEditorTogglesForwarderDNSSECValidation(t *testing.T) {
	t.Parallel()

	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	stats := &synchronizingTestStats{testStats: testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), stats, configuration, configuration.zoneStore(), "sqlite",
		testQueryLog{}, testQueryLog{}, func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response
	}

	created := post("/ui/zones/add", url.Values{
		"name": {"private.test"}, "type": {"forwarder"}, "forwarder_address": {"10.2.0.245"},
		"forwarder_protocol": {"udp"}, "forwarder_priority": {"0"},
		"dnssec_validation_present": {"1"},
	})
	forwarderZone := findZone(configuration.zoneSnapshot.Zones, "private.test")
	if created.Code != http.StatusOK || forwarderZone == nil || !forwarderZone.DNSSECValidationDisabled {
		t.Fatalf("create with validation unchecked = %d zone=%#v", created.Code, forwarderZone)
	}

	enabled := post("/ui/zones/dnssec", url.Values{
		"zone": {"private.test"}, "dnssec_validation_present": {"1"}, "dnssec_validation": {"true"},
	})
	forwarderZone = findZone(configuration.zoneSnapshot.Zones, "private.test")
	if enabled.Code != http.StatusOK || forwarderZone.DNSSECValidationDisabled {
		t.Fatalf("DNSSEC dialog re-enable = %d zone=%#v", enabled.Code, forwarderZone)
	}

	disabled := post("/ui/zones/dnssec", url.Values{
		"zone": {"private.test"}, "dnssec_validation_present": {"1"},
	})
	forwarderZone = findZone(configuration.zoneSnapshot.Zones, "private.test")
	if disabled.Code != http.StatusOK || !forwarderZone.DNSSECValidationDisabled {
		t.Fatalf("DNSSEC dialog disable = %d zone=%#v", disabled.Code, forwarderZone)
	}

	// A submission without the paired marker must leave the switch untouched.
	unrelated := post("/ui/zones/settings", url.Values{"zone": {"private.test"}, "default_ttl": {"600"}})
	forwarderZone = findZone(configuration.zoneSnapshot.Zones, "private.test")
	if unrelated.Code != http.StatusOK || !forwarderZone.DNSSECValidationDisabled || forwarderZone.DefaultTTL != 600 {
		t.Fatalf("settings without the validation field = %d zone=%#v", unrelated.Code, forwarderZone)
	}

	detail := serveRequest(server, http.MethodGet, "/zones/private.test")
	body := detail.Body.String()
	if !strings.Contains(body, `name="dnssec_validation"`) {
		t.Fatal("forwarder zone DNSSEC dialog does not expose the validation switch")
	}
	// The signing controls belong to primary zones only.
	if strings.Contains(body, `name="zsk_lifetime"`) {
		t.Fatal("forwarder zone DNSSEC dialog exposes zone-signing controls")
	}
}

func TestZoneEditorPublishesCatalogZonesAndTracksMembership(t *testing.T) {
	t.Parallel()

	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{}, configuration, configuration.zoneStore(), "sqlite",
		testQueryLog{}, testQueryLog{}, func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response
	}

	catalog := post("/ui/zones/add", url.Values{"name": {"Catalog.Invalid."}, "type": {"catalog"}})
	if catalog.Code != http.StatusOK || !strings.Contains(catalog.Body.String(), "Authoritative zone created") {
		t.Fatalf("create catalog zone = %d %s", catalog.Code, catalog.Body.String())
	}
	catalogZone := findZone(configuration.zoneSnapshot.Zones, "catalog.invalid")
	if catalogZone == nil || catalogZone.Type != "catalog" || len(catalogZone.PrimaryServers) != 0 {
		t.Fatalf("catalog zone = %#v", catalogZone)
	}

	if member := post("/ui/zones/add", url.Values{"name": {"example.test"}, "type": {"primary"}}); member.Code != http.StatusOK {
		t.Fatalf("create member zone = %d %s", member.Code, member.Body.String())
	}
	joined := post("/ui/zones/settings", url.Values{
		"zone": {"example.test"}, "default_ttl": {"300"},
		"catalog_zone": {"catalog.invalid"}, "catalog_group": {"operator-x-foo"},
	})
	if joined.Code != http.StatusOK || !strings.Contains(joined.Body.String(), "Zone settings updated") {
		t.Fatalf("join catalog = %d %s", joined.Code, joined.Body.String())
	}
	memberZone := findZone(configuration.zoneSnapshot.Zones, "example.test")
	if memberZone == nil || memberZone.CatalogZone != "catalog.invalid" || memberZone.CatalogGroup != "operator-x-foo" {
		t.Fatalf("member zone = %#v", memberZone)
	}

	for name, form := range map[string]url.Values{
		"unknown catalog": {"zone": {"example.test"}, "default_ttl": {"300"}, "catalog_zone": {"absent.invalid"}},
		"not a catalog":   {"zone": {"example.test"}, "default_ttl": {"300"}, "catalog_zone": {"example.test"}},
	} {
		rejected := post("/ui/zones/settings", form)
		if strings.Contains(rejected.Body.String(), "Zone settings updated") {
			t.Errorf("%s was accepted: %s", name, rejected.Body.String())
		}
	}
	if current := findZone(configuration.zoneSnapshot.Zones, "example.test"); current.CatalogZone != "catalog.invalid" {
		t.Fatalf("a rejected membership change was applied: %#v", current)
	}

	page := serveRequest(server, http.MethodGet, "/zones")
	for _, expected := range []string{">Catalog<", `value="secondary_catalog"`, `name="catalog_zone"`} {
		if !strings.Contains(page.Body.String(), expected) {
			t.Errorf("zones UI does not contain %q", expected)
		}
	}
}

func TestZoneEditorKeepsCatalogManagedZonesReadOnly(t *testing.T) {
	t.Parallel()

	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	configuration.zoneSnapshot.Zones = []zonemodel.Zone{
		{
			Name: "catalog.example", Type: "catalog", DefaultTTL: 300,
			PrimaryServers: []string{"192.0.2.53"}, PrimaryProtocol: "tcp",
			Records: []zonemodel.Record{
				{Name: "@", Type: "SOA", TTL: 300, Value: "invalid. hostmaster.catalog.example. 1 3600 600 1209600 300"},
				{Name: "@", Type: "NS", TTL: 300, Value: "invalid."},
				{Name: "version", Type: "TXT", TTL: 300, Value: `"2"`},
			},
		},
		{
			Name: "member.example", Type: "secondary", DefaultTTL: 300,
			PrimaryServers: []string{"192.0.2.53"}, PrimaryProtocol: "tcp",
			CatalogZone: "catalog.example", CatalogMemberID: "aaa",
			Records: []zonemodel.Record{
				{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.member.example. hostmaster.member.example. 1 3600 600 1209600 300"},
				{Name: "@", Type: "NS", TTL: 300, Value: "ns1.member.example."},
			},
		},
	}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{}, configuration, configuration.zoneStore(), "sqlite",
		testQueryLog{}, testQueryLog{}, func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/ui/zones/settings", strings.NewReader(url.Values{
		"zone": {"member.example"}, "default_ttl": {"900"},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)

	if !strings.Contains(response.Body.String(), "managed by catalog") {
		t.Fatalf("catalog-managed settings edit = %d %s", response.Code, response.Body.String())
	}
	if findZone(configuration.zoneSnapshot.Zones, "member.example").DefaultTTL != 300 {
		t.Fatal("a catalog-managed zone was edited")
	}

	// Both catalog roles share one zone type, so the badge has to say which one
	// this is rather than labelling a transferred catalog as a local one.
	page := serveRequest(server, http.MethodGet, "/zones")
	if !strings.Contains(page.Body.String(), ">Secondary Catalog<") {
		t.Fatalf("zones UI does not label the subscribed catalog: %s", page.Body.String())
	}
}
