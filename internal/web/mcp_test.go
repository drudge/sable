package web

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/web/pages"
	zonemodel "github.com/drudge/sable/internal/zone"
)

// validatingTestZoneStore runs the zone manager's normalization and
// validation, so the tests see the same rejections a real node would.
type validatingTestZoneStore struct{ *editableTestZoneStore }

func (store validatingTestZoneStore) UpdateZones(ctx context.Context, mutate func(*[]zonemodel.Zone) error) error {
	return store.editableTestZoneStore.UpdateZones(ctx, func(zones *[]zonemodel.Zone) error {
		if err := mutate(zones); err != nil {
			return err
		}
		zonemodel.NormalizeAll(*zones)
		return zonemodel.ValidateAll(*zones, nil)
	})
}

type mcpTestAuthenticator struct {
	testAuthenticator
	tokens map[string]auth.Principal
}

func (authenticator mcpTestAuthenticator) AuthenticateToken(_ context.Context, token string) (auth.Principal, error) {
	principal, found := authenticator.tokens[token]
	if !found {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	return principal, nil
}

func mcpZoneGrant(permission, zoneID string) auth.Grant {
	return auth.Grant{Permission: permission, Surface: auth.SurfaceAPI, ResourceType: auth.ResourceZone, ResourceID: zoneID}
}

func mcpTestZone(id, name, zoneType string) zonemodel.Zone {
	return zonemodel.Zone{ID: id, Name: name, Type: zoneType, DefaultTTL: 300, Records: []zonemodel.Record{
		{Name: "@", Type: "SOA", Value: "ns1." + name + ". hostmaster." + name + ". 2026010101 3600 600 1209600 300", TTL: 300},
		{Name: "@", Type: "NS", Value: "ns1." + name + ".", TTL: 300},
		{Name: "ns1", Type: "A", Value: "192.0.2.1", TTL: 300},
		{Name: "www", Type: "A", Value: "192.0.2.10", TTL: 300},
	}}
}

func newMCPTestServer(t *testing.T) (*Server, *editableTestConfiguration) {
	t.Helper()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	configuration.snapshot.Config.MCP = config.MCP{Configured: true, Enabled: true, Tools: config.DefaultMCPTools()}
	configuration.zoneSnapshot.Zones = []zonemodel.Zone{
		mcpTestZone("zone-example", "example.test", "primary"),
		mcpTestZone("zone-other", "other.test", "primary"),
		mcpTestZone("zone-secondary", "secondary.test", "secondary"),
	}
	configuration.zoneSnapshot.Zones[2].PrimaryServers = []string{"192.0.2.53"}
	authenticator := mcpTestAuthenticator{tokens: map[string]auth.Principal{
		"sable_pat_admin": {UserID: 1, Username: "admin", AuthenticatedByToken: true, Surface: auth.SurfaceAPI, Permissions: []string{auth.PermissionAll}},
		"sable_pat_reader": {UserID: 2, Username: "reader", AuthenticatedByToken: true, Surface: auth.SurfaceAPI, Grants: []auth.Grant{
			mcpZoneGrant(auth.PermissionZonesRead, "zone-example"),
		}},
		"sable_pat_creator": {UserID: 6, Username: "creator", AuthenticatedByToken: true, Surface: auth.SurfaceAPI, Grants: []auth.Grant{
			{Permission: auth.PermissionZonesCreate, Surface: auth.SurfaceAPI},
			mcpZoneGrant(auth.PermissionZonesRead, "zone-example"),
		}},
		"sable_pat_logs":     {UserID: 7, Username: "analyst", AuthenticatedByToken: true, Surface: auth.SurfaceAPI, Permissions: []string{auth.PermissionLogsRead}},
		"sable_pat_metrics":  {UserID: 4, Username: "glance", AuthenticatedByToken: true, Surface: auth.SurfaceAPI, Permissions: []string{auth.PermissionMetricsRead}},
		"sable_pat_settings": {UserID: 9, Username: "tinkerer", AuthenticatedByToken: true, Surface: auth.SurfaceAPI, Permissions: []string{auth.PermissionSettingsRead}},
		"sable_pat_updates":  {UserID: 8, Username: "watcher", AuthenticatedByToken: true, Surface: auth.SurfaceAPI, Permissions: []string{auth.PermissionUpdatesRead}},
		"sable_pat_blocking": {UserID: 5, Username: "helper", AuthenticatedByToken: true, Surface: auth.SurfaceAPI, Permissions: []string{auth.PermissionBlockingRead, auth.PermissionBlockingWrite}},
		"sable_pat_scoped": {UserID: 3, Username: "deploy", AuthenticatedByToken: true, Surface: auth.SurfaceAPI, Grants: []auth.Grant{
			mcpZoneGrant(auth.PermissionZonesRead, "zone-example"),
			mcpZoneGrant(auth.PermissionZonesRecords, "zone-example"),
		}},
	}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		mcpTestStats{testStats: testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}}},
		configuration, validatingTestZoneStore{configuration.zoneStore()}, "sqlite",
		testQueryLog{}, &mcpTestQueries{}, func(context.Context) error { return nil },
		authenticator, true, false, false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return server, configuration
}

// mcpTestQueries keeps the last MCP use in memory the way the store keeps it
// in its metadata table.
type mcpTestQueries struct {
	testQueryLog
	mu     sync.Mutex
	use    store.MCPUse
	filter querylog.Filter
}

func (queries *mcpTestQueries) LoadMCPUse(context.Context) (store.MCPUse, error) {
	queries.mu.Lock()
	defer queries.mu.Unlock()
	return queries.use, nil
}

// QueryEvents answers the query log search with two lookups from one device
// and remembers the filter it was asked for.
func (queries *mcpTestQueries) QueryEvents(_ context.Context, filter querylog.Filter) (querylog.Page, error) {
	queries.mu.Lock()
	defer queries.mu.Unlock()
	queries.filter = filter
	now := time.Now()
	return querylog.Page{TotalEntries: 2, Entries: []querylog.Entry{
		{ID: 2, Event: querylog.Event{OccurredAt: now, ClientIP: "10.99.7.20", Name: "ads.example", RecordType: dns.TypeA,
			ResponseCode: dns.RcodeNameError, Source: querylog.SourceBlocked, Decision: querylog.Decision{PolicyRule: "ads.example"}}},
		{ID: 1, Event: querylog.Event{OccurredAt: now.Add(-time.Minute), ClientIP: "10.99.7.20", Name: "www.example.com", RecordType: dns.TypeAAAA,
			Source: querylog.SourceUpstream, Answer: "2001:db8::1", Duration: 1500 * time.Microsecond}},
	}}, nil
}

func (queries *mcpTestQueries) SaveMCPUse(_ context.Context, use store.MCPUse) error {
	queries.mu.Lock()
	defer queries.mu.Unlock()
	queries.use = use
	return nil
}

type mcpTestReply struct {
	status int
	header http.Header
	body   map[string]any
}

func postMCP(t *testing.T, server *Server, token, body string) mcpTestReply {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, mcpPath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	reply := mcpTestReply{status: response.Code, header: response.Header()}
	if response.Body.Len() > 0 {
		if err := json.Unmarshal(response.Body.Bytes(), &reply.body); err != nil {
			t.Fatalf("decode %q: %v", response.Body.String(), err)
		}
	}
	return reply
}

// callMCPToolForTest returns the tool result's structured content, or its
// error text when the tool reported a failure.
func callMCPToolForTest(t *testing.T, server *Server, token, tool string, arguments any) (map[string]any, string) {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 7, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": arguments},
	})
	if err != nil {
		t.Fatal(err)
	}
	reply := postMCP(t, server, token, string(encoded))
	if reply.status != http.StatusOK {
		t.Fatalf("%s status = %d body = %v", tool, reply.status, reply.body)
	}
	result, ok := reply.body["result"].(map[string]any)
	if !ok {
		t.Fatalf("%s returned no result: %v", tool, reply.body)
	}
	if result["isError"] == true {
		content := result["content"].([]any)[0].(map[string]any)
		return nil, content["text"].(string)
	}
	structured, _ := result["structuredContent"].(map[string]any)
	return structured, ""
}

func mcpZoneRecords(configuration *editableTestConfiguration, zoneName, name, recordType string) []zonemodel.Record {
	var records []zonemodel.Record
	for _, current := range configuration.zoneSnapshot.Zones {
		if current.Name != zoneName {
			continue
		}
		for _, record := range current.Records {
			if record.Name == name && record.Type == recordType {
				records = append(records, record)
			}
		}
	}
	return records
}

func TestMCPHandshake(t *testing.T) {
	t.Parallel()
	server, _ := newMCPTestServer(t)

	initialized := postMCP(t, server, "sable_pat_admin",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	result, _ := initialized.body["result"].(map[string]any)
	if initialized.status != http.StatusOK || result["protocolVersion"] != "2025-06-18" {
		t.Fatalf("initialize = %d %v", initialized.status, initialized.body)
	}
	if info := result["serverInfo"].(map[string]any); info["name"] != "sable" {
		t.Fatalf("serverInfo = %v", info)
	}

	unknownVersion := postMCP(t, server, "sable_pat_admin", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`)
	if got := unknownVersion.body["result"].(map[string]any)["protocolVersion"]; got != mcpLatestProtocol {
		t.Fatalf("unknown version negotiated %v", got)
	}

	if notified := postMCP(t, server, "sable_pat_admin", `{"jsonrpc":"2.0","method":"notifications/initialized"}`); notified.status != http.StatusAccepted {
		t.Fatalf("notification status = %d", notified.status)
	}

	listed := postMCP(t, server, "sable_pat_admin", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools := listed.body["result"].(map[string]any)["tools"].([]any)
	var names []string
	for _, tool := range tools {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "list_zones,list_records,add_record,set_records,update_record,delete_record,lookup,purge_cache,check_domain,allow_domain,block_domain,remove_domain_rule,list_block_lists,list_findings,get_version,get_stats,get_dynamic_dns" {
		t.Fatalf("tools = %v", names)
	}

	unknown := postMCP(t, server, "sable_pat_admin", `{"jsonrpc":"2.0","id":3,"method":"resources/list"}`)
	if failure, _ := unknown.body["error"].(map[string]any); failure == nil || failure["code"] != float64(mcpMethodNotFound) {
		t.Fatalf("unknown method = %v", unknown.body)
	}
}

func TestMCPRequiresBearerToken(t *testing.T) {
	t.Parallel()
	server, _ := newMCPTestServer(t)
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`

	for _, token := range []string{"", "sable_pat_wrong"} {
		reply := postMCP(t, server, token, ping)
		if reply.status != http.StatusUnauthorized || !strings.HasPrefix(reply.header.Get("WWW-Authenticate"), "Bearer") {
			t.Fatalf("token %q: status = %d header = %q", token, reply.status, reply.header.Get("WWW-Authenticate"))
		}
	}

	// A console session cookie is not enough: assistants act through tokens.
	request := httptest.NewRequest(http.MethodPost, mcpPath, strings.NewReader(ping))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: server.sessionCookieName(), Value: "session-token"})
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("session cookie status = %d", response.Code)
	}
}

func TestMCPRefusesBrowserRequests(t *testing.T) {
	t.Parallel()
	server, _ := newMCPTestServer(t)
	send := func(contentType string, header map[string]string) int {
		request := httptest.NewRequest(http.MethodPost, mcpPath, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		request.Header.Set("Content-Type", contentType)
		request.Header.Set("Authorization", "Bearer sable_pat_admin")
		for key, value := range header {
			request.Header.Set(key, value)
		}
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response.Code
	}
	if status := send("text/plain", nil); status != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain status = %d", status)
	}
	if status := send("application/json", map[string]string{"Sec-Fetch-Site": "cross-site"}); status != http.StatusForbidden {
		t.Fatalf("cross-site status = %d", status)
	}
	if status := send("application/json; charset=utf-8", nil); status != http.StatusOK {
		t.Fatalf("json with charset status = %d", status)
	}

	request := httptest.NewRequest(http.MethodGet, mcpPath, nil)
	request.Header.Set("Authorization", "Bearer sable_pat_admin")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d", response.Code)
	}
}

func TestMCPRecordLifecycle(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	const token = "sable_pat_admin"

	added, failure := callMCPToolForTest(t, server, token, "add_record", map[string]any{
		"zone": "example.test", "name": "api.example.test", "type": "a", "value": "192.0.2.20", "comment": "deploy",
	})
	if failure != "" || added["changed"] != true || added["serial"].(float64) <= 2026010101 {
		t.Fatalf("add_record = %v %q", added, failure)
	}
	if records := mcpZoneRecords(configuration, "example.test", "api", "A"); len(records) != 1 || records[0].Comments != "deploy" || records[0].TTL != 300 {
		t.Fatalf("stored records = %+v", records)
	}
	serial := added["serial"]

	repeated, failure := callMCPToolForTest(t, server, token, "add_record", map[string]any{
		"zone": "example.test", "name": "api", "type": "A", "value": "192.0.2.20",
	})
	if failure != "" || repeated["changed"] != false || repeated["serial"] != serial {
		t.Fatalf("repeated add_record = %v %q", repeated, failure)
	}

	updated, failure := callMCPToolForTest(t, server, token, "update_record", map[string]any{
		"zone": "example.test", "name": "api", "type": "A", "value": "192.0.2.20", "new_value": "192.0.2.21", "new_ttl": 60,
	})
	if failure != "" || updated["changed"] != true {
		t.Fatalf("update_record = %v %q", updated, failure)
	}
	if records := mcpZoneRecords(configuration, "example.test", "api", "A"); len(records) != 1 || records[0].Value != "192.0.2.21" || records[0].TTL != 60 || records[0].Comments != "deploy" {
		t.Fatalf("updated records = %+v", records)
	}

	if _, failure := callMCPToolForTest(t, server, token, "delete_record", map[string]any{
		"zone": "example.test", "name": "api", "type": "A", "value": "192.0.2.21",
	}); failure != "" {
		t.Fatalf("delete_record failed: %s", failure)
	}
	if records := mcpZoneRecords(configuration, "example.test", "api", "A"); len(records) != 0 {
		t.Fatalf("records after delete = %+v", records)
	}
	if _, failure := callMCPToolForTest(t, server, token, "delete_record", map[string]any{
		"zone": "example.test", "name": "api", "type": "A", "value": "192.0.2.21",
	}); !strings.Contains(failure, "list_records") {
		t.Fatalf("second delete failure = %q", failure)
	}

	text, failure := callMCPToolForTest(t, server, token, "add_record", map[string]any{
		"zone": "example.test", "name": "@", "type": "TXT", "value": `v=spf1 include:"mail" -all`,
	})
	if failure != "" || text["changed"] != true {
		t.Fatalf("add TXT = %v %q", text, failure)
	}
	if records := mcpZoneRecords(configuration, "example.test", "@", "TXT"); len(records) != 1 || records[0].Value != `"v=spf1 include:\"mail\" -all"` {
		t.Fatalf("TXT records = %+v", records)
	}

	listed, failure := callMCPToolForTest(t, server, token, "list_records", map[string]any{"zone": "example.test", "name": "www.example.test."})
	records, _ := listed["records"].([]any)
	if failure != "" || len(records) != 1 || records[0].(map[string]any)["fqdn"] != "www.example.test" {
		t.Fatalf("list_records = %v %q", listed, failure)
	}
}

func TestMCPSetRecordsIsIdempotent(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	const token = "sable_pat_admin"
	set := func(values ...string) map[string]any {
		t.Helper()
		result, failure := callMCPToolForTest(t, server, token, "set_records", map[string]any{
			"zone": "example.test", "name": "app", "type": "A", "values": values,
		})
		if failure != "" {
			t.Fatalf("set_records(%v) failed: %s", values, failure)
		}
		return result
	}

	if first := set("192.0.2.30", "192.0.2.31"); first["changed"] != true || len(first["added"].([]any)) != 2 {
		t.Fatalf("first set = %v", first)
	}
	moved := set("192.0.2.31", "192.0.2.32")
	if moved["changed"] != true || len(moved["added"].([]any)) != 1 || len(moved["removed"].([]any)) != 1 {
		t.Fatalf("moved set = %v", moved)
	}
	serial := moved["serial"]
	if again := set("192.0.2.32", "192.0.2.31"); again["changed"] != false || again["serial"] != serial {
		t.Fatalf("repeated set = %v", again)
	}
	var values []string
	for _, record := range mcpZoneRecords(configuration, "example.test", "app", "A") {
		values = append(values, record.Value)
	}
	if strings.Join(values, ",") != "192.0.2.31,192.0.2.32" {
		t.Fatalf("stored values = %v", values)
	}

	if _, failure := callMCPToolForTest(t, server, token, "set_records", map[string]any{
		"zone": "example.test", "name": "www", "type": "CNAME", "values": []string{"app"},
	}); !strings.Contains(failure, "CNAME") {
		t.Fatalf("CNAME beside an A record failure = %q", failure)
	}
	cname, failure := callMCPToolForTest(t, server, token, "set_records", map[string]any{
		"zone": "example.test", "name": "docs", "type": "CNAME", "values": []string{"app"},
	})
	if failure != "" || cname["changed"] != true {
		t.Fatalf("CNAME set = %v %q", cname, failure)
	}
	if records := mcpZoneRecords(configuration, "example.test", "docs", "CNAME"); len(records) != 1 || records[0].Value != "app.example.test." {
		t.Fatalf("CNAME records = %+v", records)
	}
}

func TestMCPRefusesProtectedRecords(t *testing.T) {
	t.Parallel()
	server, _ := newMCPTestServer(t)
	const token = "sable_pat_admin"
	tests := []struct {
		name      string
		tool      string
		arguments map[string]any
		want      string
	}{
		{"SOA", "add_record", map[string]any{"zone": "example.test", "name": "@", "type": "SOA", "value": "x"}, "SOA"},
		{"SOA delete", "delete_record", map[string]any{"zone": "example.test", "name": "@", "type": "SOA", "value": "ns1.example.test. hostmaster.example.test. 2026010101 3600 600 1209600 300"}, "automatically"},
		{"bad address", "add_record", map[string]any{"zone": "example.test", "name": "x", "type": "A", "value": "2001:db8::1"}, "not a valid A address"},
		{"secondary zone", "add_record", map[string]any{"zone": "secondary.test", "name": "x", "type": "A", "value": "192.0.2.1"}, "only Primary"},
		{"missing zone", "add_record", map[string]any{"zone": "missing.test", "name": "x", "type": "A", "value": "192.0.2.1"}, "not found"},
		{"unknown argument", "add_record", map[string]any{"zone": "example.test", "name": "x", "type": "A", "value": "192.0.2.1", "tll": 60}, "unknown field"},
		{"empty set", "set_records", map[string]any{"zone": "example.test", "name": "x", "type": "A", "values": []string{}}, "delete_record"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, failure := callMCPToolForTest(t, server, token, test.tool, test.arguments); !strings.Contains(failure, test.want) {
				t.Fatalf("failure = %q, want %q", failure, test.want)
			}
		})
	}
}

func TestMCPFollowsZoneGrants(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)

	zones, failure := callMCPToolForTest(t, server, "sable_pat_reader", "list_zones", map[string]any{})
	listed, _ := zones["zones"].([]any)
	if failure != "" || len(listed) != 1 || listed[0].(map[string]any)["name"] != "example.test" || listed[0].(map[string]any)["editable"] != false {
		t.Fatalf("reader list_zones = %v %q", zones, failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_reader", "add_record", map[string]any{
		"zone": "example.test", "name": "x", "type": "A", "value": "192.0.2.40",
	}); !strings.Contains(failure, "not change its records") {
		t.Fatalf("reader write failure = %q", failure)
	}
	// A zone outside the token's grants looks exactly like a missing one.
	if _, failure := callMCPToolForTest(t, server, "sable_pat_scoped", "list_records", map[string]any{"zone": "other.test"}); failure != "zone other.test was not found" {
		t.Fatalf("scoped read of other zone = %q", failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_scoped", "add_record", map[string]any{
		"zone": "other.test", "name": "x", "type": "A", "value": "192.0.2.40",
	}); failure != "zone other.test was not found" {
		t.Fatalf("scoped write to other zone = %q", failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_scoped", "add_record", map[string]any{
		"zone": "example.test", "name": "x", "type": "A", "value": "192.0.2.40",
	}); failure != "" || len(mcpZoneRecords(configuration, "example.test", "x", "A")) != 1 {
		t.Fatalf("scoped write failed: %q", failure)
	}
}

func TestMCPReplicaServesReadsOnly(t *testing.T) {
	t.Parallel()
	server, _ := newMCPTestServer(t)
	server.SetClusterController(testReplicaClusterController{})

	zones, failure := callMCPToolForTest(t, server, "sable_pat_admin", "list_zones", map[string]any{})
	if failure != "" || zones["note"] != replicaWriteMessage {
		t.Fatalf("replica list_zones = %v %q", zones, failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "add_record", map[string]any{
		"zone": "example.test", "name": "x", "type": "A", "value": "192.0.2.50",
	}); failure != replicaWriteMessage {
		t.Fatalf("replica write failure = %q", failure)
	}
}

func TestMCPCreateZone(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	addMCPTools(configuration, "create_zone", "delete_zone")

	created, failure := callMCPToolForTest(t, server, "sable_pat_admin", "create_zone", map[string]any{"name": "New.Test.", "default_ttl": 600})
	if failure != "" || created["zone"] != "new.test" || created["message"] != "Zone created" {
		t.Fatalf("create_zone = %v %q", created, failure)
	}
	zone := findZone(configuration.zoneSnapshot.Zones, "new.test")
	if zone == nil || zone.Type != "primary" || zone.DefaultTTL != 600 || len(zone.Records) != 2 {
		t.Fatalf("created zone = %+v", zone)
	}
	if soa := mcpZoneRecords(configuration, "new.test", "@", "SOA"); len(soa) != 1 || !strings.HasPrefix(soa[0].Value, "ns1.new.test. hostmaster.new.test. ") {
		t.Fatalf("SOA = %+v", soa)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "add_record", map[string]any{
		"zone": "new.test", "name": "app", "type": "A", "value": "192.0.2.60",
	}); failure != "" {
		t.Fatalf("record in new zone failed: %s", failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "create_zone", map[string]any{"name": "new.test"}); !strings.Contains(failure, "already exists") {
		t.Fatalf("duplicate create = %q", failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_scoped", "create_zone", map[string]any{"name": "other.new.test"}); !strings.Contains(failure, "zones.create") {
		t.Fatalf("scoped create = %q", failure)
	}
	limited, failure := callMCPToolForTest(t, server, "sable_pat_creator", "create_zone", map[string]any{"name": "limited.test"})
	if failure != "" || !strings.Contains(limited["message"].(string), "cannot change its records") {
		t.Fatalf("limited create = %v %q", limited, failure)
	}
	server.SetClusterController(testReplicaClusterController{})
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "create_zone", map[string]any{"name": "replica.test"}); failure != replicaWriteMessage {
		t.Fatalf("replica create = %q", failure)
	}
}

func TestMCPIsOffUntilSetUp(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	configuration.snapshot.Config.MCP = config.MCP{Tools: config.DefaultMCPTools()}
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`

	if reply := postMCP(t, server, "sable_pat_admin", ping); reply.status != http.StatusNotFound || reply.body["error"] != mcpDisabledMessage {
		t.Fatalf("disabled status = %d body = %v", reply.status, reply.body)
	}
	// Without a token the answer stays a sign-in failure, so the switch does
	// not tell a stranger anything.
	if reply := postMCP(t, server, "", ping); reply.status != http.StatusUnauthorized {
		t.Fatalf("disabled without token status = %d", reply.status)
	}

	post := func(path, form string) string {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		if path == "/ui/integrations/mcp/remove" {
			server.removeMCP(response, request)
		} else {
			server.setMCPEnabled(response, request)
		}
		if response.Code != http.StatusOK {
			t.Fatalf("%s %s = %d", path, form, response.Code)
		}
		return response.Body.String()
	}
	state := func() config.MCP { return configuration.snapshot.Config.MCP }

	if body := post("/ui/integrations/mcp/enabled", "enabled=true"); !strings.Contains(body, "MCP server set up") || !strings.Contains(body, ">Active<") {
		t.Fatalf("set up body lacks message or badge")
	}
	if got := state(); !got.Configured || !got.Enabled {
		t.Fatalf("after set up = %+v", got)
	}
	if reply := postMCP(t, server, "sable_pat_admin", ping); reply.status != http.StatusOK {
		t.Fatalf("enabled status = %d", reply.status)
	}
	if body := post("/ui/integrations/mcp/enabled", "enabled=false"); !strings.Contains(body, ">Paused<") || !strings.Contains(body, "Resume") {
		t.Fatalf("pause body lacks badge or Resume")
	}
	if got := state(); !got.Configured || got.Enabled {
		t.Fatalf("after pause = %+v", got)
	}
	if reply := postMCP(t, server, "sable_pat_admin", ping); reply.status != http.StatusNotFound {
		t.Fatalf("paused status = %d", reply.status)
	}
	if body := post("/ui/integrations/mcp/enabled", "enabled=true"); !strings.Contains(body, "MCP server resumed") {
		t.Fatalf("resume body lacks message")
	}
	if body := post("/ui/integrations/mcp/remove", ""); !strings.Contains(body, "Set Up MCP Server") || !strings.Contains(body, ">Not set up<") {
		t.Fatalf("remove body lacks setup button")
	}
	if got := state(); got.Configured || got.Enabled {
		t.Fatalf("after remove = %+v", got)
	}
}

type mcpPrimaryClusterController struct {
	clusterController
	state cluster.State
}

func (controller mcpPrimaryClusterController) Snapshot() cluster.State { return controller.state }

func TestMCPAddressPrefersPrimaryHTTPS(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	request := httptest.NewRequest(http.MethodGet, "http://10.0.0.5:8080/integrations", nil)

	if address, secure := server.mcpAddress(request.Context(), request); address != "http://10.0.0.5:8080/mcp" || secure {
		t.Fatalf("plain address = %s secure=%t", address, secure)
	}
	proxied := httptest.NewRequest(http.MethodGet, "http://dns.example.test/integrations", nil)
	proxied.Header.Set("X-Forwarded-Proto", "https")
	if address, secure := server.mcpAddress(proxied.Context(), proxied); address != "https://dns.example.test/mcp" || !secure {
		t.Fatalf("proxied address = %s secure=%t", address, secure)
	}

	configuration.snapshot.Config.Server.HTTPSListen = "0.0.0.0:5443"
	configuration.snapshot.Config.EncryptedDNS.CertificateMode = "acme"
	configuration.snapshot.Config.EncryptedDNS.ACME.Domains = []string{"*.example.test", "ns1.example.test"}
	if address, _ := server.mcpAddress(request.Context(), request); address != "https://ns1.example.test:5443/mcp" {
		t.Fatalf("certificate address = %s", address)
	}

	// Browsing a replica still hands out the primary, the only node that
	// accepts changes.
	server.SetClusterController(mcpPrimaryClusterController{state: cluster.State{
		Initialized: true, LocalRole: cluster.RoleReplica, PrimaryURL: "https://ns1.penree.example:5443/",
	}})
	if address, secure := server.mcpAddress(request.Context(), request); address != "https://ns1.penree.example:5443/mcp" || !secure {
		t.Fatalf("cluster address = %s secure=%t", address, secure)
	}
}

func TestMCPCardShowsToolsAndLastUse(t *testing.T) {
	t.Parallel()
	server, _ := newMCPTestServer(t)
	card := func() string {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/integrations", nil)
		response := httptest.NewRecorder()
		if err := pages.MCPCard(server.integrationsView(request, "", "").MCP).Render(request.Context(), response); err != nil {
			t.Fatal(err)
		}
		return response.Body.String()
	}
	before := card()
	if !strings.Contains(before, fmt.Sprintf(">%d<", len(mcpToolList(config.MCP{Tools: config.DefaultMCPTools()})))) || !strings.Contains(before, ">Never<") {
		t.Fatalf("card before any call lacks the tool count or Never")
	}

	// Listing tools is the client probing; only a tool call counts as use.
	postMCP(t, server, "sable_pat_admin", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if !strings.Contains(card(), ">Never<") {
		t.Fatal("tools/list counted as use")
	}

	request := httptest.NewRequest(http.MethodPost, mcpPath, strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_zones","arguments":{}}}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer sable_pat_scoped")
	request.Header.Set("User-Agent", "claude-code/2.1.0 (cli)")
	server.httpServer.Handler.ServeHTTP(httptest.NewRecorder(), request)
	after := card()
	if strings.Contains(after, ">Never<") || !strings.Contains(after, "deploy with claude-code, list_zones") {
		t.Fatalf("card after a call does not show the use")
	}
	if !strings.Contains(after, `Calls today</span><span class="integration-fact-value">1<`) {
		t.Fatal("card does not count the call")
	}
	// Concurrent calls must each be counted, not overwrite one another.
	var wait sync.WaitGroup
	for range 5 {
		wait.Go(func() {
			postMCP(t, server, "sable_pat_scoped", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_zones","arguments":{}}}`)
		})
	}
	wait.Wait()
	if !strings.Contains(card(), `Calls today</span><span class="integration-fact-value">6<`) {
		t.Fatal("concurrent calls were not all counted")
	}
}

func TestMCPClientName(t *testing.T) {
	t.Parallel()
	for userAgent, want := range map[string]string{
		"claude-code/2.1.0 (cli)": "claude-code",
		"codex_cli_rs/0.40.0":     "codex_cli_rs",
		"node":                    "node",
		"":                        "",
	} {
		if got := mcpClientName(userAgent); got != want {
			t.Errorf("mcpClientName(%q) = %q, want %q", userAgent, got, want)
		}
	}
}

// addMCPTools turns on tools beyond the defaults.
func addMCPTools(configuration *editableTestConfiguration, groups ...string) {
	configuration.snapshot.Config.MCP.Tools = append(configuration.snapshot.Config.MCP.Tools, groups...)
}
