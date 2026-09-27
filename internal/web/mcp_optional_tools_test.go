package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/querylog"
	zonemodel "github.com/drudge/sable/internal/zone"
)

func mcpListedTools(t *testing.T, server *Server) []string {
	t.Helper()
	reply := postMCP(t, server, "sable_pat_admin", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	var names []string
	for _, tool := range reply.body["result"].(map[string]any)["tools"].([]any) {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	return names
}

func TestMCPOptionalToolsStayHiddenUntilTurnedOn(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	optional := []string{"delete_zone", "list_block_lists", "add_block_list", "remove_block_list", "refresh_block_lists", "list_findings", "search_queries"}

	listed := strings.Join(mcpListedTools(t, server), ",")
	for _, name := range optional {
		if strings.Contains(listed, name) {
			t.Fatalf("%s offered while its option is off: %s", name, listed)
		}
	}
	// A client holding an old tool list is told the tool is off, not that it
	// does not exist.
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "search_queries", map[string]any{}); !strings.Contains(failure, "turned off") {
		t.Fatalf("disabled tool failure = %q", failure)
	}

	configuration.snapshot.Config.MCP.BlockLists = true
	listed = strings.Join(mcpListedTools(t, server), ",")
	if !strings.Contains(listed, "add_block_list") || strings.Contains(listed, "delete_zone") || strings.Contains(listed, "search_queries") {
		t.Fatalf("with block lists on, tools = %s", listed)
	}
	configuration.snapshot.Config.MCP = config.MCP{Configured: true, Enabled: true, DeleteZones: true, BlockLists: true, InsightFindings: true, QueryLog: true}
	if got := len(mcpListedTools(t, server)); got != len(mcpAllTools()) {
		t.Fatalf("with every option on, %d of %d tools offered", got, len(mcpAllTools()))
	}
}

func TestMCPDeleteZoneOnlyDeletesItsOwnZones(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	configuration.snapshot.Config.MCP.DeleteZones = true

	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "create_zone", map[string]any{"name": "preview.test"}); failure != "" {
		t.Fatalf("create_zone failed: %s", failure)
	}
	if zone := findZone(configuration.zoneSnapshot.Zones, "preview.test"); zone == nil || zone.Source != zonemodel.SourceMCP {
		t.Fatalf("created zone = %+v", zone)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "delete_zone", map[string]any{"zone": "example.test", "confirm": "example.test"}); !strings.Contains(failure, "only be deleted in the Sable console") {
		t.Fatalf("delete of a console zone = %q", failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "delete_zone", map[string]any{"zone": "preview.test", "confirm": "preview"}); !strings.Contains(failure, "confirm must repeat") {
		t.Fatalf("delete without confirmation = %q", failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_scoped", "delete_zone", map[string]any{"zone": "example.test", "confirm": "example.test"}); !strings.Contains(failure, "zones.delete") {
		t.Fatalf("delete without zones.delete = %q", failure)
	}
	deleted, failure := callMCPToolForTest(t, server, "sable_pat_admin", "delete_zone", map[string]any{"zone": "preview.test", "confirm": "Preview.Test."})
	if failure != "" || deleted["deleted"] != true || findZone(configuration.zoneSnapshot.Zones, "preview.test") != nil {
		t.Fatalf("delete_zone = %v %q", deleted, failure)
	}
	server.SetClusterController(testReplicaClusterController{})
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "delete_zone", map[string]any{"zone": "example.test", "confirm": "example.test"}); failure != replicaWriteMessage {
		t.Fatalf("replica delete = %q", failure)
	}
}

func TestMCPBlockListTools(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	configuration.snapshot.Config.MCP.BlockLists = true
	configuration.snapshot.Config.Blocking.Lists = []config.BlockList{{Name: "Example Hosts", URL: "https://lists.example.test/hosts.txt", Format: "auto"}}

	listed, failure := callMCPToolForTest(t, server, "sable_pat_blocking", "list_block_lists", map[string]any{})
	lists, _ := listed["lists"].([]any)
	if failure != "" || len(lists) != 1 || lists[0].(map[string]any)["name"] != "Example Hosts" {
		t.Fatalf("list_block_lists = %v %q", listed, failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_blocking", "add_block_list", map[string]any{"url": "ftp://lists.example.test/x"}); failure == "" {
		t.Fatal("add_block_list accepted a non-HTTPS URL")
	}
	if repeated, failure := callMCPToolForTest(t, server, "sable_pat_blocking", "add_block_list", map[string]any{"url": "https://lists.example.test/hosts.txt"}); failure != "" || repeated["changed"] != false {
		t.Fatalf("adding a configured list = %v %q", repeated, failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_reader", "remove_block_list", map[string]any{"list": "Example Hosts"}); !strings.Contains(failure, "blocking.write") {
		t.Fatalf("reader remove = %q", failure)
	}
	removed, failure := callMCPToolForTest(t, server, "sable_pat_blocking", "remove_block_list", map[string]any{"list": "https://lists.example.test/hosts.txt"})
	if failure != "" || removed["changed"] != true || len(configuration.snapshot.Config.Blocking.Lists) != 0 {
		t.Fatalf("remove_block_list = %v %q", removed, failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_blocking", "refresh_block_lists", map[string]any{}); !strings.Contains(failure, "no remote block lists") {
		t.Fatalf("refresh with no lists = %q", failure)
	}
}

func TestMCPInsightAndQueryLogTools(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	configuration.snapshot.Config.MCP.InsightFindings = true
	configuration.snapshot.Config.MCP.QueryLog = true

	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "list_findings", map[string]any{"range": "fortnight"}); failure != "" {
		t.Fatalf("list_findings failed: %s", failure)
	}
	for _, tool := range []string{"list_findings", "search_queries"} {
		if _, failure := callMCPToolForTest(t, server, "sable_pat_blocking", tool, map[string]any{}); !strings.Contains(failure, "logs.read") {
			t.Fatalf("%s without logs.read = %q", tool, failure)
		}
	}

	found, failure := callMCPToolForTest(t, server, "sable_pat_logs", "search_queries", map[string]any{
		"client": "10.99.7.20", "name": "Example", "blocked_only": true, "limit": 5000, "hours": 2,
	})
	queries, _ := found["queries"].([]any)
	if failure != "" || len(queries) != 2 || found["matching"] != float64(2) {
		t.Fatalf("search_queries = %v %q", found, failure)
	}
	blocked := queries[0].(map[string]any)
	if blocked["blocked_by"] != "ads.example" || blocked["result"] != "NXDOMAIN" || blocked["type"] != "A" {
		t.Fatalf("blocked entry = %v", blocked)
	}
	filter := server.queries.(*mcpTestQueries).filter
	if filter.PageSize != mcpMaximumQueryLimit || filter.ClientIP != "10.99.7.20" || filter.Name != "example" || filter.Source != querylog.SourceBlocked {
		t.Fatalf("filter = %+v", filter)
	}
}

func TestMCPOptionalToolsSaveFromTheCard(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	request := httptest.NewRequest(http.MethodPost, "/ui/integrations/mcp/tools", strings.NewReader("block_lists=true&query_log=true"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	server.setMCPTools(response, request)
	got := configuration.snapshot.Config.MCP
	if response.Code != http.StatusOK || !got.BlockLists || !got.QueryLog || got.DeleteZones || got.InsightFindings || !got.Enabled {
		t.Fatalf("saved options = %+v, status %d", got, response.Code)
	}
	if !strings.Contains(response.Body.String(), "Optional tools saved") {
		t.Fatal("save did not confirm")
	}
	encoded, _ := json.Marshal(mcpToolList(got))
	if !strings.Contains(string(encoded), "search_queries") || strings.Contains(string(encoded), "delete_zone") {
		t.Fatal("saved options did not change the offered tools")
	}
}
