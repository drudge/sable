package web

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/querylog"
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

func TestMCPAdvancedToolsStayHiddenUntilTurnedOn(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	advanced := []string{"create_zone", "delete_zone", "add_block_list", "remove_block_list", "refresh_block_lists", "search_queries", "sync_dynamic_dns", "search_server_logs"}

	listed := strings.Join(mcpListedTools(t, server), ",")
	for _, name := range advanced {
		if strings.Contains(listed, name) {
			t.Fatalf("%s offered while its option is off: %s", name, listed)
		}
	}
	// A client holding an old tool list is told the tool is off, not that it
	// does not exist.
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "search_queries", map[string]any{}); !strings.Contains(failure, "turned off") {
		t.Fatalf("disabled tool failure = %q", failure)
	}

	addMCPTools(configuration, "add_block_list", "remove_block_list", "refresh_block_lists")
	listed = strings.Join(mcpListedTools(t, server), ",")
	if !strings.Contains(listed, "add_block_list") || strings.Contains(listed, "delete_zone") || strings.Contains(listed, "search_queries") {
		t.Fatalf("with block lists on, tools = %s", listed)
	}
	configuration.snapshot.Config.MCP = config.MCP{Configured: true, Enabled: true, Tools: config.MCPTools}
	if got := len(mcpListedTools(t, server)); got != len(mcpAllTools()) {
		t.Fatalf("with every option on, %d of %d tools offered", got, len(mcpAllTools()))
	}
}

// delete_zone reaches any zone the token may delete, but only when the
// assistant repeats the zone name, which it should ask the user for first.
func TestMCPDeleteZoneNeedsGrantAndConfirmation(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	addMCPTools(configuration, "create_zone", "delete_zone")

	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "create_zone", map[string]any{"name": "preview.test"}); failure != "" {
		t.Fatalf("create_zone failed: %s", failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "delete_zone", map[string]any{"zone": "example.test", "confirm": "example"}); !strings.Contains(failure, "confirm must repeat") {
		t.Fatalf("delete without confirmation = %q", failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_scoped", "delete_zone", map[string]any{"zone": "example.test", "confirm": "example.test"}); !strings.Contains(failure, "zones.delete") {
		t.Fatalf("delete without zones.delete = %q", failure)
	}
	// A zone made in the console is fair game once the token may delete it.
	deleted, failure := callMCPToolForTest(t, server, "sable_pat_admin", "delete_zone", map[string]any{"zone": "example.test", "confirm": "Example.Test."})
	if failure != "" || deleted["deleted"] != true || findZone(configuration.zoneSnapshot.Zones, "example.test") != nil {
		t.Fatalf("delete_zone = %v %q", deleted, failure)
	}
	server.SetClusterController(testReplicaClusterController{})
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "delete_zone", map[string]any{"zone": "preview.test", "confirm": "preview.test"}); failure != replicaWriteMessage {
		t.Fatalf("replica delete = %q", failure)
	}
}

func TestMCPBlockListTools(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	addMCPTools(configuration, "add_block_list", "remove_block_list", "refresh_block_lists")
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
	addMCPTools(configuration, "list_findings", "search_queries")

	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "list_findings", map[string]any{"range": "fortnight"}); failure != "" {
		t.Fatalf("list_findings failed: %s", failure)
	}
	configuration.snapshot.Config.Insights.Enabled = false
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "list_findings", map[string]any{}); failure != errInsightsOff.Error() {
		t.Fatalf("list_findings with Insights off = %q", failure)
	}
	configuration.snapshot.Config.Insights.Enabled = true
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

func TestMCPSetupWizardSavesTools(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	save := func(form string) string {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/ui/integrations/mcp/setup", strings.NewReader(form))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		server.saveMCPSetup(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("save %q = %d", form, response.Code)
		}
		return response.Body.String()
	}

	// The first save sets the server up and turns it on with the chosen
	// tools, kept in the console's order, unknown ones dropped.
	configuration.snapshot.Config.MCP = config.MCP{Tools: config.DefaultMCPTools()}
	if body := save("tools=add_block_list&tools=list_zones&tools=bogus"); !strings.Contains(body, "MCP server set up") {
		t.Fatal("first save did not set the server up")
	}
	got := configuration.snapshot.Config.MCP
	if !got.Configured || !got.Enabled || strings.Join(got.Tools, ",") != "list_zones,add_block_list" {
		t.Fatalf("after setup = %+v", got)
	}

	// Editing a paused server changes its tools but leaves it paused.
	configuration.snapshot.Config.MCP.Enabled = false
	if body := save("tools=search_queries"); !strings.Contains(body, "MCP server saved") {
		t.Fatal("edit did not confirm")
	}
	got = configuration.snapshot.Config.MCP
	if got.Enabled || !got.Configured || strings.Join(got.Tools, ",") != "search_queries" {
		t.Fatalf("after edit = %+v", got)
	}
	if offered := mcpToolList(got); len(offered) != 1 || offered[0].Name != "search_queries" {
		t.Fatalf("offered tools = %v", offered)
	}
}

// The wizard lists every tool once, in a known section, with its grant.
func TestMCPToolSectionsListEveryTool(t *testing.T) {
	t.Parallel()
	var listed []string
	for _, section := range mcpToolSectionViews(config.MCP{Tools: config.DefaultMCPTools()}) {
		for _, tool := range section.Tools {
			if tool.Grant == "" {
				t.Errorf("%s has no grant", tool.Name)
			}
			if tool.On != slices.Contains(config.DefaultMCPTools(), tool.Name) {
				t.Errorf("%s on = %t by default", tool.Name, tool.On)
			}
			listed = append(listed, tool.Name)
		}
	}
	if !slices.Equal(listed, config.MCPTools) {
		t.Fatalf("wizard lists %v, config knows %v", listed, config.MCPTools)
	}
	var defined []string
	for _, tool := range mcpAllTools() {
		defined = append(defined, tool.Name)
	}
	slices.Sort(defined)
	known := slices.Clone(config.MCPTools)
	slices.Sort(known)
	if !slices.Equal(defined, known) {
		t.Fatalf("defined tools %v, config knows %v", defined, known)
	}
}
