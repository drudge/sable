//go:build browser

package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"

	webassets "github.com/drudge/sable/internal/web/assets"
	"github.com/drudge/sable/internal/web/pages"
)

// Going on to Connect while the wizard's group lacks a checked tool's grant
// warns that the tool won't work, and Go Back stays on Access.
func TestBrowserMCPWizardWarnsAboutMissingGrants(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", webassets.Handler())
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		console := pages.DashboardView{CSRFToken: "fixture-csrf", CanSettings: true, CanWriteSettings: true}
		view := pages.MCPAppView{Setup: true, Address: "https://dns.example.net/mcp", Secure: true,
			Sections: []pages.MCPToolSectionView{
				{Key: "records", Title: "Records & Zones", Tools: []pages.MCPToolView{{Name: "list_zones", Grant: "zones.read", ReadOnly: true, On: true}}},
				{Key: "server", Title: "Server", Tools: []pages.MCPToolView{
					{Name: "get_stats", Grant: "metrics.read", ReadOnly: true, On: true},
					{Name: "get_cluster_status", Grant: "cluster.read", ReadOnly: true, On: r.URL.Query().Has("two")},
				}},
			},
			Group: pages.MCPGroupView{Needed: []string{"zones.read", "metrics.read"}, Name: "MCP Server", Grants: []string{"zones.read"},
				Coverage: "MCP Server lacks these grants:", CoverageGrants: []string{"metrics.read"}, NeedsUpdate: true,
				CanManage: !r.URL.Query().Has("reader"), InGroup: true},
		}
		_ = pages.AppDocument(console, "MCP wizard", "integrations", pages.MCPSetupDialog(view)).Render(r.Context(), w)
	})
	server := httptest.NewServer(secureHeaders(mux, false))
	defer server.Close()
	command := exec.Command("node", "../../scripts/browser/mcp-wizard.cjs", server.URL)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser MCP wizard: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
