//go:build browser

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
)

// testRemovableClusterController accepts Remove, so a panel's action can be
// followed back to the page.
type testRemovableClusterController struct {
	testClusterPageController
}

func (testRemovableClusterController) Remove(context.Context, string) error { return nil }

// Block lists and cluster nodes open their panels at their own addresses:
// from a click, from Back and Forward, and from a link opened fresh.
func TestBrowserDetailsPanels(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("0.0.0.0 one.example\n0.0.0.0 two.example\n"))
	}))
	defer remote.Close()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}, baseDirectory: t.TempDir()}
	configuration.snapshot.Config.Blocking.Lists = []config.BlockList{{Name: "Test Feed", URL: remote.URL + "/hosts", Path: "blocklists/test-feed.txt", Format: "auto"}}
	cached := filepath.Join(configuration.baseDirectory, "blocklists/test-feed.txt")
	if err := os.MkdirAll(filepath.Dir(cached), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cached, []byte("cached.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := newDetailsPanelTestServer(t, configuration)
	app.SetClusterController(testRemovableClusterController{testClusterPageController{testMCPLeadClusterController{
		testMCPClusterController: testMCPClusterController{state: cluster.State{
			Initialized: true, Mode: "primary-replica", ClusterID: "cluster-1", NodeID: "node-1", PrimaryID: "node-1", LocalRole: cluster.RolePrimary,
			Nodes: []cluster.Node{
				{ID: "node-1", Name: "ns1", Role: cluster.RolePrimary, State: cluster.StateOnline, SyncState: cluster.SyncCurrent},
				{ID: "node-2", Name: "ns2", Role: cluster.RoleReplica, State: cluster.StateOnline, SyncState: cluster.SyncCurrent, Addresses: []string{"192.0.2.2"}},
			},
		}},
		reported: map[string][]alerts.Alert{"node-2": {{ID: "certificates.renewal", Problem: true, Title: "Certificate renewal failing", Headline: "Certificate renewal is failing on ns2."}}},
	}}})
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/details-panels.cjs", server.URL)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser details panels: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
