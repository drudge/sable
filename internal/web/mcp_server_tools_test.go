package web

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/update"
	"github.com/drudge/sable/internal/version"
)

// testCachedUpdateController remembers how fresh a check had to be.
type testCachedUpdateController struct {
	testUpdateController
	fresh []time.Duration
}

func (controller *testCachedUpdateController) CheckIfStale(_ context.Context, preRelease bool, fresh time.Duration) (update.Status, error) {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	controller.fresh = append(controller.fresh, fresh)
	controller.preRelease = preRelease
	return controller.status, nil
}

type testMCPClusterController struct {
	clusterController
	state cluster.State
}

func (controller testMCPClusterController) Snapshot() cluster.State { return controller.state }

func setMCPTestRelease(t *testing.T, release string) {
	t.Helper()
	previous := version.Release
	version.Release = release
	t.Cleanup(func() { version.Release = previous })
}

// get_version reads the version from the build, so it cannot run in parallel
// with other tests that change it.
func TestMCPGetVersion(t *testing.T) {
	server, configuration := newMCPTestServer(t)

	setMCPTestRelease(t, "dev")
	development, failure := callMCPToolForTest(t, server, "sable_pat_updates", "get_version", map[string]any{"check": true})
	if failure != "" || development["development"] != true || development["latest"] != nil {
		t.Fatalf("development build = %v %q", development, failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_metrics", "get_version", map[string]any{}); !strings.Contains(failure, "updates.read") {
		t.Fatalf("without updates.read = %q", failure)
	}

	setMCPTestRelease(t, "1.5.1-beta.3")
	controller := &testCachedUpdateController{testUpdateController: testUpdateController{status: update.Status{
		CurrentVersion: "1.5.1-beta.3", LatestVersion: "1.5.1", ReleaseURL: "https://github.com/drudge/sable/releases/tag/v1.5.1",
		ReleaseNotes: "## Fixed\n- Referral loops.", Available: true, CheckedAt: time.Now().Add(-time.Hour),
		Releases: []update.ReleaseNote{
			{Version: "1.5.1", Notes: "## Fixed\n- Referral loops."},
			{Version: "1.5.1-rc.1", Notes: "## Added\n- A minimization switch.", PreRelease: true},
		},
	}}}
	server.SetUpdateController(controller)
	server.SetClusterController(testMCPClusterController{state: cluster.State{Initialized: true, Nodes: []cluster.Node{
		{Name: "ns1", Role: cluster.RolePrimary, Version: "1.5.1-beta.3"},
		{Name: "ns2", Role: cluster.RoleReplica, Version: "1.5.1-beta.2"},
	}}})

	result, failure := callMCPToolForTest(t, server, "sable_pat_admin", "get_version", map[string]any{})
	latest, _ := result["latest"].(map[string]any)
	notes, _ := latest["notes"].(string)
	if failure != "" || result["update_available"] != true || latest["release"] != "1.5.1" || result["channel"] != "stable" {
		t.Fatalf("get_version = %v %q", result, failure)
	}
	if !strings.Contains(notes, "# 1.5.1\n") || !strings.Contains(notes, "# 1.5.1-rc.1\n") || strings.Index(notes, "1.5.1-rc.1") < strings.Index(notes, "Referral") {
		t.Fatalf("rolled-up notes = %q", notes)
	}
	if nodes, _ := result["nodes"].([]any); len(nodes) != 2 || nodes[1].(map[string]any)["version"] != "1.5.1-beta.2" {
		t.Fatalf("nodes = %v", result["nodes"])
	}
	if len(controller.fresh) != 0 {
		t.Fatal("get_version asked GitHub without check")
	}

	// Nodes need cluster.read, and notes can be left out.
	quiet, _ := callMCPToolForTest(t, server, "sable_pat_updates", "get_version", map[string]any{"notes": false, "check": true})
	if quiet["nodes"] != nil || quiet["latest"].(map[string]any)["notes"] != nil {
		t.Fatalf("updates.read only, no notes = %v", quiet)
	}
	if len(controller.fresh) != 1 || controller.fresh[0] != mcpVersionCheckFloor || controller.preRelease {
		t.Fatalf("forced check freshness = %v, pre-release %t", controller.fresh, controller.preRelease)
	}

	// A check on the stable channel says nothing about pre-releases.
	configuration.snapshot.Config.Updates.PreRelease = true
	other, _ := callMCPToolForTest(t, server, "sable_pat_updates", "get_version", map[string]any{})
	if other["channel"] != "pre-release" || other["latest"] != nil || !strings.Contains(other["note"].(string), "check true") {
		t.Fatalf("other channel = %v", other)
	}
}

func TestMCPReleaseNotesStayUnderTheCap(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("- A line about a fix that matters.\n", 400)
	status := update.Status{Releases: []update.ReleaseNote{{Version: "1.2.0", Notes: long}, {Version: "1.1.0", Notes: long}}}
	notes, truncated := mcpReleaseNotes(status)
	if !truncated || len(notes) > mcpMaximumNotesBytes || !strings.HasPrefix(notes, "# 1.2.0") || !strings.HasSuffix(notes, "matters.") {
		t.Fatalf("notes are %d bytes, truncated %t, ending %q", len(notes), truncated, notes[len(notes)-20:])
	}
	if notes, truncated := mcpReleaseNotes(update.Status{ReleaseNotes: "Short."}); notes != "Short." || truncated {
		t.Fatalf("latest-only notes = %q %t", notes, truncated)
	}
}
