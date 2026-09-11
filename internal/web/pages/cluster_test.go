package pages

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/cluster"
)

func TestClusterNodeStatusUsesAvatarIndicators(t *testing.T) {
	t.Parallel()
	var response bytes.Buffer
	view := ClusterPageView{
		Initialized: true,
		LocalRole:   "Primary",
		Nodes: []ClusterNodeView{
			{ID: "node-primary", Name: "ns1", Role: "Primary", State: "online", SyncState: "current", Local: true},
			{ID: "node-replica", Name: "ns2", AdvertiseURL: "https://ns2.example.test:5380", Role: "Replica", State: "unreachable", SyncState: "behind"},
		},
	}
	if err := ClusterContent(view).Render(context.Background(), &response); err != nil {
		t.Fatal(err)
	}
	markup := response.String()
	for _, expected := range []string{
		`class="cluster-node-icon online local"`, `aria-label="Connection status: Online"`,
		`class="cluster-node-icon unreachable"`, `aria-label="Connection status: Unreachable"`,
		`class="cluster-updated-badge"`, `icon-clock`, `Updated`,
	} {
		if !strings.Contains(markup, expected) {
			t.Fatalf("cluster content missing %q: %s", expected, markup)
		}
	}
	if strings.Contains(markup, `status-badge active">Online`) {
		t.Fatalf("cluster content still renders Online as a text badge: %s", markup)
	}
	if strings.Contains(markup, `class="cluster-observed"`) || strings.Contains(markup, `class="count-badge"`) {
		t.Fatalf("cluster content still renders the redundant node count: %s", markup)
	}
}

func TestClusterProgressSurvivesRestartsWithoutOfferingAnotherRollout(t *testing.T) {
	for _, phase := range []string{"preparing", "updating", "restarting", "verifying", "complete", "failed", "stopped"} {
		t.Run(phase, func(t *testing.T) {
			view := ClusterUpdateView{CanApply: true, Rollout: cluster.RolloutStatus{ID: "rollout", Version: "v1.2.0", Phase: phase}}
			var response bytes.Buffer
			if err := ClusterUpdatePanel(view, true).Render(context.Background(), &response); err != nil {
				t.Fatal(err)
			}
			markup := response.String()
			for _, expected := range []string{`class="card cluster-update-card"`, `cluster-update-version`, `v1.2.0`} {
				if !strings.Contains(markup, expected) {
					t.Fatalf("missing %q during %s", expected, phase)
				}
			}
			if strings.Contains(markup, `id="cluster-update-start"`) || strings.Contains(markup, "Sable v1.2.0") || strings.Contains(markup, `icon-sparkles`) {
				t.Fatal("persisted rollout must retain its version badge without implying a new update")
			}
		})
	}
}

func TestClusterProgressDistinguishesCompletedActiveAndWaitingNodes(t *testing.T) {
	for _, test := range []struct {
		phase, nodePhase, label string
		spinners                int
	}{
		{"preparing", "queued", "Checking nodes", 0},
		{"updating", "install", "Installing", 1},
		{"updating", "restart", "Restarting", 1},
		{"verifying", "restart", "Verifying sync", 2},
		{"failed", "install", "Failed", 0},
		{"stopped", "restart", "Stopped", 0},
	} {
		t.Run(test.phase+"/"+test.nodePhase, func(t *testing.T) {
			view := ClusterUpdateView{Rollout: cluster.RolloutStatus{ID: "rollout", Phase: test.phase, Index: 1, Nodes: []cluster.RolloutNode{
				{Name: "ns2", Phase: "complete"}, {Name: "ns3", Phase: test.nodePhase}, {Name: "ns1", Phase: "queued"},
			}}}
			checks := 1
			if test.phase == "preparing" {
				view.Rollout.Nodes[0].Phase = "queued"
				checks = 0
			}
			var response bytes.Buffer
			if err := ClusterUpdatePanel(view, false).Render(context.Background(), &response); err != nil {
				t.Fatal(err)
			}
			markup := response.String()
			if strings.Count(markup, "icon-loader-circle") != test.spinners || strings.Count(markup, `icon-check`) != checks || !strings.Contains(markup, test.label) {
				t.Fatalf("incorrect progress icons or labels: %s", markup)
			}
			if (test.phase == "preparing" || test.phase == "updating") && !strings.Contains(markup, `aria-hidden="true">3</span>`) {
				t.Fatal("waiting node should show its position in a styled step")
			}
		})
	}
}

func TestClusterUpdateBadgeAndCompletedActions(t *testing.T) {
	view := ClusterUpdateView{Supported: true, CanApply: true, Version: "1.2.0", Release: UpdateView{CanCheck: true, LatestVersion: "1.2.0", Checked: true}}
	var response bytes.Buffer
	if err := ClusterUpdatePanel(view, false).Render(context.Background(), &response); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(response.String(), `icon-sparkles`) || !strings.Contains(response.String(), `id="cluster-update-start"`) {
		t.Fatal("available update should show a sparkle and update action")
	}
	view.Version = ""
	view.Rollout = cluster.RolloutStatus{ID: "rollout", Version: "v1.2.0", Phase: "complete"}
	response.Reset()
	if err := ClusterUpdatePanel(view, false).Render(context.Background(), &response); err != nil {
		t.Fatal(err)
	}
	markup := response.String()
	if strings.Contains(markup, `icon-sparkles`) || strings.Contains(markup, `id="cluster-update-start"`) || strings.Contains(markup, `/about#about-update`) {
		t.Fatal("up-to-date cluster must not offer another installation or redirect to About")
	}
	if strings.Contains(markup, `class="cluster-update-status"`) || !strings.Contains(markup, `cluster-update-version current`) || !strings.Contains(markup, `icon-check`) {
		t.Fatal("completed rollout should indicate success in its version badge without a redundant status heading")
	}
	for _, expected := range []string{`hx-post="/ui/updates/command-check"`, `icon-refresh`, `Check again`, `button outline compact`} {
		if !strings.Contains(markup, expected) {
			t.Fatalf("missing compact update check: %q", expected)
		}
	}
}

func TestClusterUpdatesRefreshInSidebarWithSharedReleaseNotes(t *testing.T) {
	view := ClusterPageView{Initialized: true, Update: ClusterUpdateView{
		Supported: true, CanApply: true, Version: "1.2.0",
		Release: UpdateView{LatestVersion: "1.2.0", ReleaseNotes: "### Improvements\n\n- Faster DNS", ReleaseURL: "https://github.com/drudge/sable/releases/tag/v1.2.0"},
	}}
	var response bytes.Buffer
	if err := ClusterContent(view).Render(context.Background(), &response); err != nil {
		t.Fatal(err)
	}
	markup := response.String()
	aside, updates, local := strings.Index(markup, `<aside`), strings.Index(markup, `id="cluster-updates"`), strings.Index(markup, `class="card cluster-details"`)
	if aside < 0 || updates < aside || local < updates || strings.Count(markup, `id="cluster-updates"`) != 1 {
		t.Fatal("rolling updates must appear once, in the sidebar before Local Node")
	}
	if strings.Contains(markup, "hx-swap-oob") {
		t.Fatal("initial page should render its sidebar directly")
	}
	for _, supported := range []bool{true, false, true} {
		view.Update.Supported = supported
		response.Reset()
		if err := ClusterLiveStatusUpdate(view).Render(context.Background(), &response); err != nil {
			t.Fatal(err)
		}
		markup = response.String()
		if !strings.Contains(markup, `id="cluster-live-status"`) || !strings.Contains(markup, `id="cluster-updates"`) || !strings.Contains(markup, `hx-swap-oob="outerHTML"`) {
			t.Fatal("live response must refresh both the main column and stable sidebar target")
		}
		if strings.Contains(markup, `class="card cluster-update-card"`) != supported || strings.Contains(markup, `data-dialog-open="cluster-release-notes-dialog"`) != supported {
			t.Fatal("card and release notes must follow cluster support")
		}
		if supported && (!strings.Contains(markup, `<h3>Improvements</h3>`) || !strings.Contains(markup, `class="custom-server-dialog update-release-dialog"`)) {
			t.Fatal("cluster notes must use the shared Markdown release dialog")
		}
		if !supported && !strings.Contains(markup, `id="cluster-updates" hidden`) {
			t.Fatal("unsupported cluster must keep a hidden target for future refreshes")
		}
	}
}
