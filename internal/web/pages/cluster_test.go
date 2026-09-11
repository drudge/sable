package pages

import (
	"bytes"
	"context"
	"strings"
	"testing"
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
