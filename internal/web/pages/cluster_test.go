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
