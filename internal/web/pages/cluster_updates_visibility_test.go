package pages

import (
	"context"
	"strings"
	"testing"
)

func TestUnsupportedRollingUpdatesRemainVisibleInCluster(t *testing.T) {
	var html strings.Builder
	view := ClusterUpdateView{Initialized: true, UnavailableReason: "replica-2: automatic restart unavailable"}
	if err := ClusterUpdatePanel(view, false).Render(context.Background(), &html); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Rolling Updates", view.UnavailableReason, "disabled", "Update all"} {
		if !strings.Contains(html.String(), expected) {
			t.Fatalf("missing %q", expected)
		}
	}
	if strings.Contains(html.String(), `id="cluster-updates" hidden`) || strings.Contains(html.String(), `id="cluster-update-start"`) {
		t.Fatal("unsupported section hidden or start action enabled")
	}
	if (ClusterUpdateView{}).Visible() {
		t.Fatal("standalone unsupported panel should remain hidden")
	}
}
