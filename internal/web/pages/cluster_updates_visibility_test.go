package pages

import (
	"context"
	"strings"
	"testing"
)

func TestUnsupportedRollingUpdatesRemainVisibleInCluster(t *testing.T) {
	var html strings.Builder
	view := ClusterUpdateView{Initialized: true, UnavailableReason: "replica-2: automatic restart unavailable", Release: UpdateView{CanCheck: true}}
	if err := ClusterUpdatePanel(view, false).Render(context.Background(), &html); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Rolling Updates", view.UnavailableReason, "warning-box", "icon-alert-triangle"} {
		if !strings.Contains(html.String(), expected) {
			t.Fatalf("missing %q", expected)
		}
	}
	if strings.Contains(html.String(), `id="cluster-updates" hidden`) || strings.Contains(html.String(), "<button") {
		t.Fatal("unsupported section hidden or start action enabled")
	}
	if (ClusterUpdateView{}).Visible() {
		t.Fatal("standalone unsupported panel should remain hidden")
	}
}
