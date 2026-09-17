package pages

import (
	"context"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/cluster"
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

func TestActiveRollingUpdateHidesTransientUnavailableWarning(t *testing.T) {
	var html strings.Builder
	view := ClusterUpdateView{
		Initialized:       true,
		UnavailableReason: "Waiting for update capability information from replica-2.",
		CanApply:          true,
		Rollout: cluster.RolloutStatus{
			ID: "rollout", Version: "v1.2.0", Phase: "restarting",
			Nodes: []cluster.RolloutNode{{Name: "replica-2", Phase: "restarting"}},
		},
	}
	if err := ClusterUpdatePanel(view, false).Render(context.Background(), &html); err != nil {
		t.Fatal(err)
	}
	markup := html.String()
	if strings.Contains(markup, "Rolling updates unavailable") || strings.Contains(markup, view.UnavailableReason) {
		t.Fatalf("active rollout showed a transient capability warning: %s", markup)
	}
	for _, expected := range []string{"Restarting", `id="cluster-update-stop"`, `data-state="restarting"`} {
		if !strings.Contains(markup, expected) {
			t.Fatalf("active rollout lost %q while capability was renegotiated: %s", expected, markup)
		}
	}
}
