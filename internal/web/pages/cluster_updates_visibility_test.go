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

// The panel tells the page whether a rollout is running, what it installs,
// and which server process rendered it, so the page can reload once a rollout
// that restarted its server is over.
func TestRollingUpdatePanelTellsThePageWhenToReload(t *testing.T) {
	var html strings.Builder
	view := ClusterUpdateView{Initialized: true, InstanceID: "m3k9", Rollout: cluster.RolloutStatus{ID: "rollout", Version: "1.2.0", Phase: "complete"}}
	if err := ClusterUpdatePanel(view, true).Render(context.Background(), &html); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`data-rollout-id="rollout"`, `data-rollout-active="false"`, `data-rollout-phase="complete"`,
		`data-rollout-version="v1.2.0"`, `data-instance-id="m3k9"`,
	} {
		if !strings.Contains(html.String(), expected) {
			t.Errorf("panel is missing %s", expected)
		}
	}
}

// The status poll redraws the panel every two seconds. A check in progress
// keeps its button, shown as checking, instead of blinking out of the card.
func TestRollingUpdateCheckStaysVisibleWhileChecking(t *testing.T) {
	var html strings.Builder
	view := ClusterUpdateView{
		Initialized: true, Supported: true, CanApply: true,
		Release: UpdateView{CanCheck: true, Checked: true, Busy: true, Phase: "checking"},
		Rollout: cluster.RolloutStatus{ID: "rollout", Version: "1.2.0", Phase: "complete"},
	}
	if err := ClusterUpdatePanel(view, true).Render(context.Background(), &html); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`id="cluster-update-check"`, `aria-busy="true"`, "disabled"} {
		if !strings.Contains(html.String(), expected) {
			t.Errorf("checking panel is missing %s", expected)
		}
	}

	html.Reset()
	view.Release.Phase = "installing"
	if err := ClusterUpdatePanel(view, true).Render(context.Background(), &html); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html.String(), `id="cluster-update-check"`) {
		t.Error("an installation still offered a release check")
	}
}

// A running rollout marks its version as the one being installed, not the
// one the cluster already runs.
func TestRollingUpdateVersionShowsInstallTarget(t *testing.T) {
	var html strings.Builder
	view := ClusterUpdateView{Initialized: true, CanApply: true, Rollout: cluster.RolloutStatus{
		ID: "rollout", Version: "1.2.0", Phase: "updating",
		Nodes: []cluster.RolloutNode{{Name: "replica-2", Phase: "installing"}},
	}}
	if err := ClusterUpdatePanel(view, false).Render(context.Background(), &html); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"cluster-update-version installing", "Updating to ", "v1.2.0"} {
		if !strings.Contains(html.String(), expected) {
			t.Errorf("rollout badge is missing %q", expected)
		}
	}
}

// A rollout that failed says so in red. One an operator stopped is a
// warning, not a failure, so it says so in amber.
func TestRollingUpdateEndingIsRedOrAmber(t *testing.T) {
	for phase, want := range map[string]string{
		"failed":  `<div class="unifi-status error" role="alert">`,
		"stopped": `<div class="unifi-status warning" role="status">`,
	} {
		var html strings.Builder
		view := ClusterUpdateView{Initialized: true, CanApply: true, Rollout: cluster.RolloutStatus{ID: "rollout", Version: "v1.2.0", Phase: phase, Error: "replica-2 did not come back."}}
		if err := ClusterUpdatePanel(view, false).Render(context.Background(), &html); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(html.String(), want) || !strings.Contains(html.String(), "replica-2 did not come back.") {
			t.Errorf("a %s rollout does not show %s: %s", phase, want, html.String())
		}
	}
}
