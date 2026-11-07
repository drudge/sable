package cluster

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

var (
	allRolloutPhases     = []RolloutPhase{RolloutPreparing, RolloutUpdating, RolloutRestarting, RolloutVerifying, RolloutComplete, RolloutFailed, RolloutStopped}
	allRolloutNodePhases = []RolloutNodePhase{RolloutNodeQueued, RolloutNodeInstalling, RolloutNodeRestarting, RolloutNodeComplete}
	allNodePhases        = []NodePhase{"", nodePrepared, nodeInstalling, nodeInstalled, nodeRestarting, nodeComplete, nodeFailed}
)

// The phase strings are saved in update-rollout.json and node-update.json and
// travel between releases, so they must never change.
func TestUpdatePhasesKeepTheirSavedValues(t *testing.T) {
	want := []string{"preparing", "updating", "restarting", "verifying", "complete", "failed", "stopped"}
	for i, phase := range allRolloutPhases {
		if string(phase) != want[i] {
			t.Fatalf("rollout phase %d = %q, want %q", i, phase, want[i])
		}
	}
	if got := []string{string(RolloutNodeQueued), string(RolloutNodeInstalling), string(RolloutNodeRestarting), string(RolloutNodeComplete)}; !slices.Equal(got, []string{"queued", "install", "restart", "complete"}) {
		t.Fatalf("rollout node phases = %v", got)
	}
	if got := []string{string(nodePrepared), string(nodeInstalling), string(nodeInstalled), string(nodeRestarting), string(nodeComplete), string(nodeFailed)}; !slices.Equal(got, []string{"prepared", "installing", "installed", "restarting", "complete", "failed"}) {
		t.Fatalf("node phases = %v", got)
	}
	if got := []string{string(actionPrepare), string(actionInstall), string(actionRestart), string(actionRelease)}; !slices.Equal(got, []string{"prepare", "install", "restart", "release"}) {
		t.Fatalf("actions = %v", got)
	}
	encoded, err := json.Marshal(RolloutStatus{Phase: RolloutRestarting, Nodes: []RolloutNode{{Phase: RolloutNodeInstalling}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"phase":"restarting"`) || !strings.Contains(string(encoded), `"phase":"install"`) {
		t.Fatalf("encoded rollout = %s", encoded)
	}
}

func TestRolloutPhaseTransitions(t *testing.T) {
	legal := map[RolloutPhase][]RolloutPhase{
		RolloutPreparing:  {RolloutUpdating, RolloutFailed, RolloutStopped},
		RolloutUpdating:   {RolloutRestarting, RolloutVerifying, RolloutFailed, RolloutStopped},
		RolloutRestarting: {RolloutVerifying, RolloutFailed, RolloutStopped},
		RolloutVerifying:  {RolloutComplete, RolloutFailed, RolloutStopped},
	}
	for _, from := range allRolloutPhases {
		if from.Active() != (legal[from] != nil) {
			t.Errorf("%s.Active() = %t", from, from.Active())
		}
		for _, to := range allRolloutPhases {
			want := from == to || slices.Contains(legal[from], to)
			if got := from.CanMoveTo(to); got != want {
				t.Errorf("%s -> %s = %t, want %t", from, to, got, want)
			}
		}
	}
	if RolloutPhase("unknown").Active() || RolloutPhase("unknown").CanMoveTo(RolloutComplete) {
		t.Fatal("an unknown phase is running")
	}
}

func TestRolloutNodePhaseTransitionsAndActions(t *testing.T) {
	legal := map[RolloutNodePhase][]RolloutNodePhase{
		RolloutNodeQueued:     {RolloutNodeInstalling, RolloutNodeComplete},
		RolloutNodeInstalling: {RolloutNodeRestarting, RolloutNodeComplete},
		RolloutNodeRestarting: {RolloutNodeComplete},
	}
	for _, from := range allRolloutNodePhases {
		for _, to := range allRolloutNodePhases {
			if got, want := from.CanMoveTo(to), slices.Contains(legal[from], to); got != want {
				t.Errorf("%s -> %s = %t, want %t", from, to, got, want)
			}
		}
	}
	actions := map[RolloutNodePhase]UpdateAction{RolloutNodeQueued: actionPrepare, RolloutNodeInstalling: actionInstall, RolloutNodeRestarting: actionRestart}
	for _, phase := range append(allRolloutNodePhases, "unknown") {
		action, ok := phase.Action()
		if want, sends := actions[phase]; action != want || ok != sends {
			t.Errorf("%s.Action() = %q, %t", phase, action, ok)
		}
	}
}

func TestNodePhaseTransitions(t *testing.T) {
	legal := map[NodePhase][]NodePhase{
		"":             {nodePrepared, nodeFailed},
		nodePrepared:   {nodeInstalling, nodeFailed},
		nodeInstalling: {nodeInstalled, nodeFailed},
		nodeInstalled:  {nodeRestarting, nodeFailed},
		nodeRestarting: {nodeFailed},
	}
	for _, from := range allNodePhases {
		for _, to := range allNodePhases {
			if got, want := from.CanMoveTo(to), slices.Contains(legal[from], to); got != want {
				t.Errorf("%q -> %q = %t, want %t", from, to, got, want)
			}
		}
	}
}

func TestSaveRolloutRefusesIllegalMoves(t *testing.T) {
	fixture := newRolloutFixture(t, 1)
	primary := fixture.nodes[0]
	if err := primary.StartRollout(context.Background(), "1.1.0"); err != nil {
		t.Fatal(err)
	}
	primary.updates.mu.Lock()
	defer primary.updates.mu.Unlock()
	started := primary.updates.rollout
	for name, change := range map[string]func(*RolloutStatus){
		"skip to complete":           func(rollout *RolloutStatus) { rollout.Phase = RolloutComplete },
		"restart before updating":    func(rollout *RolloutStatus) { rollout.Phase = RolloutRestarting },
		"node skips install":         func(rollout *RolloutStatus) { rollout.Nodes[0].Phase = RolloutNodeRestarting },
		"new rollout already ended":  func(rollout *RolloutStatus) { rollout.ID, rollout.Phase = "other", RolloutComplete },
		"new rollout with node done": func(rollout *RolloutStatus) { rollout.ID, rollout.Nodes[0].Phase = "other", RolloutNodeComplete },
	} {
		next := started
		next.Nodes = slices.Clone(started.Nodes)
		change(&next)
		if err := primary.saveRollout(next); err == nil {
			t.Errorf("%s: saved", name)
		}
		if primary.updates.rollout.Phase != RolloutPreparing || primary.updates.rollout.Nodes[0].Phase != RolloutNodeQueued {
			t.Fatalf("%s: rollout changed to %+v", name, primary.updates.rollout)
		}
	}
	stopped := started
	stopped.Phase = RolloutStopped
	if err := primary.saveRollout(stopped); err != nil {
		t.Fatal(err)
	}
	stopped.Phase = RolloutUpdating
	if err := primary.saveRollout(stopped); err == nil {
		t.Fatal("a stopped rollout started again")
	}
}

// Before, advanceRollout treated any phase it did not name as updating. A
// phase no release knows is not running, so it neither advances nor sends a
// node anything but a release.
func TestUnknownRolloutPhaseNeverAdvances(t *testing.T) {
	fixture := newRolloutFixture(t, 1)
	primary := fixture.nodes[0]
	if err := primary.StartRollout(context.Background(), "1.1.0"); err != nil {
		t.Fatal(err)
	}
	primary.updates.mu.Lock()
	primary.updates.rollout.Phase = "rebooting"
	primary.updates.mu.Unlock()
	for range 10 {
		fixture.tick(t)
	}
	for i, updater := range fixture.updaters {
		if len(updater.installs) != 0 || updater.reserved != "" {
			t.Fatalf("node %d acted on an unknown phase: %+v", i, updater)
		}
	}
	if command := primary.updateCommand(fixture.nodes[1].nodeID); command == nil || command.Action != actionRelease {
		t.Fatalf("command = %+v", command)
	}
	if status := primary.RolloutStatus(); status.Phase != "rebooting" || status.Active() {
		t.Fatalf("rollout = %+v", status)
	}
}
