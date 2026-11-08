package cluster

import (
	"context"
	"testing"
	"time"
)

func TestGenerationHistorySettlesOnWhatTheAllowanceAgoHeld(t *testing.T) {
	start := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	var history generationHistory
	if got := history.settled(start, 7, rolloutLagAllowance); got != 7 {
		t.Fatalf("settled with no history = %d, want the current 7", got)
	}
	for second := range 10 {
		history.record(start.Add(time.Duration(second)*time.Second), uint64(second+1))
	}
	now := start.Add(9 * time.Second)
	// Generation 5 was reached at 4s, the newest sample at or before 9s-5s.
	if got := history.settled(now, 10, rolloutLagAllowance); got != 5 {
		t.Fatalf("settled = %d, want 5", got)
	}
	// Generation 8 was reached at 7s, the newest sample at or before 9s-2s.
	if got := history.settled(now, 10, primaryRestartLagAllowance); got != 8 {
		t.Fatalf("settled with the primary restart allowance = %d, want 8", got)
	}
	if len(history.samples) != 6 {
		t.Fatalf("kept %d samples, want 6 (4s through 9s)", len(history.samples))
	}
	if got := history.settled(now, 3, rolloutLagAllowance); got != 3 {
		t.Fatalf("settled past current = %d, want the current 3", got)
	}
}

// Under steady writes a replica is usually a generation behind (#594). A
// rollout keeps going while every node has applied what the primary
// published rolloutLagAllowance ago, and waits on one that has not.
func TestRestartWaitsOnlyForANodeThatIsNotKeepingUp(t *testing.T) {
	for _, test := range []struct {
		name       string
		authorized bool
		history    func(now time.Time, generation uint64) []generationSample
	}{
		{
			name: "behind on a generation published a second ago", authorized: true,
			history: func(now time.Time, generation uint64) []generationSample {
				return []generationSample{{now.Add(-10 * time.Second), generation - 1}, {now.Add(-time.Second), generation}}
			},
		},
		{
			name: "behind on a generation published three seconds ago", authorized: true,
			history: func(now time.Time, generation uint64) []generationSample {
				return []generationSample{{now.Add(-10 * time.Second), generation - 1}, {now.Add(-3 * time.Second), generation}}
			},
		},
		{
			name: "behind on a generation published ten seconds ago", authorized: false,
			history: func(now time.Time, generation uint64) []generationSample {
				return []generationSample{{now.Add(-10 * time.Second), generation}}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRolloutFixture(t, 2)
			primary := fixture.nodes[0]
			if err := primary.StartRollout(context.Background(), "1.1.0"); err != nil {
				t.Fatal(err)
			}
			for range 12 {
				fixture.tick(t)
				if primary.RolloutStatus().Nodes[0].Phase == "restart" {
					break
				}
			}
			if primary.RolloutStatus().Nodes[0].Phase != "restart" {
				t.Fatal("fixture did not reach restart authorization")
			}
			other := fixture.nodes[2]
			observed := primary.telemetry[other.nodeID]
			observed.heartbeat.AppliedGeneration = primary.manifest.Generation - 1
			primary.telemetry[other.nodeID] = observed
			primary.updates.mu.Lock()
			primary.updates.generations.samples = test.history(time.Now(), primary.manifest.Generation)
			primary.updates.mu.Unlock()
			if command := primary.updateCommand(fixture.nodes[1].nodeID); (command != nil) != test.authorized {
				t.Fatalf("restart command = %+v, want authorized %t", command, test.authorized)
			}
		})
	}
}

// The primary restarts in place, so if it does not come back a recovery
// promotion keeps only what a replica applied. Its restart waits until peers
// hold what it published primaryRestartLagAllowance ago, keeping the loss
// window at about the last second (docs/clustering.md).
func TestPrimaryRestartWaitsForPeersWithinTheLossWindow(t *testing.T) {
	for _, test := range []struct {
		name       string
		published  time.Duration
		authorized bool
	}{
		{name: "replica behind on a generation published a second ago", published: time.Second, authorized: true},
		{name: "replica behind on a generation published three seconds ago", published: 3 * time.Second, authorized: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRolloutFixture(t, 2)
			primary := fixture.nodes[0]
			if err := primary.StartRollout(context.Background(), "1.1.0"); err != nil {
				t.Fatal(err)
			}
			for index := 1; index <= 2; index++ {
				for range 15 {
					fixture.tick(t)
				}
				fixture.restart(t, index, "1.1.0")
			}
			for range 15 {
				fixture.tick(t)
			}
			last := len(primary.RolloutStatus().Nodes) - 1
			if node := primary.RolloutStatus().Nodes[last]; node.ID != primary.nodeID || node.Phase != "restart" {
				t.Fatalf("fixture did not reach the primary's restart: %+v", primary.RolloutStatus())
			}
			other := fixture.nodes[2]
			observed := primary.telemetry[other.nodeID]
			observed.heartbeat.AppliedGeneration = primary.manifest.Generation - 1
			primary.telemetry[other.nodeID] = observed
			// The primary applied its own restart in the same tick, which
			// marked the rollout restarting; ask again as of just before.
			primary.updates.mu.Lock()
			now := time.Now()
			primary.updates.rollout.Phase = RolloutUpdating
			primary.updates.generations.samples = []generationSample{{now.Add(-10 * time.Second), primary.manifest.Generation - 1}, {now.Add(-test.published), primary.manifest.Generation}}
			primary.updates.mu.Unlock()
			command := primary.updateCommand(primary.nodeID)
			if authorized := command != nil && command.Action == actionRestart; authorized != test.authorized {
				t.Fatalf("primary restart command = %+v, want authorized %t", command, test.authorized)
			}
		})
	}
}
