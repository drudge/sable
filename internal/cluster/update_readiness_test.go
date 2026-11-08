package cluster

import (
	"context"
	"testing"
	"time"
)

func TestGenerationHistorySettlesOnWhatTheAllowanceAgoHeld(t *testing.T) {
	start := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	var history generationHistory
	if got := history.settled(start, 7); got != 7 {
		t.Fatalf("settled with no history = %d, want the current 7", got)
	}
	for second := range 10 {
		history.record(start.Add(time.Duration(second)*time.Second), uint64(second+1))
	}
	now := start.Add(9 * time.Second)
	// Generation 5 was reached at 4s, the newest sample at or before 9s-5s.
	if got := history.settled(now, 10); got != 5 {
		t.Fatalf("settled = %d, want 5", got)
	}
	if len(history.samples) != 6 {
		t.Fatalf("kept %d samples, want 6 (4s through 9s)", len(history.samples))
	}
	if got := history.settled(now, 3); got != 3 {
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
