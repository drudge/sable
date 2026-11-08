//go:build integration

package clusterfault

import (
	"testing"
	"time"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/clustertest"
	"github.com/drudge/sable/internal/faultinject"
)

const (
	// skew is past the 30s window a node accepts heartbeat timestamps in
	// (heartbeatClockSkew), so a skewed member's heartbeats are refused until
	// its clock comes back.
	skew = 45 * time.Second
	// fastClock is inside that window, so a member running this far ahead
	// keeps synchronizing.
	fastClock = 20 * time.Second
	// resumeWithin is how soon synchronization must resume once a clock is
	// set right: two heartbeat freshness windows (heartbeatFreshness).
	resumeWithin = 10 * time.Second
)

// TestReplicaClockSkewRecovers skews a replica's clock ahead and behind
// until the primary drops it, takes writes, then sets the clock right; the
// replica must catch up on every write.
func TestReplicaClockSkewRecovers(t *testing.T) {
	for _, offset := range []time.Duration{skew, -skew} {
		t.Run(offset.String(), func(t *testing.T) {
			faultCluster := startCluster(t, 3)
			checks, records := newInvariants(), &ledger{}
			replica := faultCluster.members[1]
			replica.setFaults(t, faultinject.Faults{ClockOffset: offset})
			waitDropped(t, faultCluster)
			writeAndObserve(t, faultCluster, checks, records, 3)
			replica.setFaults(t, faultinject.Faults{})
			checks.converged(t, faultCluster, records)
		})
	}
}

// TestPrimaryClockSkewRecovers skews the primary's clock until it drops its
// replicas, takes writes, then sets it right; every replica must converge.
func TestPrimaryClockSkewRecovers(t *testing.T) {
	for _, offset := range []time.Duration{skew, -skew} {
		t.Run(offset.String(), func(t *testing.T) {
			faultCluster := startCluster(t, 3)
			checks, records := newInvariants(), &ledger{}
			faultCluster.members[0].setFaults(t, faultinject.Faults{ClockOffset: offset})
			if offset > 0 {
				// A primary set back can't be seen dropping replicas: the
				// offset moves its monotonic clock too, so heartbeats it
				// already holds look fresh for the size of the step.
				waitDropped(t, faultCluster)
			}
			writeAndObserve(t, faultCluster, checks, records, 3)
			faultCluster.members[0].setFaults(t, faultinject.Faults{})
			checks.converged(t, faultCluster, records)
		})
	}
}

// TestPrimaryClockStepBackKeepsSynchronizing runs the primary's clock fast,
// then steps it back to true time, as NTP does to a clock that ran ahead.
func TestPrimaryClockStepBackKeepsSynchronizing(t *testing.T) {
	stepClockBack(t, 0)
}

// TestReplicaClockStepBackKeepsSynchronizing is the same step on a replica.
func TestReplicaClockStepBackKeepsSynchronizing(t *testing.T) {
	stepClockBack(t, 1)
}

// stepClockBack runs one member's clock fastClock ahead until the cluster
// converges, steps it back to true time, and requires synchronization to
// resume within resumeWithin and every write to converge.
func stepClockBack(t *testing.T, index int) {
	t.Helper()
	faultCluster := startCluster(t, 3)
	checks, records := newInvariants(), &ledger{}
	node := faultCluster.members[index]
	node.setFaults(t, faultinject.Faults{ClockOffset: fastClock})
	writeAndObserve(t, faultCluster, checks, records, 2)
	checks.converged(t, faultCluster, records)
	node.setFaults(t, faultinject.Faults{})
	writeAndObserve(t, faultCluster, checks, records, 2)
	requireConvergedWithin(t, faultCluster, records, resumeWithin)
	checks.converged(t, faultCluster, records)
}

// waitDropped waits until the primary no longer counts every running member
// synchronized, which shows a fault is in force.
func waitDropped(t *testing.T, faultCluster *faultCluster) {
	t.Helper()
	primary, want := faultCluster.primary(), len(faultCluster.running())
	clustertest.WaitForClusterState(t, primary.node, primary.client, primary.ports.HTTPS, func(state cluster.State) bool {
		return state.Synchronized < want
	})
}

// requireConvergedWithin fails the test unless every running member is
// synchronized and serves every acknowledged write within limit.
func requireConvergedWithin(t *testing.T, faultCluster *faultCluster, records *ledger, limit time.Duration) {
	t.Helper()
	running := faultCluster.running()
	var states []cluster.State
	for deadline := time.Now().Add(limit); time.Now().Before(deadline); time.Sleep(clustertest.PollingInterval) {
		states = states[:0]
		for _, node := range running {
			states = append(states, node.state(t))
		}
		if synchronized(states, len(running)) && settled(t, faultCluster, records) {
			return
		}
	}
	t.Fatalf("cluster did not converge within %s: %+v", limit, states)
}
