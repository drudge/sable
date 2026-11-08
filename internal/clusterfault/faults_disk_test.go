//go:build integration

package clusterfault

import (
	"testing"
	"time"

	"github.com/drudge/sable/internal/clustertest"
	"github.com/drudge/sable/internal/faultinject"
)

// holdFor is how long a held-back member must stay behind: several
// synchronization intervals.
const holdFor = 3 * time.Second

// TestReplicaDiskFullRecovers fills a replica's disk while the primary takes
// writes, then frees it; the replica must catch up on every write.
func TestReplicaDiskFullRecovers(t *testing.T) {
	cluster := startCluster(t, 3)
	checks, records := newInvariants(), &ledger{}
	replica := cluster.members[1]
	replica.setFaults(t, faultinject.Faults{DiskFull: true})
	writeAndObserve(t, cluster, checks, records, 3)
	requireHeldBack(t, cluster, replica)
	replica.setFaults(t, faultinject.Faults{})
	checks.converged(t, cluster, records)
}

// TestPrimaryDiskFullRecovers fills the primary's disk during writes. Writes
// it can't store must be refused, not acknowledged; once the disk is freed,
// writes go through again and every node converges.
func TestPrimaryDiskFullRecovers(t *testing.T) {
	cluster := startCluster(t, 3)
	checks, records := newInvariants(), &ledger{}
	writeAndObserve(t, cluster, checks, records, 2)
	primary := cluster.members[0]
	primary.setFaults(t, faultinject.Faults{DiskFull: true})
	for range 3 {
		if records.write(primary) {
			t.Errorf("primary acknowledged ledger write %d with a full disk", records.attempted)
		}
		checks.observe(t, cluster)
	}
	primary.setFaults(t, faultinject.Faults{})
	writeAndObserve(t, cluster, checks, records, 2)
	checks.converged(t, cluster, records)
}

// requireHeldBack waits for the primary to move past node's generation, then
// fails the test if node catches up within holdFor: the fault on it must stop
// it applying changes.
func requireHeldBack(t *testing.T, cluster *faultCluster, node *member) {
	t.Helper()
	primary := cluster.primary()
	behind := func() bool { return node.state(t).Generation < primary.state(t).Generation }
	clustertest.WaitForCondition(t, primary.node, behind)
	for deadline := time.Now().Add(holdFor); time.Now().Before(deadline); time.Sleep(clustertest.PollingInterval) {
		if !behind() {
			t.Fatalf("%s caught up with the primary while its fault was in force", node.name)
		}
	}
}
