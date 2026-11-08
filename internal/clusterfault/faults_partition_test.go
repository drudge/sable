//go:build integration

package clusterfault

import (
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/clustertest"
	"github.com/drudge/sable/internal/faultinject"
)

// TestIsolatedPrimaryIsReplacedAndFencedOnHeal cuts the primary off from
// both replicas, promotes one of them for recovery, and heals the partition.
// The old primary must step down to the newer term (#529) and converge, and
// a write it took while cut off is discarded, as docs/clustering.md says.
func TestIsolatedPrimaryIsReplacedAndFencedOnHeal(t *testing.T) {
	faults := startCluster(t, 3)
	checks, records := newInvariants(), &ledger{}
	writeAndObserve(t, faults, checks, records, 3)
	checks.converged(t, faults, records)
	old, successor := faults.members[0], faults.members[1]
	term := old.state(t).Term
	heal := partition(t, faults, old)
	waitDropped(t, faults)
	successor.promote(t)
	waitRole(t, successor, cluster.RolePrimary, term)
	writeThroughAndObserve(t, faults, successor, checks, records, 3)
	stale := strandedWrite(t, old)
	checks.observe(t, faults)
	heal()
	waitRole(t, old, cluster.RoleReplica, term)
	checks.converged(t, faults, records)
	requireAbsent(t, faults, stale)
}

// TestMinorityPartitionStepsDownOnHeal splits five nodes into the primary
// with one replica and a majority of three, promotes a primary in the
// majority, and takes writes on both sides. On heal the minority must follow
// the majority's newer term and keep none of its own writes.
func TestMinorityPartitionStepsDownOnHeal(t *testing.T) {
	knownBug(t, "drudge/sable#588")
	faults := startCluster(t, 5)
	checks, records := newInvariants(), &ledger{}
	writeAndObserve(t, faults, checks, records, 2)
	checks.converged(t, faults, records)
	old, follower, successor := faults.members[0], faults.members[1], faults.members[2]
	term := old.state(t).Term
	heal := partition(t, faults, old, follower)
	successor.promote(t)
	waitRole(t, successor, cluster.RolePrimary, term)
	for _, replica := range faults.members[3:] {
		waitFollowing(t, replica, successor)
	}
	writeThroughAndObserve(t, faults, successor, checks, records, 3)
	stale := strandedWrite(t, old)
	checks.observe(t, faults)
	heal()
	waitRole(t, old, cluster.RoleReplica, term)
	waitFollowing(t, follower, successor)
	checks.converged(t, faults, records)
	requireAbsent(t, faults, stale)
}

// TestRecoveryPromotionRedirectsReplicas kills the primary for good and
// promotes a replica for recovery: the other replica must follow it without
// the former primary ever coming back.
func TestRecoveryPromotionRedirectsReplicas(t *testing.T) {
	knownBug(t, "drudge/sable#588")
	faults := startCluster(t, 3)
	checks, records := newInvariants(), &ledger{}
	writeAndObserve(t, faults, checks, records, 2)
	checks.converged(t, faults, records)
	old, successor := faults.members[0], faults.members[1]
	term := old.state(t).Term
	old.kill(t)
	successor.promote(t)
	waitRole(t, successor, cluster.RolePrimary, term)
	waitFollowing(t, faults.members[2], successor)
	writeAndObserve(t, faults, checks, records, 2)
	checks.converged(t, faults, records)
}

// TestReplicaPartitionedFromPrimaryCatchesUp cuts one replica off both ways
// while the primary keeps taking writes; after the heal it must catch up.
func TestReplicaPartitionedFromPrimaryCatchesUp(t *testing.T) {
	faults := startCluster(t, 3)
	checks, records := newInvariants(), &ledger{}
	writeAndObserve(t, faults, checks, records, 2)
	heal := partition(t, faults, faults.members[2])
	waitDropped(t, faults)
	writeAndObserve(t, faults, checks, records, 3)
	requireHeldBack(t, faults, faults.members[2])
	heal()
	requireConvergedWithin(t, faults, records, 10*time.Second)
	checks.converged(t, faults, records)
}

// TestPrimaryCutToReplicaKeepsReplicating cuts only the primary's own
// connections to a replica. Replicas pull from the primary, so the replica
// must keep up while the primary's fencing probes to it fail.
func TestPrimaryCutToReplicaKeepsReplicating(t *testing.T) {
	faults := startCluster(t, 3)
	checks, records := newInvariants(), &ledger{}
	writeAndObserve(t, faults, checks, records, 2)
	primary, replica := faults.members[0], faults.members[2]
	primary.setFaults(t, faultinject.Faults{Unreachable: []string{replica.ports.HTTPS}})
	writeAndObserve(t, faults, checks, records, 3)
	requireConvergedWithin(t, faults, records, 10*time.Second)
	primary.setFaults(t, faultinject.Faults{})
	checks.converged(t, faults, records)
}

// TestReplicaCutToPrimaryCatchesUp cuts only a replica's connections to the
// primary: it can neither pull nor report in, so it falls behind, and it
// must catch up once the cut heals.
func TestReplicaCutToPrimaryCatchesUp(t *testing.T) {
	faults := startCluster(t, 3)
	checks, records := newInvariants(), &ledger{}
	writeAndObserve(t, faults, checks, records, 2)
	primary, replica := faults.members[0], faults.members[2]
	replica.setFaults(t, faultinject.Faults{Unreachable: []string{primary.ports.HTTPS}})
	waitDropped(t, faults)
	writeAndObserve(t, faults, checks, records, 3)
	requireHeldBack(t, faults, replica)
	replica.setFaults(t, faultinject.Faults{})
	requireConvergedWithin(t, faults, records, 10*time.Second)
	checks.converged(t, faults, records)
}

// partition cuts every connection between group and the rest of the
// cluster, both ways, and returns a function that heals it.
func partition(t *testing.T, faults *faultCluster, group ...*member) func() {
	t.Helper()
	var inside, outside []string
	for _, node := range faults.members {
		if slices.Contains(group, node) {
			inside = append(inside, node.ports.HTTPS)
		} else {
			outside = append(outside, node.ports.HTTPS)
		}
	}
	for _, node := range faults.members {
		unreachable := inside
		if slices.Contains(group, node) {
			unreachable = outside
		}
		node.setFaults(t, faultinject.Faults{Unreachable: unreachable})
	}
	return func() {
		t.Helper()
		for _, node := range faults.members {
			node.setFaults(t, faultinject.Faults{})
		}
	}
}

// writeThroughAndObserve makes count acknowledged writes through node, which
// faults.primary may not pick while two nodes think they are primary.
func writeThroughAndObserve(t *testing.T, faults *faultCluster, node *member, checks *invariants, records *ledger, count int) {
	t.Helper()
	for range count {
		if !records.write(node) {
			t.Fatalf("%s refused ledger write %d", node.name, records.attempted)
		}
		checks.observe(t, faults)
	}
}

// strandedWrite adds a record through a primary that has been replaced but
// can't know it yet, outside the ledger, and returns its name.
func strandedWrite(t *testing.T, node *member) string {
	t.Helper()
	const name = "stranded"
	status, err := node.postForm("/ui/zones/records/add", url.Values{
		"zone": {ledgerZone}, "name": {name}, "type": {"A"}, "value": {"203.0.113.1"}, "ttl": {"60"},
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("%s refused the stranded write = %d: %v", node.name, status, err)
	}
	return name
}

// requireAbsent fails the test if any running node answers for name.
func requireAbsent(t *testing.T, faults *faultCluster, name string) {
	t.Helper()
	for _, node := range faults.running() {
		if got := resolveA(node, name+"."+ledgerZone); got != "" {
			t.Errorf("%s kept the stranded write %s: answered %q", node.name, name, got)
		}
	}
}

// waitFollowing waits until node reports leader as its primary.
func waitFollowing(t *testing.T, node, leader *member) {
	t.Helper()
	clustertest.WaitForClusterState(t, node.node, node.client, node.ports.HTTPS, func(state cluster.State) bool {
		return state.LocalRole == cluster.RoleReplica && state.PrimaryID == leader.id
	})
}
