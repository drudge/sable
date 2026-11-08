//go:build integration

package clusterfault

import (
	"net/http"
	"testing"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/clustertest"
)

// TestPrimaryKillPromoteAndRestartFencesTheOldPrimary kills the primary
// without warning once its writes have replicated, promotes a replica for
// recovery, and restarts the old primary, which must step down to the newer
// term (#529) and take the new primary's data.
func TestPrimaryKillPromoteAndRestartFencesTheOldPrimary(t *testing.T) {
	faults := startCluster(t, 3)
	checks, records := newInvariants(), &ledger{}
	writeAndObserve(t, faults, checks, records, 3)
	checks.converged(t, faults, records)
	old, successor := faults.members[0], faults.members[1]
	term := old.state(t).Term
	old.kill(t)
	successor.promote(t)
	waitRole(t, successor, cluster.RolePrimary, term)
	writeAndObserve(t, faults, checks, records, 3)
	old.start(t)
	checks.observe(t, faults)
	waitRole(t, old, cluster.RoleReplica, term)
	checks.converged(t, faults, records)
}

// TestRecoveryPromotionKeepsSOASerialsMonotonic crashes the primary inside
// the replication window and brings it back after a recovery promotion. The
// former primary must never serve an older SOA serial than it already served.
func TestRecoveryPromotionKeepsSOASerialsMonotonic(t *testing.T) {
	faults, checks, _ := crashPrimaryInsideReplicationWindow(t)
	checks.observe(t, faults)
}

// TestRecoveryPromotionLosesOnlyTheReplicationWindow holds what
// docs/clustering.md promises (#582): writes a replica had before the primary
// crashed survive a recovery promotion, and writes acknowledged inside the
// replication window survive on every node or are gone from every node.
func TestRecoveryPromotionLosesOnlyTheReplicationWindow(t *testing.T) {
	faults, _, records := crashPrimaryInsideReplicationWindow(t)
	// The former primary served the lost writes' serials before it crashed;
	// holding its serials across the crash is #581's test, so check the
	// recovered cluster on its own here.
	checks := newInvariants()
	checks.converged(t, faults, records)
	checks.sameWindowEverywhere(t, faults, records)
}

// crashPrimaryInsideReplicationWindow makes writes the replicas pull, then
// kills the primary right after it acknowledges more, before a replica pulls
// them. It promotes a replica and waits for the restarted former primary to
// step down. The ledger marks the last writes as inside the window.
func crashPrimaryInsideReplicationWindow(t *testing.T) (*faultCluster, *invariants, *ledger) {
	t.Helper()
	faults := startCluster(t, 3)
	checks, records := newInvariants(), &ledger{}
	writeAndObserve(t, faults, checks, records, 3)
	checks.converged(t, faults, records)
	writeAndObserve(t, faults, checks, records, 3)
	records.insideWindow(3)
	old, successor := faults.members[0], faults.members[1]
	term := old.state(t).Term
	old.kill(t)
	successor.promote(t)
	waitRole(t, successor, cluster.RolePrimary, term)
	old.start(t)
	waitRole(t, old, cluster.RoleReplica, term)
	return faults, checks, records
}

// TestReplicaKillAndRestartMidWrites kills a replica while the primary keeps
// taking writes, then restarts it; it must catch up on all of them.
func TestReplicaKillAndRestartMidWrites(t *testing.T) {
	faults := startCluster(t, 3)
	checks, records := newInvariants(), &ledger{}
	writeAndObserve(t, faults, checks, records, 2)
	replica := faults.members[1]
	replica.kill(t)
	writeAndObserve(t, faults, checks, records, 3)
	replica.start(t)
	writeAndObserve(t, faults, checks, records, 2)
	checks.converged(t, faults, records)
}

// writeAndObserve makes count acknowledged writes through the primary,
// checking the invariants after each.
func writeAndObserve(t *testing.T, faults *faultCluster, checks *invariants, records *ledger, count int) {
	t.Helper()
	for range count {
		records.mustWrite(t, faults)
		checks.observe(t, faults)
	}
}

// promote asks the member to take over as primary for recovery.
func (node *member) promote(t *testing.T) {
	t.Helper()
	clustertest.RequestJSON(t, node.client, http.MethodPost,
		"https://"+node.ports.HTTPS+"/api/v1/cluster/nodes/"+node.id+"/promote", nil, http.StatusOK, nil)
}

// waitRole waits until the member holds role in a term after term.
func waitRole(t *testing.T, node *member, role string, term uint64) {
	t.Helper()
	clustertest.WaitForClusterState(t, node.node, node.client, node.ports.HTTPS, func(state cluster.State) bool {
		return state.LocalRole == role && state.Term > term
	})
}
