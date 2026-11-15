package cluster

import (
	"slices"
	"testing"
)

// Review of #637. A primary rebuilt from its backup starts its lease counter
// again, below what the replicas already hold of it. Its new leases must
// still reach them: a replica raises its own counter in this spot
// (TestLeaseMirrorWipedReplicaRaisesItsCounterPastThePrimary), and nothing
// does it for the primary. On the real binaries the rebuilt primary leased
// 192.0.2.7 to a new client and the replica kept the old client on it.
func TestReview637RebuiltPrimaryLeasesReachTheReplica(t *testing.T) {
	t.Parallel()
	primary, replica, lead, follower := mirroringCluster(t)
	for _, address := range []string{"10.0.0.10", "10.0.0.11", "10.0.0.12"} {
		lead.save(primary.nodeID, address, "before")
	}
	synchronize(t, replica, 3)
	if got := follower.hostnames(primary.nodeID); len(got) != 3 {
		t.Fatalf("the replica holds %v of the primary's leases before the rebuild", got)
	}

	rebuilt := newLeaseStore()
	primary.SetLeaseMirror(rebuilt.mirror())
	rebuilt.save(primary.nodeID, "10.0.0.10", "after-rebuild")
	synchronize(t, replica, 4)

	if got := follower.hostnames(primary.nodeID); !slices.Contains(got, "after-rebuild") {
		t.Fatalf("the replica holds %v of the primary's leases; the one written after the rebuild never reached it", got)
	}
}
