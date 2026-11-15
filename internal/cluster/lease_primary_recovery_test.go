package cluster

import (
	"fmt"
	"testing"
)

// A primary whose database was wiped or restored from an older backup takes
// its own leases back from a replica's mirror, batch by batch, however many
// it has leased since (docs/design/dhcp.md §3). A lease it forgot could be
// offered to a second client while the first still holds it (RFC 2131
// §4.3.1).
func TestLeaseMirrorRestoredPrimaryRecoversItsOwnLeases(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ total, since int }{{20, 3}, {20, 25}, {leaseBatchLimit + 20, 3}} {
		t.Run(fmt.Sprintf("%d held, %d since", test.total, test.since), func(t *testing.T) {
			t.Parallel()
			testRestoredPrimaryRecovers(t, test.total, test.since)
		})
	}
}

func testRestoredPrimaryRecovers(t *testing.T, total, since int) {
	primary, replica, lead, follower := mirroringCluster(t)
	for index := range total {
		lead.save(primary.nodeID, fmt.Sprintf("10.0.%d.%d", index/250, index%250+1), "before")
	}
	synchronize(t, replica, 4)
	if got := len(follower.hostnames(primary.nodeID)); got != total {
		t.Fatalf("the replica holds %d of the primary's leases, want %d", got, total)
	}

	wiped := newLeaseStore()
	for index := range since {
		wiped.save(primary.nodeID, fmt.Sprintf("10.1.0.%d", index+1), "after-wipe")
	}
	primary.SetLeaseMirror(wiped.mirror())
	synchronize(t, replica, 6)

	if got := len(wiped.hostnames(primary.nodeID)); got != total+since {
		t.Fatalf("the restored primary holds %d of its own leases, want the %d it held before and %d since", got, total, since)
	}
	if got := len(follower.hostnames(primary.nodeID)); got != total+since {
		t.Fatalf("the replica holds %d of the primary's leases, want %d", got, total+since)
	}
	if _, open, _ := wiped.Recovery(t.Context(), primary.nodeID); open {
		t.Fatal("the recovery is still open after the primary took its leases back")
	}
	wiped.save(primary.nodeID, "10.2.0.1", "next")
	if seq := wiped.seq(primary.nodeID, "10.2.0.1"); seq <= int64(total) {
		t.Fatalf("the next lease took sequence %d, at or below the %d the replica held", seq, total)
	}
}
