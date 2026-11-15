package cluster

import (
	"fmt"
	"slices"
	"testing"
	"time"
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

// Each replica mirrors the primary on its own, so one that holds none of the
// primary's leases says nothing of another that does: a restored primary
// keeps its recovery open until every replica has said it holds none past
// it, or the second replica's leases could be offered again (RFC 2131
// §4.3.1).
func TestLeaseMirrorRestoredPrimaryAsksEveryReplica(t *testing.T) {
	t.Parallel()
	primary, replica, lead, _ := mirroringCluster(t)
	primary.mu.Lock()
	primary.manifest.Nodes = append(primary.manifest.Nodes, member{ID: "replica-b", Name: "replica-b", Role: "replica"})
	primary.mu.Unlock()
	lead.save(primary.nodeID, "10.1.0.1", "after-wipe")

	if answer := lead.exchangeAsPrimary(t, primary, replica.nodeID, &LeaseReport{Held: map[string]int64{}}); answer.Wanted != nil {
		t.Fatalf("the primary wants leases from a replica that holds none, after %d", *answer.Wanted)
	}
	if _, open, _ := lead.Recovery(t.Context(), primary.nodeID); !open {
		t.Fatal("the recovery ended on one replica's report while another had yet to report")
	}
	if answer := lead.exchangeAsPrimary(t, primary, "replica-b", &LeaseReport{Held: map[string]int64{primary.nodeID: 5}}); answer.Wanted == nil {
		t.Fatal("the primary doesn't want the leases the second replica holds of it")
	}
	lead.exchangeAsPrimary(t, primary, "replica-b", &LeaseReport{Held: map[string]int64{primary.nodeID: 5}, Rows: []SharedLease{
		{NodeID: primary.nodeID, Address: "10.0.0.9", ScopeID: "lan", ClientKey: "01:9", Hostname: "kept", State: "active", Seq: 5, ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)},
	}})
	if !slices.Contains(lead.hostnames(primary.nodeID), "kept") {
		t.Fatalf("the primary holds %v, without the lease the second replica sent back", lead.hostnames(primary.nodeID))
	}
	if _, open, _ := lead.Recovery(t.Context(), primary.nodeID); open {
		t.Fatal("the recovery is still open after every replica sent what it held")
	}
}

// A primary whose database was wiped and that has leased nothing since, the
// usual case when a replica is up to send a heartbeat within two seconds of
// the primary's start, still takes its own leases back from the replica's
// mirror (docs/design/dhcp.md §3). The replica's first report lifts the
// primary's counter, so no lease it grants afterward takes number 1.
func TestLeaseMirrorWipedPrimaryThatLeasedNothingRecovers(t *testing.T) {
	t.Parallel()
	testRestoredPrimaryRecovers(t, 20, 0)
}

// A primary restored from an older backup holds some of its leases and a
// counter that never starts over: it takes back the ones granted after the
// backup was made.
func TestLeaseMirrorPrimaryRestoredFromBackupRecovers(t *testing.T) {
	t.Parallel()
	primary, replica, lead, follower := mirroringCluster(t)
	backup := newLeaseStore()
	for index := range 20 {
		address := fmt.Sprintf("10.0.0.%d", index+1)
		lead.save(primary.nodeID, address, "before")
		if index < 12 {
			backup.save(primary.nodeID, address, "before")
		}
	}
	delete(backup.recovery, primary.nodeID) // the backup was made long after the counter's first number
	synchronize(t, replica, 4)
	if got := len(follower.hostnames(primary.nodeID)); got != 20 {
		t.Fatalf("the replica holds %d of the primary's leases, want 20", got)
	}

	primary.SetLeaseMirror(backup.mirror())
	synchronize(t, replica, 6)

	if got := len(backup.hostnames(primary.nodeID)); got != 20 {
		t.Fatalf("the primary restored from a backup of 12 leases holds %d of its own, want the 20 the replica mirrors", got)
	}
	if _, open, _ := backup.Recovery(t.Context(), primary.nodeID); open {
		t.Fatal("the recovery is still open after the primary took its leases back")
	}
	backup.save(primary.nodeID, "10.2.0.1", "next")
	if seq := backup.seq(primary.nodeID, "10.2.0.1"); seq <= 20 {
		t.Fatalf("the next lease took sequence %d, at or below the 20 the replica held", seq)
	}
}
