package cluster

import (
	"fmt"
	"testing"
)

// A wiped replica takes back every lease the primary holds of it, however
// many it has leased since the wipe (as many as it held before, or more) and
// whether or not its first heartbeat after starting carried a lease report
// (docs/design/dhcp.md §3). A lease it forgot could be offered to a second
// client while the first still holds it (RFC 2131 §4.3.1).
func TestLeaseMirrorWipedReplicaRecoversEveryLease(t *testing.T) {
	t.Parallel()
	for _, since := range []int{3, 25} {
		for name, restarted := range map[string]bool{
			"it leased before it asked the primary":        false,
			"it started before it could reach the primary": true,
		} {
			t.Run(fmt.Sprintf("%d since, %s", since, name), func(t *testing.T) {
				t.Parallel()
				testWipedReplicaRecovers(t, since, restarted)
			})
		}
	}
}

func testWipedReplicaRecovers(t *testing.T, since int, restarted bool) {
	_, replica, lead, follower := mirroringCluster(t)
	const total = 20
	for index := range total {
		follower.save(replica.nodeID, fmt.Sprintf("10.0.0.%d", index+1), "before")
	}
	synchronize(t, replica, 3)
	if got := len(lead.hostnames(replica.nodeID)); got != total {
		t.Fatalf("the primary holds %d of the replica's leases, want %d", got, total)
	}

	wiped := newLeaseStore()
	for index := range since {
		wiped.save(replica.nodeID, fmt.Sprintf("10.0.1.%d", index+1), "after-wipe")
	}
	replica.SetLeaseMirror(wiped.mirror())
	if restarted {
		// A restarted node hasn't heard the primary mirror yet, so its first
		// heartbeat carries no report.
		replica.mu.Lock()
		replica.leasePrimaryID, replica.leaseAcknowledged, replica.leaseRecovered = "", 0, 0
		replica.mu.Unlock()
	}
	synchronize(t, replica, 4)

	if got := len(wiped.hostnames(replica.nodeID)); got != total+since {
		t.Fatalf("the wiped replica holds %d of its own leases, want the %d it held before the wipe and %d since", got, total, since)
	}
	if got := len(lead.hostnames(replica.nodeID)); got != total+since {
		t.Fatalf("the primary holds %d of the replica's leases, want %d", got, total+since)
	}
	if _, open, _ := wiped.Recovery(t.Context(), replica.nodeID); open {
		t.Fatal("the recovery is still open after the replica took its leases back")
	}
}

// A batch cut part way through rows that share a number ends before them, so
// a recovery that moves past the batch's last number skips none of them.
func TestWholeLeaseNumbersEndsBeforeASharedNumber(t *testing.T) {
	t.Parallel()
	numbers := func(rows []SharedLease) (seqs []int64) {
		for _, row := range rows {
			seqs = append(seqs, row.Seq)
		}
		return seqs
	}
	rows := []SharedLease{{Seq: 1}, {Seq: 2}, {Seq: 3}, {Seq: 3}}
	if got := numbers(wholeLeaseNumbers(rows)); len(got) != 2 || got[1] != 2 {
		t.Fatalf("wholeLeaseNumbers(1 2 3 3) = %v; want 1 2", got)
	}
	if got := wholeLeaseNumbers(rows[2:]); len(got) != 2 {
		t.Fatalf("wholeLeaseNumbers(3 3) = %v; want both, so the recovery still moves", numbers(got))
	}
}
