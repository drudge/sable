package cluster

import (
	"fmt"
	"testing"
)

// A wiped replica takes back every lease the primary holds of it, however
// many it has leased since the wipe and whether or not its first heartbeat
// after starting carried a lease report (docs/design/dhcp.md §3). A lease it
// forgot could be offered to a second client while the first still holds it
// (RFC 2131 §4.3.1).
func TestLeaseMirrorWipedReplicaRecoversEveryLease(t *testing.T) {
	t.Parallel()
	for name, restarted := range map[string]bool{
		"it leased before it asked the primary":        false,
		"it started before it could reach the primary": true,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
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
			for index := range 3 {
				wiped.save(replica.nodeID, fmt.Sprintf("10.0.1.%d", index+1), "after-wipe")
			}
			replica.SetLeaseMirror(wiped.mirror())
			if restarted {
				// A restarted node hasn't heard the primary mirror yet, so its
				// first heartbeat carries no report.
				replica.mu.Lock()
				replica.leasePrimaryID, replica.leaseAcknowledged, replica.leaseRecovered = "", 0, 0
				replica.mu.Unlock()
			}
			synchronize(t, replica, 4)

			if got := len(wiped.hostnames(replica.nodeID)); got != total+3 {
				t.Fatalf("the wiped replica holds %d of its own leases, want the %d it held before the wipe and 3 since", got, total+3)
			}
		})
	}
}
