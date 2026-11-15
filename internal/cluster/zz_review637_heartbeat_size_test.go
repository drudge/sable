package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Review of #637. The primary reads at most MaximumHeartbeatBytes of one
// heartbeat and refuses the rest with 400, so the leases a replica puts on a
// heartbeat have to fit whatever the clients sent. A lease row keeps the
// client identifier, host name, and vendor class as sent, 255 bytes each, and
// JSON writes < and & as six bytes. 245 such leases renewed while the primary
// was away made every other synchronization fail on the real binaries, for
// good: the batch never shrinks, so the replica's leases stop reaching the
// primary and their names stop following them.
func TestReview637LeaseBatchFitsTheHeartbeat(t *testing.T) {
	t.Parallel()
	_, replica, _, follower := mirroringCluster(t)
	synchronize(t, replica, 1)
	follower.mu.Lock()
	for index := range 245 {
		identifier := fmt.Sprintf("%04x", index) + strings.Repeat("ab", 253)
		follower.counter[replica.nodeID]++
		address := fmt.Sprintf("192.0.2.%d", index+10)
		follower.rows[[2]string{replica.nodeID, address}] = SharedLease{
			NodeID: replica.nodeID, Address: address, ScopeID: "lan", ClientKey: identifier, ClientID: identifier,
			MAC: fmt.Sprintf("02:f0:00:00:%02x:%02x", index>>8, index&255), Hostname: strings.Repeat("<", 255),
			VendorClass: strings.Repeat("&", 255), State: "active", Seq: follower.counter[replica.nodeID],
			BoundAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(),
		}
	}
	follower.mu.Unlock()

	report, _ := replica.leaseReportForPrimary(context.Background())
	if report == nil || len(report.Rows) == 0 {
		t.Fatal("the heartbeat carries none of the replica's leases")
	}
	body, err := json.Marshal(Heartbeat{NodeID: replica.nodeID, Leases: report})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > MaximumHeartbeatBytes {
		t.Fatalf("a heartbeat with %d leases is %d bytes; the primary reads %d and refuses the synchronization",
			len(report.Rows), len(body), MaximumHeartbeatBytes)
	}
}
