package web

import (
	"net/http"
	"testing"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/store"
)

// Review of #638. A lease is ended by the node that granted it (design §3),
// so on a cluster a replica has to take the removal of its own leases: it
// changes only this node. On the real binaries a lease the replica granted
// couldn't be removed anywhere: the primary answered 404 "192.0.2.130 has no
// lease on this node" for a lease its own list shows, and the replica
// answered 409 "Make control-plane changes on the cluster primary". Two
// gates refuse it on the replica: the route (replicaLocal) and the DHCP
// service's own refuseOnReplica.
func TestReview638ReplicaRemovesItsOwnLeases(t *testing.T) {
	t.Parallel()
	server, _, controller := newDHCPTestServer(t)
	server.SetClusterController(testMCPClusterController{state: cluster.State{
		Initialized: true, NodeID: "node-a", PrimaryID: "node-b", LocalRole: cluster.RoleReplica,
		Nodes: []cluster.Node{{ID: "node-b", Name: "ns1", Role: cluster.RolePrimary}, {ID: "node-a", Name: "ns2", Role: cluster.RoleReplica}},
	}})
	response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodDelete, "/api/v1/dhcp/leases/192.0.2.120", "")
	if response.Code != http.StatusNoContent || controller.leases[0].State != store.DHCPLeaseReleased {
		t.Fatalf("removing the replica's own lease on the replica = %d %s; the lease is still %s",
			response.Code, response.Body.String(), controller.leases[0].State)
	}
}
