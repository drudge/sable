package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
)

// testDHCPClusterController is a two-node cluster whose Promote records the
// node it was asked to promote and makes it the primary.
type testDHCPClusterController struct {
	testClusterPageController
	state    *cluster.State
	promoted *[]string
}

func (controller testDHCPClusterController) Snapshot() cluster.State { return *controller.state }

func (controller testDHCPClusterController) Promote(_ context.Context, node string) error {
	*controller.promoted = append(*controller.promoted, node)
	controller.state.PrimaryID, controller.state.LocalRole = node, cluster.RolePrimary
	return nil
}

func newDHCPClusterConsoleServer(t *testing.T, local string, offline string) (*Server, *editableTestConfiguration, *[]string) {
	t.Helper()
	server, configuration, controller := newDHCPConsoleServer(t)
	phone := controller.leases[0]
	phone.Address, phone.MAC, phone.ClientKey, phone.Label = netip.MustParseAddr("192.0.2.150"), "00:11:22:33:44:50", "0100:11:22:33:44:50", "phone"
	controller.leases = append(controller.leases, phone)
	nodes := []cluster.Node{
		{ID: "node-a", Name: "ns1", Role: cluster.RolePrimary, State: cluster.StateOnline, SyncState: cluster.SyncCurrent},
		{ID: "node-b", Name: "ns2", Role: cluster.RoleReplica, State: cluster.StateOnline, SyncState: cluster.SyncCurrent},
	}
	for index := range nodes {
		if nodes[index].ID == offline {
			nodes[index].State = cluster.StateUnreachable
		}
	}
	role := cluster.RolePrimary
	if local != "node-a" {
		role = cluster.RoleReplica
	}
	promoted := &[]string{}
	state := &cluster.State{Initialized: true, Mode: "primary-replica", ClusterID: "cluster-1", NodeID: local, PrimaryID: "node-a", LocalRole: role, Nodes: nodes}
	server.SetClusterController(testDHCPClusterController{state: state, promoted: promoted})
	configuration.snapshot.Config.DHCP.Scopes[0].Ranges = []config.DHCPRange{
		{Start: "192.0.2.100", End: "192.0.2.149", Node: "node-a"}, {Start: "192.0.2.150", End: "192.0.2.199", Node: "node-b"}}
	return server, configuration, promoted
}

// On a cluster the scope dialog edits the scope's whole range and splits it
// evenly across the nodes (design §3), shows each node's slice, and warns
// when a slice can't carry the scope's active leases alone. Saving the same
// range keeps the split it has, so a takeover isn't undone by an edit.
func TestDHCPConsoleSplitsRangeOnCluster(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPClusterConsoleServer(t, "node-a", "")

	add := url.Values{"new": {"1"}, "id": {"guest"}, "name": {"Guest"}, "subnet": {"198.51.100.0/24"},
		"range_start": {"198.51.100.50"}, "range_end": {"198.51.100.149"}}
	if response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/scopes", add); response.Code != http.StatusOK {
		t.Fatalf("add scope on a cluster = %d: %s", response.Code, response.Body.String())
	}
	want := []config.DHCPRange{{Start: "198.51.100.50", End: "198.51.100.99", Node: "node-a"}, {Start: "198.51.100.100", End: "198.51.100.149", Node: "node-b"}}
	if got := configuration.snapshot.Config.DHCP.Scopes[1].Ranges; !slices.Equal(got, want) {
		t.Fatalf("added scope's ranges = %v; want %v", got, want)
	}

	page := dhcpConsoleRequest(t, server, http.MethodGet, "/dhcp?tab=scopes", nil).Body.String()
	expectContains(t, "Scopes tab on a cluster", page, "198.51.100.50 – 198.51.100.149", "Split evenly across the 2 cluster nodes",
		"ns1", "198.51.100.50 – 198.51.100.99", "ns2", "198.51.100.100 – 198.51.100.149")
	if strings.Contains(page, "more range") {
		t.Error("the dialog calls a cluster's split ranges more ranges in sable.toml")
	}

	configuration.snapshot.Config.DHCP.Scopes[0].Ranges = []config.DHCPRange{{Start: "192.0.2.100", End: "192.0.2.199"}}
	page = dhcpConsoleRequest(t, server, http.MethodGet, "/dhcp?tab=scopes", nil).Body.String()
	expectContains(t, "an unpinned range on a cluster", page, "No node leases from it; save the scope to split it")
	edit := url.Values{"id": {"lan"}, "name": {"Home"}, "subnet": {"192.0.2.0/24"}, "range_start": {"192.0.2.100"}, "range_end": {"192.0.2.199"}}
	if response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/scopes", edit); response.Code != http.StatusOK {
		t.Fatalf("save an unpinned scope = %d: %s", response.Code, response.Body.String())
	}
	want = []config.DHCPRange{{Start: "192.0.2.100", End: "192.0.2.149", Node: "node-a"}, {Start: "192.0.2.150", End: "192.0.2.199", Node: "node-b"}}
	if got := configuration.snapshot.Config.DHCP.Scopes[0].Ranges; !slices.Equal(got, want) {
		t.Fatalf("saving an unpinned range must split it: %v; want %v", got, want)
	}

	taken := []config.DHCPRange{{Start: "192.0.2.100", End: "192.0.2.149", Node: "node-a"}, {Start: "192.0.2.150", End: "192.0.2.199", Node: "node-a"}}
	configuration.snapshot.Config.DHCP.Scopes[0].Ranges = slices.Clone(taken)
	if response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/scopes", edit); response.Code != http.StatusOK {
		t.Fatalf("edit scope = %d: %s", response.Code, response.Body.String())
	}
	if got := configuration.snapshot.Config.DHCP.Scopes[0].Ranges; !slices.Equal(got, taken) {
		t.Fatalf("an edit that keeps the range moved its split: %v; want %v", got, taken)
	}

	edit.Set("range_end", "192.0.2.101")
	if response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/scopes", edit); response.Code != http.StatusOK {
		t.Fatalf("shrink scope = %d: %s", response.Code, response.Body.String())
	}
	want = []config.DHCPRange{{Start: "192.0.2.100", End: "192.0.2.100", Node: "node-a"}, {Start: "192.0.2.101", End: "192.0.2.101", Node: "node-b"}}
	if got := configuration.snapshot.Config.DHCP.Scopes[0].Ranges; !slices.Equal(got, want) {
		t.Fatalf("a changed range must split again: %v; want %v", got, want)
	}
	page = dhcpConsoleRequest(t, server, http.MethodGet, "/dhcp?tab=scopes", nil).Body.String()
	expectContains(t, "a slice smaller than the active leases", page, "Too small to carry the scope&#39;s 2 active leases alone")
}

// Take Over moves an offline node's ranges to this node (design §3); an
// online node, this node, and a node with no ranges are refused.
func TestDHCPTakeOverRanges(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPClusterConsoleServer(t, "node-a", "node-b")

	page := dhcpConsoleRequest(t, server, http.MethodGet, "/ui/cluster/node?name=ns2", nil).Body.String()
	expectContains(t, "offline node's panel", page, `hx-post="/ui/dhcp/takeover"`, `name="node" value="node-b"`, "Take Over DHCP Ranges")

	response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/takeover", url.Values{"node": {"node-b"}})
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Took over 1 DHCP range from ns2") {
		t.Fatalf("take over = %d: %s", response.Code, response.Body.String())
	}
	for _, pool := range configuration.snapshot.Config.DHCP.Scopes[0].Ranges {
		if pool.Node != "node-a" {
			t.Fatalf("range %v still pinned to %s after takeover", pool, pool.Node)
		}
	}
	if strings.Contains(dhcpConsoleRequest(t, server, http.MethodGet, "/ui/cluster/node?name=ns2", nil).Body.String(), "Take Over DHCP Ranges") {
		t.Error("a node with no ranges left still offers Take Over")
	}
	for node, want := range map[string]string{"node-b": "ns2 has no DHCP ranges", "node-a": "This node already serves its own ranges", "node-z": "node-z isn&#39;t a member of this cluster"} {
		response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/takeover", url.Values{"node": {node}})
		if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), want) {
			t.Errorf("take over %s = %d: %s; want %q", node, response.Code, response.Body.String(), want)
		}
	}

	online, configuration, _ := newDHCPClusterConsoleServer(t, "node-a", "")
	response = dhcpConsoleRequest(t, online, http.MethodPost, "/ui/dhcp/takeover", url.Values{"node": {"node-b"}})
	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "ns2 is online") ||
		configuration.snapshot.Config.DHCP.Scopes[0].Ranges[1].Node != "node-b" {
		t.Fatalf("take over an online node = %d: %s", response.Code, response.Body.String())
	}
	if strings.Contains(dhcpConsoleRequest(t, online, http.MethodGet, "/ui/cluster/node?name=ns2", nil).Body.String(), "Take Over DHCP Ranges") {
		t.Error("an online node's panel offers Take Over")
	}
}

// A replica promoted for recovery takes over its old primary's ranges in the
// same step when the promote form asks for it.
func TestDHCPPromoteTakesOverPrimaryRanges(t *testing.T) {
	t.Parallel()
	server, configuration, promoted := newDHCPClusterConsoleServer(t, "node-b", "node-a")

	page := dhcpConsoleRequest(t, server, http.MethodGet, "/ui/cluster/node?name=ns2", nil).Body.String()
	expectContains(t, "local replica's panel", page, `hx-post="/ui/cluster/nodes/node-b/promote"`, `name="dhcp_takeover" value="node-a"`,
		"also takes over ns1&#39;s DHCP ranges")

	response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/cluster/nodes/node-b/promote", url.Values{"dhcp_takeover": {"node-a"}})
	if response.Code != http.StatusOK || !slices.Equal(*promoted, []string{"node-b"}) {
		t.Fatalf("promote = %d (%v): %s", response.Code, *promoted, response.Body.String())
	}
	expectContains(t, "promote message", response.Body.String(), "This node is now the cluster primary and took over 1 DHCP range from ns1")
	for _, pool := range configuration.snapshot.Config.DHCP.Scopes[0].Ranges {
		if pool.Node != "node-b" {
			t.Fatalf("range %v still pinned to %s after promote with takeover", pool, pool.Node)
		}
	}
}

// The API takes over an offline node's ranges like the Cluster page does.
func TestDHCPTakeOverRangesAPI(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPClusterConsoleServer(t, "node-a", "node-b")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/dhcp/takeover", strings.NewReader(`{"node":"node-b"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Took over 1 DHCP range from ns2") ||
		configuration.snapshot.Config.DHCP.Scopes[0].Ranges[1].Node != "node-a" {
		t.Fatalf("POST /api/v1/dhcp/takeover = %d: %s", response.Code, response.Body.String())
	}
}

// A takeover writes new settings and leaves the ones the running server
// holds alone, so the reload sees the moved ranges and serves them.
func TestDHCPTakeOverLeavesTheSettingsInUseAlone(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPClusterConsoleServer(t, "node-a", "node-b")
	inUse := configuration.snapshot.Config.DHCP

	response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/takeover", url.Values{"node": {"node-b"}})
	if response.Code != http.StatusOK {
		t.Fatalf("take over = %d: %s", response.Code, response.Body.String())
	}
	if got := inUse.Scopes[0].Ranges[1].Node; got != "node-b" {
		t.Fatalf("the takeover rewrote the settings in use (range pinned to %s), so the reload sees nothing to apply", got)
	}
	if got := configuration.snapshot.Config.DHCP.Scopes[0].Ranges[1].Node; got != "node-a" {
		t.Fatalf("the saved settings pin the range to %s; want node-a", got)
	}
}

// Remove Replica says when the node still has DHCP ranges pinned to it:
// once it's gone no node leases from them.
func TestDHCPRemoveReplicaWarnsAboutItsRanges(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPClusterConsoleServer(t, "node-a", "")
	page := dhcpConsoleRequest(t, server, http.MethodGet, "/ui/cluster/node?name=ns2", nil).Body.String()
	expectContains(t, "Remove Replica for a node with a range", page,
		"It still has 1 DHCP range pinned to it, and no node leases from it once it&#39;s gone")

	configuration.snapshot.Config.DHCP.Scopes[0].Ranges[1].Node = "node-a"
	if page := dhcpConsoleRequest(t, server, http.MethodGet, "/ui/cluster/node?name=ns2", nil).Body.String(); strings.Contains(page, "DHCP range pinned") {
		t.Error("Remove Replica warns about DHCP ranges for a node with none")
	}
}
