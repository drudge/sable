package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dhcp"
)

// testDHCPCluster is an initialized cluster of the members, all on v1.9.0,
// each at 10.0.7.1 plus its position.
func testDHCPCluster(members ...string) func() cluster.State {
	state := cluster.State{Initialized: true, NodeID: members[0], ClusterID: "cluster-1"}
	for index, id := range members {
		state.Nodes = append(state.Nodes, cluster.Node{
			ID: id, Name: id, Version: "v1.9.0",
			Addresses: []string{netip.AddrFrom4([4]byte{10, 0, 7, byte(index + 2)}).String()},
		})
	}
	return func() cluster.State { return state }
}

// dhcpPinnedSettings splits the test scope's pool between node-a and node-b.
func dhcpPinnedSettings(t *testing.T) config.DHCP {
	t.Helper()
	settings := dhcpTestSettings(t)
	settings.Scopes[0].Ranges = []config.DHCPRange{
		{Start: "10.0.7.100", End: "10.0.7.109", Node: "node-a"},
		{Start: "10.0.7.110", End: "10.0.7.119", Node: "node-b"},
	}
	return settings
}

// Every cluster node serves the ranges pinned to it, primary and replica
// alike (design §3), and a node still joining holds the settings (F30).
func TestDHCPServesOnEveryClusterNode(t *testing.T) {
	for _, role := range []string{cluster.RolePrimary, cluster.RoleReplica} {
		t.Run(role, func(t *testing.T) {
			service, listens, _ := newTestDHCPService(t, role)
			service.cluster = testDHCPCluster("node-a", "node-b")
			ctx := context.Background()
			if err := service.Apply(ctx, ctx, dhcpPinnedSettings(t)); err != nil {
				t.Fatalf("Apply pinned ranges as %s = %v", role, err)
			}
			waitDHCPEvents(t, listens, []string{"listen"})
			if !dhcpServed(dhcpPinnedSettings(t), role) {
				t.Fatalf("dhcpServed as %s = false; names wouldn't publish", role)
			}
		})
	}
	service, listens, _ := newTestDHCPService(t, dhcpRoleJoining)
	ctx := context.Background()
	if err := service.Apply(ctx, ctx, dhcpPinnedSettings(t)); err != nil {
		t.Fatalf("Apply while joining = %v", err)
	}
	waitDHCPEvents(t, listens, nil)
	if dhcpServed(dhcpPinnedSettings(t), dhcpRoleJoining) {
		t.Fatal("dhcpServed while joining = true")
	}
	if role := dhcpClusterRole(cluster.State{Joining: true}); role != dhcpRoleJoining {
		t.Fatalf("dhcpClusterRole while joining = %q", role)
	}
}

// A replica holding settings its primary refused never leases from an
// unpinned range; with nothing else to answer it doesn't bind port 67.
func TestDHCPClusterNodeLeavesUnpinnedRangesAlone(t *testing.T) {
	service, listens, _ := newTestDHCPService(t, cluster.RoleReplica)
	service.cluster = testDHCPCluster("node-b", "node-a")
	ctx := context.Background()
	if err := service.Apply(ctx, ctx, dhcpTestSettings(t)); err != nil {
		t.Fatal(err)
	}
	waitDHCPEvents(t, listens, nil)
	served := dhcpNodeSettings(dhcpTestSettings(t), true)
	if len(served.Scopes[0].Ranges) != 0 || len(dhcpTestSettings(t).Scopes[0].Ranges) != 1 {
		t.Fatalf("dhcpNodeSettings on a cluster kept %v, or changed its input", served.Scopes[0].Ranges)
	}
	if dhcpServesAnything(served, "node-a") {
		t.Fatal("dhcpServesAnything with no range or reservation = true")
	}
	served.Scopes[0].Reservations = []config.DHCPReservation{{MAC: "aa:bb:cc:dd:ee:01", Address: "10.0.7.20"}}
	if !dhcpServesAnything(served, "node-a") {
		t.Fatal("dhcpServesAnything with a reservation = false; every node answers reservations")
	}
}

// The node whose sable.toml is edited refuses what a cluster can't serve
// safely: an unpinned range, a node that isn't a member, a member too old to
// read [dhcp]. A replica only holds what its primary sends (F29).
func TestDHCPClusterCheck(t *testing.T) {
	pinned := dhcpPinnedSettings(t)
	unpinned := dhcpTestSettings(t)
	stranger := dhcpPinnedSettings(t)
	stranger.Scopes[0].Ranges[1].Node = "node-c"
	members := testDHCPCluster("node-a", "node-b")()
	older := testDHCPCluster("node-a", "node-b")()
	older.Nodes[1].Version = "v1.8.2"
	standalone := cluster.State{NodeID: "node-a"}
	cases := []struct {
		name     string
		settings config.DHCP
		state    cluster.State
		wantErr  bool
	}{
		{"pinned to members", pinned, members, false},
		{"unpinned on a cluster", unpinned, members, true},
		{"pinned to a stranger", stranger, members, true},
		{"member on an older release", pinned, older, true},
		{"unpinned standalone", unpinned, standalone, false},
		{"pinned to another node standalone", pinned, standalone, true},
	}
	for _, test := range cases {
		err := checkDHCPCluster(test.settings, test.state, "v1.9.0")
		if (err != nil) != test.wantErr {
			t.Errorf("%s: checkDHCPCluster = %v; want error %v", test.name, err, test.wantErr)
		}
	}
	if err := checkDHCPCluster(unpinned, members, "v1.9.0"); !errors.Is(err, errDHCPRangeUnpinned) {
		t.Errorf("unpinned range = %v; want errDHCPRangeUnpinned", err)
	}
	service, _, _ := newTestDHCPService(t, cluster.RoleReplica)
	service.cluster = testDHCPCluster("node-a", "node-b")
	if err := service.Check(unpinned); err != nil {
		t.Errorf("replica Check = %v; a replica holds what its primary sends", err)
	}
}

// The other-server probe treats cluster peers as this node (D36): a peer's
// OFFER isn't another server, and a peer's probe isn't answered.
func TestDHCPProbeTreatsClusterPeersAsThisNode(t *testing.T) {
	service, _, _ := newTestDHCPService(t, cluster.RolePrimary)
	service.cluster = testDHCPCluster("node-a", "node-b")
	own := service.ownAddresses(nil)
	if !own[netip.MustParseAddr("10.0.7.3")] {
		t.Fatalf("ownAddresses = %v; want node-b's 10.0.7.3", own)
	}
	peer := dhcpOwnProbes{cluster: func() string { return "cluster-1" }}
	probe := dhcpProbeDiscover(net.HardwareAddr{0, 0x44, 0, 0, 0, 1}, peer.tag())
	self := dhcpOwnProbes{cluster: func() string { return "cluster-1" }}
	if !self.sent(probe.Marshal()) {
		t.Fatal("a peer's probe reached the engine")
	}
	other := dhcpOwnProbes{cluster: func() string { return "cluster-2" }}
	standalone := dhcpOwnProbes{}
	if other.sent(probe.Marshal()) || standalone.sent(probe.Marshal()) {
		t.Fatal("another cluster or a standalone server dropped the probe; it should answer, so they find each other")
	}
	client := dhcpProbeDiscover(net.HardwareAddr{0, 0x44, 0, 0, 0, 2}, nil)
	client.Options = append(client.Options, dhcp.Option{Code: dhcpOptionVendorClass, Data: []byte("MSFT 5.0")})
	if self.sent(client.Marshal()) {
		t.Fatal("a client's DISCOVER was taken for a peer's probe")
	}
}
