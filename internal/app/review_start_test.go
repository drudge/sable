package app

import (
	"context"
	"testing"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/version"
)

// Review of #638. At start a node serves what [dhcp] pins to it, whatever
// became of the other members since the settings were saved; refusing is for
// the edit (Check, through checkDHCP), which nothing here changes.
//
// On the real binaries: node-a died and was removed from the cluster with a
// range still pinned to it. The last node kept serving until its next
// restart, then logged "DHCP server not started ... is not a cluster member"
// and answered no DISCOVER at all.
func TestReview638StartServesAfterAMemberIsRemoved(t *testing.T) {
	service, listens, _ := newTestDHCPService(t, cluster.RolePrimary)
	service.cluster = testDHCPCluster("node-a") // node-b was removed; its range still names it
	ctx := context.Background()
	if err := service.Apply(ctx, ctx, dhcpPinnedSettings(t)); err != nil {
		t.Fatalf("start with a range pinned to a removed member = %v; the node's own range goes unserved", err)
	}
	waitDHCPEvents(t, listens, []string{"listen"})
}

// On the real binaries: both nodes on 9.9.0 serving DHCP, the primary updated
// to 9.9.1 first. It logged "update node-b (9.9.0) to Sable 9.9.1 or later
// before serving DHCP on this cluster" and didn't bind port 67, and stayed
// that way after node-b was updated too, until it was restarted again.
func TestReview638StartServesWhenThePrimaryIsUpdatedFirst(t *testing.T) {
	previous := version.Release
	version.Release = "v1.9.1"
	t.Cleanup(func() { version.Release = previous })
	service, listens, _ := newTestDHCPService(t, cluster.RolePrimary)
	state := testDHCPCluster("node-a", "node-b")() // node-b still reports v1.9.0
	state.Nodes[0].Version = "v1.9.1"
	service.cluster = func() cluster.State { return state }
	ctx := context.Background()
	if err := service.Apply(ctx, ctx, dhcpPinnedSettings(t)); err != nil {
		t.Fatalf("start on a primary newer than a replica = %v; settings that replica already holds go unserved", err)
	}
	waitDHCPEvents(t, listens, []string{"listen"})
}
