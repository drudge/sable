package app

import (
	"context"
	"errors"
	"testing"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
)

// Creating or joining a cluster is refused while [dhcp] is enabled (D31), and
// the refusal leaves the node out of a cluster. With DHCP off it goes ahead.
func TestClusterInitAndJoinRefusedWhileDHCPEnabled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	enabled := true
	guard := dhcpClusterGuard{Service: openTestClusterService(t), dhcpEnabled: func() bool { return enabled }}
	if err := guard.Initialize(ctx, "cluster.example.test", []string{"192.0.2.1"}); !errors.Is(err, errClusterWithDHCP) {
		t.Fatalf("Initialize with DHCP on = %v; want errClusterWithDHCP", err)
	}
	if guard.Snapshot().Initialized {
		t.Fatal("a refused Initialize made the node a cluster")
	}
	options := cluster.JoinOptions{PrimaryURL: "https://ns1.example.test:5380", Token: "unused", Addresses: []string{"192.0.2.2"}}
	if err := guard.Join(ctx, options); !errors.Is(err, errClusterWithDHCP) {
		t.Fatalf("Join with DHCP on = %v; want errClusterWithDHCP", err)
	}
	enabled = false
	if err := guard.Initialize(ctx, "cluster.example.test", []string{"192.0.2.1"}); err != nil {
		t.Fatalf("Initialize with DHCP off = %v", err)
	}
	if !guard.Snapshot().Initialized {
		t.Fatal("Initialize with DHCP off left the node out of a cluster")
	}
}

func openTestClusterService(t *testing.T) *cluster.Service {
	t.Helper()
	service, err := cluster.Open(cluster.Options{DataDirectory: t.TempDir(), NodeName: "ns1", AdvertiseURL: "https://ns1.example.test:5380"})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// On a cluster with [dhcp] enabled, DHCP is refused at start; a reload that
// leaves [dhcp] alone must still apply, and one that changes it is refused
// (F28, D30).
func TestReloadOnClusterWithDHCPLeftAlone(t *testing.T) {
	t.Parallel()
	service, _, _ := newTestDHCPService(t, cluster.RolePrimary)
	process := &process{dhcp: service}
	settings := dhcpTestSettings(t)
	changed, err := process.checkDHCP(settings, settings)
	if changed || err != nil {
		t.Fatalf("checkDHCP with [dhcp] unchanged = %v, %v; want false, nil", changed, err)
	}
	if _, err := process.checkDHCP(config.DHCP{}, settings); !errors.Is(err, errDHCPOnCluster) {
		t.Fatalf("checkDHCP enabling DHCP on a cluster = %v; want errDHCPOnCluster", err)
	}
}
