//go:build integration

package app_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/clustertest"
	"github.com/drudge/sable/internal/config"
)

// A primary restarted with [dhcp] enabled in sable.toml doesn't serve DHCP,
// and its replica still takes every later change from it (F29).
func TestClusterReplicaFollowsPrimaryWithDHCPEnabled(t *testing.T) {
	primaryDirectory, replicaDirectory := t.TempDir(), t.TempDir()
	primaryPorts, replicaPorts := clustertest.AllocatePorts(t), clustertest.AllocatePorts(t)
	primaryCertificate := clustertest.GeneratePrimaryCertificate(t, primaryDirectory)
	primaryConfiguration := clustertest.NodeConfiguration(primaryDirectory, primaryPorts, "primary", primaryCertificate)
	primaryConfigurationPath := clustertest.WriteConfiguration(t, primaryDirectory, primaryConfiguration)
	primaryClient := clustertest.TrustedHTTPClient(t, filepath.Join(primaryDirectory, primaryCertificate.CAFile))
	primary := clustertest.StartNode(t, primaryConfigurationPath, primaryClient, primaryPorts.HTTPS)
	clustertest.InitializePrimary(t, primaryClient, primaryPorts.HTTPS)
	enrollment := clustertest.CreateEnrollmentToken(t, primaryClient, primaryPorts.HTTPS)

	replicaCertificate := clustertest.GenerateClusterCertificate(t, replicaDirectory, "replica")
	replicaConfiguration := clustertest.NodeConfiguration(replicaDirectory, replicaPorts, "replica", replicaCertificate)
	replicaConfigurationPath := clustertest.WriteConfiguration(t, replicaDirectory, replicaConfiguration)
	replicaClient := clustertest.TrustedHTTPClient(t, filepath.Join(replicaDirectory, replicaCertificate.CAFile))
	replica := clustertest.StartNode(t, replicaConfigurationPath, replicaClient, replicaPorts.HTTPS)
	clustertest.JoinReplica(t, replicaClient, replicaPorts.HTTPS, primaryPorts.HTTPS, enrollment.Token)
	clustertest.WaitForClusterState(t, replica, replicaClient, replicaPorts.HTTPS, func(state cluster.State) bool {
		return state.LocalRole == cluster.RoleReplica && state.Synchronized == 2
	})

	// sable.toml is the only way to turn DHCP on until the console has it.
	clustertest.StopNode(t, primary)
	primaryConfiguration.DHCP = testDHCPSettings()
	clustertest.WriteConfiguration(t, primaryDirectory, primaryConfiguration)
	primary = clustertest.StartNode(t, primaryConfigurationPath, primaryClient, primaryPorts.HTTPS)

	const domain = "dhcp-replication.test"
	clustertest.AddBlockedDomain(t, primaryClient, primaryPorts.HTTPS, primaryConfigurationPath, domain)
	clustertest.WaitForBlockedDNSResponse(t, replica, replicaPorts.DNS, domain)
}

// A replica that joins a primary whose sable.toml has [dhcp] enabled holds
// the primary's settings without serving them, even while the join is still
// applying them (F30).
func TestClusterReplicaJoiningPrimaryWithDHCPEnabledDoesNotServe(t *testing.T) {
	primaryDirectory, replicaDirectory := t.TempDir(), t.TempDir()
	primaryPorts, replicaPorts := clustertest.AllocatePorts(t), clustertest.AllocatePorts(t)
	primaryCertificate := clustertest.GeneratePrimaryCertificate(t, primaryDirectory)
	primaryConfiguration := clustertest.NodeConfiguration(primaryDirectory, primaryPorts, "primary", primaryCertificate)
	primaryConfigurationPath := clustertest.WriteConfiguration(t, primaryDirectory, primaryConfiguration)
	primaryClient := clustertest.TrustedHTTPClient(t, filepath.Join(primaryDirectory, primaryCertificate.CAFile))
	primary := clustertest.StartNode(t, primaryConfigurationPath, primaryClient, primaryPorts.HTTPS)
	clustertest.InitializePrimary(t, primaryClient, primaryPorts.HTTPS)

	clustertest.StopNode(t, primary)
	primaryConfiguration.DHCP = testDHCPSettings()
	clustertest.WriteConfiguration(t, primaryDirectory, primaryConfiguration)
	clustertest.StartNode(t, primaryConfigurationPath, primaryClient, primaryPorts.HTTPS)
	enrollment := clustertest.CreateEnrollmentToken(t, primaryClient, primaryPorts.HTTPS)

	replicaCertificate := clustertest.GenerateClusterCertificate(t, replicaDirectory, "replica")
	replicaConfiguration := clustertest.NodeConfiguration(replicaDirectory, replicaPorts, "replica", replicaCertificate)
	replicaConfigurationPath := clustertest.WriteConfiguration(t, replicaDirectory, replicaConfiguration)
	replicaClient := clustertest.TrustedHTTPClient(t, filepath.Join(replicaDirectory, replicaCertificate.CAFile))
	replica := clustertest.StartNode(t, replicaConfigurationPath, replicaClient, replicaPorts.HTTPS)
	clustertest.JoinReplica(t, replicaClient, replicaPorts.HTTPS, primaryPorts.HTTPS, enrollment.Token)
	clustertest.WaitForClusterState(t, replica, replicaClient, replicaPorts.HTTPS, func(state cluster.State) bool {
		return state.LocalRole == cluster.RoleReplica && state.Synchronized == 2
	})

	time.Sleep(200 * time.Millisecond)
	if logs := replica.Logs(); strings.Contains(logs, "DHCP server not running") || strings.Contains(logs, "DHCP server started") {
		t.Fatalf("replica tried to serve DHCP on a cluster:\n%s", logs)
	}
	held, err := config.Load(replicaConfigurationPath)
	if err != nil {
		t.Fatal(err)
	}
	if !held.DHCP.Enabled || len(held.DHCP.Scopes) != 1 {
		t.Fatalf("replica didn't keep the primary's [dhcp]: %+v", held.DHCP)
	}
}

func testDHCPSettings() config.DHCP {
	enabled := true
	return config.DHCP{Enabled: true, Scopes: []config.DHCPScope{{
		ID: "lan", Name: "LAN", Subnet: "192.0.2.0/24", Enabled: &enabled,
		Lease:  config.Duration{Duration: time.Hour},
		Ranges: []config.DHCPRange{{Start: "192.0.2.100", End: "192.0.2.119"}},
	}}}
}
