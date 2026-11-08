//go:build integration

package app_test

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/clustertest"
	"github.com/drudge/sable/internal/config"
)

const (
	initialBlockedDomain       = "enrollment-replication.test"
	updatedBlockedDomain       = "heartbeat-replication.test"
	handoffBlockedDomain       = "handoff-replication.test"
	replicatedAlertDestination = "integration-hook"
	replicatedAlertSecret      = "integration-hook-token"
)

func TestTwoNodeClusterReplicaEnrollmentAndSynchronization(t *testing.T) {
	primaryDirectory := t.TempDir()
	replicaDirectory := t.TempDir()
	primaryPorts := clustertest.AllocatePorts(t)
	replicaPorts := clustertest.AllocatePorts(t)

	primaryCertificate := clustertest.GeneratePrimaryCertificate(t, primaryDirectory)
	primaryConfiguration := clustertest.NodeConfiguration(primaryDirectory, primaryPorts, "primary", primaryCertificate)
	primaryConfiguration.Blocking.Domains = []string{initialBlockedDomain}
	// Written the way an older release left it, so the primary moves the
	// secret into its vault on start.
	primaryConfiguration.Alerts.Destinations = []config.AlertDestination{{
		ID: replicatedAlertDestination, Name: "Integration hook", URL: "https://hooks.example.test/" + replicatedAlertSecret,
	}}
	primaryConfigurationPath := clustertest.WriteConfiguration(t, primaryDirectory, primaryConfiguration)
	primaryClient := clustertest.TrustedHTTPClient(t, filepath.Join(primaryDirectory, primaryCertificate.CAFile))
	primary := clustertest.StartNode(t, primaryConfigurationPath, primaryClient, primaryPorts.HTTPS)

	clustertest.InitializePrimary(t, primaryClient, primaryPorts.HTTPS)
	enrollment := clustertest.CreateEnrollmentToken(t, primaryClient, primaryPorts.HTTPS)

	replicaCertificate := clustertest.GenerateClusterCertificate(t, replicaDirectory, "replica")
	replicaConfiguration := clustertest.NodeConfiguration(replicaDirectory, replicaPorts, "replica", replicaCertificate)
	replicaConfiguration.Blocking.Enabled = false
	replicaConfiguration.QueryLog.Enabled = true
	replicaConfigurationPath := clustertest.WriteConfiguration(t, replicaDirectory, replicaConfiguration)
	replicaClient := clustertest.TrustedHTTPClient(t, filepath.Join(replicaDirectory, replicaCertificate.CAFile))
	replica := clustertest.StartNode(t, replicaConfigurationPath, replicaClient, replicaPorts.HTTPS)

	clustertest.JoinReplica(t, replicaClient, replicaPorts.HTTPS, primaryPorts.HTTPS, enrollment.Token)
	clustertest.WaitForClusterState(t, primary, primaryClient, primaryPorts.HTTPS, func(state cluster.State) bool {
		return state.Connected == 2 && state.Synchronized == 2 && len(state.Nodes) == 2
	})
	replicaState := clustertest.WaitForClusterState(t, replica, replicaClient, replicaPorts.HTTPS, func(state cluster.State) bool {
		return state.Initialized && state.LocalRole == cluster.RoleReplica && state.Synchronized == 2
	})
	if replicaState.PrimaryURL != "https://"+primaryPorts.HTTPS {
		t.Fatalf("replica primary URL = %q", replicaState.PrimaryURL)
	}

	clustertest.WaitForBlockedDNSResponse(t, replica, replicaPorts.DNS, initialBlockedDomain)
	// Alert destinations follow the primary, and their secrets land in the
	// replica's vault rather than in its configuration file.
	clustertest.WaitForCondition(t, replica, func() bool {
		contents, err := os.ReadFile(replicaConfigurationPath)
		return err == nil && strings.Contains(string(contents), replicatedAlertDestination)
	})
	for _, path := range []string{primaryConfigurationPath, replicaConfigurationPath} {
		if contents, err := os.ReadFile(path); err != nil || strings.Contains(string(contents), replicatedAlertSecret) {
			t.Fatalf("%s holds an alert secret or cannot be read: %v", path, err)
		}
	}
	clustertest.AddBlockedDomain(t, primaryClient, primaryPorts.HTTPS, primaryConfigurationPath, updatedBlockedDomain)
	updatedPrimaryState := clustertest.WaitForClusterState(t, primary, primaryClient, primaryPorts.HTTPS, func(state cluster.State) bool {
		return state.Generation > replicaState.Generation
	})
	updatedReplicaState := clustertest.WaitForClusterState(t, replica, replicaClient, replicaPorts.HTTPS, func(state cluster.State) bool {
		return state.Generation == updatedPrimaryState.Generation && state.Synchronized == 2
	})
	clustertest.WaitForBlockedDNSResponse(t, replica, replicaPorts.DNS, updatedBlockedDomain)
	if updatedReplicaState.Generation != updatedPrimaryState.Generation {
		t.Fatalf("cluster generations after update: primary=%d replica=%d", updatedPrimaryState.Generation, updatedReplicaState.Generation)
	}
	clustertest.WaitForClusterState(t, primary, primaryClient, primaryPorts.HTTPS, func(state cluster.State) bool {
		return state.Generation == updatedPrimaryState.Generation && state.Connected == 2 && state.Synchronized == 2
	})

	var handoffState cluster.State
	clustertest.RequestJSON(t, primaryClient, http.MethodPost,
		"https://"+primaryPorts.HTTPS+"/api/v1/cluster/nodes/"+replicaState.NodeID+"/promote",
		nil, http.StatusOK, &handoffState)
	if handoffState.LocalRole != cluster.RoleReplica || handoffState.PrimaryID != replicaState.NodeID {
		t.Fatalf("former primary after planned handoff = %#v", handoffState)
	}
	promotedReplicaState := clustertest.WaitForClusterState(t, replica, replicaClient, replicaPorts.HTTPS, func(state cluster.State) bool {
		return state.LocalRole == cluster.RolePrimary && state.PrimaryID == state.NodeID && state.Generation >= handoffState.Generation
	})
	clustertest.AddBlockedDomain(t, replicaClient, replicaPorts.HTTPS, replicaConfigurationPath, handoffBlockedDomain)
	promotedGeneration := clustertest.WaitForClusterState(t, replica, replicaClient, replicaPorts.HTTPS, func(state cluster.State) bool {
		return state.Generation > promotedReplicaState.Generation
	}).Generation
	// Membership heartbeats can advance the generation again before the replica polls it.
	clustertest.WaitForClusterState(t, primary, primaryClient, primaryPorts.HTTPS, func(state cluster.State) bool {
		return state.LocalRole == cluster.RoleReplica && state.PrimaryID == replicaState.NodeID &&
			state.Generation >= promotedGeneration && state.Connected == 2 && state.Synchronized == 2
	})
	clustertest.WaitForBlockedDNSResponse(t, primary, primaryPorts.DNS, handoffBlockedDomain)
}
