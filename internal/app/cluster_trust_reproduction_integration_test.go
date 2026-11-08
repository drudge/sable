//go:build integration

package app_test

import (
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/clustertest"
	"github.com/drudge/sable/internal/config"
)

// Exercise real HTTPS listeners and the replica's UI enrollment endpoint.
func TestTwoNodeClusterPrivateCATrustEnrollment(t *testing.T) {
	for _, mode := range []string{"missing_trust_anchor", "configured_trust_anchor", "installer_self_signed", "regenerated_private_ca"} {
		configured := mode != "missing_trust_anchor"
		name := mode
		t.Run(name, func(t *testing.T) {
			primaryDirectory, replicaDirectory := t.TempDir(), t.TempDir()
			primaryPorts, replicaPorts := clustertest.AllocatePorts(t), clustertest.AllocatePorts(t)
			primaryCertificate := clustertest.GeneratePrimaryCertificate(t, primaryDirectory)
			if mode == "installer_self_signed" {
				primaryCertificate = clustertest.GenerateReplicaCertificate(t, primaryDirectory)
			}
			primaryConfiguration := clustertest.NodeConfiguration(primaryDirectory, primaryPorts, "primary", primaryCertificate)
			if !configured {
				primaryConfiguration.Cluster.TrustAnchorFile = ""
			}
			primaryTrust := primaryCertificate.CAFile
			if mode == "installer_self_signed" {
				primaryTrust = primaryCertificate.CertificateFile
			}
			primaryClient := clustertest.TrustedHTTPClient(t, filepath.Join(primaryDirectory, primaryTrust))
			primary := clustertest.StartNode(t, clustertest.WriteConfiguration(t, primaryDirectory, primaryConfiguration), primaryClient, primaryPorts.HTTPS)
			clustertest.InitializePrimary(t, primaryClient, primaryPorts.HTTPS)
			enrollment := clustertest.CreateEnrollmentToken(t, primaryClient, primaryPorts.HTTPS)
			bundled := strings.HasPrefix(enrollment.Token, "sable-enroll-v1.")
			if bundled != configured || (!configured && len(enrollment.Token) != 43) {
				t.Fatalf("unexpected token format: bundled=%v, length=%d", bundled, len(enrollment.Token))
			}
			t.Logf("Token length=%d, CA bundled=%v", len(enrollment.Token), bundled)

			if mode == "regenerated_private_ca" {
				// Recreate the empty cluster through the real UI endpoints,
				// retaining the original certificate paths and running process.
				response, err := primaryClient.PostForm("https://"+primaryPorts.HTTPS+"/ui/cluster/delete", nil)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusOK {
					t.Fatalf("delete cluster: %d", response.StatusCode)
				}
				response, err = primaryClient.PostForm("https://"+primaryPorts.HTTPS+"/ui/cluster/onboarding", url.Values{
					"workflow": {"primary"}, "certificate_source": {"generated"},
					"data_dir": {primaryConfiguration.Cluster.DataDirectory}, "node_name": {"primary"},
					"advertise_url": {"https://" + primaryPorts.HTTPS}, "generated_https_listen": {primaryPorts.HTTPS},
					"replace_cluster_ca": {"confirmed"}, "generated_valid_days": {"1"}, "generated_storage_dir": {"data/cluster/pki"},
				})
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "Restart Sable to continue") {
					t.Fatalf("regeneration did not require restart: %d %s", response.StatusCode, body)
				}
				primaryClient.CloseIdleConnections()
				clustertest.StopNode(t, primary)
				reloaded, err := config.Load(filepath.Join(primaryDirectory, "sable.toml"))
				if err != nil {
					t.Fatal(err)
				}
				primaryClient = clustertest.TrustedHTTPClient(t, reloaded.ClusterTrustAnchorPath(primaryDirectory))
				primary = clustertest.StartNode(t, filepath.Join(primaryDirectory, "sable.toml"), primaryClient, primaryPorts.HTTPS)
				clustertest.InitializePrimary(t, primaryClient, primaryPorts.HTTPS)
				enrollment = clustertest.CreateEnrollmentToken(t, primaryClient, primaryPorts.HTTPS)
				t.Log("Explicitly replaced HTTPS while preserving prior files, required restart, and issued fresh token")
			}

			replicaCertificate := clustertest.GenerateClusterCertificate(t, replicaDirectory, "replica")
			if mode == "installer_self_signed" {
				replicaCertificate = clustertest.GenerateReplicaCertificate(t, replicaDirectory)
			}
			replicaConfiguration := clustertest.NodeConfiguration(replicaDirectory, replicaPorts, "replica", replicaCertificate)
			replicaTrust := replicaCertificate.CAFile
			if mode == "installer_self_signed" {
				replicaTrust = replicaCertificate.CertificateFile
			}
			replicaClient := clustertest.TrustedHTTPClient(t, filepath.Join(replicaDirectory, replicaTrust))
			replica := clustertest.StartNode(t, clustertest.WriteConfiguration(t, replicaDirectory, replicaConfiguration), replicaClient, replicaPorts.HTTPS)
			if configured {
				clustertest.JoinReplica(t, replicaClient, replicaPorts.HTTPS, primaryPorts.HTTPS, enrollment.Token)
				clustertest.WaitForClusterState(t, primary, primaryClient, primaryPorts.HTTPS, func(state cluster.State) bool {
					return state.Connected == 2 && state.Synchronized == 2
				})
				clustertest.WaitForClusterState(t, replica, replicaClient, replicaPorts.HTTPS, func(state cluster.State) bool {
					return state.LocalRole == cluster.RoleReplica && state.Synchronized == 2
				})
				t.Log("Both nodes connected and synchronized")
				return
			}
			response, err := replicaClient.PostForm("https://"+replicaPorts.HTTPS+"/ui/cluster/join", url.Values{
				"primary_url": {"https://" + primaryPorts.HTTPS}, "token": {enrollment.Token}, "addresses": {"127.0.0.1"},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			// The macOS system verifier uses different wording from Go's verifier.
			failure := "x509: certificate signed by unknown authority"
			if strings.Contains(string(body), "x509: “primary” certificate is not trusted") {
				failure = "x509: “primary” certificate is not trusted"
			}
			if response.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(body), "contact cluster primary: Post") || !strings.Contains(string(body), failure) {
				t.Fatalf("expected unknown authority failure, got %d: %s", response.StatusCode, body)
			}
			if clustertest.FetchClusterState(t, replicaClient, replicaPorts.HTTPS).Initialized {
				t.Fatal("failed enrollment initialized the replica")
			}
			t.Logf("Reproduced HTTP %d: %s", response.StatusCode, failure)
		})
	}
}
