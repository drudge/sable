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
	"github.com/drudge/sable/internal/config"
)

// Exercise real HTTPS listeners and the replica's UI enrollment endpoint.
func TestTwoNodeClusterPrivateCATrustEnrollment(t *testing.T) {
	for _, mode := range []string{"missing_trust_anchor", "configured_trust_anchor", "installer_self_signed", "regenerated_private_ca"} {
		configured := mode != "missing_trust_anchor"
		name := mode
		t.Run(name, func(t *testing.T) {
			primaryDirectory, replicaDirectory := t.TempDir(), t.TempDir()
			primaryPorts, replicaPorts := allocateIntegrationNodePorts(t), allocateIntegrationNodePorts(t)
			primaryCertificate := generatePrimaryCertificate(t, primaryDirectory)
			if mode == "installer_self_signed" {
				primaryCertificate = generateReplicaCertificate(t, primaryDirectory)
			}
			primaryConfiguration := integrationNodeConfiguration(primaryDirectory, primaryPorts, "primary", primaryCertificate)
			if !configured {
				primaryConfiguration.Cluster.TrustAnchorFile = ""
			}
			primaryTrust := primaryCertificate.CAFile
			if mode == "installer_self_signed" {
				primaryTrust = primaryCertificate.CertificateFile
			}
			primaryClient := trustedHTTPClient(t, filepath.Join(primaryDirectory, primaryTrust))
			primary := startIntegrationNode(t, writeIntegrationConfiguration(t, primaryDirectory, primaryConfiguration), primaryClient, primaryPorts.https)
			initializePrimary(t, primaryClient, primaryPorts.https)
			enrollment := createEnrollmentToken(t, primaryClient, primaryPorts.https)
			bundled := strings.HasPrefix(enrollment.Token, "sable-enroll-v1.")
			if bundled != configured || (!configured && len(enrollment.Token) != 43) {
				t.Fatalf("unexpected token format: bundled=%v, length=%d", bundled, len(enrollment.Token))
			}
			t.Logf("Token length=%d, CA bundled=%v", len(enrollment.Token), bundled)

			if mode == "regenerated_private_ca" {
				// Recreate the empty cluster through the real UI endpoints,
				// retaining the original certificate paths and running process.
				response, err := primaryClient.PostForm("https://"+primaryPorts.https+"/ui/cluster/delete", nil)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusOK {
					t.Fatalf("delete cluster: %d", response.StatusCode)
				}
				response, err = primaryClient.PostForm("https://"+primaryPorts.https+"/ui/cluster/onboarding", url.Values{
					"workflow": {"primary"}, "certificate_source": {"generated"},
					"data_dir": {primaryConfiguration.Cluster.DataDirectory}, "node_name": {"primary"},
					"advertise_url": {"https://" + primaryPorts.https}, "generated_https_listen": {primaryPorts.https},
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
				stopIntegrationNode(t, primary)
				reloaded, err := config.Load(filepath.Join(primaryDirectory, "sable.toml"))
				if err != nil {
					t.Fatal(err)
				}
				primaryClient = trustedHTTPClient(t, reloaded.ClusterTrustAnchorPath(primaryDirectory))
				primary = startIntegrationNode(t, filepath.Join(primaryDirectory, "sable.toml"), primaryClient, primaryPorts.https)
				initializePrimary(t, primaryClient, primaryPorts.https)
				enrollment = createEnrollmentToken(t, primaryClient, primaryPorts.https)
				t.Log("Explicitly replaced HTTPS while preserving prior files, required restart, and issued fresh token")
			}

			replicaCertificate := generateClusterCertificate(t, replicaDirectory, "replica")
			if mode == "installer_self_signed" {
				replicaCertificate = generateReplicaCertificate(t, replicaDirectory)
			}
			replicaConfiguration := integrationNodeConfiguration(replicaDirectory, replicaPorts, "replica", replicaCertificate)
			replicaTrust := replicaCertificate.CAFile
			if mode == "installer_self_signed" {
				replicaTrust = replicaCertificate.CertificateFile
			}
			replicaClient := trustedHTTPClient(t, filepath.Join(replicaDirectory, replicaTrust))
			replica := startIntegrationNode(t, writeIntegrationConfiguration(t, replicaDirectory, replicaConfiguration), replicaClient, replicaPorts.https)
			if configured {
				joinReplica(t, replicaClient, replicaPorts.https, primaryPorts.https, enrollment.Token)
				waitForClusterState(t, primary, primaryClient, primaryPorts.https, func(state cluster.State) bool {
					return state.Connected == 2 && state.Synchronized == 2
				})
				waitForClusterState(t, replica, replicaClient, replicaPorts.https, func(state cluster.State) bool {
					return state.LocalRole == cluster.RoleReplica && state.Synchronized == 2
				})
				t.Log("Both nodes connected and synchronized")
				return
			}
			response, err := replicaClient.PostForm("https://"+replicaPorts.https+"/ui/cluster/join", url.Values{
				"primary_url": {"https://" + primaryPorts.https}, "token": {enrollment.Token}, "addresses": {"127.0.0.1"},
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
			if fetchClusterState(t, replicaClient, replicaPorts.https).Initialized {
				t.Fatal("failed enrollment initialized the replica")
			}
			t.Logf("Reproduced HTTP %d: %s", response.StatusCode, failure)
		})
	}
}
