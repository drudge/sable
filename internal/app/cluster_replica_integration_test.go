//go:build integration

package app_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pelletier/go-toml/v2"

	"github.com/drudge/sable/internal/app"
	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsclient"
)

const (
	clusterIntegrationTimeout  = 15 * time.Second
	clusterPollingInterval     = 100 * time.Millisecond
	clusterCertificateLife     = 24 * time.Hour
	integrationShutdownTimeout = 5 * time.Second
	initialBlockedDomain       = "enrollment-replication.test"
	updatedBlockedDomain       = "heartbeat-replication.test"
	handoffBlockedDomain       = "handoff-replication.test"
)

type integrationNodePorts struct {
	http  string
	https string
	dns   string
}

type runningIntegrationNode struct {
	cancel context.CancelFunc
	done   chan error
	logs   *synchronizedBuffer
	stop   sync.Once
}

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer strings.Builder
}

func (buffer *synchronizedBuffer) Write(contents []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(contents)
}

func (buffer *synchronizedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

func TestTwoNodeClusterReplicaEnrollmentAndSynchronization(t *testing.T) {
	primaryDirectory := t.TempDir()
	replicaDirectory := t.TempDir()
	primaryPorts := allocateIntegrationNodePorts(t)
	replicaPorts := allocateIntegrationNodePorts(t)

	primaryCertificate := generatePrimaryCertificate(t, primaryDirectory)
	primaryConfiguration := integrationNodeConfiguration(primaryDirectory, primaryPorts, "primary", primaryCertificate)
	primaryConfiguration.Blocking.Domains = []string{initialBlockedDomain}
	primaryConfigurationPath := writeIntegrationConfiguration(t, primaryDirectory, primaryConfiguration)
	primaryClient := trustedHTTPClient(t, filepath.Join(primaryDirectory, primaryCertificate.CAFile))
	primary := startIntegrationNode(t, primaryConfigurationPath, primaryClient, primaryPorts.https)

	initializePrimary(t, primaryClient, primaryPorts.https)
	enrollment := createEnrollmentToken(t, primaryClient, primaryPorts.https)

	replicaCertificate := generateClusterCertificate(t, replicaDirectory, "replica")
	replicaConfiguration := integrationNodeConfiguration(replicaDirectory, replicaPorts, "replica", replicaCertificate)
	replicaConfiguration.Blocking.Enabled = false
	replicaConfiguration.QueryLog.Enabled = true
	replicaConfigurationPath := writeIntegrationConfiguration(t, replicaDirectory, replicaConfiguration)
	replicaClient := trustedHTTPClient(t, filepath.Join(replicaDirectory, replicaCertificate.CAFile))
	replica := startIntegrationNode(t, replicaConfigurationPath, replicaClient, replicaPorts.https)

	joinReplica(t, replicaClient, replicaPorts.https, primaryPorts.https, enrollment.Token)
	waitForClusterState(t, primary, primaryClient, primaryPorts.https, func(state cluster.State) bool {
		return state.Connected == 2 && state.Synchronized == 2 && len(state.Nodes) == 2
	})
	replicaState := waitForClusterState(t, replica, replicaClient, replicaPorts.https, func(state cluster.State) bool {
		return state.Initialized && state.LocalRole == cluster.RoleReplica && state.Synchronized == 2
	})
	if replicaState.PrimaryURL != "https://"+primaryPorts.https {
		t.Fatalf("replica primary URL = %q", replicaState.PrimaryURL)
	}

	waitForBlockedDNSResponse(t, replica, replicaPorts.dns, initialBlockedDomain)
	addBlockedDomain(t, primaryClient, primaryPorts.https, primaryConfigurationPath, updatedBlockedDomain)
	updatedPrimaryState := waitForClusterState(t, primary, primaryClient, primaryPorts.https, func(state cluster.State) bool {
		return state.Generation > replicaState.Generation
	})
	updatedReplicaState := waitForClusterState(t, replica, replicaClient, replicaPorts.https, func(state cluster.State) bool {
		return state.Generation == updatedPrimaryState.Generation && state.Synchronized == 2
	})
	waitForBlockedDNSResponse(t, replica, replicaPorts.dns, updatedBlockedDomain)
	if updatedReplicaState.Generation != updatedPrimaryState.Generation {
		t.Fatalf("cluster generations after update: primary=%d replica=%d", updatedPrimaryState.Generation, updatedReplicaState.Generation)
	}
	waitForClusterState(t, primary, primaryClient, primaryPorts.https, func(state cluster.State) bool {
		return state.Generation == updatedPrimaryState.Generation && state.Connected == 2 && state.Synchronized == 2
	})

	var handoffState cluster.State
	requestJSON(t, primaryClient, http.MethodPost,
		"https://"+primaryPorts.https+"/api/v1/cluster/nodes/"+replicaState.NodeID+"/promote",
		nil, http.StatusOK, &handoffState)
	if handoffState.LocalRole != cluster.RoleReplica || handoffState.PrimaryID != replicaState.NodeID {
		t.Fatalf("former primary after planned handoff = %#v", handoffState)
	}
	promotedReplicaState := waitForClusterState(t, replica, replicaClient, replicaPorts.https, func(state cluster.State) bool {
		return state.LocalRole == cluster.RolePrimary && state.PrimaryID == state.NodeID && state.Generation >= handoffState.Generation
	})
	addBlockedDomain(t, replicaClient, replicaPorts.https, replicaConfigurationPath, handoffBlockedDomain)
	promotedGeneration := waitForClusterState(t, replica, replicaClient, replicaPorts.https, func(state cluster.State) bool {
		return state.Generation > promotedReplicaState.Generation
	}).Generation
	waitForClusterState(t, primary, primaryClient, primaryPorts.https, func(state cluster.State) bool {
		return state.LocalRole == cluster.RoleReplica && state.PrimaryID == replicaState.NodeID && state.Generation == promotedGeneration
	})
	waitForBlockedDNSResponse(t, primary, primaryPorts.dns, handoffBlockedDomain)
}

func integrationNodeConfiguration(directory string, ports integrationNodePorts, nodeName string, certificate certificates.GeneratedCertificate) config.Config {
	configuration := config.Defaults()
	configuration.Server.HTTPListen = ports.http
	configuration.Server.HTTPSListen = ports.https
	configuration.Server.DNSListen = []string{ports.dns}
	configuration.Server.ShutdownTimeout = config.Duration{Duration: integrationShutdownTimeout}
	configuration.Database.DSN = filepath.Join(directory, "data", "sable.db")
	configuration.Resolver.DNSSECValidation = false
	configuration.Resolver.DNSSECTrustAnchorUpdates = false
	configuration.QueryLog.Enabled = false
	configuration.EncryptedDNS.CertificateFile = certificate.CertificateFile
	configuration.EncryptedDNS.PrivateKeyFile = certificate.PrivateKeyFile
	configuration.Security.Enabled = false
	configuration.Cluster.NodeName = nodeName
	configuration.Cluster.AdvertiseURL = "https://" + ports.https
	configuration.Cluster.TrustAnchorFile = certificate.CAFile
	configuration.Reload.Watch = false
	return configuration
}

func generatePrimaryCertificate(t *testing.T, directory string) certificates.GeneratedCertificate {
	return generateClusterCertificate(t, directory, "primary")
}

func generateClusterCertificate(t *testing.T, directory, nodeName string) certificates.GeneratedCertificate {
	t.Helper()
	generated, err := certificates.New(nil, integrationLogger(io.Discard), directory).GenerateClusterPKI(
		context.Background(),
		certificates.ClusterPKIOptions{
			NodeName: nodeName, Names: []string{"127.0.0.1"},
			StorageDirectory: "data/cluster/pki", ValidFor: clusterCertificateLife,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return generated
}

func generateReplicaCertificate(t *testing.T, directory string) certificates.GeneratedCertificate {
	t.Helper()
	generated, err := certificates.New(nil, integrationLogger(io.Discard), directory).GenerateSelfSigned(
		context.Background(),
		certificates.ManualCertificateOptions{
			Names: []string{"127.0.0.1"}, StorageDirectory: "data/tls/self-signed", ValidFor: clusterCertificateLife,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return generated
}

func writeIntegrationConfiguration(t *testing.T, directory string, configuration config.Config) string {
	t.Helper()
	contents, err := toml.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "sable.toml")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func startIntegrationNode(t *testing.T, configurationPath string, client *http.Client, httpsAddress string) *runningIntegrationNode {
	t.Helper()
	logs := &synchronizedBuffer{}
	node := &runningIntegrationNode{done: make(chan error, 1), logs: logs}
	if binaryPath := strings.TrimSpace(os.Getenv("SABLE_INTEGRATION_BINARY")); binaryPath != "" {
		command := exec.Command(binaryPath, "serve", "--config", configurationPath)
		command.Stdout = logs
		command.Stderr = logs
		if err := command.Start(); err != nil {
			t.Fatalf("start Sable integration binary: %v", err)
		}
		node.cancel = func() {
			_ = command.Process.Signal(os.Interrupt)
		}
		go func() { node.done <- command.Wait() }()
	} else {
		ctx, cancel := context.WithCancel(context.Background())
		node.cancel = cancel
		go func() {
			node.done <- app.Run(ctx, configurationPath, integrationLogger(logs))
		}()
	}
	t.Cleanup(func() { stopIntegrationNode(t, node) })
	waitForCondition(t, node, func() bool {
		response, err := client.Get("https://" + httpsAddress + "/api/v1/health")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK
	})
	return node
}

func stopIntegrationNode(t *testing.T, node *runningIntegrationNode) {
	t.Helper()
	node.stop.Do(func() {
		node.cancel()
		select {
		case err := <-node.done:
			if err != nil {
				t.Errorf("stop Sable integration node: %v\n%s", err, node.logs.String())
			}
		case <-time.After(clusterIntegrationTimeout):
			t.Errorf("Sable integration node did not stop\n%s", node.logs.String())
		}
	})
}

func initializePrimary(t *testing.T, client *http.Client, httpsAddress string) {
	t.Helper()
	requestJSON(t, client, http.MethodPost, "https://"+httpsAddress+"/api/v1/cluster", map[string]any{
		"domain": "integration.sable.test", "addresses": []string{"127.0.0.1"},
	}, http.StatusCreated, nil)
}

func createEnrollmentToken(t *testing.T, client *http.Client, httpsAddress string) cluster.EnrollmentToken {
	t.Helper()
	var enrollment cluster.EnrollmentToken
	requestJSON(t, client, http.MethodPost, "https://"+httpsAddress+"/api/v1/cluster/enrollment-tokens", map[string]string{
		"ttl": "5m",
	}, http.StatusCreated, &enrollment)
	if enrollment.Token == "" {
		t.Fatal("primary returned an empty enrollment token")
	}
	return enrollment
}

func joinReplica(t *testing.T, client *http.Client, replicaHTTPSAddress, primaryHTTPSAddress, token string) {
	t.Helper()
	form := url.Values{
		"primary_url": {"https://" + primaryHTTPSAddress},
		"token":       {token},
		"addresses":   {"127.0.0.1"},
	}
	response, err := client.PostForm("https://"+replicaHTTPSAddress+"/ui/cluster/join", form)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		contents, _ := io.ReadAll(response.Body)
		t.Fatalf("join replica = %d: %s", response.StatusCode, contents)
	}
}

func addBlockedDomain(t *testing.T, client *http.Client, httpsAddress, configurationPath, domain string) {
	t.Helper()
	response, err := client.PostForm("https://"+httpsAddress+"/ui/blocking/domains/add", url.Values{"domain": {domain}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		contents, _ := io.ReadAll(response.Body)
		t.Fatalf("add blocked domain = %d: %s", response.StatusCode, contents)
	}
	updated, err := config.Load(configurationPath)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(updated.Blocking.Domains, domain) {
		t.Fatalf("primary configuration does not contain blocked domain %q", domain)
	}
}

func waitForClusterState(t *testing.T, node *runningIntegrationNode, client *http.Client, httpsAddress string, ready func(cluster.State) bool) cluster.State {
	t.Helper()
	var state cluster.State
	waitForConditionWithDetails(t, node, func() bool {
		state = fetchClusterState(t, client, httpsAddress)
		return ready(state)
	}, func() any {
		return state
	})
	return state
}

func fetchClusterState(t *testing.T, client *http.Client, httpsAddress string) cluster.State {
	t.Helper()
	var state cluster.State
	requestJSON(t, client, http.MethodGet, "https://"+httpsAddress+"/api/v1/cluster", nil, http.StatusOK, &state)
	return state
}

func waitForBlockedDNSResponse(t *testing.T, node *runningIntegrationNode, dnsAddress, domain string) {
	t.Helper()
	waitForCondition(t, node, func() bool {
		result, err := dnsclient.Query(context.Background(), dnsclient.Request{
			Server: dnsAddress, Name: domain, Type: "TXT", Transport: "udp", Timeout: time.Second,
		})
		if err != nil || result.Response.Rcode != dns.RcodeSuccess || len(result.Response.Answer) != 1 {
			return false
		}
		report, ok := result.Response.Answer[0].(*dns.TXT)
		return ok && len(report.Txt) == 1 && report.Txt[0] == "blocked by Sable"
	})
}

func waitForCondition(t *testing.T, node *runningIntegrationNode, condition func() bool) {
	t.Helper()
	waitForConditionWithDetails(t, node, condition, nil)
}

func waitForConditionWithDetails(t *testing.T, node *runningIntegrationNode, condition func() bool, details func() any) {
	t.Helper()
	deadline := time.Now().Add(clusterIntegrationTimeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-node.done:
			t.Fatalf("Sable integration node stopped early: %v\n%s", err, node.logs.String())
		default:
		}
		if condition() {
			return
		}
		time.Sleep(clusterPollingInterval)
	}
	if details != nil {
		t.Fatalf("timed out waiting for Sable integration node; last observed state: %#v\n%s", details(), node.logs.String())
	}
	t.Fatalf("timed out waiting for Sable integration node\n%s", node.logs.String())
}

func requestJSON(t *testing.T, client *http.Client, method, endpoint string, input any, expectedStatus int, output any) {
	t.Helper()
	var body io.Reader
	if input != nil {
		contents, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		body = strings.NewReader(string(contents))
	}
	request, err := http.NewRequestWithContext(context.Background(), method, endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		contents, _ := io.ReadAll(response.Body)
		t.Fatalf("%s %s = %d: %s", method, endpoint, response.StatusCode, contents)
	}
	if output != nil {
		if err := json.NewDecoder(response.Body).Decode(output); err != nil {
			t.Fatal(err)
		}
	}
}

func trustedHTTPClient(t *testing.T, certificatePath string) *http.Client {
	t.Helper()
	certificate, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatalf("load trusted certificate %s", certificatePath)
	}
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots,
		}},
	}
}

func allocateIntegrationNodePorts(t *testing.T) integrationNodePorts {
	t.Helper()
	return integrationNodePorts{http: allocateTCPAddress(t), https: allocateTCPAddress(t), dns: allocateTCPAddress(t)}
}

func allocateTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate local integration-test listener: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func integrationLogger(writer io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
