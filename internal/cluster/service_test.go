package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/certificates"
)

func TestValidatePrimaryURLRejectsMalformedHostname(t *testing.T) {
	t.Parallel()
	if _, err := validatePrimaryURL("https://localhoist;5443"); err == nil || !strings.Contains(err.Error(), "valid hostname") {
		t.Fatalf("malformed primary URL error = %v", err)
	}
	for _, value := range []string{"https://localhost:5443", "https://dns-1.example.test:5443", "https://127.0.0.1:5443", "https://[::1]:5443"} {
		if _, err := validatePrimaryURL(value); err != nil {
			t.Errorf("valid primary URL %q: %v", value, err)
		}
	}
}

func TestNodeIdentityPersistsAcrossOpen(t *testing.T) {
	directory := t.TempDir()
	first, err := Open(Options{DataDirectory: directory, NodeName: "dns-1"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(Options{DataDirectory: directory, NodeName: "dns-1"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Snapshot().NodeID != second.Snapshot().NodeID {
		t.Fatal("node identity changed across restart")
	}
	info, err := os.Stat(filepath.Join(directory, identityFileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("node identity permissions: info=%v error=%v", info, err)
	}
}

func TestCloseStopsAndJoinsMonitoring(t *testing.T) {
	t.Parallel()

	service, err := Open(Options{DataDirectory: t.TempDir(), NodeName: "dns-1"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	service.StartMonitoring(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-service.monitorDone:
	default:
		t.Fatal("Close() returned before the monitoring worker stopped")
	}
	if err := service.Close(ctx); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestCloseBeforeMonitoringPreventsWorkerStart(t *testing.T) {
	t.Parallel()

	service, err := Open(Options{DataDirectory: t.TempDir(), NodeName: "dns-1"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := service.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	service.StartMonitoring(context.Background())

	service.monitorLifecycleMu.Lock()
	done := service.monitorDone
	service.monitorLifecycleMu.Unlock()
	if done != nil {
		t.Fatal("StartMonitoring() started a worker after Close()")
	}
}

func TestNormalizeAddressesAcceptsOptionalDNSPort(t *testing.T) {
	t.Parallel()
	addresses, err := normalizeAddresses([]string{"127.0.0.1:8054", "[2001:db8::53]:5353", "192.0.2.53"})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"127.0.0.1:8054", "192.0.2.53", "[2001:db8::53]:5353"} {
		if !slices.Contains(addresses, expected) {
			t.Errorf("addresses %#v do not contain %q", addresses, expected)
		}
	}
	if _, err := normalizeAddresses([]string{"dns.example:53"}); err == nil || !strings.Contains(err.Error(), "optional port") {
		t.Fatalf("hostname address error = %v", err)
	}
}

func TestEffectiveDNSAddressesAddsNonstandardListenerPort(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		addresses []string
		listeners []string
		expected  string
	}{
		{name: "matching IPv4 listener", addresses: []string{"127.0.0.1"}, listeners: []string{"127.0.0.1:8054"}, expected: "127.0.0.1:8054"},
		{name: "wildcard listener", addresses: []string{"192.0.2.53"}, listeners: []string{"0.0.0.0:5353"}, expected: "192.0.2.53:5353"},
		{name: "explicit port wins", addresses: []string{"127.0.0.1:9953"}, listeners: []string{"127.0.0.1:8054"}, expected: "127.0.0.1:9953"},
		{name: "standard port remains concise", addresses: []string{"192.0.2.53"}, listeners: []string{"0.0.0.0:53"}, expected: "192.0.2.53"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			actual := effectiveDNSAddresses(test.addresses, test.listeners)
			if len(actual) != 1 || actual[0] != test.expected {
				t.Fatalf("effectiveDNSAddresses() = %#v, want %q", actual, test.expected)
			}
		})
	}
}

func TestHeartbeatRefreshesReplicaDNSServiceEndpoint(t *testing.T) {
	primary, err := Open(Options{DataDirectory: t.TempDir(), NodeName: "ns1", AdvertiseURL: "https://ns1.example:5443"})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	token, err := primary.CreateEnrollmentToken(context.Background(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replicaID := "11111111-1111-4111-8111-111111111111"
	if _, err := primary.Enroll(context.Background(), JoinRequest{
		Token: token.Token, NodeID: replicaID, Name: "ns2",
		AdvertiseURL: "https://ns2.example:5444", Addresses: []string{"127.0.0.1"}, Version: "dev",
	}); err != nil {
		t.Fatal(err)
	}
	before := primary.Snapshot().Generation
	heartbeat := Heartbeat{
		NodeID: replicaID, Name: "ns2", AdvertiseURL: "https://ns2.example:5444",
		Addresses: []string{"127.0.0.1:8054"}, Version: "dev",
		AppliedGeneration: before, SentAt: time.Now(), UpSince: time.Now().Add(-time.Minute),
	}
	if _, err := primary.Synchronize(context.Background(), heartbeat, heartbeatSignature(primary.manifest.StatusKey, heartbeat)); err != nil {
		t.Fatal(err)
	}
	after := primary.Snapshot()
	if after.Generation != before+1 {
		t.Fatalf("generation = %d, want %d", after.Generation, before+1)
	}
	index := slices.IndexFunc(after.Nodes, func(node Node) bool { return node.ID == replicaID })
	if index < 0 || len(after.Nodes[index].Addresses) != 1 || after.Nodes[index].Addresses[0] != "127.0.0.1:8054" {
		t.Fatalf("replica addresses = %#v", after.Nodes)
	}
}

func TestInitializePersistsPrimaryManifest(t *testing.T) {
	directory := t.TempDir()
	startedAt := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	service, err := Open(Options{
		DataDirectory: directory, NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380/",
		Version: "0.1.0", StartedAt: startedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Initialize(context.Background(), "CLUSTER.EXAMPLE.", []string{"2001:db8::1", "192.0.2.10", "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	state := service.Snapshot()
	if !state.Initialized || state.ClusterDomain != "cluster.example" || state.Generation != 1 || state.Mode != "primary-replica" {
		t.Fatalf("unexpected state: %#v", state)
	}
	if state.PrimaryID != state.NodeID || state.LocalRole != RolePrimary || state.Connected != 1 || state.Synchronized != 1 {
		t.Fatalf("unexpected primary state: %#v", state)
	}
	if len(state.Nodes) != 1 || state.Nodes[0].Role != RolePrimary || state.Nodes[0].AppliedGeneration != 1 || state.Nodes[0].SyncState != SyncCurrent {
		t.Fatalf("unexpected nodes: %#v", state.Nodes)
	}
	if got := state.Nodes[0].Addresses; len(got) != 2 || got[0] != "192.0.2.10" || got[1] != "2001:db8::1" {
		t.Fatalf("addresses = %#v", got)
	}
	reopened, err := Open(Options{DataDirectory: directory, NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380"})
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Snapshot().ClusterID != state.ClusterID || reopened.Snapshot().Generation != 1 {
		t.Fatal("cluster manifest did not persist")
	}
	if err := reopened.Initialize(context.Background(), "other.example", []string{"192.0.2.20"}); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second Initialize() error = %v", err)
	}
}

func TestEnrollmentCreatesReplicaAndTokenIsSingleUse(t *testing.T) {
	directory := t.TempDir()
	primary, err := Open(Options{DataDirectory: directory, NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380"})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	token, err := primary.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(directory, enrollmentFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), token.Token) {
		t.Fatal("enrollment token was stored in plaintext")
	}
	nodeID, _ := newID()
	joined, err := primary.Enroll(context.Background(), JoinRequest{
		Token: token.Token, NodeID: nodeID, Name: "dns-2", AdvertiseURL: "https://dns-2.example:5380",
		Addresses: []string{"192.0.2.2"}, Version: "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if joined.Generation != 2 || joined.PrimaryID != primary.nodeID || len(joined.Members) != 2 {
		t.Fatalf("enrollment response = %#v", joined)
	}
	index := slices.IndexFunc(primary.Snapshot().Nodes, func(node Node) bool { return node.ID == nodeID })
	if index < 0 || primary.Snapshot().Nodes[index].Role != RoleReplica {
		t.Fatalf("replica missing after enrollment: %#v", primary.Snapshot())
	}
	otherID, _ := newID()
	_, err = primary.Enroll(context.Background(), JoinRequest{
		Token: token.Token, NodeID: otherID, Name: "dns-3", AdvertiseURL: "https://dns-3.example:5380", Addresses: []string{"192.0.2.3"},
	})
	if !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("reused token error = %v", err)
	}
}

func TestPrivateClusterCATrustIsBundledAndPersistsOnReplica(t *testing.T) {
	primaryDirectory := t.TempDir()
	certificateManager := certificates.New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), primaryDirectory)
	generated, err := certificateManager.GenerateClusterPKI(context.Background(), certificates.ClusterPKIOptions{
		NodeName: "dns-1", Names: []string{"127.0.0.1"}, StorageDirectory: "pki", ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	primary, err := Open(Options{
		DataDirectory: primaryDirectory,
		NodeName:      "dns-1", AdvertiseURL: "https://127.0.0.1:5443",
		TrustAnchorFile: filepath.Join(primaryDirectory, generated.CAFile),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	token, err := primary.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token.Token, enrollmentBundlePrefix) {
		t.Fatalf("enrollment token does not carry private trust: %q", token.Token)
	}
	rawToken, trustAnchor, err := decodeEnrollmentBundle(token.Token)
	if err != nil || rawToken == token.Token || len(trustAnchor) == 0 {
		t.Fatalf("decode enrollment bundle: token=%q trust=%d error=%v", rawToken, len(trustAnchor), err)
	}
	certificatePEM, err := os.ReadFile(filepath.Join(primaryDirectory, generated.CertificateFile))
	if err != nil {
		t.Fatal(err)
	}
	certificateBlock, _ := pem.Decode(certificatePEM)
	if certificateBlock == nil {
		t.Fatal("generated node certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	trustedClient, err := httpClientWithClusterTrust(nil, trustAnchor)
	if err != nil {
		t.Fatal(err)
	}
	transport := trustedClient.Transport.(*http.Transport)
	if subjects := transport.TLSClientConfig.RootCAs.Subjects(); len(subjects) != 1 {
		t.Fatalf("cluster trust pool contains %d roots, want the pinned cluster CA only", len(subjects))
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "127.0.0.1", Roots: transport.TLSClientConfig.RootCAs}); err != nil {
		t.Fatalf("bundled CA does not trust the leader certificate: %v", err)
	}
	privateKeyPEM, err := os.ReadFile(filepath.Join(primaryDirectory, generated.PrivateKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	keyPair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	serverConnection, clientConnection := net.Pipe()
	defer serverConnection.Close()
	defer clientConnection.Close()
	serverTLS := tls.Server(serverConnection, &tls.Config{Certificates: []tls.Certificate{keyPair}, MinVersion: tls.VersionTLS13})
	clientConfiguration := transport.TLSClientConfig.Clone()
	clientConfiguration.ServerName = "127.0.0.1"
	clientTLS := tls.Client(clientConnection, clientConfiguration)
	serverHandshake := make(chan error, 1)
	go func() { serverHandshake <- serverTLS.Handshake() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake with bundled cluster CA: %v", err)
	}
	if err := <-serverHandshake; err != nil {
		t.Fatalf("server handshake with bundled cluster CA: %v", err)
	}

	replicaDirectory := t.TempDir()
	trustPath, err := writeClusterTrustAnchor(replicaDirectory, trustAnchor)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(trustPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("persisted trust anchor: info=%v error=%v", info, err)
	}

	reopened, err := Open(Options{DataDirectory: replicaDirectory, NodeName: "dns-2", AdvertiseURL: "https://dns-2.example:5380"})
	if err != nil {
		t.Fatal(err)
	}
	reopenedTransport := reopened.httpClient.Transport.(*http.Transport)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "127.0.0.1", Roots: reopenedTransport.TLSClientConfig.RootCAs}); err != nil {
		t.Fatalf("persisted cluster trust was not loaded: %v", err)
	}

	replicaCertificateManager := certificates.New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), replicaDirectory)
	replicaCertificate, err := replicaCertificateManager.GenerateClusterPKI(context.Background(), certificates.ClusterPKIOptions{
		NodeName: "dns-2", Names: []string{"dns-2.example"}, StorageDirectory: "replica-pki", ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	withLocalIdentity, err := Open(Options{
		DataDirectory: replicaDirectory, NodeName: "dns-2", AdvertiseURL: "https://dns-2.example:5380",
		TrustAnchorFile: filepath.Join(replicaDirectory, replicaCertificate.CAFile),
	})
	if err != nil {
		t.Fatal(err)
	}
	identityTransport := withLocalIdentity.httpClient.Transport.(*http.Transport)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "127.0.0.1", Roots: identityTransport.TLSClientConfig.RootCAs}); err != nil {
		t.Fatalf("local node identity displaced persisted primary trust: %v", err)
	}
}

func TestReplicaJoinSyncAndManualPromotion(t *testing.T) {
	primary, err := Open(Options{DataDirectory: t.TempDir(), NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380"})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	token, err := primary.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replicaClient := &http.Client{Transport: serviceRoundTripper{primary: primary}}
	replica, err := Open(Options{
		DataDirectory: t.TempDir(), NodeName: "dns-2", AdvertiseURL: "https://dns-2.example:5380", HTTPClient: replicaClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.Join(context.Background(), JoinOptions{PrimaryURL: "https://dns-1.example:5380", Token: token.Token, Addresses: []string{"192.0.2.2"}}); err != nil {
		t.Fatal(err)
	}
	if state := replica.Snapshot(); state.LocalRole != RoleReplica || state.Generation != 2 || state.PrimaryID != primary.nodeID || state.Synchronized != 0 || state.Nodes[1].SyncState != "unverified" {
		t.Fatalf("unverified replica state = %#v", state)
	}
	if state := primary.Snapshot(); len(state.Nodes) != 2 || state.Nodes[0].ID != primary.nodeID || state.Nodes[0].Role != RolePrimary {
		t.Fatalf("primary is not first in cluster nodes: %#v", state.Nodes)
	}
	primary.StartMonitoring(context.Background())
	if err := replica.syncFromPrimary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := replica.Snapshot(); state.Synchronized != 2 || state.Nodes[0].SyncState != SyncCurrent || state.Nodes[1].SyncState != SyncCurrent {
		t.Fatalf("verified replica state = %#v", state)
	}
	state := primary.Snapshot()
	index := slices.IndexFunc(state.Nodes, func(node Node) bool { return node.ID == replica.nodeID })
	if index < 0 || state.Nodes[index].State != StateOnline || state.Nodes[index].SyncState != SyncCurrent {
		t.Fatalf("primary telemetry = %#v", state)
	}
	if err := replica.Promote(context.Background(), replica.nodeID); err != nil {
		t.Fatal(err)
	}
	if state := replica.Snapshot(); state.LocalRole != RolePrimary || state.PrimaryID != replica.nodeID || state.Generation != 3 {
		t.Fatalf("promoted state = %#v", state)
	}
}

func TestPrimaryHandsOffToReplicaOnNextSynchronization(t *testing.T) {
	primary, err := Open(Options{
		DataDirectory: t.TempDir(), NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	token, err := primary.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replicaDirectory := t.TempDir()
	replica, err := Open(Options{
		DataDirectory: replicaDirectory, NodeName: "dns-2", AdvertiseURL: "https://dns-2.example:5380",
		HTTPClient: &http.Client{Transport: serviceRoundTripper{primary: primary}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.Join(context.Background(), JoinOptions{
		PrimaryURL: "https://dns-1.example:5380", Token: token.Token, Addresses: []string{"192.0.2.2"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := replica.syncFromPrimary(context.Background()); err != nil {
		t.Fatalf("initial replica synchronization: %v", err)
	}
	if err := primary.Promote(context.Background(), replica.nodeID); err != nil {
		t.Fatalf("planned primary handoff: %v", err)
	}
	if state := primary.Snapshot(); state.PrimaryID != replica.nodeID || state.LocalRole != RoleReplica {
		t.Fatalf("former primary state after handoff = %#v", state)
	}
	if err := replica.syncFromPrimary(context.Background()); err != nil {
		t.Fatalf("replica converge planned handoff: %v", err)
	}
	if state := replica.Snapshot(); state.PrimaryID != replica.nodeID || state.LocalRole != RolePrimary || state.Generation != 3 {
		t.Fatalf("promoted replica state = %#v", state)
	}
	primary.baseHTTPClient = &http.Client{Transport: serviceRoundTripper{primary: replica}}
	if err := primary.syncFromPrimary(context.Background()); err != nil {
		t.Fatalf("former primary synchronize from promoted replica: %v", err)
	}
	if state := primary.Snapshot(); state.PrimaryID != replica.nodeID || state.LocalRole != RoleReplica || state.Generation != 3 {
		t.Fatalf("former primary after reverse synchronization = %#v", state)
	}
	if err := primary.Promote(context.Background(), "00000000-0000-4000-8000-000000000000"); err == nil {
		t.Fatal("replica promoted a different, unknown node")
	}
}

func TestReplicaSynchronizationEndpointDoesNotCreateMembershipGeneration(t *testing.T) {
	primary, replica := joinedClusterServices(t)
	before := replica.Snapshot()
	heartbeat := Heartbeat{
		NodeID: primary.nodeID, Name: "changed-primary", AdvertiseURL: "https://changed-primary.example:5380",
		Version: "changed", Addresses: []string{"192.0.2.99"}, AppliedGeneration: before.Generation,
		StateDigest: replica.manifest.StateDigest, UpSince: time.Now(), SentAt: time.Now(),
	}
	if _, err := replica.Synchronize(context.Background(), heartbeat, heartbeatSignature(replica.manifest.StatusKey, heartbeat)); err != nil {
		t.Fatal(err)
	}
	after := replica.Snapshot()
	if after.Generation != before.Generation || after.PrimaryID != before.PrimaryID {
		t.Fatalf("replica synchronization endpoint changed membership: before=%#v after=%#v", before, after)
	}
}

func TestReplicaAcceptsEqualGenerationHandoffFromTrustedPrimary(t *testing.T) {
	primary, replica := joinedClusterServices(t)
	if err := primary.Promote(context.Background(), replica.nodeID); err != nil {
		t.Fatal(err)
	}

	replica.mu.Lock()
	conflicting := cloneManifest(replica.manifest)
	conflicting.Generation = primary.manifest.Generation
	conflicting.UpdatedAt = time.Now()
	replica.manifest = conflicting
	replica.mu.Unlock()

	if err := replica.syncFromPrimary(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := replica.Snapshot()
	if state.LocalRole != RolePrimary || state.PrimaryID != replica.nodeID || state.Generation != primary.manifest.Generation {
		t.Fatalf("equal-generation handoff was not applied: %#v", state)
	}
}

func joinedClusterServices(t *testing.T) (*Service, *Service) {
	t.Helper()
	primary, err := Open(Options{
		DataDirectory: t.TempDir(), NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	token, err := primary.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := Open(Options{
		DataDirectory: t.TempDir(), NodeName: "dns-2", AdvertiseURL: "https://dns-2.example:5380",
		HTTPClient: &http.Client{Transport: serviceRoundTripper{primary: primary}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.Join(context.Background(), JoinOptions{
		PrimaryURL: "https://dns-1.example:5380", Token: token.Token, Addresses: []string{"192.0.2.2"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := replica.syncFromPrimary(context.Background()); err != nil {
		t.Fatal(err)
	}
	return primary, replica
}

func TestPlannedHandoffTrustsPromotedReplicasPrivateCA(t *testing.T) {
	primary, err := Open(Options{
		DataDirectory: t.TempDir(), NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	replicaDirectory := t.TempDir()
	manager := certificates.New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), replicaDirectory)
	generated, err := manager.GenerateClusterPKI(context.Background(), certificates.ClusterPKIOptions{
		NodeName: "dns-2", Names: []string{"dns-2.example"}, StorageDirectory: "pki", ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	replicaCA, err := os.ReadFile(filepath.Join(replicaDirectory, generated.CAFile))
	if err != nil {
		t.Fatal(err)
	}
	token, err := primary.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replicaID, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := primary.Enroll(context.Background(), JoinRequest{
		Token: token.Token, NodeID: replicaID, Name: "dns-2", AdvertiseURL: "https://dns-2.example:5380",
		TrustAnchor: string(replicaCA), Addresses: []string{"192.0.2.2"},
	}); err != nil {
		t.Fatal(err)
	}
	primary.telemetry[replicaID] = nodeTelemetry{
		heartbeat: Heartbeat{NodeID: replicaID, AppliedGeneration: primary.manifest.Generation, StateDigest: primary.manifest.StateDigest},
		received:  primary.clock(),
	}
	if err := primary.Promote(context.Background(), replicaID); err != nil {
		t.Fatal(err)
	}
	promoted, found := manifestMember(primary.manifest, replicaID)
	if !found {
		t.Fatal("promoted replica missing from manifest")
	}
	client, err := primary.httpClientForMember(promoted)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	certificatePEM, err := os.ReadFile(filepath.Join(replicaDirectory, generated.CertificateFile))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		t.Fatal("replica certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "dns-2.example", Roots: transport.TLSClientConfig.RootCAs}); err != nil {
		t.Fatalf("former primary does not trust promoted replica: %v", err)
	}
}

func TestClusterNodesOrderPrimaryThenReplicasByName(t *testing.T) {
	nodes := []Node{
		{ID: "replica-z", Name: "Zulu", Role: RoleReplica},
		{ID: "replica-a", Name: "alpha", Role: RoleReplica},
		{ID: "primary", Name: "middle", Role: RolePrimary},
	}
	sortClusterNodes(nodes, "primary")
	want := []string{"primary", "replica-a", "replica-z"}
	for index, node := range nodes {
		if node.ID != want[index] {
			t.Fatalf("node %d = %q, want %q (all nodes: %#v)", index, node.ID, want[index], nodes)
		}
	}
}

func TestPrimaryRemovesReplicaMembership(t *testing.T) {
	primary, err := Open(Options{DataDirectory: t.TempDir(), NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380"})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	token, err := primary.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replicaDirectory := t.TempDir()
	replica, err := Open(Options{
		DataDirectory: replicaDirectory, NodeName: "dns-2", AdvertiseURL: "https://dns-2.example:5380",
		HTTPClient: &http.Client{Transport: serviceRoundTripper{primary: primary}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.Join(context.Background(), JoinOptions{
		PrimaryURL: "https://dns-1.example:5380", Token: token.Token, Addresses: []string{"192.0.2.2"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := primary.Remove(context.Background(), replica.nodeID); err != nil {
		t.Fatal(err)
	}
	state := primary.Snapshot()
	if len(state.Nodes) != 1 || state.Nodes[0].ID != primary.nodeID {
		t.Fatalf("cluster nodes after removal = %#v", state.Nodes)
	}
	if state.Generation != 3 {
		t.Fatalf("cluster generation after removal = %d, want 3", state.Generation)
	}
	replicaNodeID := replica.nodeID
	if err := replica.syncFromPrimary(context.Background()); err != nil {
		t.Fatalf("replica apply membership removal: %v", err)
	}
	if state := replica.Snapshot(); state.Initialized || state.NodeID != replicaNodeID || len(state.Nodes) != 0 {
		t.Fatalf("removed replica retained cluster membership: %#v", state)
	}
	if _, err := os.Stat(filepath.Join(replicaDirectory, manifestFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed replica manifest still exists: %v", err)
	}
	if err := primary.Delete(context.Background()); err != nil {
		t.Fatalf("delete single-node cluster after removal: %v", err)
	}
}

func TestReplicaLeavesClusterAndPreservesLocalIdentityAndDNSState(t *testing.T) {
	primaryState := &memoryStateReplicator{contents: []byte(`{"zones":["example.test"]}`)}
	primary, err := Open(Options{
		DataDirectory: t.TempDir(), NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380",
		Replicator: primaryState,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if err := primary.Leave(context.Background()); err == nil || !strings.Contains(err.Error(), "primary cannot leave") {
		t.Fatalf("primary leave error = %v", err)
	}
	token, err := primary.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replicaDirectory := t.TempDir()
	replicaState := &memoryStateReplicator{}
	replica, err := Open(Options{
		DataDirectory: replicaDirectory, NodeName: "dns-2", AdvertiseURL: "https://dns-2.example:5380",
		HTTPClient: &http.Client{Transport: serviceRoundTripper{primary: primary}}, Replicator: replicaState,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.Join(context.Background(), JoinOptions{
		PrimaryURL: "https://dns-1.example:5380", Token: token.Token, Addresses: []string{"192.0.2.2"},
	}); err != nil {
		t.Fatal(err)
	}
	replicaNodeID := replica.nodeID
	if err := replica.Leave(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := replica.Snapshot(); state.Initialized || state.NodeID != replicaNodeID || len(state.Nodes) != 0 {
		t.Fatalf("replica retained cluster membership after leave: %#v", state)
	}
	if got := string(replicaState.current()); got != `{"zones":["example.test"]}` {
		t.Fatalf("replicated DNS state after leave = %s", got)
	}
	if len(primary.Snapshot().Nodes) != 2 {
		t.Fatalf("local leave unexpectedly changed primary membership: %#v", primary.Snapshot().Nodes)
	}
	if _, err := os.Stat(filepath.Join(replicaDirectory, manifestFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replica manifest still exists after leave: %v", err)
	}
	reopened, err := Open(Options{DataDirectory: replicaDirectory, NodeName: "dns-2", AdvertiseURL: "https://dns-2.example:5380"})
	if err != nil {
		t.Fatal(err)
	}
	if state := reopened.Snapshot(); state.Initialized || state.NodeID != replicaNodeID {
		t.Fatalf("reopened replica state after leave = %#v", state)
	}
}

func TestPrimaryDeletesClusterAndReleasesEnrolledReplica(t *testing.T) {
	primaryDirectory := t.TempDir()
	primary, err := Open(Options{DataDirectory: primaryDirectory, NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380"})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	token, err := primary.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := Open(Options{
		DataDirectory: t.TempDir(), NodeName: "dns-2", AdvertiseURL: "https://dns-2.example:5380",
		HTTPClient: &http.Client{Transport: serviceRoundTripper{primary: primary}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.Join(context.Background(), JoinOptions{
		PrimaryURL: "https://dns-1.example:5380", Token: token.Token, Addresses: []string{"192.0.2.2"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := primary.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := primary.Snapshot(); state.Initialized {
		t.Fatalf("deleted primary retained cluster state: %#v", state)
	}
	if _, err := os.Stat(filepath.Join(primaryDirectory, revocationsFileName)); err != nil {
		t.Fatalf("destroyed cluster record was not persisted: %v", err)
	}
	if err := primary.Initialize(context.Background(), "replacement.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if err := replica.syncFromPrimary(context.Background()); err != nil {
		t.Fatalf("release replica after cluster deletion: %v", err)
	}
	if state := replica.Snapshot(); state.Initialized {
		t.Fatalf("replica retained membership after cluster deletion: %#v", state)
	}
	reopened, err := Open(Options{DataDirectory: primaryDirectory, NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.revocations) != 1 {
		t.Fatalf("persisted destroyed cluster records = %#v", reopened.revocations)
	}
}

func TestNodeIdentityChangesSynchronizeAfterRestart(t *testing.T) {
	primary, err := Open(Options{
		DataDirectory: t.TempDir(), NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380", Version: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	token, err := primary.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := Open(Options{
		DataDirectory: t.TempDir(), NodeName: "dns-2", AdvertiseURL: "https://dns-2.example:5380", Version: "1.0.0",
		HTTPClient: &http.Client{Transport: serviceRoundTripper{primary: primary}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.Join(context.Background(), JoinOptions{
		PrimaryURL: "https://dns-1.example:5380", Token: token.Token, Addresses: []string{"192.0.2.2"},
	}); err != nil {
		t.Fatal(err)
	}
	replica.mu.Lock()
	replica.nodeName = "edge-dns"
	replica.configuredName = "edge-dns"
	replica.advertiseURL = "https://edge-dns.example:5443"
	replica.version = "1.1.0"
	replica.mu.Unlock()
	if err := replica.syncFromPrimary(context.Background()); err != nil {
		t.Fatal(err)
	}
	primaryState := primary.Snapshot()
	updatedReplica := primaryState.Nodes[1]
	if updatedReplica.ID != replica.nodeID || updatedReplica.Name != "edge-dns" || updatedReplica.AdvertiseURL != "https://edge-dns.example:5443" || updatedReplica.Version != "1.1.0" {
		t.Fatalf("primary replica identity after synchronization = %#v", updatedReplica)
	}
	if replica.Snapshot().Generation != primaryState.Generation {
		t.Fatalf("replica generation = %d, primary generation = %d", replica.Snapshot().Generation, primaryState.Generation)
	}

	primary.mu.Lock()
	primary.nodeName = "core-dns"
	primary.configuredName = "core-dns"
	primary.advertiseURL = "https://core-dns.example:5443"
	primary.version = "1.2.0"
	primary.mu.Unlock()
	if err := primary.refreshPrimaryState(context.Background()); err != nil {
		t.Fatal(err)
	}
	local := primary.Snapshot().Nodes[0]
	if local.ID != primary.nodeID || local.Name != "core-dns" || local.AdvertiseURL != "https://core-dns.example:5443" || local.Version != "1.2.0" {
		t.Fatalf("primary identity after restart reconciliation = %#v", local)
	}
}

func TestReplicaAppliesStateAtEnrollmentAndOnSynchronization(t *testing.T) {
	var primaryLogs bytes.Buffer
	var replicaLogs bytes.Buffer
	primaryState := &memoryStateReplicator{contents: []byte(`{"zones":["example.test"]}`)}
	primary, err := Open(Options{
		DataDirectory: t.TempDir(), NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380",
		Replicator: primaryState, Logger: slog.New(slog.NewTextHandler(&primaryLogs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	token, err := primary.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replicaState := &memoryStateReplicator{}
	replica, err := Open(Options{
		DataDirectory: t.TempDir(), NodeName: "dns-2", AdvertiseURL: "https://dns-2.example:5380",
		HTTPClient: &http.Client{Transport: serviceRoundTripper{primary: primary}}, Replicator: replicaState,
		Logger: slog.New(slog.NewTextHandler(&replicaLogs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.Join(context.Background(), JoinOptions{
		PrimaryURL: "https://dns-1.example:5380", Token: token.Token, Addresses: []string{"192.0.2.2"},
	}); err != nil {
		t.Fatal(err)
	}
	if got := string(replicaState.current()); got != `{"zones":["example.test"]}` {
		t.Fatalf("enrolled replica state = %q", got)
	}
	if replica.Snapshot().Generation != 2 {
		t.Fatalf("enrolled generation = %d", replica.Snapshot().Generation)
	}

	primaryState.replace([]byte(`{"zones":["example.test","internal.test"]}`))
	if err := replica.syncFromPrimary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := string(replicaState.current()); got != `{"zones":["example.test","internal.test"]}` {
		t.Fatalf("synchronized replica state = %q", got)
	}
	if replica.Snapshot().Generation != 3 {
		t.Fatalf("synchronized generation = %d", replica.Snapshot().Generation)
	}
	if logs := replicaLogs.String(); !strings.Contains(logs, `msg="cluster synchronization applied"`) || !strings.Contains(logs, "from_generation=2") || !strings.Contains(logs, "generation=3") || !strings.Contains(logs, "state_updated=true") {
		t.Fatalf("replica synchronization logs = %q", logs)
	}
	if logs := primaryLogs.String(); !strings.Contains(logs, `msg="cluster replica synchronization observed"`) || !strings.Contains(logs, "applied_generation=2") || !strings.Contains(logs, "current_generation=3") {
		t.Fatalf("primary synchronization logs = %q", logs)
	}
	if err := replica.syncFromPrimary(context.Background()); err != nil {
		t.Fatal(err)
	}
	primaryAfterConvergence := primaryLogs.String()
	replicaAfterConvergence := replicaLogs.String()
	if !strings.Contains(primaryAfterConvergence, "applied_generation=3") || !strings.Contains(primaryAfterConvergence, "sync_state=current") {
		t.Fatalf("primary convergence logs = %q", primaryAfterConvergence)
	}
	if err := replica.syncFromPrimary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if logs := primaryLogs.String(); logs != primaryAfterConvergence {
		t.Fatalf("unchanged heartbeat produced a primary log: before=%q after=%q", primaryAfterConvergence, logs)
	}
	if logs := replicaLogs.String(); logs != replicaAfterConvergence {
		t.Fatalf("unchanged synchronization produced a replica log: before=%q after=%q", replicaAfterConvergence, logs)
	}
	info, err := os.Stat(stateSnapshotPath(replica.directory, replica.manifest.StateDigest))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("replica snapshot permissions: info=%v error=%v", info, err)
	}
}

func TestReplicaCanRetryEnrollmentAfterLocalStateApplyFailure(t *testing.T) {
	primaryState := &memoryStateReplicator{contents: []byte(`{"zones":["example.test"]}`)}
	primary, err := Open(Options{
		DataDirectory: t.TempDir(), NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380",
		Replicator: primaryState,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	replicaState := &failOnceStateReplicator{failures: 1}
	replica, err := Open(Options{
		DataDirectory: t.TempDir(), NodeName: "dns-2", AdvertiseURL: "https://dns-2.example:5380",
		HTTPClient: &http.Client{Transport: serviceRoundTripper{primary: primary}}, Replicator: replicaState,
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := primary.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	options := JoinOptions{PrimaryURL: "https://dns-1.example:5380", Token: token.Token, Addresses: []string{"192.0.2.2"}}
	if err := replica.Join(context.Background(), options); err == nil {
		t.Fatal("first enrollment unexpectedly succeeded")
	}

	token, err = primary.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	options.Token = token.Token
	if err := replica.Join(context.Background(), options); err != nil {
		t.Fatalf("retry enrollment: %v", err)
	}
	if got := string(replicaState.current()); got != `{"zones":["example.test"]}` {
		t.Fatalf("replica state after retry = %q", got)
	}
	if state := primary.Snapshot(); len(state.Nodes) != 2 {
		t.Fatalf("primary nodes after retry = %d, want 2", len(state.Nodes))
	}
}

func TestDeletePreservesStableNodeIdentity(t *testing.T) {
	directory := t.TempDir()
	service, err := Open(Options{DataDirectory: directory, AdvertiseURL: "https://dns-1.example:5380"})
	if err != nil {
		t.Fatal(err)
	}
	nodeID := service.nodeID
	if err := service.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if err := service.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(Options{DataDirectory: directory})
	if err != nil {
		t.Fatal(err)
	}
	if reopened.nodeID != nodeID || reopened.Snapshot().Initialized {
		t.Fatalf("delete changed stable identity: %#v", reopened.Snapshot())
	}
}

type serviceRoundTripper struct{ primary *Service }

type memoryStateReplicator struct {
	mu       sync.Mutex
	contents []byte
}

type failOnceStateReplicator struct {
	memoryStateReplicator
	failures int
}

func (replicator *failOnceStateReplicator) Apply(_ context.Context, contents []byte) error {
	if replicator.failures > 0 {
		replicator.failures--
		return errors.New("simulated local state apply failure")
	}
	replicator.replace(contents)
	return nil
}

func (replicator *memoryStateReplicator) Capture(context.Context) ([]byte, error) {
	return replicator.current(), nil
}

func (replicator *memoryStateReplicator) Apply(_ context.Context, contents []byte) error {
	replicator.replace(contents)
	return nil
}

func (replicator *memoryStateReplicator) current() []byte {
	replicator.mu.Lock()
	defer replicator.mu.Unlock()
	return append([]byte(nil), replicator.contents...)
}

func (replicator *memoryStateReplicator) replace(contents []byte) {
	replicator.mu.Lock()
	defer replicator.mu.Unlock()
	replicator.contents = append([]byte(nil), contents...)
}

func (roundTripper serviceRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	status := http.StatusOK
	var body any
	switch request.URL.Path {
	case enrollmentPath:
		var input JoinRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			return nil, err
		}
		configuration, err := roundTripper.primary.Enroll(request.Context(), input)
		body = configuration
		status = http.StatusCreated
		if err != nil {
			body = map[string]string{"error": err.Error()}
			status = http.StatusUnprocessableEntity
		}
	case syncPath:
		var heartbeat Heartbeat
		if err := json.NewDecoder(request.Body).Decode(&heartbeat); err != nil {
			return nil, err
		}
		configuration, err := roundTripper.primary.Synchronize(request.Context(), heartbeat, request.Header.Get("X-Sable-Cluster-Signature"))
		body = configuration
		if err != nil {
			body = map[string]string{"error": err.Error()}
			if errors.Is(err, ErrNodeRemoved) {
				status = http.StatusGone
			} else {
				status = http.StatusUnprocessableEntity
			}
		}
	default:
		status = http.StatusNotFound
		body = map[string]string{"error": "not found"}
	}
	contents, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status), Header: make(http.Header),
		Body: io.NopCloser(bytes.NewReader(contents)), Request: request,
	}, nil
}
