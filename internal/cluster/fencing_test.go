package cluster

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// hostRoundTripper delivers each request to the service at the request's
// host, so several services can probe one another.
type hostRoundTripper map[string]*Service

func (services hostRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	service, found := services[request.URL.Host]
	if !found {
		return &http.Response{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway", Body: http.NoBody, Header: make(http.Header), Request: request}, nil
	}
	return serviceRoundTripper{primary: service}.RoundTrip(request)
}

// fencingCluster is a primary and a replica that can reach each other, each
// with its own state.
func fencingCluster(t *testing.T) (*Service, *memoryStateReplicator, *Service, *memoryStateReplicator) {
	t.Helper()
	primaryState := &memoryStateReplicator{contents: []byte(`{"zones":["primary.test"]}`)}
	primary, err := Open(Options{DataDirectory: t.TempDir(), NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380", Replicator: primaryState})
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
	router := hostRoundTripper{"dns-1.example:5380": primary}
	client := &http.Client{Transport: router}
	replicaState := &memoryStateReplicator{}
	replica, err := Open(Options{DataDirectory: t.TempDir(), NodeName: "dns-2", AdvertiseURL: "https://dns-2.example:5380", HTTPClient: client, Replicator: replicaState})
	if err != nil {
		t.Fatal(err)
	}
	router["dns-2.example:5380"] = replica
	primary.baseHTTPClient, primary.httpClient = client, client
	if err := replica.Join(context.Background(), JoinOptions{PrimaryURL: "https://dns-1.example:5380", Token: token.Token, Addresses: []string{"192.0.2.2"}}); err != nil {
		t.Fatal(err)
	}
	if err := replica.syncFromPrimary(context.Background()); err != nil {
		t.Fatal(err)
	}
	return primary, primaryState, replica, replicaState
}

// changeState publishes a new state on a primary, which raises its
// generation without changing its term.
func changeState(t *testing.T, service *Service, state *memoryStateReplicator, contents string) {
	t.Helper()
	state.replace([]byte(contents))
	if err := service.refreshPrimaryState(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRestoredPrimaryStepsDownToNewerTerm(t *testing.T) {
	stale, staleState, promoted, promotedState := fencingCluster(t)
	// The primary goes away and the replica is promoted for recovery.
	if err := promoted.Promote(context.Background(), promoted.nodeID); err != nil {
		t.Fatal(err)
	}
	changeState(t, promoted, promotedState, `{"zones":["promoted.test"]}`)
	// The old primary comes back from a backup and takes enough changes to
	// pass the promoted primary's generation, so only the term tells them
	// apart.
	for index := range 4 {
		changeState(t, stale, staleState, `{"zones":["stale-`+string(rune('a'+index))+`.test"]}`)
	}
	if stale.Snapshot().Generation <= promoted.Snapshot().Generation {
		t.Fatalf("stale generation %d does not pass promoted generation %d", stale.Snapshot().Generation, promoted.Snapshot().Generation)
	}
	promotedBefore := promoted.Snapshot()

	// The promoted primary's probe tells the stale one a newer term exists.
	promoted.probePeersOnce(context.Background())
	select {
	case <-stale.probeNow:
	default:
		t.Fatal("a probe from a newer term did not ask the stale primary to probe")
	}
	if after := promoted.Snapshot(); after.LocalRole != RolePrimary || after.Generation != promotedBefore.Generation || after.Conflict != nil {
		t.Fatalf("a stale primary's answer changed the promoted primary: before=%#v after=%#v", promotedBefore, after)
	}

	stale.probePeersOnce(context.Background())
	state := stale.Snapshot()
	if state.LocalRole != RoleReplica || state.PrimaryID != promoted.nodeID || state.Term != promotedBefore.Term || state.Generation != promotedBefore.Generation {
		t.Fatalf("stale primary did not step down: %#v", state)
	}
	if got := string(staleState.current()); got != `{"zones":["promoted.test"]}` {
		t.Fatalf("stale primary kept its own state: %q", got)
	}
	if err := stale.syncFromPrimary(context.Background()); err != nil {
		t.Fatalf("former stale primary synchronizes from the promoted primary: %v", err)
	}
	if state := promoted.Snapshot(); state.LocalRole != RolePrimary || state.Synchronized != 2 {
		t.Fatalf("promoted primary after convergence = %#v", state)
	}
}

func TestPrimaryProbeNeverPublishesTheSendersIdentity(t *testing.T) {
	primary, _, replica, _ := fencingCluster(t)
	before := replica.Snapshot()
	heartbeat := Heartbeat{
		NodeID: primary.nodeID, Name: "renamed", AdvertiseURL: "https://renamed.example:5380",
		Version: "changed", Addresses: []string{"192.0.2.99"}, AppliedGeneration: before.Generation + 10,
		UpSince: time.Now(), SentAt: time.Now(), Primary: &PrimaryClaim{Term: before.Term},
	}
	if _, err := primary.Synchronize(context.Background(), Heartbeat{}, ""); err == nil {
		t.Fatal("unsigned heartbeat accepted")
	}
	// A primary that receives a probe from a node in its term keeps its own
	// manifest, however high the sender's generation.
	if err := replica.Promote(context.Background(), replica.nodeID); err != nil {
		t.Fatal(err)
	}
	before = replica.Snapshot()
	heartbeat.Primary.Term = before.Term
	heartbeat.SentAt = time.Now()
	configuration, err := replica.Synchronize(context.Background(), heartbeat, heartbeatSignature(replica.manifest.StatusKey, heartbeat))
	if err != nil {
		t.Fatal(err)
	}
	if configuration.UpdateCommand != nil || configuration.ClientIdentities != nil || configuration.AlertProtocol != 0 {
		t.Fatalf("probe answer carried primary-only extras: %#v", configuration)
	}
	after := replica.Snapshot()
	if after.Generation != before.Generation || slices.ContainsFunc(after.Nodes, func(node Node) bool { return node.Name == "renamed" }) {
		t.Fatalf("probe changed the manifest: before=%#v after=%#v", before, after)
	}
	if after.Conflict == nil || after.Conflict.NodeID != primary.nodeID {
		t.Fatalf("same-term probe did not raise a conflict: %#v", after)
	}
	if _, err := replica.Synchronize(context.Background(), heartbeat, heartbeatSignature(replica.manifest.StatusKey, heartbeat)); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replayed probe = %v", err)
	}
}

func TestSameTermPrimariesConflictUntilOneIsKept(t *testing.T) {
	first, _, second, secondState := fencingCluster(t)
	// Simulate two recovery promotions in one term, as clusters promoted
	// before terms existed have.
	second.mu.Lock()
	split := cloneManifest(second.manifest)
	split.PrimaryID = second.nodeID
	for index := range split.Nodes {
		split.Nodes[index].Role = ifRole(split.Nodes[index].ID == second.nodeID)
	}
	second.manifest = split
	second.mu.Unlock()

	first.probePeersOnce(context.Background())
	second.probePeersOnce(context.Background())
	for _, service := range []*Service{first, second} {
		state := service.Snapshot()
		if state.LocalRole != RolePrimary || state.Conflict == nil {
			t.Fatalf("%s did not report the conflict: %#v", service.nodeName, state)
		}
		for _, node := range state.Nodes {
			if node.SyncState != SyncConflict || node.Role != RolePrimary || node.State != StateOnline {
				t.Fatalf("%s shows node %s as %#v", service.nodeName, node.Name, node)
			}
		}
	}

	// Keeping the second node starts a new term, and the first steps down.
	generation := second.Snapshot().Generation
	if err := second.Promote(context.Background(), second.nodeID); err != nil {
		t.Fatal(err)
	}
	kept := second.Snapshot()
	if kept.Term != 1 || kept.Generation != generation+1 || kept.Conflict != nil {
		t.Fatalf("kept primary = %#v", kept)
	}
	first.probePeersOnce(context.Background())
	if state := first.Snapshot(); state.LocalRole != RoleReplica || state.PrimaryID != second.nodeID || state.Term != 1 {
		t.Fatalf("other primary did not step down: %#v", state)
	}
	if string(secondState.current()) == "" {
		t.Fatal("kept primary lost its state")
	}
}

func TestPromotingTheCurrentPrimaryWithoutConflictChangesNothing(t *testing.T) {
	primary, _, _, _ := fencingCluster(t)
	before := primary.Snapshot()
	if err := primary.Promote(context.Background(), primary.nodeID); err != nil {
		t.Fatal(err)
	}
	if after := primary.Snapshot(); after.Generation != before.Generation || after.Term != before.Term {
		t.Fatalf("promote without conflict changed the manifest: before=%#v after=%#v", before, after)
	}
}

func TestReplicaFollowsNewerTermAtLowerGeneration(t *testing.T) {
	active := &manifest{Term: 0, Generation: 9}
	if !manifestOlder(&manifest{Term: 0, Generation: 8}, active) || manifestOlder(&manifest{Term: 1, Generation: 4}, active) || manifestOlder(&manifest{Term: 0, Generation: 9}, active) {
		t.Fatal("manifest order must compare the term first, then the generation")
	}
}

func ifRole(primary bool) string {
	if primary {
		return RolePrimary
	}
	return RoleReplica
}
