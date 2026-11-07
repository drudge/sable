package cluster

import (
	"context"
	"testing"
	"time"
)

// demoteToStandaloneByDelete makes service a stale primary of its cluster and
// deletes the cluster from it, which records the other members as revoked.
func demoteToStandaloneByDelete(t *testing.T, service *Service) {
	t.Helper()
	service.mu.Lock()
	stale := cloneManifest(service.manifest)
	stale.PrimaryID = service.nodeID
	service.manifest = stale
	service.mu.Unlock()
	if err := service.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(service.revocations) != 1 {
		t.Fatalf("delete did not record the cluster: %#v", service.revocations)
	}
}

func TestRejoiningADeletedClusterKeepsItsMembersAfterHandoff(t *testing.T) {
	primary, _, rejoined, _ := fencingCluster(t)
	demoteToStandaloneByDelete(t, rejoined)
	token, err := primary.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := rejoined.Join(context.Background(), JoinOptions{PrimaryURL: "https://dns-1.example:5380", Token: token.Token, Addresses: []string{"192.0.2.2"}}); err != nil {
		t.Fatal(err)
	}
	if len(rejoined.revocations) != 0 {
		t.Fatalf("joining the cluster kept its destroyed record: %#v", rejoined.revocations)
	}
	if err := rejoined.syncFromPrimary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := primary.Promote(context.Background(), rejoined.nodeID); err != nil {
		t.Fatal(err)
	}
	if err := rejoined.syncFromPrimary(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The former primary's first heartbeat to the rejoined node, now the
	// primary, used to be answered 410 Gone, which released it.
	if err := primary.syncFromPrimary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := primary.Snapshot(); !state.Initialized || state.LocalRole != RoleReplica || state.PrimaryID != rejoined.nodeID {
		t.Fatalf("former primary after handoff to the rejoined node = %#v", state)
	}
}

func TestOpenForgetsTheRecordOfTheClusterThisNodeBelongsTo(t *testing.T) {
	_, _, member, _ := fencingCluster(t)
	other := revokedCluster{ClusterID: "11111111-1111-4111-8111-111111111111", StatusKey: "old", NodeIDs: []string{"22222222-2222-4222-8222-222222222222"}, CreatedAt: time.Now()}
	stale := revokedCluster{ClusterID: member.manifest.ClusterID, StatusKey: member.manifest.StatusKey, NodeIDs: []string{"33333333-3333-4333-8333-333333333333"}, CreatedAt: time.Now()}
	if err := writeRevocations(member.directory, []revokedCluster{other, stale}); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(Options{DataDirectory: member.directory, NodeName: "dns-2", AdvertiseURL: "https://dns-2.example:5380"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.revocations) != 1 || reopened.revocations[0].ClusterID != other.ClusterID {
		t.Fatalf("revocations after reopening a member = %#v", reopened.revocations)
	}
	persisted, err := loadRevocations(member.directory)
	if err != nil || len(persisted) != 1 {
		t.Fatalf("persisted revocations = %#v, %v", persisted, err)
	}
}
