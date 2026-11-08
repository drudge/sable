package cluster

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestSynchronizeAcceptsHeartbeatsAfterTheMembersClockStepsBack is #580: a
// member whose clock steps back inside the clock window sends heartbeats
// older than its last one. They are new heartbeats, not replays.
func TestSynchronizeAcceptsHeartbeatsAfterTheMembersClockStepsBack(t *testing.T) {
	service, memberID := serviceWithMember(t)
	sent := time.Now()
	for _, at := range []time.Time{sent, sent.Add(-20 * time.Second), sent.Add(-19 * time.Second)} {
		heartbeat := Heartbeat{NodeID: memberID, SentAt: at, UpSince: sent.Add(-time.Minute)}
		if _, err := service.Synchronize(context.Background(), heartbeat, heartbeatSignature(service.manifest.StatusKey, heartbeat)); err != nil {
			t.Fatalf("heartbeat sent %s from the first: %v", at.Sub(sent), err)
		}
	}
}

// TestSynchronizeRefusesAReplayInAnySpelling sends one heartbeat again with
// its signature spelled as validHeartbeatSignature still accepts it.
func TestSynchronizeRefusesAReplayInAnySpelling(t *testing.T) {
	service, memberID := serviceWithMember(t)
	heartbeat := Heartbeat{NodeID: memberID, SentAt: time.Now(), UpSince: time.Now().Add(-time.Minute)}
	signature := heartbeatSignature(service.manifest.StatusKey, heartbeat)
	if _, err := service.Synchronize(context.Background(), heartbeat, signature); err != nil {
		t.Fatal(err)
	}
	for _, replay := range []string{signature, strings.ToUpper(signature), " " + signature + "\n"} {
		if _, err := service.Synchronize(context.Background(), heartbeat, replay); err == nil || !strings.Contains(err.Error(), "replayed") {
			t.Fatalf("replay signed %q: error = %v, want replayed", replay, err)
		}
	}
}

// TestPrimaryProbeAcceptedAfterTheSendersClockStepsBack keeps fencing probes
// working through a primary's clock stepping back.
func TestPrimaryProbeAcceptedAfterTheSendersClockStepsBack(t *testing.T) {
	primary, _, replica, _ := fencingCluster(t)
	state := replica.Snapshot()
	sent := time.Now()
	for _, at := range []time.Time{sent, sent.Add(-20 * time.Second)} {
		heartbeat := Heartbeat{
			NodeID: primary.nodeID, AppliedGeneration: state.Generation, UpSince: sent.Add(-time.Minute),
			SentAt: at, Primary: &PrimaryClaim{Term: state.Term},
		}
		if _, err := replica.Synchronize(context.Background(), heartbeat, heartbeatSignature(replica.manifest.StatusKey, heartbeat)); err != nil {
			t.Fatalf("probe sent %s from the first: %v", at.Sub(sent), err)
		}
	}
}

func TestReplayGuardForgetsHeartbeatsOutsideTheClockWindow(t *testing.T) {
	guard := make(replayGuard)
	now := time.Now()
	guard.record("node", "aa", now.Add(-heartbeatClockSkew-time.Second), now)
	guard.record("node", "bb", now, now)
	if guard.seen("node", "aa") || !guard.seen("node", "bb") || len(guard["node"]) != 1 {
		t.Fatalf("guard = %v, want only the heartbeat inside the window", guard)
	}
}

// serviceWithMember is an initialized primary with one enrolled member.
func serviceWithMember(t *testing.T) (*Service, string) {
	t.Helper()
	service, err := Open(Options{
		DataDirectory: t.TempDir(), NodeName: "dns-1", AdvertiseURL: "https://dns-1.example:5380",
		Replicator: &controlledStateReplicator{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Initialize(context.Background(), "cluster.example", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	token, err := service.CreateEnrollmentToken(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	const memberID = "11111111-1111-4111-8111-111111111111"
	if _, err := service.Enroll(context.Background(), JoinRequest{
		Token: token.Token, NodeID: memberID, Name: "dns-2", AdvertiseURL: "https://dns-2.example:5380",
		Addresses: []string{"192.0.2.2"}, Version: "dev",
	}); err != nil {
		t.Fatal(err)
	}
	return service, memberID
}
