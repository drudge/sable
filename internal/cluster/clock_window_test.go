package cluster

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A member whose clock is five minutes ahead is refused, but it signed the
// heartbeat, so the primary shows it as up with its clock out of step and
// says why, instead of unreachable (F76, D107). A forged heartbeat, or the
// same one replayed, doesn't count.
func TestPrimaryShowsAMemberRefusedForItsClockAsUp(t *testing.T) {
	service, memberID := serviceWithMember(t)
	heartbeat := Heartbeat{NodeID: memberID, SentAt: time.Now().Add(5 * time.Minute), UpSince: time.Now().Add(-time.Hour)}
	forged := heartbeat
	if _, err := service.Synchronize(context.Background(), forged, strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted a forged heartbeat")
	}
	if node := memberNode(t, service, memberID); node.State == StateOnline {
		t.Fatalf("a forged heartbeat shows the member as %s", node.State)
	}
	signature := heartbeatSignature(service.manifest.StatusKey, heartbeat)
	_, err := service.Synchronize(context.Background(), heartbeat, signature)
	if err == nil || !strings.Contains(err.Error(), clockWindowRefusal) || !strings.Contains(err.Error(), "5m0s ahead") {
		t.Fatalf("error = %v; want the clock window, naming 5m0s ahead", err)
	}
	node := memberNode(t, service, memberID)
	if node.State != StateOnline || node.SyncState != SyncClock || node.ClockOffsetSeconds/60 != 5 {
		t.Fatalf("member = %s/%s offset %ds; want online/clock about 300s", node.State, node.SyncState, node.ClockOffsetSeconds)
	}
	first := service.clockRefused[memberID].received
	_, _ = service.Synchronize(context.Background(), heartbeat, signature)
	if service.clockRefused[memberID].received != first {
		t.Fatal("a replayed heartbeat refreshed the member's clock refusal")
	}
	inStep := Heartbeat{NodeID: memberID, SentAt: time.Now(), UpSince: heartbeat.UpSince}
	if _, err := service.Synchronize(context.Background(), inStep, heartbeatSignature(service.manifest.StatusKey, inStep)); err != nil {
		t.Fatal(err)
	}
	if node := memberNode(t, service, memberID); node.SyncState == SyncClock {
		t.Fatal("member still shows its clock out of step after a heartbeat inside the window")
	}
}

// A replica the primary refuses for its clock reads the reason from the body
// instead of logging 401 Unauthorized, and shows the primary as up and both
// clocks out of step (F76, D107).
func TestReplicaNamesThePrimarysClockRefusal(t *testing.T) {
	_, _, replica, _ := fencingCluster(t)
	response := &http.Response{
		StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized",
		Body: io.NopCloser(strings.NewReader(`{"error":"` + (&clockWindowError{offset: -5 * time.Minute}).Error() + `"}`)),
	}
	err := replica.primaryRefusal(response)
	if err == nil || !strings.Contains(err.Error(), "clock") {
		t.Fatalf("error = %v; want it to name the clock", err)
	}
	state := replica.Snapshot()
	for _, node := range state.Nodes {
		if (node.ID == state.PrimaryID || node.ID == replica.nodeID) && (node.State != StateOnline || node.SyncState != SyncClock) {
			t.Fatalf("%s = %s/%s; want online with its clock out of step", node.ID, node.State, node.SyncState)
		}
	}
	other := &http.Response{StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized",
		Body: io.NopCloser(strings.NewReader(`{"error":"synchronization signature is invalid"}`))}
	if err := replica.primaryRefusal(other); !strings.Contains(err.Error(), "signature is invalid") {
		t.Fatalf("error = %v; want the primary's reason", err)
	}
}

func memberNode(t *testing.T, service *Service, id string) Node {
	t.Helper()
	for _, node := range service.Snapshot().Nodes {
		if node.ID == id {
			return node
		}
	}
	t.Fatalf("no member %s", id)
	return Node{}
}
