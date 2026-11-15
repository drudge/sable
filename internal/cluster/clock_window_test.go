package cluster

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A member whose clock is five minutes off is refused, but it signed the
// heartbeat and answered the primary's one-time challenge, so the primary
// shows it as up with its clock out of step and says why, instead of
// unreachable (F76, D107). A forged heartbeat, the same one replayed, or one
// that doesn't answer the latest challenge doesn't count (F78, D109).
func TestPrimaryShowsAMemberRefusedForItsClockAsUp(t *testing.T) {
	for _, skew := range []time.Duration{5 * time.Minute, -5 * time.Minute} {
		t.Run(skew.String(), func(t *testing.T) { primaryShowsClockRefusedMemberAsUp(t, skew) })
	}
}

func primaryShowsClockRefusedMemberAsUp(t *testing.T, skew time.Duration) {
	service, memberID := serviceWithMember(t)
	refuse := func(heartbeat Heartbeat, signature string) string {
		t.Helper()
		_, err := service.Synchronize(context.Background(), heartbeat, signature)
		if err == nil || !strings.Contains(err.Error(), clockWindowRefusal) {
			t.Fatalf("error = %v; want the clock window", err)
		}
		return ClockChallenge(err)
	}
	heartbeat := Heartbeat{NodeID: memberID, SentAt: time.Now().Add(skew), UpSince: time.Now().Add(-time.Hour)}
	if _, err := service.Synchronize(context.Background(), heartbeat, strings.Repeat("0", 64)); err == nil || ClockChallenge(err) != "" {
		t.Fatalf("forged heartbeat: error = %v, challenge %q; want a refusal with no challenge", err, ClockChallenge(err))
	}
	first := refuse(heartbeat, heartbeatSignature(service.manifest.StatusKey, heartbeat))
	if !validClockChallenge(first) {
		t.Fatalf("challenge = %q; want 16 random bytes in hex", first)
	}
	if node := memberNode(t, service, memberID); node.State == StateOnline {
		t.Fatal("a heartbeat that answers no challenge shows the member as up")
	}
	answer := Heartbeat{NodeID: memberID, SentAt: time.Now().Add(skew), UpSince: heartbeat.UpSince, ClockChallenge: first}
	answerSignature := heartbeatSignature(service.manifest.StatusKey, answer)
	second := refuse(answer, answerSignature)
	node := memberNode(t, service, memberID)
	if node.State != StateOnline || node.SyncState != SyncClock || node.ClockOffsetSeconds/60 != int64(skew/time.Minute) {
		t.Fatalf("member = %s/%s offset %ds; want online/clock about %v", node.State, node.SyncState, node.ClockOffsetSeconds, skew)
	}
	counted := service.clockRefused[memberID].received
	if again := refuse(answer, answerSignature); again != second || service.clockRefused[memberID].received != counted {
		t.Fatal("a replayed answer counted, or replaced the challenge the member must answer next")
	}
	next := Heartbeat{NodeID: memberID, SentAt: time.Now().Add(skew), UpSince: heartbeat.UpSince, ClockChallenge: second}
	if refuse(next, heartbeatSignature(service.manifest.StatusKey, next)); !service.clockRefused[memberID].received.After(counted) {
		t.Fatal("the member's answer to the latest challenge didn't count")
	}
	inStep := Heartbeat{NodeID: memberID, SentAt: time.Now(), UpSince: heartbeat.UpSince}
	if _, err := service.Synchronize(context.Background(), inStep, heartbeatSignature(service.manifest.StatusKey, inStep)); err != nil {
		t.Fatal(err)
	}
	if node := memberNode(t, service, memberID); node.SyncState == SyncClock {
		t.Fatal("member still shows its clock out of step after a heartbeat inside the window")
	}
}

// A challenge older than heartbeatFreshness no longer proves the member is up
// now: answering it doesn't count, and the primary issues a new one (D109).
func TestPrimaryIgnoresAStaleClockChallenge(t *testing.T) {
	service, memberID := serviceWithMember(t)
	now := time.Now()
	heartbeat := Heartbeat{NodeID: memberID, SentAt: now.Add(5 * time.Minute), UpSince: now.Add(-time.Hour)}
	_, err := service.Synchronize(context.Background(), heartbeat, heartbeatSignature(service.manifest.StatusKey, heartbeat))
	stale := ClockChallenge(err)
	service.mu.Lock()
	refusal := service.clockRefused[memberID]
	refusal.issued = refusal.issued.Add(-heartbeatFreshness - time.Second)
	service.clockRefused[memberID] = refusal
	service.mu.Unlock()
	answer := Heartbeat{NodeID: memberID, SentAt: now.Add(5 * time.Minute), UpSince: heartbeat.UpSince, ClockChallenge: stale}
	_, err = service.Synchronize(context.Background(), answer, heartbeatSignature(service.manifest.StatusKey, answer))
	if fresh := ClockChallenge(err); fresh == "" || fresh == stale || !service.clockRefused[memberID].received.IsZero() {
		t.Fatalf("stale answer: new challenge %q (old %q), counted at %v; want a new challenge and nothing counted", fresh, stale, service.clockRefused[memberID].received)
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
	primaryID := replica.Snapshot().PrimaryID
	err := replica.primaryRefusal(primaryID, response)
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
	if err := replica.primaryRefusal(primaryID, other); !strings.Contains(err.Error(), "signature is invalid") {
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

// A replica answers the primary's clock challenge in its next heartbeat only,
// and sends the field to no primary that didn't issue one: an older primary
// refuses fields it doesn't know (D109).
func TestReplicaAnswersThePrimarysClockChallengeOnce(t *testing.T) {
	_, _, replica, _ := fencingCluster(t)
	primaryID := replica.Snapshot().PrimaryID
	refusal := func(body string) *http.Response {
		return &http.Response{StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Body: io.NopCloser(strings.NewReader(body))}
	}
	heartbeat := func() Heartbeat {
		replica.mu.Lock()
		defer replica.mu.Unlock()
		primary, found := manifestMember(replica.manifest, primaryID)
		built, _, _ := replica.primaryHeartbeatLocked(nil, primary, found)
		return built
	}
	reason := (&clockWindowError{offset: time.Minute}).Error()
	challenge := strings.Repeat("ab", 16)
	_ = replica.primaryRefusal(primaryID, refusal(`{"error":"`+reason+`","clock_challenge":"`+challenge+`"}`))
	if got := heartbeat().ClockChallenge; got != challenge {
		t.Fatalf("next heartbeat answers %q; want %q", got, challenge)
	}
	if got := heartbeat().ClockChallenge; got != "" {
		t.Fatalf("a second heartbeat answers %q again", got)
	}
	_ = replica.primaryRefusal(primaryID, refusal(`{"error":"`+reason+`"}`))
	contents, _ := json.Marshal(heartbeat())
	if strings.Contains(string(contents), "clock_challenge") {
		t.Fatalf("heartbeat to a primary that gave no challenge carries one: %s", contents)
	}
	_ = replica.primaryRefusal(primaryID, refusal(`{"error":"`+reason+`","clock_challenge":"not hex"}`))
	if got := heartbeat().ClockChallenge; got != "" {
		t.Fatalf("replica signed a malformed challenge %q", got)
	}
}
