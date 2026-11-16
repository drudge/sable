package cluster

import (
	"bytes"
	"context"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// The primary warns once per out-of-step episode, when the member first
// answers its clock challenge. A heartbeat replayed after the member stopped
// answers nothing, so it neither counts (D109) nor logs a new warning; the
// member's next live answer starts a new episode and does.
func TestPrimaryLogsAClockEpisodeOnceAndNotOnAReplay(t *testing.T) {
	service, memberID := serviceWithMember(t)
	var logs bytes.Buffer
	service.logger = slog.New(slog.NewTextHandler(&logs, nil))
	warnings := func() int { return strings.Count(logs.String(), "clock is out of step") }
	refuse := func(challenge string) (Heartbeat, string) {
		t.Helper()
		heartbeat := Heartbeat{NodeID: memberID, SentAt: time.Now().Add(5 * time.Minute), UpSince: time.Now().Add(-time.Hour), ClockChallenge: challenge}
		_, err := service.Synchronize(context.Background(), heartbeat, heartbeatSignature(service.manifest.StatusKey, heartbeat))
		return heartbeat, ClockChallenge(err)
	}
	_, first := refuse("")
	answer, second := refuse(first)
	refuse(second)
	if got := warnings(); got != 1 {
		t.Fatalf("warnings while out of step = %d; want 1\n%s", got, logs.String())
	}
	ageClockRefusal(service, memberID, heartbeatFreshness+time.Second)
	_, err := service.Synchronize(context.Background(), answer, heartbeatSignature(service.manifest.StatusKey, answer))
	if got := warnings(); got != 1 {
		t.Fatalf("warnings after a replay = %d; want still 1\n%s", got, logs.String())
	}
	if refuse(ClockChallenge(err)); warnings() != 2 {
		t.Fatalf("warnings after the member came back out of step = %d; want 2\n%s", warnings(), logs.String())
	}
}

// A member on a release without the clock challenge (1.8.2) can't answer it,
// so it shows as offline. The primary's log still names its clock (F82): once
// the member has left a challenge unanswered, and not again for
// clockUnansweredLogEvery. One stray heartbeat, as a single replay is, logs
// nothing.
func TestPrimaryNamesTheClockOfAMemberThatCannotAnswer(t *testing.T) {
	service, memberID := serviceWithMember(t)
	var logs bytes.Buffer
	service.logger = slog.New(slog.NewTextHandler(&logs, nil))
	unanswered := func() int { return strings.Count(logs.String(), "left the clock check unanswered") }
	beat := func(ahead time.Duration) {
		t.Helper()
		heartbeat := Heartbeat{NodeID: memberID, SentAt: time.Now().Add(ahead), UpSince: time.Now().Add(-time.Hour)}
		if _, err := service.Synchronize(context.Background(), heartbeat, heartbeatSignature(service.manifest.StatusKey, heartbeat)); err == nil {
			t.Fatal("accepted a heartbeat 5 minutes ahead")
		}
	}
	beat(5 * time.Minute)
	if got := unanswered(); got != 0 {
		t.Fatalf("warnings after one heartbeat = %d; want 0: it hasn't had a challenge to answer\n%s", got, logs.String())
	}
	for second := range 3 {
		beat(5*time.Minute + time.Duration(second+1)*time.Second)
	}
	if got := unanswered(); got != 1 {
		t.Fatalf("warnings after four heartbeats that answer nothing = %d; want 1\n%s", got, logs.String())
	}
	if !strings.Contains(logs.String(), "offset=5m") || strings.Contains(logs.String(), "clock is out of step") {
		t.Fatalf("the warning should give the offset and not claim the member is up and out of step:\n%s", logs.String())
	}
	ageClockRefusal(service, memberID, clockUnansweredLogEvery+time.Second)
	beat(5 * time.Minute)
	beat(5*time.Minute + time.Second)
	if got := unanswered(); got != 2 {
		t.Fatalf("warnings %s on = %d; want 2\n%s", clockUnansweredLogEvery, got, logs.String())
	}
}

// The replay #659 was for: a member whose clock was right stops, and a
// heartbeat it sent earlier comes back once it is outside the window. The
// primary has no refusal on file for the member, and the member is down, not
// out of step: one replay logs nothing, and more of them only ever get the
// line that says a replay is possible.
func TestReplayForAStoppedMemberNeverLogsItsClockAsOutOfStep(t *testing.T) {
	service, memberID := serviceWithMember(t)
	var logs bytes.Buffer
	service.logger = slog.New(slog.NewTextHandler(&logs, nil))
	replay := func(age time.Duration) {
		t.Helper()
		heartbeat := Heartbeat{NodeID: memberID, SentAt: time.Now().Add(-age), UpSince: time.Now().Add(-time.Hour)}
		if _, err := service.Synchronize(context.Background(), heartbeat, heartbeatSignature(service.manifest.StatusKey, heartbeat)); ClockChallenge(err) == "" {
			t.Fatalf("heartbeat sent %s ago wasn't refused for its clock: %v", age, err)
		}
	}
	replay(time.Minute)
	if logs.Len() != 0 {
		t.Fatalf("one replayed heartbeat for a stopped member logged:\n%s", logs.String())
	}
	replay(59 * time.Second)
	replay(58 * time.Second)
	if strings.Contains(logs.String(), "clock is out of step") || strings.Count(logs.String(), "left the clock check unanswered") != 1 {
		t.Fatalf("three replayed heartbeats should log one \"left the clock check unanswered\" line and never \"clock is out of step\":\n%s", logs.String())
	}
}

// ageClockRefusal moves every time a member's clock refusal holds back by
// age, as if the member stopped sending heartbeats that long ago. It reaches
// the unexported fields so the test doesn't depend on which ones there are.
func ageClockRefusal(service *Service, memberID string, age time.Duration) {
	service.mu.Lock()
	defer service.mu.Unlock()
	refusal := service.clockRefused[memberID]
	fields := reflect.ValueOf(&refusal).Elem()
	for index := range fields.NumField() {
		field := fields.Field(index)
		field = reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
		if at, ok := field.Interface().(time.Time); ok {
			field.Set(reflect.ValueOf(at.Add(-age)))
		}
	}
	service.clockRefused[memberID] = refusal
}
