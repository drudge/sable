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

// ageClockRefusal moves every time a member's clock refusal holds back by
// age, as if the member stopped sending heartbeats that long ago. It reaches
// the unexported fields so the test doesn't depend on which ones there are,
// except latest, which is a time on the member's clock, not this node's.
func ageClockRefusal(service *Service, memberID string, age time.Duration) {
	service.mu.Lock()
	defer service.mu.Unlock()
	refusal := service.clockRefused[memberID]
	fields := reflect.ValueOf(&refusal).Elem()
	for index := range fields.NumField() {
		if fields.Type().Field(index).Name == "latest" {
			continue
		}
		field := fields.Field(index)
		field = reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
		if at, ok := field.Interface().(time.Time); ok {
			field.Set(reflect.ValueOf(at.Add(-age)))
		}
	}
	service.clockRefused[memberID] = refusal
}

// A member too old to answer the clock challenge (1.8.2) still gets one
// warning per out-of-step episode from its live heartbeats (F82), and a
// heartbeat of its replayed after it stopped writes no new one.
func TestPrimaryLogsAClockEpisodeForAMemberThatCantAnswer(t *testing.T) {
	service, memberID := serviceWithMember(t)
	var logs bytes.Buffer
	service.logger = slog.New(slog.NewTextHandler(&logs, nil))
	warnings := func() int { return strings.Count(logs.String(), "clock is out of step") }
	send := func(heartbeat Heartbeat) {
		t.Helper()
		_, err := service.Synchronize(context.Background(), heartbeat, heartbeatSignature(service.manifest.StatusKey, heartbeat))
		if ClockChallenge(err) == "" {
			t.Fatalf("heartbeat 5 minutes ahead wasn't refused for its clock: %v", err)
		}
	}
	start := time.Now().Add(5 * time.Minute)
	var sent []Heartbeat
	for beat := range 4 {
		heartbeat := Heartbeat{NodeID: memberID, SentAt: start.Add(time.Duration(beat) * 10 * time.Second), UpSince: time.Now().Add(-time.Hour)}
		send(heartbeat)
		sent = append(sent, heartbeat)
	}
	if got := warnings(); got != 1 {
		t.Fatalf("warnings from 4 live heartbeats that can't answer = %d; want 1\n%s", got, logs.String())
	}
	ageClockRefusal(service, memberID, heartbeatFreshness+time.Second)
	send(sent[len(sent)-1])
	if got := warnings(); got != 1 {
		t.Fatalf("warnings after a replay = %d; want still 1\n%s", got, logs.String())
	}
}
