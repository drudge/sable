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
