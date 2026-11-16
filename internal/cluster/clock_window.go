package cluster

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// clockWindowRefusal starts a refusal for the clock. A replica looks for it
// in the primary's answer; primaries before D107 send it too.
const clockWindowRefusal = "synchronization timestamp is outside the accepted clock window"

// clockWindowError is an authentic heartbeat sent more than
// heartbeatClockSkew from this node's clock. The window is the replay guard
// (#580), so the heartbeat is refused, but the member that signed it is up
// and keeps serving: it isn't offline, and its ranges can't be taken over
// (D107). challenge is the one-time clock challenge the primary answers it
// with (D109).
type clockWindowError struct {
	offset    time.Duration
	challenge string
}

// ClockChallenge is the one-time challenge a primary issued with a refusal
// for the clock, for the refusal's body; empty for any other error.
func ClockChallenge(err error) string {
	var window *clockWindowError
	if errors.As(err, &window) {
		return window.challenge
	}
	return ""
}

func (err *clockWindowError) Error() string {
	direction, magnitude := "ahead of", err.offset
	if magnitude < 0 {
		direction, magnitude = "behind", -magnitude
	}
	return fmt.Sprintf("%s: the member's clock is %s %s this node's; clocks must agree within %s",
		clockWindowRefusal, magnitude.Round(time.Second), direction, heartbeatClockSkew)
}

// clockRefusal is a member's standing with the primary while it is refused
// for its clock: received is when a refusal last counted, challenge the one
// the member must answer next, issued at issued, latest the newest SentAt of
// its authentic refused heartbeats, and warned when the log last named it.
type clockRefusal struct {
	received  time.Time
	offset    time.Duration
	challenge string
	issued    time.Time
	latest    time.Time
	warned    time.Time
}

// noteClockRefusal answers an authentic member heartbeat refused for its
// clock with a one-time challenge, and counts the member as up only when the
// heartbeat answers the challenge issued with its last refusal, within
// heartbeatFreshness. A timestamp can't tell a replayed heartbeat from a
// clock that stepped back, so freshness comes from this node (D109). A
// heartbeat that doesn't answer leaves a young challenge in place, so a replay
// can't spoil the member's next answer. It warns once per out-of-step
// episode, on the first live heartbeat after none for heartbeatFreshness: one
// that answers the challenge, or one with no answer at all (a member too old
// to answer, F82) sent after every one seen before. A replay answers a stale
// challenge or repeats an old SentAt, so it never logs.
func (service *Service) noteClockRefusal(heartbeat Heartbeat, signature string, err error) {
	var window *clockWindowError
	if !errors.As(err, &window) || heartbeat.Primary != nil {
		return
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	now := service.clock()
	refusal, seen := service.clockRefused[heartbeat.NodeID]
	young := seen && now.Sub(refusal.issued) <= heartbeatFreshness
	answered := young && heartbeat.ClockChallenge != "" && hmac.Equal([]byte(heartbeat.ClockChallenge), []byte(refusal.challenge))
	live := answered || heartbeat.ClockChallenge == "" && heartbeat.SentAt.After(refusal.latest)
	if heartbeat.SentAt.After(refusal.latest) {
		refusal.latest = heartbeat.SentAt
	}
	if live && service.logger != nil && now.Sub(refusal.warned) > heartbeatFreshness {
		service.logger.Warn("cluster member's clock is out of step; refusing its heartbeats",
			"node_id", heartbeat.NodeID, "offset", window.offset.Round(time.Second), "allowed", heartbeatClockSkew)
	}
	if live {
		refusal.warned = now
	}
	if answered {
		refusal.received, refusal.offset = now, window.offset
	}
	if answered || !young {
		refusal.challenge, refusal.issued = newClockChallenge(), now
	}
	service.clockRefused[heartbeat.NodeID] = refusal
	window.challenge = refusal.challenge
}

func newClockChallenge() string {
	challenge := make([]byte, 16)
	_, _ = rand.Read(challenge)
	return hex.EncodeToString(challenge)
}

// clearClockRefusalLocked forgets a member's clock refusal once one of its
// heartbeats is accepted.
func (service *Service) clearClockRefusalLocked(nodeID string) {
	refusal, found := service.clockRefused[nodeID]
	if !found {
		return
	}
	delete(service.clockRefused, nodeID)
	if service.logger != nil && !refusal.received.IsZero() {
		service.logger.Info("cluster member's clock is back in step", "node_id", nodeID)
	}
}

// primaryRefusal is the error for a primary's non-200 answer, with the reason
// from its body. A refusal for the clock is remembered, so this replica shows
// the primary as up with its clock out of step, and so is its challenge, for
// the next heartbeat to answer (D109).
func (service *Service) primaryRefusal(primaryID string, response *http.Response) error {
	var body struct {
		Error          string `json:"error"`
		ClockChallenge string `json:"clock_challenge"`
	}
	_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&body)
	if strings.Contains(body.Error, clockWindowRefusal) {
		service.mu.Lock()
		service.primaryClockRefusedAt = service.clock()
		service.clockChallenge, service.clockChallengeFor = "", ""
		if validClockChallenge(body.ClockChallenge) {
			service.clockChallenge, service.clockChallengeFor = body.ClockChallenge, primaryID
		}
		service.mu.Unlock()
		return fmt.Errorf("cluster primary refused synchronization: this node's clock is more than %s from the primary's; set both clocks by NTP", heartbeatClockSkew)
	}
	if body.Error != "" {
		return fmt.Errorf("cluster primary rejected synchronization: %s: %s", response.Status, body.Error)
	}
	return fmt.Errorf("cluster primary rejected synchronization: %s", response.Status)
}

// validClockChallenge reports whether a primary's challenge has the shape
// newClockChallenge gives it, so a replica signs nothing else.
func validClockChallenge(challenge string) bool {
	decoded, err := hex.DecodeString(challenge)
	return err == nil && len(decoded) == 16
}

// applyClockRefusals shows a node refused for its clock in the last
// heartbeatFreshness as up with its clock out of step: on the primary, the
// member it refused; on a replica, the primary that refused it, and itself.
// A counted refusal stays the node's last contact once it goes stale, so a
// node that dies while out of step is down from its last check-in (F81).
func (service *Service) applyClockRefusals(state *State, now time.Time) {
	for index := range state.Nodes {
		node := &state.Nodes[index]
		switch {
		case node.ID == service.nodeID:
			if state.LocalRole == RoleReplica && now.Sub(service.primaryClockRefusedAt) <= heartbeatFreshness {
				markClockOutOfStep(state, node, 0)
			}
		case node.ID == state.PrimaryID && state.LocalRole == RoleReplica:
			if service.primaryClockRefusedAt.After(node.LastContact) {
				node.LastContact = service.primaryClockRefusedAt
				if now.Sub(service.primaryClockRefusedAt) <= heartbeatFreshness {
					markClockOutOfStep(state, node, 0)
				}
			}
		default:
			refusal, found := service.clockRefused[node.ID]
			if found && refusal.received.After(node.LastContact) {
				node.LastContact = refusal.received
				if now.Sub(refusal.received) <= heartbeatFreshness {
					markClockOutOfStep(state, node, refusal.offset)
				}
			}
		}
	}
}

func markClockOutOfStep(state *State, node *Node, offset time.Duration) {
	if node.State != StateOnline {
		state.Connected++
	}
	if node.SyncState == SyncCurrent {
		state.Synchronized--
	}
	node.State, node.SyncState, node.ClockOffsetSeconds = StateOnline, SyncClock, int64(offset.Round(time.Second)/time.Second)
}
