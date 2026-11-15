package cluster

import (
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
// (D107).
type clockWindowError struct{ offset time.Duration }

func (err *clockWindowError) Error() string {
	direction, magnitude := "ahead of", err.offset
	if magnitude < 0 {
		direction, magnitude = "behind", -magnitude
	}
	return fmt.Sprintf("%s: the member's clock is %s %s this node's; clocks must agree within %s",
		clockWindowRefusal, magnitude.Round(time.Second), direction, heartbeatClockSkew)
}

// clockRefusal is the newest authentic heartbeat a member sent outside the
// clock window.
type clockRefusal struct {
	received time.Time
	sentAt   time.Time
	offset   time.Duration
}

// noteClockRefusal records a member refused for its clock, and logs it when
// it starts. A heartbeat counts only when it was sent after the last one
// counted, so a captured heartbeat replayed can't keep a stopped member up.
func (service *Service) noteClockRefusal(heartbeat Heartbeat, signature string, err error) {
	var window *clockWindowError
	if !errors.As(err, &window) || heartbeat.Primary != nil {
		return
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	now := service.clock()
	previous, seen := service.clockRefused[heartbeat.NodeID]
	if seen && !heartbeat.SentAt.After(previous.sentAt) {
		return
	}
	service.clockRefused[heartbeat.NodeID] = clockRefusal{received: now, sentAt: heartbeat.SentAt, offset: window.offset}
	if service.logger != nil && (!seen || now.Sub(previous.received) > heartbeatFreshness) {
		service.logger.Warn("cluster member's clock is out of step; refusing its heartbeats",
			"node_id", heartbeat.NodeID, "offset", window.offset.Round(time.Second), "allowed", heartbeatClockSkew)
	}
}

// clearClockRefusalLocked forgets a member's clock refusal once one of its
// heartbeats is accepted.
func (service *Service) clearClockRefusalLocked(nodeID string) {
	if _, found := service.clockRefused[nodeID]; !found {
		return
	}
	delete(service.clockRefused, nodeID)
	if service.logger != nil {
		service.logger.Info("cluster member's clock is back in step", "node_id", nodeID)
	}
}

// primaryRefusal is the error for a primary's non-200 answer, with the reason
// from its body. A refusal for the clock is remembered, so this replica shows
// the primary as up with its clock out of step.
func (service *Service) primaryRefusal(response *http.Response) error {
	var body struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&body)
	if strings.Contains(body.Error, clockWindowRefusal) {
		service.mu.Lock()
		service.primaryClockRefusedAt = service.clock()
		service.mu.Unlock()
		return fmt.Errorf("cluster primary refused synchronization: this node's clock is more than %s from the primary's; set both clocks by NTP", heartbeatClockSkew)
	}
	if body.Error != "" {
		return fmt.Errorf("cluster primary rejected synchronization: %s: %s", response.Status, body.Error)
	}
	return fmt.Errorf("cluster primary rejected synchronization: %s", response.Status)
}

// applyClockRefusals shows a node refused for its clock in the last
// heartbeatFreshness as up with its clock out of step: on the primary, the
// member it refused; on a replica, the primary that refused it, and itself.
func (service *Service) applyClockRefusals(state *State, now time.Time) {
	for index := range state.Nodes {
		node := &state.Nodes[index]
		switch {
		case node.ID == service.nodeID:
			if state.LocalRole == RoleReplica && now.Sub(service.primaryClockRefusedAt) <= heartbeatFreshness {
				markClockOutOfStep(state, node, 0)
			}
		case node.ID == state.PrimaryID && state.LocalRole == RoleReplica:
			if now.Sub(service.primaryClockRefusedAt) <= heartbeatFreshness {
				node.LastContact = service.primaryClockRefusedAt
				markClockOutOfStep(state, node, 0)
			}
		default:
			refusal, found := service.clockRefused[node.ID]
			if found && now.Sub(refusal.received) <= heartbeatFreshness && refusal.received.After(node.LastContact) {
				node.LastContact = refusal.received
				markClockOutOfStep(state, node, refusal.offset)
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
