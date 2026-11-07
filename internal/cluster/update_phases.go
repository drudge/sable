package cluster

import (
	"fmt"
	"slices"
)

// A cluster update is tracked at three layers, each with its own phase type:
// the coordinator's rollout (RolloutPhase), the coordinator's view of each
// node in it (RolloutNodePhase), and each node's own progress (NodePhase).
// Commands on the wire are a fourth type, UpdateAction, so the values saved
// with a rollout never double as protocol. The strings are persisted in
// update-rollout.json and node-update.json and must not change.

// RolloutPhase is where the coordinator's rollout stands.
type RolloutPhase string

const (
	RolloutPreparing  RolloutPhase = "preparing"
	RolloutUpdating   RolloutPhase = "updating"
	RolloutRestarting RolloutPhase = "restarting"
	RolloutVerifying  RolloutPhase = "verifying"
	RolloutComplete   RolloutPhase = "complete"
	RolloutFailed     RolloutPhase = "failed"
	RolloutStopped    RolloutPhase = "stopped"
)

// rolloutTransitions lists the phases each phase may move to. Any running
// phase may fail or be stopped; the ending phases move nowhere.
var rolloutTransitions = map[RolloutPhase][]RolloutPhase{
	RolloutPreparing:  {RolloutUpdating, RolloutFailed, RolloutStopped},
	RolloutUpdating:   {RolloutRestarting, RolloutVerifying, RolloutFailed, RolloutStopped},
	RolloutRestarting: {RolloutVerifying, RolloutFailed, RolloutStopped},
	RolloutVerifying:  {RolloutComplete, RolloutFailed, RolloutStopped},
}

// Active reports whether a rollout in this phase is still running.
func (phase RolloutPhase) Active() bool {
	_, running := rolloutTransitions[phase]
	return running
}

// CanMoveTo reports whether a rollout may move from phase to next. Staying in
// the same phase is allowed, since a rollout is saved as its nodes advance.
func (phase RolloutPhase) CanMoveTo(next RolloutPhase) bool {
	if phase == next {
		return true
	}
	for _, allowed := range rolloutTransitions[phase] {
		if allowed == next {
			return true
		}
	}
	return false
}

// RolloutNodePhase is the coordinator's record of one node in a rollout. The
// install and restart phases keep their historical saved values, but they
// are turned into commands only through Action.
type RolloutNodePhase string

const (
	RolloutNodeQueued     RolloutNodePhase = "queued"
	RolloutNodeInstalling RolloutNodePhase = "install"
	RolloutNodeRestarting RolloutNodePhase = "restart"
	RolloutNodeComplete   RolloutNodePhase = "complete"
)

var rolloutNodeTransitions = map[RolloutNodePhase][]RolloutNodePhase{
	RolloutNodeQueued:     {RolloutNodeInstalling, RolloutNodeComplete},
	RolloutNodeInstalling: {RolloutNodeRestarting, RolloutNodeComplete},
	RolloutNodeRestarting: {RolloutNodeComplete},
}

// CanMoveTo reports whether a node in a rollout may move from phase to next.
func (phase RolloutNodePhase) CanMoveTo(next RolloutNodePhase) bool {
	for _, allowed := range rolloutNodeTransitions[phase] {
		if allowed == next {
			return true
		}
	}
	return false
}

// Action is the command the coordinator sends a node in this phase while it
// is the node being updated, and false for a phase that sends none.
func (phase RolloutNodePhase) Action() (UpdateAction, bool) {
	switch phase {
	case RolloutNodeQueued:
		return actionPrepare, true
	case RolloutNodeInstalling:
		return actionInstall, true
	case RolloutNodeRestarting:
		return actionRestart, true
	}
	return "", false
}

// NodePhase is one node's own progress through an update.
type NodePhase string

const (
	nodePrepared   NodePhase = "prepared"
	nodeInstalling NodePhase = "installing"
	nodeInstalled  NodePhase = "installed"
	nodeRestarting NodePhase = "restarting"
	nodeComplete   NodePhase = "complete"
	nodeFailed     NodePhase = "failed"
)

// nodeTransitions lists the moves a node makes while it runs commands. A
// node restored after a restart is set complete or failed directly.
var nodeTransitions = map[NodePhase][]NodePhase{
	"":             {nodePrepared, nodeFailed},
	nodePrepared:   {nodeInstalling, nodeFailed},
	nodeInstalling: {nodeInstalled, nodeFailed},
	nodeInstalled:  {nodeRestarting, nodeFailed},
	nodeRestarting: {nodeFailed},
}

// CanMoveTo reports whether a node may move from phase to next.
func (phase NodePhase) CanMoveTo(next NodePhase) bool {
	for _, allowed := range nodeTransitions[phase] {
		if allowed == next {
			return true
		}
	}
	return false
}

// UpdateAction is a command the coordinator sends a node.
type UpdateAction string

const (
	actionPrepare UpdateAction = "prepare"
	actionInstall UpdateAction = "install"
	actionRestart UpdateAction = "restart"
	actionRelease UpdateAction = "release"
)

// checkRolloutMove refuses to save next over saved when the move is not in
// the transition tables. A new rollout must start out preparing with every
// node queued.
func checkRolloutMove(saved, next RolloutStatus) error {
	if saved.ID != next.ID {
		if next.Phase != RolloutPreparing || slices.ContainsFunc(next.Nodes, func(node RolloutNode) bool { return node.Phase != RolloutNodeQueued }) {
			return fmt.Errorf("a new rollout cannot start %s", next.Phase)
		}
		return nil
	}
	if !saved.Phase.CanMoveTo(next.Phase) {
		return fmt.Errorf("a rollout cannot move from %s to %s", saved.Phase, next.Phase)
	}
	for i, node := range next.Nodes {
		if i < len(saved.Nodes) && node.Phase != saved.Nodes[i].Phase && !saved.Nodes[i].Phase.CanMoveTo(node.Phase) {
			return fmt.Errorf("%s cannot move from %s to %s", node.Name, saved.Nodes[i].Phase, node.Phase)
		}
	}
	return nil
}
