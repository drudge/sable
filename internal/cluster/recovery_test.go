package cluster

import (
	"context"
	"errors"
	"testing"
)

type recoveryStateReplicator struct {
	memoryStateReplicator
	prepared int
	err      error
}

func (replicator *recoveryStateReplicator) PrepareRecovery(context.Context) error {
	replicator.prepared++
	return replicator.err
}

func TestRecoveryPromotionPreparesStateBeforeTakingOver(t *testing.T) {
	_, replica := joinedClusterServices(t)
	state := &recoveryStateReplicator{err: errors.New("simulated prepare failure")}
	replica.replicator = state
	if err := replica.Promote(context.Background(), replica.nodeID); err == nil {
		t.Fatal("recovery promotion succeeded although preparing its state failed")
	}
	if snapshot := replica.Snapshot(); snapshot.LocalRole != RoleReplica {
		t.Fatalf("replica took over after a failed prepare: %#v", snapshot)
	}
	state.err = nil
	if err := replica.Promote(context.Background(), replica.nodeID); err != nil {
		t.Fatal(err)
	}
	if snapshot := replica.Snapshot(); snapshot.LocalRole != RolePrimary || state.prepared != 2 {
		t.Fatalf("promoted role = %s after %d prepares, want primary after 2", snapshot.LocalRole, state.prepared)
	}
	if err := replica.Promote(context.Background(), replica.nodeID); err != nil {
		t.Fatal(err)
	}
	if state.prepared != 2 {
		t.Fatalf("promoting the current primary prepared recovery again (%d prepares)", state.prepared)
	}
}

func TestPlannedHandoffDoesNotPrepareRecovery(t *testing.T) {
	primary, replica := joinedClusterServices(t)
	primaryState, replicaState := &recoveryStateReplicator{}, &recoveryStateReplicator{}
	primary.replicator, replica.replicator = primaryState, replicaState
	if err := primary.Promote(context.Background(), replica.nodeID); err != nil {
		t.Fatal(err)
	}
	if primaryState.prepared != 0 || replicaState.prepared != 0 {
		t.Fatalf("planned handoff prepared recovery: primary %d, replica %d", primaryState.prepared, replicaState.prepared)
	}
}
