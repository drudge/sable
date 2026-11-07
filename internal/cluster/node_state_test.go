package cluster

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClassifyNode(t *testing.T) {
	cases := []struct {
		name         string
		local        bool
		role         string
		heard, fresh bool
		lag          uint64
		state        NodeState
		sync         SyncState
	}{
		{"local primary", true, RolePrimary, true, true, 0, StateOnline, SyncCurrent},
		{"local replica waits for the primary", true, RoleReplica, true, true, 0, StateOnline, SyncUnverified},
		{"member never heard from", false, RoleReplica, false, false, 0, StateUnknown, SyncUnknown},
		{"member gone stale", false, RoleReplica, true, false, 3, StateUnreachable, SyncUnknown},
		{"stale primary is no more current than a replica", false, RolePrimary, true, false, 0, StateUnreachable, SyncUnknown},
		{"member caught up", false, RoleReplica, true, true, 0, StateOnline, SyncCurrent},
		{"member behind", false, RoleReplica, true, true, 2, StateOnline, SyncBehind},
	}
	for _, test := range cases {
		state, sync := classifyNode(test.local, test.role, test.heard, test.fresh, test.lag)
		if state != test.state || sync != test.sync {
			t.Errorf("%s: classifyNode = %s/%s, want %s/%s", test.name, state, sync, test.state, test.sync)
		}
	}
}

// TestClassifyNodeNeverPairsIllegalStates checks every input: only an online
// node has a known sync state, and an unverified one is always local.
func TestClassifyNodeNeverPairsIllegalStates(t *testing.T) {
	for _, local := range []bool{false, true} {
		for _, role := range []string{RolePrimary, RoleReplica, ""} {
			for _, heard := range []bool{false, true} {
				for _, fresh := range []bool{false, true} {
					for _, lag := range []uint64{0, 1, 1 << 40} {
						state, sync := classifyNode(local, role, heard, fresh, lag)
						if state != StateOnline && sync != SyncUnknown {
							t.Errorf("classifyNode(%v, %q, %v, %v, %d) = %s/%s: a node that is not online cannot have a known sync state", local, role, heard, fresh, lag, state, sync)
						}
						if sync == SyncUnverified && !local {
							t.Errorf("classifyNode(%v, %q, %v, %v, %d) = %s/%s: only the local replica is unverified", local, role, heard, fresh, lag, state, sync)
						}
						if sync == SyncConflict {
							t.Errorf("classifyNode never reports a conflict; applyPrimaryConflict does")
						}
					}
				}
			}
		}
	}
}

// The web console, MCP, alerts, and metrics read these values, so their
// spelling is part of the API.
func TestNodeStateWireValues(t *testing.T) {
	want := map[string]string{
		string(StateUnknown): "unknown", string(StateOnline): "online", string(StateUnreachable): "unreachable",
	}
	for got, value := range want {
		if got != value {
			t.Errorf("node state %q, want %q", got, value)
		}
	}
	for got, value := range map[SyncState]string{
		SyncUnknown: "unknown", SyncUnverified: "unverified", SyncCurrent: "current", SyncBehind: "behind", SyncConflict: "conflict",
	} {
		if string(got) != value {
			t.Errorf("sync state %q, want %q", got, value)
		}
	}
	contents, err := json.Marshal(Node{State: StateUnreachable, SyncState: SyncBehind})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), `"state":"unreachable"`) || !strings.Contains(string(contents), `"sync_state":"behind"`) {
		t.Fatalf("node JSON = %s", contents)
	}
}
