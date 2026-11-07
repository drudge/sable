package dnssec

import (
	"encoding/json"
	"testing"
)

func TestKeyStateTransitions(t *testing.T) {
	states := []KeyState{StatePublished, StateReady, StateActive, StateRetiring, "", "removed"}
	allowed := map[[2]KeyState]bool{
		{StatePublished, StateReady}: true,
		{StateReady, StateActive}:    true,
		{StateActive, StateRetiring}: true,
	}
	for _, from := range states {
		for _, to := range states {
			if got, want := from.CanMoveTo(to), allowed[[2]KeyState{from, to}]; got != want {
				t.Errorf("%q.CanMoveTo(%q) = %v, want %v", from, to, got, want)
			}
		}
	}
	for _, state := range states {
		if got, want := state.Valid(), state != "" && state != "removed"; got != want {
			t.Errorf("%q.Valid() = %v, want %v", state, got, want)
		}
		if got, want := state.Pending(), state == StatePublished || state == StateReady; got != want {
			t.Errorf("%q.Pending() = %v, want %v", state, got, want)
		}
	}
}

// The states are stored in the vault, so their encoding must not change.
func TestKeyStateStoredValues(t *testing.T) {
	for state, want := range map[KeyState]string{
		StatePublished: "published", StateReady: "ready", StateActive: "active", StateRetiring: "retiring",
	} {
		encoded, err := json.Marshal(Key{State: state})
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct{ State string }
		if err := json.Unmarshal(encoded, &decoded); err != nil || decoded.State != want {
			t.Errorf("%q encodes as %s", state, encoded)
		}
	}
}
