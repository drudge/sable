package trustanchor

import "time"

// AnchorState is where an anchor stands in the RFC 5011 section 4 state
// table. The values are persisted, so they never change.
type AnchorState string

const (
	// StateStart is RFC 5011's Start: the key isn't tracked. It is never
	// persisted; an anchor that moves to Start is dropped from the snapshot,
	// and an observed key that no anchor covers starts here.
	StateStart      AnchorState = "start"
	StateAddPending AnchorState = "add-pending"
	StateValid      AnchorState = "valid"
	StateMissing    AnchorState = "missing"
	StateRevoked    AnchorState = "revoked"
	// StateRemoved anchors are kept after the remove hold-down so a key that
	// comes back revoked isn't tracked again.
	StateRemoved AnchorState = "removed"
)

// Trusted reports whether an anchor in this state validates the trust point.
func (state AnchorState) Trusted() bool {
	return state == StateValid || state == StateMissing
}

// Revoked reports whether an anchor in this state has been revoked.
func (state AnchorState) Revoked() bool {
	return state == StateRevoked || state == StateRemoved
}

// revocable reports whether an authenticated revocation moves an anchor in
// this state to Revoked.
func (state AnchorState) revocable() bool {
	return state.Trusted() || state == StateAddPending
}

// anchorEvent is what one DNSKEY observation says about one anchor.
type anchorEvent struct {
	// revoked: the key appeared with the REVOKE bit and a valid
	// self-signature.
	revoked bool
	// authenticated: a current trust anchor signed the DNSKEY RRset.
	authenticated bool
	// present: the key is in the RRset.
	present bool
	// revokeBit: the key carries the REVOKE bit, authenticated or not.
	revokeBit bool
	// sourcesRevoked: every key that vouched for this pending key is revoked.
	sourcesRevoked bool
	// addHoldDownDone: the add hold-down has passed.
	addHoldDownDone bool
	// removeHoldDownDone: the remove hold-down has passed since revocation.
	removeHoldDownDone bool
}

// seen reports whether the observation is an authenticated sighting of the
// key in good standing.
func (event anchorEvent) seen() bool {
	return event.authenticated && event.present && !event.revokeBit
}

// nextAnchorState is the RFC 5011 section 4 transition table: the state an
// anchor moves to after one observation. It has no side effects; apply
// records what the move means for the anchor's other fields.
func nextAnchorState(state AnchorState, event anchorEvent) AnchorState {
	if event.revoked {
		if state.revocable() {
			return StateRevoked
		}
		return state
	}
	if !event.authenticated {
		if state == StateAddPending && event.sourcesRevoked {
			return StateStart
		}
		return state
	}
	switch state {
	case StateValid, StateMissing:
		if !event.present {
			return StateMissing
		}
		if event.revokeBit {
			return state
		}
		return StateValid
	case StateAddPending:
		if !event.present || event.revokeBit || event.sourcesRevoked {
			return StateStart
		}
		if event.addHoldDownDone {
			return StateValid
		}
		return StateAddPending
	case StateRevoked:
		if !event.present && event.removeHoldDownDone {
			return StateRemoved
		}
	}
	return state
}

// apply moves the anchor to next and updates the fields the move touches.
// value is the observed key's anchor text, used when the key is seen.
func (anchor *Anchor) apply(next AnchorState, event anchorEvent, value string, now time.Time) {
	previous := anchor.State
	anchor.State = next
	switch {
	case next == StateRevoked && previous != StateRevoked:
		anchor.RevokedAt = now
		anchor.LastSeen = now
	case previous == StateAddPending && event.seen():
		anchor.LastSeen = now
		if next == StateValid {
			anchor.SourceKeyIDs = nil
		}
	case previous.Trusted() && next == StateValid && event.seen():
		anchor.LastSeen = now
		anchor.DNSKEY = value
	}
}

// CountStates sets the snapshot's status counts from its anchors.
func CountStates(snapshot *Snapshot) {
	snapshot.Status.Active, snapshot.Status.Pending, snapshot.Status.Missing, snapshot.Status.Revoked = 0, 0, 0, 0
	for _, anchor := range snapshot.Anchors {
		switch anchor.State {
		case StateValid:
			snapshot.Status.Active++
		case StateMissing:
			snapshot.Status.Active++
			snapshot.Status.Missing++
		case StateAddPending:
			snapshot.Status.Pending++
		case StateRevoked:
			snapshot.Status.Revoked++
		}
	}
}
