package trustanchor

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNextAnchorStateFollowsRFC5011Table(t *testing.T) {
	authenticated := anchorEvent{authenticated: true, present: true}
	cases := []struct {
		name  string
		from  AnchorState
		event anchorEvent
		want  AnchorState
	}{
		{"pending key seen inside hold-down stays pending", StateAddPending, authenticated, StateAddPending},
		{"pending key seen after hold-down becomes valid", StateAddPending, with(authenticated, func(e *anchorEvent) { e.addHoldDownDone = true }), StateValid},
		{"pending key that disappears goes back to start", StateAddPending, with(authenticated, func(e *anchorEvent) { e.present = false }), StateStart},
		{"pending key with the revoke bit goes back to start", StateAddPending, with(authenticated, func(e *anchorEvent) { e.revokeBit = true }), StateStart},
		{"pending key whose sources are revoked goes back to start", StateAddPending, with(authenticated, func(e *anchorEvent) { e.sourcesRevoked = true }), StateStart},
		{"unauthenticated pending key whose sources are revoked goes back to start", StateAddPending, anchorEvent{sourcesRevoked: true}, StateStart},
		{"pending key revoked by itself is revoked", StateAddPending, anchorEvent{revoked: true}, StateRevoked},
		{"valid key that disappears is missing", StateValid, with(authenticated, func(e *anchorEvent) { e.present = false }), StateMissing},
		{"missing key that comes back is valid", StateMissing, authenticated, StateValid},
		{"valid key revoked by itself is revoked", StateValid, anchorEvent{revoked: true}, StateRevoked},
		{"missing key revoked by itself is revoked", StateMissing, anchorEvent{revoked: true}, StateRevoked},
		{"revoked key gone past the remove hold-down is removed", StateRevoked, with(authenticated, func(e *anchorEvent) { e.present = false; e.removeHoldDownDone = true }), StateRemoved},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := nextAnchorState(test.from, test.event); got != test.want {
				t.Fatalf("nextAnchorState(%s) = %s, want %s", test.from, got, test.want)
			}
		})
	}
}

func TestNextAnchorStateRefusesIllegalTransitions(t *testing.T) {
	for _, event := range allAnchorEvents() {
		for _, from := range []AnchorState{StateAddPending, StateValid, StateMissing, StateRevoked, StateRemoved} {
			to := nextAnchorState(from, event)
			if !legalAnchorTransition(from, to) {
				t.Fatalf("nextAnchorState(%s, %+v) = %s, an illegal transition", from, event, to)
			}
			if to == StateValid && from == StateAddPending && (!event.authenticated || !event.addHoldDownDone) {
				t.Fatalf("pending key became valid without an authenticated sighting after the hold-down: %+v", event)
			}
			if to == StateRevoked && from != StateRevoked && !event.revoked {
				t.Fatalf("%s became revoked without an authenticated revocation: %+v", from, event)
			}
			if to == StateRemoved && from == StateRevoked && (event.present || !event.removeHoldDownDone) {
				t.Fatalf("revoked key removed before the remove hold-down or while present: %+v", event)
			}
		}
	}
}

// legalAnchorTransition is RFC 5011 section 4.2's diagram. Staying put is
// always legal.
func legalAnchorTransition(from, to AnchorState) bool {
	if from == to {
		return true
	}
	legal := map[AnchorState][]AnchorState{
		StateAddPending: {StateStart, StateValid, StateRevoked},
		StateValid:      {StateMissing, StateRevoked},
		StateMissing:    {StateValid, StateRevoked},
		StateRevoked:    {StateRemoved},
	}
	return slices.Contains(legal[from], to)
}

// TestAdvanceAnchorsMatchesTheFormerTwoLoopGuards checks every combination of
// two anchors, one vouching for the other, against the revocation loop and
// switch advanceAnchors used before the transition table, so the two former
// guard sites and nextAnchorState agree.
func TestAdvanceAnchorsMatchesTheFormerTwoLoopGuards(t *testing.T) {
	manager := &Manager{opts: Options{Owner: ".", RemoveHoldDown: 30 * 24 * time.Hour}}
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	setups := anchorSetups(now)
	compared := 0
	for _, subject := range setups {
		for _, source := range setups {
			for _, authenticated := range []bool{false, true} {
				build := func() (*Snapshot, map[string]*Anchor, map[string]*dns.DNSKEY, map[string]struct{}) {
					return twoAnchorObservation(subject, source)
				}
				want, existingWant, observed, revocations := build()
				legacyAdvanceAnchors(manager, want, now, observed, existingWant, revocations, authenticated)
				got, existingGot, observed, revocations := build()
				manager.advanceAnchors(got, now, observed, existingGot, revocations, authenticated)
				if !reflect.DeepEqual(sortedAnchors(*got), sortedAnchors(*want)) {
					t.Fatalf("subject %+v source %+v authenticated %v:\n got %+v\nwant %+v", subject, source, authenticated, got.Anchors, want.Anchors)
				}
				compared++
			}
		}
	}
	if compared < 10000 {
		t.Fatalf("compared only %d cases", compared)
	}
}

type anchorSetup struct {
	state     AnchorState
	presence  int // 0 absent, 1 present, 2 present with the revoke bit
	revoked   bool
	holdDown  time.Time
	revokedAt time.Time
}

func anchorSetups(now time.Time) []anchorSetup {
	var setups []anchorSetup
	for _, state := range []AnchorState{StateAddPending, StateValid, StateMissing, StateRevoked, StateRemoved} {
		for presence := range 3 {
			for _, revoked := range []bool{false, true} {
				for _, holdDown := range []time.Time{now.Add(-time.Hour), now.Add(time.Hour)} {
					for _, revokedAt := range []time.Time{{}, now.Add(-31 * 24 * time.Hour), now.Add(-time.Hour)} {
						setups = append(setups, anchorSetup{state, presence, revoked, holdDown, revokedAt})
					}
				}
			}
		}
	}
	return setups
}

func twoAnchorObservation(subject, source anchorSetup) (*Snapshot, map[string]*Anchor, map[string]*dns.DNSKEY, map[string]struct{}) {
	snapshot := &Snapshot{}
	observed := make(map[string]*dns.DNSKEY)
	revocations := make(map[string]struct{})
	for index, setup := range []anchorSetup{subject, source} {
		keyID := fmt.Sprintf("key-%d", index)
		anchor := Anchor{Owner: ".", KeyID: keyID, DNSKEY: "old", State: setup.state, HoldDownUntil: setup.holdDown, RevokedAt: setup.revokedAt}
		if index == 0 {
			anchor.SourceKeyIDs = []string{"key-1"}
		}
		snapshot.Anchors = append(snapshot.Anchors, anchor)
		if setup.presence > 0 {
			flags := uint16(257)
			if setup.presence == 2 {
				flags |= revokeFlag
			}
			observed[keyID] = &dns.DNSKEY{Hdr: dns.RR_Header{Name: "."}, Flags: flags, Protocol: 3, Algorithm: 13, PublicKey: keyID}
		}
		if setup.revoked {
			revocations[keyID] = struct{}{}
		}
	}
	existing := make(map[string]*Anchor, len(snapshot.Anchors))
	for index := range snapshot.Anchors {
		existing[snapshot.Anchors[index].KeyID] = &snapshot.Anchors[index]
	}
	return snapshot, existing, observed, revocations
}

func sortedAnchors(snapshot Snapshot) []Anchor {
	anchors := slices.Clone(snapshot.Anchors)
	slices.SortFunc(anchors, func(left, right Anchor) int { return strings.Compare(left.KeyID, right.KeyID) })
	return anchors
}

func allAnchorEvents() []anchorEvent {
	var events []anchorEvent
	for bits := range 1 << 7 {
		events = append(events, anchorEvent{
			revoked:            bits&1 != 0,
			authenticated:      bits&2 != 0,
			present:            bits&4 != 0,
			revokeBit:          bits&8 != 0 && bits&4 != 0,
			sourcesRevoked:     bits&16 != 0,
			addHoldDownDone:    bits&32 != 0,
			removeHoldDownDone: bits&64 != 0,
		})
	}
	return events
}

func with(event anchorEvent, change func(*anchorEvent)) anchorEvent {
	change(&event)
	return event
}

// legacyAdvanceAnchors is advanceAnchors as it was before the transition
// table: a revocation loop, then a switch on the state. It stays here only as
// the reference the table is checked against.
func legacyAdvanceAnchors(
	manager *Manager,
	current *Snapshot,
	now time.Time,
	observed map[string]*dns.DNSKEY,
	existing map[string]*Anchor,
	revocations map[string]struct{},
	authenticated bool,
) {
	legacySourcesRevoked := func(sourceIDs []string) bool {
		if len(sourceIDs) == 0 {
			return false
		}
		for _, sourceID := range sourceIDs {
			anchor := existing[sourceID]
			if anchor != nil && anchor.State != StateRevoked && anchor.State != StateRemoved {
				return false
			}
		}
		return true
	}
	for keyID := range revocations {
		anchor := existing[keyID]
		if anchor == nil || anchor.State == StateRevoked || anchor.State == StateRemoved {
			continue
		}
		anchor.State = StateRevoked
		anchor.RevokedAt = now
		anchor.LastSeen = now
	}
	discard := make(map[string]struct{})
	for keyID, anchor := range existing {
		if _, revoked := revocations[keyID]; revoked {
			continue
		}
		if !authenticated {
			if anchor.State == StateAddPending && legacySourcesRevoked(anchor.SourceKeyIDs) {
				discard[keyID] = struct{}{}
			}
			continue
		}
		key, present := observed[keyID]
		switch anchor.State {
		case StateValid, StateMissing:
			if present && key.Flags&revokeFlag == 0 {
				anchor.State = StateValid
				anchor.LastSeen = now
				anchor.DNSKEY = anchorValue(key)
			} else if !present {
				anchor.State = StateMissing
			}
		case StateAddPending:
			if !present || key.Flags&revokeFlag != 0 || legacySourcesRevoked(anchor.SourceKeyIDs) {
				discard[keyID] = struct{}{}
				continue
			}
			anchor.LastSeen = now
			if !now.Before(anchor.HoldDownUntil) && authenticated {
				anchor.State = StateValid
				anchor.SourceKeyIDs = nil
			}
		case StateRevoked:
			if !present && !anchor.RevokedAt.IsZero() && !now.Before(anchor.RevokedAt.Add(manager.opts.RemoveHoldDown)) {
				anchor.State = StateRemoved
			}
		}
	}
	current.Anchors = slices.DeleteFunc(current.Anchors, func(anchor Anchor) bool {
		_, remove := discard[anchor.KeyID]
		return remove
	})
}
