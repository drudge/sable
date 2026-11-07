package app

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	dnssecstate "github.com/drudge/sable/internal/dnssec"
)

// legacyKeyLifecycleDue and legacyAdvanceKeyState are the two copies of the
// rollover guards that keyLifecycleDue and advanceKeyState had before they
// shared nextTransitions, with the signer and zone lookups passed in as rules.
// TestNextTransitionsMatchesLegacy holds the new code to them.
func legacyKeyLifecycleDue(state dnssecstate.State, rules keyRules, now time.Time) (bool, error) {
	for _, key := range state.Keys {
		if key.State == dnssecstate.StatePublished && !now.Before(key.PublishedAt.Add(rules.rolloverDelay)) {
			return true, nil
		}
		if key.State == dnssecstate.StateReady && key.Role == dnssecstate.RoleZSK {
			return true, nil
		}
		if key.State == dnssecstate.StateReady && key.Role == dnssecstate.RoleKSK {
			keyTag, tagErr := rules.keyTag(key)
			if tagErr != nil {
				return false, tagErr
			}
			if rules.parentDSKeyTag == keyTag {
				return true, nil
			}
		}
		if key.State == dnssecstate.StateRetiring && !key.RemoveAt.IsZero() && !now.Before(key.RemoveAt) {
			return true, nil
		}
	}
	if _, pending := pendingKey(state, dnssecstate.RoleZSK); !pending && activeKeyAge(state, dnssecstate.RoleZSK, now) >= rolloverStartAge(rules.zskLifetime, rules.rolloverDelay) {
		return true, nil
	}
	activeKSK, active := activeKey(state, dnssecstate.RoleKSK)
	if !active {
		return false, nil
	}
	activeTag, err := rules.keyTag(activeKSK)
	if err != nil {
		return false, err
	}
	_, pending := pendingKey(state, dnssecstate.RoleKSK)
	return !pending && rules.parentDSKeyTag == activeTag && activeKeyAge(state, dnssecstate.RoleKSK, now) >= rolloverStartAge(rules.kskLifetime, rules.rolloverDelay), nil
}

func legacyAdvanceKeyState(state *dnssecstate.State, rules keyRules, now time.Time, generate func(role string) dnssecstate.Key) (bool, error) {
	changed := false
	state.Keys = slices.DeleteFunc(state.Keys, func(key dnssecstate.Key) bool {
		remove := key.State == dnssecstate.StateRetiring && !key.RemoveAt.IsZero() && !now.Before(key.RemoveAt)
		changed = changed || remove
		return remove
	})
	for index := range state.Keys {
		key := &state.Keys[index]
		if key.State == dnssecstate.StatePublished && !now.Before(key.PublishedAt.Add(rules.rolloverDelay)) {
			key.State = dnssecstate.StateReady
			changed = true
		}
	}
	retireRole := func(role string, removeAt time.Time) {
		for index := range state.Keys {
			key := &state.Keys[index]
			if key.Role == role && key.State == dnssecstate.StateActive {
				key.State, key.RemoveAt = dnssecstate.StateRetiring, removeAt
			}
		}
	}
	for index := range state.Keys {
		key := &state.Keys[index]
		if key.Role == dnssecstate.RoleZSK && key.State == dnssecstate.StateReady {
			retireRole(dnssecstate.RoleZSK, now.Add(rules.retirementDelay))
			key.State, key.ActivatedAt = dnssecstate.StateActive, now
			changed = true
		}
		if key.Role == dnssecstate.RoleKSK && key.State == dnssecstate.StateReady {
			keyTag, err := rules.keyTag(*key)
			if err != nil {
				return false, err
			}
			if rules.parentDSKeyTag == keyTag {
				retireRole(dnssecstate.RoleKSK, now.Add(rules.retirementDelay))
				key.State, key.ActivatedAt = dnssecstate.StateActive, now
				changed = true
			}
		}
	}
	if _, found := pendingKey(*state, dnssecstate.RoleZSK); !found && activeKeyAge(*state, dnssecstate.RoleZSK, now) >= rolloverStartAge(rules.zskLifetime, rules.rolloverDelay) {
		state.Keys = append(state.Keys, generate(dnssecstate.RoleZSK))
		changed = true
	}
	activeKSK, found := activeKey(*state, dnssecstate.RoleKSK)
	if found {
		activeTag, err := rules.keyTag(activeKSK)
		if err != nil {
			return false, err
		}
		_, pending := pendingKey(*state, dnssecstate.RoleKSK)
		if !pending && rules.parentDSKeyTag == activeTag && now.Sub(activeKSK.ActivatedAt) >= rolloverStartAge(rules.kskLifetime, rules.rolloverDelay) {
			state.Keys = append(state.Keys, generate(dnssecstate.RoleKSK))
			changed = true
		}
	}
	return changed, nil
}

func generatedTestKey(now time.Time) func(role string) dnssecstate.Key {
	return func(role string) dnssecstate.Key {
		return dnssecstate.Key{Role: role, State: dnssecstate.StatePublished, DNSKEY: "generated " + role, CreatedAt: now, PublishedAt: now}
	}
}

// randomKeyState builds a key set that validateKeyState would accept: one
// active key per role, at most one pending key per role, and any number of
// retiring keys.
func randomKeyState(rng *rand.Rand, base time.Time) dnssecstate.State {
	at := func() time.Time { return base.Add(time.Duration(rng.IntN(400)-200) * time.Hour) }
	var state dnssecstate.State
	tag := 0
	add := func(role string, keyState dnssecstate.KeyState) {
		tag++
		key := dnssecstate.Key{Role: role, State: keyState, DNSKEY: fmt.Sprintf("key %d", tag), CreatedAt: at(), PublishedAt: at()}
		switch keyState {
		case dnssecstate.StateActive:
			key.ActivatedAt = at()
		case dnssecstate.StateRetiring:
			key.RemoveAt = at()
		}
		state.Keys = append(state.Keys, key)
	}
	for _, role := range []string{dnssecstate.RoleKSK, dnssecstate.RoleZSK} {
		add(role, dnssecstate.StateActive)
		switch rng.IntN(3) {
		case 1:
			add(role, dnssecstate.StatePublished)
		case 2:
			add(role, dnssecstate.StateReady)
		}
		for range rng.IntN(3) {
			add(role, dnssecstate.StateRetiring)
		}
	}
	rng.Shuffle(len(state.Keys), func(i, j int) { state.Keys[i], state.Keys[j] = state.Keys[j], state.Keys[i] })
	return state
}

func randomKeyRules(rng *rand.Rand, state dnssecstate.State, badTag string) keyRules {
	hours := func(choices ...int) time.Duration { return time.Duration(choices[rng.IntN(len(choices))]) * time.Hour }
	rules := keyRules{
		rolloverDelay: hours(0, 1, 24, 72), retirementDelay: hours(0, 1, 24, 72),
		zskLifetime: hours(0, 12, 24*30, 24*90), kskLifetime: hours(0, 12, 24*365),
		keyTag: func(key dnssecstate.Key) (uint16, error) {
			if key.DNSKEY == badTag {
				return 0, errors.New("bad DNSKEY")
			}
			var tag uint16
			_, err := fmt.Sscanf(key.DNSKEY, "key %d", &tag)
			return tag, err
		},
	}
	// Point the parent DS at a random KSK, or at none.
	if kskTags := slices.DeleteFunc(slices.Clone(state.Keys), func(key dnssecstate.Key) bool { return key.Role != dnssecstate.RoleKSK }); rng.IntN(4) > 0 {
		tag, _ := rules.keyTag(kskTags[rng.IntN(len(kskTags))])
		rules.parentDSKeyTag = tag
	}
	return rules
}

func TestNextTransitionsMatchesLegacy(t *testing.T) {
	rng := rand.New(rand.NewPCG(540, 7583))
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	for run := range 200000 {
		state := randomKeyState(rng, base)
		badTag := ""
		if rng.IntN(20) == 0 {
			badTag = state.Keys[rng.IntN(len(state.Keys))].DNSKEY
		}
		rules := randomKeyRules(rng, state, badTag)
		now := base.Add(time.Duration(rng.IntN(400)-200) * time.Hour)

		legacy := dnssecstate.State{Keys: slices.Clone(state.Keys)}
		legacyChanged, legacyErr := legacyAdvanceKeyState(&legacy, rules, now, generatedTestKey(now))
		legacyDue, legacyDueErr := legacyKeyLifecycleDue(state, rules, now)

		plan, err := nextTransitions(state.Keys, rules, now)
		if (err != nil) != (legacyErr != nil) {
			t.Fatalf("run %d: error %v, legacy advance error %v", run, err, legacyErr)
		}
		if err != nil {
			continue
		}
		got := plan.keys
		for _, role := range plan.generate {
			got = append(got, generatedTestKey(now)(role))
		}
		if plan.changed != legacyChanged || !reflect.DeepEqual(got, legacy.Keys) {
			t.Fatalf("run %d: changed %v keys %+v\nlegacy changed %v keys %+v", run, plan.changed, got, legacyChanged, legacy.Keys)
		}
		// The old due check could stop at an early true before reaching a bad
		// key tag; where it gave an answer, it must be the same one.
		if legacyDueErr == nil && plan.changed != legacyDue {
			t.Fatalf("run %d: due %v, legacy due %v, state %+v", run, plan.changed, legacyDue, state.Keys)
		}
	}
}

// Every key move nextTransitions makes is one the lifecycle allows, and the
// input is left alone so keyLifecycleDue can call it without side effects.
func TestNextTransitionsOnlyMovesForward(t *testing.T) {
	rng := rand.New(rand.NewPCG(540, 3))
	base := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	for range 20000 {
		state := randomKeyState(rng, base)
		before := slices.Clone(state.Keys)
		plan, err := nextTransitions(state.Keys, randomKeyRules(rng, state, ""), base.Add(time.Duration(rng.IntN(400)-200)*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, state.Keys) {
			t.Fatal("nextTransitions changed its input")
		}
		after := map[string]dnssecstate.KeyState{}
		for _, key := range plan.keys {
			after[key.DNSKEY] = key.State
		}
		for _, key := range before {
			next, kept := after[key.DNSKEY]
			switch {
			case !kept && key.State != dnssecstate.StateRetiring:
				t.Fatalf("%s %s key was removed", key.State, key.Role)
			case kept && next != key.State && !key.State.CanMoveTo(next) &&
				!(key.State.CanMoveTo(dnssecstate.StateReady) && dnssecstate.StateReady.CanMoveTo(next)):
				t.Fatalf("%s key moved %s -> %s", key.Role, key.State, next)
			}
		}
	}
}

func TestMoveKeyRejectsIllegalTransitions(t *testing.T) {
	for _, test := range []struct{ from, to dnssecstate.KeyState }{
		{dnssecstate.StatePublished, dnssecstate.StateActive},
		{dnssecstate.StateReady, dnssecstate.StateRetiring},
		{dnssecstate.StateActive, dnssecstate.StateReady},
		{dnssecstate.StateRetiring, dnssecstate.StateActive},
		{dnssecstate.StateActive, dnssecstate.StateActive},
	} {
		key := dnssecstate.Key{Role: dnssecstate.RoleKSK, State: test.from}
		err := moveKey(&key, test.to)
		if err == nil || key.State != test.from || !strings.Contains(err.Error(), "cannot move") {
			t.Errorf("moveKey %s -> %s = %v, state %s", test.from, test.to, err, key.State)
		}
	}
	key := dnssecstate.Key{Role: dnssecstate.RoleZSK, State: dnssecstate.StatePublished}
	if err := moveKey(&key, dnssecstate.StateReady); err != nil || key.State != dnssecstate.StateReady {
		t.Fatalf("moveKey published -> ready = %v, state %s", err, key.State)
	}
}

// A ZSK passes through ready inside one pass, so ready is only ever stored for
// a KSK waiting on its parent DS.
func TestReadyIsOnlyStoredForKSK(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	rules := keyRules{rolloverDelay: time.Hour, retirementDelay: time.Hour, zskLifetime: 1000 * time.Hour, kskLifetime: 1000 * time.Hour,
		parentDSKeyTag: 1, keyTag: func(key dnssecstate.Key) (uint16, error) {
			var tag uint16
			_, err := fmt.Sscanf(key.DNSKEY, "key %d", &tag)
			return tag, err
		}}
	published := now.Add(-2 * time.Hour)
	keys := []dnssecstate.Key{
		{Role: dnssecstate.RoleKSK, State: dnssecstate.StateActive, DNSKEY: "key 1", ActivatedAt: now},
		{Role: dnssecstate.RoleKSK, State: dnssecstate.StatePublished, DNSKEY: "key 2", PublishedAt: published},
		{Role: dnssecstate.RoleZSK, State: dnssecstate.StateActive, DNSKEY: "key 3", ActivatedAt: now},
		{Role: dnssecstate.RoleZSK, State: dnssecstate.StatePublished, DNSKEY: "key 4", PublishedAt: published},
	}
	plan, err := nextTransitions(keys, rules, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []dnssecstate.KeyState{dnssecstate.StateActive, dnssecstate.StateReady, dnssecstate.StateRetiring, dnssecstate.StateActive}
	for index, key := range plan.keys {
		if key.State != want[index] {
			t.Errorf("%s %s = %s, want %s", key.Role, key.DNSKEY, key.State, want[index])
		}
	}
	if len(plan.generate) != 0 || !plan.changed {
		t.Fatalf("generate %v changed %v", plan.generate, plan.changed)
	}
}
