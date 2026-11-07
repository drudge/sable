package app

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	dnssecstate "github.com/drudge/sable/internal/dnssec"
	"github.com/drudge/sable/internal/zone"
)

const dnssecKeyStateVersion = 2

type zoneSigningKey struct {
	key        *dns.DNSKEY
	privateKey crypto.Signer
	role       string
	state      dnssecstate.KeyState
}

func (signer *dnssecSigner) signingKeys(ctx context.Context, zone zone.Zone) ([]zoneSigningKey, error) {
	signer.mu.Lock()
	defer signer.mu.Unlock()

	state, changed, err := signer.loadKeyState(ctx, zone)
	if err != nil {
		return nil, err
	}
	advanced, err := signer.advanceKeyState(&state, zone)
	if err != nil {
		return nil, err
	}
	if changed || advanced {
		if err := signer.saveKeyState(ctx, zone, state); err != nil {
			return nil, err
		}
	}
	return decodeZoneSigningKeys(state.Keys, zone.Name)
}

func (signer *dnssecSigner) RequestRollover(ctx context.Context, zone zone.Zone, role string) error {
	signer.mu.Lock()
	defer signer.mu.Unlock()

	if role != dnssecstate.RoleKSK && role != dnssecstate.RoleZSK {
		return fmt.Errorf("unsupported DNSSEC key role %q", role)
	}
	state, _, err := signer.loadKeyState(ctx, zone)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(state.Keys, func(key dnssecstate.Key) bool {
		return key.Role == role && key.State.Pending()
	}) {
		return fmt.Errorf("a %s rollover is already pending", strings.ToUpper(role))
	}
	key, err := signer.generateManagedKey(zone, role, dnssecstate.StatePublished, signer.now().UTC())
	if err != nil {
		return err
	}
	state.Keys = append(state.Keys, key)
	return signer.saveKeyState(ctx, zone, state)
}

func (signer *dnssecSigner) keyLifecycleDue(ctx context.Context, zone zone.Zone) (bool, error) {
	signer.mu.Lock()
	defer signer.mu.Unlock()

	state, changed, err := signer.loadKeyState(ctx, zone)
	if err != nil || changed {
		return changed, err
	}
	plan, err := nextTransitions(state.Keys, signer.keyRules(zone), signer.now().UTC())
	return plan.changed, err
}

func rolloverStartAge(lifetime, prepublish time.Duration) time.Duration {
	if lifetime <= prepublish {
		return 0
	}
	return lifetime - prepublish
}

func (signer *dnssecSigner) KeyStatus(ctx context.Context, zone zone.Zone) (dnssecstate.Status, error) {
	signer.mu.Lock()
	defer signer.mu.Unlock()

	state, _, err := signer.loadKeyState(ctx, zone)
	if err != nil {
		return dnssecstate.Status{}, err
	}
	status := dnssecstate.Status{ParentDSKeyTag: zone.ParentDSKeyTag}
	for _, managed := range state.Keys {
		key, _, err := decodeManagedKey(managed, zone.Name)
		if err != nil {
			return dnssecstate.Status{}, err
		}
		item := dnssecstate.KeyStatus{
			Role: managed.Role, State: managed.State, KeyTag: key.KeyTag(), DNSKEY: key.String(),
			CreatedAt: managed.CreatedAt, ActivatedAt: managed.ActivatedAt, RemoveAt: managed.RemoveAt,
		}
		if managed.State == dnssecstate.StatePublished {
			item.ReadyAt = managed.PublishedAt.Add(signer.rolloverDelay(zone))
		}
		if managed.Role == dnssecstate.RoleKSK {
			if ds := key.ToDS(dns.SHA256); ds != nil {
				item.DS = ds.String()
			}
		}
		status.Keys = append(status.Keys, item)
	}
	slices.SortFunc(status.Keys, func(left, right dnssecstate.KeyStatus) int {
		if left.Role != right.Role {
			return strings.Compare(left.Role, right.Role)
		}
		return strings.Compare(string(left.State), string(right.State))
	})
	status.NextAction = keyStatusNextAction(status)
	return status, nil
}

func keyStatusNextAction(status dnssecstate.Status) string {
	for _, key := range status.Keys {
		if key.Role == dnssecstate.RoleKSK && key.State == dnssecstate.StateReady {
			return "Publish the pending KSK DS record at the parent, then confirm its key tag."
		}
	}
	if status.ParentDSKeyTag == 0 {
		return "Publish the active KSK DS record at the parent and confirm its key tag."
	}
	return "Rollover policy is active."
}

func (signer *dnssecSigner) loadKeyState(ctx context.Context, zone zone.Zone) (dnssecstate.State, bool, error) {
	encoded, err := signer.vault.Get(ctx, dnssecStateSecretName(zone.Name, zone.DNSSECAlgorithm))
	if err == nil {
		var state dnssecstate.State
		if decodeErr := json.Unmarshal(encoded, &state); decodeErr != nil {
			return dnssecstate.State{}, false, errors.New("decode DNSSEC key state: invalid encrypted value")
		}
		if state.Version != dnssecKeyStateVersion || state.Zone != zone.Name || state.Algorithm != zone.DNSSECAlgorithm {
			return dnssecstate.State{}, false, errors.New("DNSSEC key state does not match the configured zone and algorithm")
		}
		if validateErr := validateKeyState(state, zone); validateErr != nil {
			return dnssecstate.State{}, false, validateErr
		}
		return state, false, nil
	}
	if !errors.Is(err, auth.ErrNotFound) {
		return dnssecstate.State{}, false, fmt.Errorf("load DNSSEC key state: %w", err)
	}

	now := signer.now().UTC()
	state := dnssecstate.State{Version: dnssecKeyStateVersion, Zone: zone.Name, Algorithm: zone.DNSSECAlgorithm}
	legacy, legacyErr := signer.vault.Get(ctx, dnssecSecretName(zone.Name, zone.DNSSECAlgorithm))
	if legacyErr == nil {
		key, _, decodeErr := decodeDNSSECKey(legacy)
		if decodeErr != nil {
			return dnssecstate.State{}, false, decodeErr
		}
		var material dnssecKeyMaterial
		if decodeErr := json.Unmarshal(legacy, &material); decodeErr != nil {
			return dnssecstate.State{}, false, decodeErr
		}
		state.Keys = append(state.Keys, dnssecstate.Key{
			Role: dnssecstate.RoleKSK, State: dnssecstate.StateActive, DNSKEY: key.String(), PrivateKey: material.PrivateKey,
			CreatedAt: now, PublishedAt: now, ActivatedAt: now,
		})
		zsk, generateErr := signer.generateManagedKey(zone, dnssecstate.RoleZSK, dnssecstate.StatePublished, now)
		if generateErr != nil {
			return dnssecstate.State{}, false, generateErr
		}
		state.Keys = append(state.Keys, zsk)
		return state, true, nil
	}
	if !errors.Is(legacyErr, auth.ErrNotFound) {
		return dnssecstate.State{}, false, fmt.Errorf("load legacy DNSSEC key: %w", legacyErr)
	}
	for _, role := range []string{dnssecstate.RoleKSK, dnssecstate.RoleZSK} {
		key, generateErr := signer.generateManagedKey(zone, role, dnssecstate.StateActive, now)
		if generateErr != nil {
			return dnssecstate.State{}, false, generateErr
		}
		state.Keys = append(state.Keys, key)
	}
	return state, true, nil
}

func (signer *dnssecSigner) saveKeyState(ctx context.Context, zone zone.Zone, state dnssecstate.State) error {
	if err := validateKeyState(state, zone); err != nil {
		return err
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode DNSSEC key state: %w", err)
	}
	if err := signer.vault.Put(ctx, dnssecStateSecretName(zone.Name, zone.DNSSECAlgorithm), encoded); err != nil {
		return fmt.Errorf("store DNSSEC key state: %w", err)
	}
	return nil
}

// advanceKeyState applies every key transition that is due and generates the
// key that starts a new rollover. keyLifecycleDue asks the same question
// through nextTransitions, so a change it reports is always one this makes.
func (signer *dnssecSigner) advanceKeyState(state *dnssecstate.State, zone zone.Zone) (bool, error) {
	now := signer.now().UTC()
	plan, err := nextTransitions(state.Keys, signer.keyRules(zone), now)
	if err != nil {
		return false, err
	}
	state.Keys = plan.keys
	for _, role := range plan.generate {
		key, err := signer.generateManagedKey(zone, role, dnssecstate.StatePublished, now)
		if err != nil {
			return false, err
		}
		state.Keys = append(state.Keys, key)
	}
	return plan.changed, nil
}

// keyRules is what the rollover schedule needs to know about one zone.
type keyRules struct {
	rolloverDelay   time.Duration
	retirementDelay time.Duration
	zskLifetime     time.Duration
	kskLifetime     time.Duration
	parentDSKeyTag  uint16
	keyTag          func(dnssecstate.Key) (uint16, error)
}

func (signer *dnssecSigner) keyRules(zone zone.Zone) keyRules {
	return keyRules{
		rolloverDelay: signer.rolloverDelay(zone), retirementDelay: signer.retirementDelay(zone),
		zskLifetime: zone.ZSKLifetime.Duration, kskLifetime: zone.KSKLifetime.Duration,
		parentDSKeyTag: zone.ParentDSKeyTag,
		keyTag:         func(key dnssecstate.Key) (uint16, error) { return managedKeyTag(key, zone.Name) },
	}
}

// keyPlan is one pass of the rollover schedule: the keys after every
// transition that is due, and the roles that need a new key generated to start
// a rollover, ZSK first.
type keyPlan struct {
	keys     []dnssecstate.Key
	generate []string
	changed  bool
}

// nextTransitions works out which key transitions are due at now without
// generating anything, so it is safe to call just to ask whether a re-sign is
// due. In order:
//   - a retiring key whose removal time has passed is removed;
//   - a published key is ready once the rollover delay has passed;
//   - a ready ZSK becomes active straight away, retiring the old one, so a ZSK
//     passes through ready within this one pass (RFC 7583 section 3.3.1);
//   - a ready KSK becomes active only once the parent DS names its key tag,
//     retiring the old one (RFC 7583 section 3.3.2);
//   - a role with no pending key whose active key is old enough starts a
//     rollover. A KSK also waits for the parent DS to name the active key.
func nextTransitions(keys []dnssecstate.Key, rules keyRules, now time.Time) (keyPlan, error) {
	plan := keyPlan{keys: slices.Clone(keys)}
	plan.keys = slices.DeleteFunc(plan.keys, func(key dnssecstate.Key) bool {
		remove := key.State == dnssecstate.StateRetiring && !key.RemoveAt.IsZero() && !now.Before(key.RemoveAt)
		plan.changed = plan.changed || remove
		return remove
	})
	for index := range plan.keys {
		key := &plan.keys[index]
		if key.State == dnssecstate.StatePublished && !now.Before(key.PublishedAt.Add(rules.rolloverDelay)) {
			if err := moveKey(key, dnssecstate.StateReady); err != nil {
				return keyPlan{}, err
			}
			plan.changed = true
		}
	}
	for index := range plan.keys {
		activate, err := readyToActivate(plan.keys[index], rules)
		if err != nil {
			return keyPlan{}, err
		}
		if !activate {
			continue
		}
		if err := activateKey(plan.keys, index, now, now.Add(rules.retirementDelay)); err != nil {
			return keyPlan{}, err
		}
		plan.changed = true
	}
	state := dnssecstate.State{Keys: plan.keys}
	for _, role := range []string{dnssecstate.RoleZSK, dnssecstate.RoleKSK} {
		start, err := rolloverDue(state, role, rules, now)
		if err != nil {
			return keyPlan{}, err
		}
		if start {
			plan.generate = append(plan.generate, role)
			plan.changed = true
		}
	}
	return plan, nil
}

func readyToActivate(key dnssecstate.Key, rules keyRules) (bool, error) {
	if key.State != dnssecstate.StateReady {
		return false, nil
	}
	if key.Role == dnssecstate.RoleZSK {
		return true, nil
	}
	if key.Role != dnssecstate.RoleKSK {
		return false, nil
	}
	keyTag, err := rules.keyTag(key)
	return err == nil && rules.parentDSKeyTag == keyTag, err
}

// activateKey makes keys[index] the active key of its role and retires the
// one it replaces.
func activateKey(keys []dnssecstate.Key, index int, now, removeAt time.Time) error {
	role := keys[index].Role
	for other := range keys {
		if keys[other].Role == role && keys[other].State == dnssecstate.StateActive {
			if err := moveKey(&keys[other], dnssecstate.StateRetiring); err != nil {
				return err
			}
			keys[other].RemoveAt = removeAt
		}
	}
	if err := moveKey(&keys[index], dnssecstate.StateActive); err != nil {
		return err
	}
	keys[index].ActivatedAt = now
	return nil
}

func rolloverDue(state dnssecstate.State, role string, rules keyRules, now time.Time) (bool, error) {
	lifetime := rules.zskLifetime
	if role == dnssecstate.RoleKSK {
		active, found := activeKey(state, role)
		if !found {
			return false, nil
		}
		keyTag, err := rules.keyTag(active)
		if err != nil || rules.parentDSKeyTag != keyTag {
			return false, err
		}
		lifetime = rules.kskLifetime
	}
	if _, pending := pendingKey(state, role); pending {
		return false, nil
	}
	return activeKeyAge(state, role, now) >= rolloverStartAge(lifetime, rules.rolloverDelay), nil
}

// moveKey changes a key's state, refusing any move the lifecycle does not
// allow.
func moveKey(key *dnssecstate.Key, next dnssecstate.KeyState) error {
	if !key.State.CanMoveTo(next) {
		return fmt.Errorf("DNSSEC %s cannot move from %s to %s", strings.ToUpper(key.Role), key.State, next)
	}
	key.State = next
	return nil
}

func validateKeyState(state dnssecstate.State, zone zone.Zone) error {
	if len(state.Keys) == 0 {
		return errors.New("DNSSEC key state contains no keys")
	}
	active := map[string]int{dnssecstate.RoleKSK: 0, dnssecstate.RoleZSK: 0}
	pending := map[string]int{dnssecstate.RoleKSK: 0, dnssecstate.RoleZSK: 0}
	for _, managed := range state.Keys {
		if managed.Role != dnssecstate.RoleKSK && managed.Role != dnssecstate.RoleZSK {
			return fmt.Errorf("DNSSEC key state contains unsupported role %q", managed.Role)
		}
		if !managed.State.Valid() {
			return fmt.Errorf("DNSSEC key state contains unsupported state %q", managed.State)
		}
		if managed.CreatedAt.IsZero() || managed.PublishedAt.IsZero() {
			return errors.New("DNSSEC key state contains a key without creation and publication timestamps")
		}
		if managed.State == dnssecstate.StateActive {
			active[managed.Role]++
			if managed.ActivatedAt.IsZero() {
				return fmt.Errorf("active %s has no activation timestamp", strings.ToUpper(managed.Role))
			}
		}
		if managed.State.Pending() {
			pending[managed.Role]++
		}
		if managed.State == dnssecstate.StateRetiring && managed.RemoveAt.IsZero() {
			return fmt.Errorf("retiring %s has no removal timestamp", strings.ToUpper(managed.Role))
		}
		key, _, err := decodeManagedKey(managed, zone.Name)
		if err != nil {
			return err
		}
		isKSK := key.Flags&dns.SEP != 0
		if isKSK != (managed.Role == dnssecstate.RoleKSK) {
			return fmt.Errorf("%s DNSKEY flags do not match its managed role", strings.ToUpper(managed.Role))
		}
	}
	if active[dnssecstate.RoleKSK] != 1 {
		return errors.New("DNSSEC key state must contain exactly one active KSK")
	}
	if active[dnssecstate.RoleZSK] > 1 {
		return errors.New("DNSSEC key state contains multiple active ZSKs")
	}
	if pending[dnssecstate.RoleKSK] > 1 || pending[dnssecstate.RoleZSK] > 1 {
		return errors.New("DNSSEC key state contains multiple pending keys for one role")
	}
	return nil
}

func activeKey(state dnssecstate.State, role string) (dnssecstate.Key, bool) {
	for _, key := range state.Keys {
		if key.Role == role && key.State == dnssecstate.StateActive {
			return key, true
		}
	}
	return dnssecstate.Key{}, false
}

func pendingKey(state dnssecstate.State, role string) (dnssecstate.Key, bool) {
	for _, key := range state.Keys {
		if key.Role == role && key.State.Pending() {
			return key, true
		}
	}
	return dnssecstate.Key{}, false
}

func activeKeyAge(state dnssecstate.State, role string, now time.Time) time.Duration {
	key, found := activeKey(state, role)
	if !found || key.ActivatedAt.IsZero() {
		return 0
	}
	return now.Sub(key.ActivatedAt)
}

func (signer *dnssecSigner) rolloverDelay(zone zone.Zone) time.Duration {
	return max(zone.KeyPrepublish.Duration, time.Duration(maximumZoneTTL(zone))*time.Second)
}

func (signer *dnssecSigner) retirementDelay(zone zone.Zone) time.Duration {
	return max(zone.KeyRetireAfter.Duration, time.Duration(maximumZoneTTL(zone))*time.Second)
}

func maximumZoneTTL(zone zone.Zone) uint32 {
	maximum := zone.DefaultTTL
	for _, record := range zone.Records {
		maximum = max(maximum, record.TTL)
	}
	return maximum
}

func (signer *dnssecSigner) generateManagedKey(zone zone.Zone, role string, state dnssecstate.KeyState, now time.Time) (dnssecstate.Key, error) {
	algorithm, bits, err := dnssecAlgorithm(zone.DNSSECAlgorithm)
	if err != nil {
		return dnssecstate.Key{}, err
	}
	flags := uint16(dns.ZONE)
	if role == dnssecstate.RoleKSK {
		flags |= dns.SEP
	}
	key := &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: dns.Fqdn(zone.Name), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: zone.DefaultTTL},
		Flags: flags, Protocol: 3, Algorithm: algorithm,
	}
	privateValue, err := key.Generate(bits)
	if err != nil {
		return dnssecstate.Key{}, fmt.Errorf("generate %s: %w", strings.ToUpper(role), err)
	}
	return dnssecstate.Key{
		Role: role, State: state, DNSKEY: key.String(), PrivateKey: key.PrivateKeyString(privateValue),
		CreatedAt: now, PublishedAt: now, ActivatedAt: func() time.Time {
			if state == dnssecstate.StateActive {
				return now
			}
			return time.Time{}
		}(),
	}, nil
}

func decodeZoneSigningKeys(keys []dnssecstate.Key, zone string) ([]zoneSigningKey, error) {
	result := make([]zoneSigningKey, 0, len(keys))
	for _, managed := range keys {
		key, privateKey, err := decodeManagedKey(managed, zone)
		if err != nil {
			return nil, err
		}
		result = append(result, zoneSigningKey{key: key, privateKey: privateKey, role: managed.Role, state: managed.State})
	}
	return result, nil
}

func decodeManagedKey(managed dnssecstate.Key, zone string) (*dns.DNSKEY, crypto.Signer, error) {
	record, err := dns.NewRR(managed.DNSKEY)
	if err != nil {
		return nil, nil, fmt.Errorf("decode %s public key: %w", strings.ToUpper(managed.Role), err)
	}
	key, ok := record.(*dns.DNSKEY)
	if !ok {
		return nil, nil, errors.New("decoded DNSSEC key is not a DNSKEY")
	}
	key.Hdr.Name = dns.Fqdn(zone)
	privateValue, err := key.NewPrivateKey(managed.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decode %s private key: %w", strings.ToUpper(managed.Role), err)
	}
	privateKey, ok := privateValue.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("decoded DNSSEC private key cannot sign")
	}
	return key, privateKey, nil
}

func managedKeyTag(managed dnssecstate.Key, zone string) (uint16, error) {
	key, _, err := decodeManagedKey(managed, zone)
	if err != nil {
		return 0, err
	}
	return key.KeyTag(), nil
}

func dnssecStateSecretName(zone, algorithm string) string {
	return "dnssec/" + strings.TrimSuffix(strings.ToLower(zone), ".") + "/keys/" + strings.ToLower(algorithm) + "/v2"
}
