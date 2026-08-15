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
	state      string
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
		return key.Role == role && (key.State == dnssecstate.StatePublished || key.State == dnssecstate.StateReady)
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
	now := signer.now().UTC()
	for _, key := range state.Keys {
		if key.State == dnssecstate.StatePublished && !now.Before(key.PublishedAt.Add(signer.rolloverDelay(zone))) {
			return true, nil
		}
		if key.State == dnssecstate.StateReady && key.Role == dnssecstate.RoleZSK {
			return true, nil
		}
		if key.State == dnssecstate.StateReady && key.Role == dnssecstate.RoleKSK {
			keyTag, tagErr := managedKeyTag(key, zone.Name)
			if tagErr != nil {
				return false, tagErr
			}
			if zone.ParentDSKeyTag == keyTag {
				return true, nil
			}
		}
		if key.State == dnssecstate.StateRetiring && !key.RemoveAt.IsZero() && !now.Before(key.RemoveAt) {
			return true, nil
		}
	}
	if _, pending := pendingKey(state, dnssecstate.RoleZSK); !pending && activeKeyAge(state, dnssecstate.RoleZSK, now) >= rolloverStartAge(zone.ZSKLifetime.Duration, signer.rolloverDelay(zone)) {
		return true, nil
	}
	activeKSK, active := activeKey(state, dnssecstate.RoleKSK)
	if !active {
		return false, nil
	}
	activeTag, err := managedKeyTag(activeKSK, zone.Name)
	if err != nil {
		return false, err
	}
	_, pending := pendingKey(state, dnssecstate.RoleKSK)
	return !pending && zone.ParentDSKeyTag == activeTag && activeKeyAge(state, dnssecstate.RoleKSK, now) >= rolloverStartAge(zone.KSKLifetime.Duration, signer.rolloverDelay(zone)), nil
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
		return strings.Compare(left.State, right.State)
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

func (signer *dnssecSigner) advanceKeyState(state *dnssecstate.State, zone zone.Zone) (bool, error) {
	now := signer.now().UTC()
	changed := false
	state.Keys = slices.DeleteFunc(state.Keys, func(key dnssecstate.Key) bool {
		remove := key.State == dnssecstate.StateRetiring && !key.RemoveAt.IsZero() && !now.Before(key.RemoveAt)
		changed = changed || remove
		return remove
	})
	for index := range state.Keys {
		key := &state.Keys[index]
		if key.State == dnssecstate.StatePublished && !now.Before(key.PublishedAt.Add(signer.rolloverDelay(zone))) {
			key.State = dnssecstate.StateReady
			changed = true
		}
	}
	for index := range state.Keys {
		key := &state.Keys[index]
		if key.Role == dnssecstate.RoleZSK && key.State == dnssecstate.StateReady {
			retireRole(state, dnssecstate.RoleZSK, now.Add(signer.retirementDelay(zone)))
			key.State, key.ActivatedAt = dnssecstate.StateActive, now
			changed = true
		}
		if key.Role == dnssecstate.RoleKSK && key.State == dnssecstate.StateReady {
			keyTag, err := managedKeyTag(*key, zone.Name)
			if err != nil {
				return false, err
			}
			if zone.ParentDSKeyTag == keyTag {
				retireRole(state, dnssecstate.RoleKSK, now.Add(signer.retirementDelay(zone)))
				key.State, key.ActivatedAt = dnssecstate.StateActive, now
				changed = true
			}
		}
	}
	if _, found := pendingKey(*state, dnssecstate.RoleZSK); !found && activeKeyAge(*state, dnssecstate.RoleZSK, now) >= rolloverStartAge(zone.ZSKLifetime.Duration, signer.rolloverDelay(zone)) {
		key, err := signer.generateManagedKey(zone, dnssecstate.RoleZSK, dnssecstate.StatePublished, now)
		if err != nil {
			return false, err
		}
		state.Keys = append(state.Keys, key)
		changed = true
	}
	activeKSK, found := activeKey(*state, dnssecstate.RoleKSK)
	if found {
		activeTag, err := managedKeyTag(activeKSK, zone.Name)
		if err != nil {
			return false, err
		}
		_, pending := pendingKey(*state, dnssecstate.RoleKSK)
		if !pending && zone.ParentDSKeyTag == activeTag && now.Sub(activeKSK.ActivatedAt) >= rolloverStartAge(zone.KSKLifetime.Duration, signer.rolloverDelay(zone)) {
			key, generateErr := signer.generateManagedKey(zone, dnssecstate.RoleKSK, dnssecstate.StatePublished, now)
			if generateErr != nil {
				return false, generateErr
			}
			state.Keys = append(state.Keys, key)
			changed = true
		}
	}
	return changed, nil
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
		if !isPublishedKeyState(managed.State) {
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
		if managed.State == dnssecstate.StatePublished || managed.State == dnssecstate.StateReady {
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

func retireRole(state *dnssecstate.State, role string, removeAt time.Time) {
	for index := range state.Keys {
		key := &state.Keys[index]
		if key.Role == role && key.State == dnssecstate.StateActive {
			key.State, key.RemoveAt = dnssecstate.StateRetiring, removeAt
		}
	}
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
		if key.Role == role && (key.State == dnssecstate.StatePublished || key.State == dnssecstate.StateReady) {
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

func (signer *dnssecSigner) generateManagedKey(zone zone.Zone, role, state string, now time.Time) (dnssecstate.Key, error) {
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
