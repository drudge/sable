package trustanchor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	StateAddPending = "add-pending"
	StateValid      = "valid"
	StateMissing    = "missing"
	StateRevoked    = "revoked"
	StateRemoved    = "removed"

	DefaultRootKSK2017 = ". DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
	DefaultRootKSK2024 = ". DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
)

const revokeFlag = uint16(1 << 7)

type Anchor struct {
	Owner         string
	KeyID         string
	DNSKEY        string
	State         string
	FirstSeen     time.Time
	HoldDownUntil time.Time
	LastSeen      time.Time
	RevokedAt     time.Time
	SourceKeyIDs  []string
}

type Status struct {
	Owner                    string    `json:"owner"`
	Initialized              bool      `json:"initialized"`
	Active                   int       `json:"active"`
	Pending                  int       `json:"pending"`
	Missing                  int       `json:"missing"`
	Revoked                  int       `json:"revoked"`
	LastSuccess              time.Time `json:"last_success,omitempty"`
	NextRefresh              time.Time `json:"next_refresh,omitempty"`
	LastError                string    `json:"last_error,omitempty"`
	OriginalTTLSeconds       uint32    `json:"original_ttl_seconds,omitempty"`
	SignatureValiditySeconds int64     `json:"signature_validity_seconds,omitempty"`
}

type Snapshot struct {
	Status  Status   `json:"status"`
	Anchors []Anchor `json:"anchors"`
}

type Store interface {
	LoadTrustAnchorSnapshot(context.Context, string) (Snapshot, error)
	SaveTrustAnchorSnapshot(context.Context, Snapshot) error
}

type Query func(context.Context, string, uint16) (*dns.Msg, error)

type Options struct {
	Owner          string
	Bootstrap      []string
	AddHoldDown    time.Duration
	RemoveHoldDown time.Duration
	MinimumRefresh time.Duration
	MaximumRefresh time.Duration
	MaximumRetry   time.Duration
	Now            func() time.Time
	Enabled        func() bool
	OnChange       func([]string, bool)
}

type Manager struct {
	store Store
	query Query
	opts  Options

	mu       sync.RWMutex
	snapshot Snapshot
}

func New(ctx context.Context, store Store, query Query, options Options) (*Manager, error) {
	if store == nil || query == nil {
		return nil, errors.New("RFC 5011 manager requires storage and a DNS query function")
	}
	options = withDefaults(options)
	snapshot, err := store.LoadTrustAnchorSnapshot(ctx, options.Owner)
	if err != nil {
		return nil, fmt.Errorf("load RFC 5011 state: %w", err)
	}
	if snapshot.Status.Owner == "" {
		snapshot.Status.Owner = options.Owner
	}
	manager := &Manager{store: store, query: query, opts: options, snapshot: cloneSnapshot(snapshot)}
	manager.publish()
	return manager, nil
}

func withDefaults(options Options) Options {
	if strings.TrimSpace(options.Owner) == "" {
		options.Owner = "."
	}
	options.Owner = normalizeName(options.Owner)
	if len(options.Bootstrap) == 0 {
		options.Bootstrap = []string{DefaultRootKSK2017, DefaultRootKSK2024}
	}
	if options.AddHoldDown <= 0 {
		options.AddHoldDown = 30 * 24 * time.Hour
	}
	if options.RemoveHoldDown <= 0 {
		options.RemoveHoldDown = 30 * 24 * time.Hour
	}
	if options.MinimumRefresh <= 0 {
		options.MinimumRefresh = time.Hour
	}
	if options.MaximumRefresh <= 0 {
		options.MaximumRefresh = 15 * 24 * time.Hour
	}
	if options.MaximumRetry <= 0 {
		options.MaximumRetry = 24 * time.Hour
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Enabled == nil {
		options.Enabled = func() bool { return true }
	}
	return options
}

func (manager *Manager) Status() Status {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.snapshot.Status
}

func (manager *Manager) ActiveAnchors() ([]string, bool) {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return activeAnchorValues(manager.snapshot), manager.snapshot.Status.Initialized
}

func (manager *Manager) Refresh(ctx context.Context) error {
	now := manager.opts.Now().UTC()
	response, err := manager.query(ctx, manager.opts.Owner, dns.TypeDNSKEY)
	if err != nil {
		return manager.recordFailure(ctx, now, fmt.Errorf("query %s DNSKEY: %w", manager.opts.Owner, err))
	}
	candidate, err := manager.observe(now, response)
	if err != nil {
		return manager.recordFailure(ctx, now, err)
	}
	if err := manager.store.SaveTrustAnchorSnapshot(ctx, candidate); err != nil {
		return fmt.Errorf("persist RFC 5011 state: %w", err)
	}
	manager.mu.Lock()
	manager.snapshot = cloneSnapshot(candidate)
	manager.mu.Unlock()
	manager.publish()
	return nil
}

func (manager *Manager) Run(ctx context.Context, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	for {
		if !manager.opts.Enabled() {
			if !waitContext(ctx, time.Minute) {
				return
			}
			continue
		}
		status := manager.Status()
		now := manager.opts.Now()
		if !status.Initialized || status.NextRefresh.IsZero() || !now.Before(status.NextRefresh) {
			if err := manager.Refresh(ctx); err != nil {
				logger.Warn("DNSSEC trust-anchor refresh failed", "owner", manager.opts.Owner, "error", err)
			} else {
				status = manager.Status()
				logger.Info("DNSSEC trust-anchor state refreshed", "owner", manager.opts.Owner, "active", status.Active, "pending", status.Pending, "revoked", status.Revoked, "next_refresh", status.NextRefresh)
			}
			continue
		}
		if !waitContext(ctx, min(time.Until(status.NextRefresh), time.Hour)) {
			return
		}
	}
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return true
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (manager *Manager) observe(now time.Time, response *dns.Msg) (Snapshot, error) {
	if response == nil || response.Rcode != dns.RcodeSuccess {
		return Snapshot{}, errors.New("RFC 5011 DNSKEY query did not return NOERROR")
	}
	rrset, signatures := dnskeyRRSet(response, manager.opts.Owner)
	if len(rrset) == 0 || len(signatures) == 0 {
		return Snapshot{}, errors.New("RFC 5011 response has no signed DNSKEY RRset")
	}

	manager.mu.RLock()
	current := cloneSnapshot(manager.snapshot)
	manager.mu.RUnlock()
	current.Status.Owner = manager.opts.Owner
	trustedRecords, err := manager.currentTrustRecords(current)
	if err != nil {
		return Snapshot{}, err
	}
	trustedKeys := matchingTrustKeys(rrset, trustedRecords)
	signerIDs, authenticated := verifyDNSKEYRRSet(rrset, signatures, trustedKeys, now)
	revocations := authenticatedRevocations(current.Anchors, rrset, signatures, now)
	if !authenticated && len(revocations) == 0 {
		return Snapshot{}, errors.New("RFC 5011 DNSKEY RRset is not authenticated by a current trust anchor")
	}

	observed := make(map[string]*dns.DNSKEY)
	for _, key := range rrset {
		if key.Protocol == 3 && key.Flags&dns.ZONE != 0 && key.Flags&dns.SEP != 0 {
			observed[keyIdentity(key)] = key
		}
	}
	bootstrapMatches := matchingTrustKeys(rrset, mustParseAnchors(manager.opts.Bootstrap))
	bootstrapIDs := make(map[string]struct{}, len(bootstrapMatches))
	for _, key := range bootstrapMatches {
		bootstrapIDs[keyIdentity(key)] = struct{}{}
	}

	existing := make(map[string]*Anchor, len(current.Anchors))
	for index := range current.Anchors {
		anchor := &current.Anchors[index]
		existing[anchor.KeyID] = anchor
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
			if anchor.State == StateAddPending && allSourcesRevoked(anchor.SourceKeyIDs, existing) {
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
			if !present || key.Flags&revokeFlag != 0 || allSourcesRevoked(anchor.SourceKeyIDs, existing) {
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

	if authenticated {
		originalTTL := minimumDNSKEYTTL(rrset)
		for keyID, key := range observed {
			if key.Flags&revokeFlag != 0 {
				continue
			}
			if _, found := existing[keyID]; found {
				continue
			}
			anchor := Anchor{Owner: manager.opts.Owner, KeyID: keyID, DNSKEY: anchorValue(key), FirstSeen: now, LastSeen: now}
			if _, bootstrap := bootstrapIDs[keyID]; bootstrap {
				anchor.State = StateValid
			} else {
				anchor.State = StateAddPending
				holdDown := max(manager.opts.AddHoldDown, time.Duration(originalTTL)*time.Second)
				anchor.HoldDownUntil = now.Add(holdDown)
				anchor.SourceKeyIDs = append([]string(nil), signerIDs...)
			}
			current.Anchors = append(current.Anchors, anchor)
		}
	}

	slices.SortFunc(current.Anchors, func(left, right Anchor) int { return strings.Compare(left.KeyID, right.KeyID) })
	ttl := minimumDNSKEYTTL(rrset)
	validity := signatureValidity(signatures, now)
	current.Status.Initialized = true
	current.Status.LastSuccess = now
	current.Status.LastError = ""
	current.Status.OriginalTTLSeconds = ttl
	current.Status.SignatureValiditySeconds = int64(validity.Seconds())
	current.Status.NextRefresh = now.Add(manager.refreshInterval(time.Duration(ttl)*time.Second, validity))
	countStates(&current)
	return current, nil
}

func (manager *Manager) currentTrustRecords(snapshot Snapshot) ([]dns.RR, error) {
	if !snapshot.Status.Initialized {
		return parseAnchors(manager.opts.Bootstrap)
	}
	values := activeAnchorValues(snapshot)
	if len(values) == 0 {
		return nil, errors.New("RFC 5011 trust point has no active anchors")
	}
	return parseAnchors(values)
}

func (manager *Manager) recordFailure(ctx context.Context, now time.Time, failure error) error {
	manager.mu.RLock()
	candidate := cloneSnapshot(manager.snapshot)
	manager.mu.RUnlock()
	candidate.Status.Owner = manager.opts.Owner
	candidate.Status.LastError = failure.Error()
	ttl := time.Duration(candidate.Status.OriginalTTLSeconds) * time.Second
	validity := time.Duration(candidate.Status.SignatureValiditySeconds) * time.Second
	candidate.Status.NextRefresh = now.Add(manager.retryInterval(ttl, validity))
	if err := manager.store.SaveTrustAnchorSnapshot(ctx, candidate); err != nil {
		return errors.Join(failure, fmt.Errorf("persist RFC 5011 failure: %w", err))
	}
	manager.mu.Lock()
	manager.snapshot = cloneSnapshot(candidate)
	manager.mu.Unlock()
	return failure
}

func (manager *Manager) refreshInterval(ttl, validity time.Duration) time.Duration {
	interval := manager.opts.MaximumRefresh
	if ttl > 0 {
		interval = min(interval, ttl/2)
	}
	if validity > 0 {
		interval = min(interval, validity/2)
	}
	return max(manager.opts.MinimumRefresh, interval)
}

func (manager *Manager) retryInterval(ttl, validity time.Duration) time.Duration {
	interval := manager.opts.MaximumRetry
	if ttl > 0 {
		interval = min(interval, ttl/10)
	}
	if validity > 0 {
		interval = min(interval, validity/10)
	}
	return max(manager.opts.MinimumRefresh, interval)
}

func (manager *Manager) publish() {
	if manager.opts.OnChange == nil {
		return
	}
	anchors, initialized := manager.ActiveAnchors()
	if initialized {
		manager.opts.OnChange(anchors, len(anchors) == 0)
	}
}

func activeAnchorValues(snapshot Snapshot) []string {
	values := make([]string, 0, len(snapshot.Anchors))
	for _, anchor := range snapshot.Anchors {
		if anchor.State == StateValid || anchor.State == StateMissing {
			values = append(values, anchor.DNSKEY)
		}
	}
	return values
}

func countStates(snapshot *Snapshot) {
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

func allSourcesRevoked(sourceIDs []string, anchors map[string]*Anchor) bool {
	if len(sourceIDs) == 0 {
		return false
	}
	for _, sourceID := range sourceIDs {
		anchor := anchors[sourceID]
		if anchor != nil && anchor.State != StateRevoked && anchor.State != StateRemoved {
			return false
		}
	}
	return true
}

func dnskeyRRSet(response *dns.Msg, owner string) ([]*dns.DNSKEY, []*dns.RRSIG) {
	owner = normalizeName(owner)
	var keys []*dns.DNSKEY
	var signatures []*dns.RRSIG
	for _, record := range response.Answer {
		if normalizeName(record.Header().Name) != owner {
			continue
		}
		if key, ok := record.(*dns.DNSKEY); ok {
			keys = append(keys, key)
		} else if signature, ok := record.(*dns.RRSIG); ok && signature.TypeCovered == dns.TypeDNSKEY {
			signatures = append(signatures, signature)
		}
	}
	return keys, signatures
}

func verifyDNSKEYRRSet(keys []*dns.DNSKEY, signatures []*dns.RRSIG, trusted []*dns.DNSKEY, now time.Time) ([]string, bool) {
	rrset := make([]dns.RR, len(keys))
	for index, key := range keys {
		rrset[index] = key
	}
	verified := make(map[string]struct{})
	for _, signature := range signatures {
		if !signature.ValidityPeriod(now) {
			continue
		}
		for _, key := range trusted {
			if key.KeyTag() == signature.KeyTag && key.Algorithm == signature.Algorithm && signature.Verify(key, rrset) == nil {
				verified[keyIdentity(key)] = struct{}{}
			}
		}
	}
	ids := make([]string, 0, len(verified))
	for keyID := range verified {
		ids = append(ids, keyID)
	}
	slices.Sort(ids)
	return ids, len(ids) > 0
}

func authenticatedRevocations(anchors []Anchor, keys []*dns.DNSKEY, signatures []*dns.RRSIG, now time.Time) map[string]struct{} {
	known := make(map[string]struct{}, len(anchors))
	for _, anchor := range anchors {
		if anchor.State == StateValid || anchor.State == StateMissing || anchor.State == StateAddPending {
			known[anchor.KeyID] = struct{}{}
		}
	}
	rrset := make([]dns.RR, len(keys))
	for index, key := range keys {
		rrset[index] = key
	}
	revoked := make(map[string]struct{})
	for _, key := range keys {
		keyID := keyIdentity(key)
		if _, found := known[keyID]; !found || key.Flags&revokeFlag == 0 {
			continue
		}
		for _, signature := range signatures {
			if signature.KeyTag == key.KeyTag() && signature.Algorithm == key.Algorithm && signature.ValidityPeriod(now) && signature.Verify(key, rrset) == nil {
				revoked[keyID] = struct{}{}
				break
			}
		}
	}
	return revoked
}

func matchingTrustKeys(keys []*dns.DNSKEY, anchors []dns.RR) []*dns.DNSKEY {
	var result []*dns.DNSKEY
	for _, key := range keys {
		for _, anchor := range anchors {
			switch typed := anchor.(type) {
			case *dns.DNSKEY:
				if dns.IsDuplicate(key, typed) {
					result = append(result, key)
				}
			case *dns.DS:
				if key.KeyTag() == typed.KeyTag && key.Algorithm == typed.Algorithm {
					computed := key.ToDS(typed.DigestType)
					if computed != nil && strings.EqualFold(computed.Digest, typed.Digest) {
						result = append(result, key)
					}
				}
			}
		}
	}
	return result
}

func parseAnchors(values []string) ([]dns.RR, error) {
	records := make([]dns.RR, 0, len(values))
	for _, value := range values {
		fields := strings.Fields(value)
		if len(fields) < 5 || (strings.ToUpper(fields[1]) != "DS" && strings.ToUpper(fields[1]) != "DNSKEY") {
			return nil, fmt.Errorf("invalid trust anchor %q", value)
		}
		record, err := dns.NewRR(fmt.Sprintf("%s 0 IN %s", dns.Fqdn(fields[0]), strings.Join(fields[1:], " ")))
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func mustParseAnchors(values []string) []dns.RR {
	records, _ := parseAnchors(values)
	return records
}

func anchorValue(key *dns.DNSKEY) string {
	return fmt.Sprintf("%s DNSKEY %d %d %d %s", normalizeName(key.Hdr.Name), key.Flags&^revokeFlag, key.Protocol, key.Algorithm, key.PublicKey)
}

func keyIdentity(key *dns.DNSKEY) string {
	identity := fmt.Sprintf("%s|%d|%d|%s", normalizeName(key.Hdr.Name), key.Protocol, key.Algorithm, key.PublicKey)
	digest := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(digest[:])
}

func minimumDNSKEYTTL(keys []*dns.DNSKEY) uint32 {
	var ttl uint32
	for _, key := range keys {
		if ttl == 0 || key.Hdr.Ttl < ttl {
			ttl = key.Hdr.Ttl
		}
	}
	return ttl
}

func signatureValidity(signatures []*dns.RRSIG, now time.Time) time.Duration {
	var validity time.Duration
	for _, signature := range signatures {
		expires := time.Unix(int64(signature.Expiration), 0)
		remaining := expires.Sub(now)
		if remaining > 0 && (validity == 0 || remaining < validity) {
			validity = remaining
		}
	}
	return validity
}

func normalizeName(name string) string {
	return strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	clone := snapshot
	clone.Anchors = make([]Anchor, len(snapshot.Anchors))
	for index, anchor := range snapshot.Anchors {
		clone.Anchors[index] = anchor
		clone.Anchors[index].SourceKeyIDs = append([]string(nil), anchor.SourceKeyIDs...)
	}
	return clone
}
