package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/trustanchor"
)

type validationState uint8

const (
	validationIndeterminate validationState = iota
	validationSecure
	validationInsecure
	validationBogus
)

type dnssecQuery func(context.Context, string, uint16) (*dns.Msg, error)

type validatedZone struct {
	state     validationState
	keys      []*dns.DNSKEY
	expiresAt time.Time
}

type dnssecValidator struct {
	anchors            map[string][]dns.RR
	deletedTrustPoints map[string]struct{}
	negativeAnchors    []string
	now                func() time.Time
	mu                 sync.RWMutex
	zones              map[string]validatedZone
	// zoneInsecure holds negative trust anchors derived from forwarder and stub
	// zones rather than from configuration, so operators can scope the
	// exception to the zone that needs it.
	zoneInsecure []string
}

func newDNSSECValidator(anchorValues, negativeAnchors []string) (*dnssecValidator, error) {
	if len(anchorValues) == 0 {
		anchorValues = []string{trustanchor.DefaultRootKSK2017, trustanchor.DefaultRootKSK2024}
	}
	anchors := make(map[string][]dns.RR)
	for _, value := range anchorValues {
		record, err := parseRuntimeTrustAnchor(value)
		if err != nil {
			return nil, err
		}
		owner := normalizeFQDN(record.Header().Name)
		anchors[owner] = append(anchors[owner], record)
	}
	return &dnssecValidator{
		anchors: anchors, negativeAnchors: append([]string(nil), negativeAnchors...),
		now: time.Now, zones: make(map[string]validatedZone), deletedTrustPoints: make(map[string]struct{}),
	}, nil
}

func parseRuntimeTrustAnchor(value string) (dns.RR, error) {
	fields := strings.Fields(value)
	if len(fields) < 5 {
		return nil, errors.New("DNSSEC trust anchor must be an owner followed by DS or DNSKEY data")
	}
	owner := dns.Fqdn(strings.ToLower(fields[0]))
	recordType := strings.ToUpper(fields[1])
	if recordType != "DS" && recordType != "DNSKEY" {
		return nil, errors.New("DNSSEC trust anchor must contain a DS or DNSKEY record")
	}
	record, err := dns.NewRR(fmt.Sprintf("%s 0 IN %s", owner, strings.Join(fields[1:], " ")))
	if err != nil {
		return nil, fmt.Errorf("parse DNSSEC trust anchor: %w", err)
	}
	return record, nil
}

func (validator *dnssecValidator) replaceManagedTrustPoint(owner string, values []string, deleted bool) {
	owner = normalizeFQDN(owner)
	records := make([]dns.RR, 0, len(values))
	for _, value := range values {
		record, err := parseRuntimeTrustAnchor(value)
		if err != nil || normalizeFQDN(record.Header().Name) != owner {
			return
		}
		records = append(records, record)
	}
	validator.mu.Lock()
	if len(records) == 0 {
		delete(validator.anchors, owner)
	} else {
		validator.anchors[owner] = records
	}
	if deleted {
		validator.deletedTrustPoints[owner] = struct{}{}
	} else {
		delete(validator.deletedTrustPoints, owner)
	}
	validator.zones = make(map[string]validatedZone)
	validator.mu.Unlock()
}

// managedTrustPointEqual reports whether the trust point already holds exactly
// these anchors. RFC 5011 refreshes republish the active set on every poll, so
// without this check an unchanged refresh would rebuild the runtime and throw
// away the response cache built under it.
func (validator *dnssecValidator) managedTrustPointEqual(owner string, values []string, deleted bool) bool {
	owner = normalizeFQDN(owner)
	candidate := make([]string, 0, len(values))
	for _, value := range values {
		record, err := parseRuntimeTrustAnchor(value)
		if err != nil || normalizeFQDN(record.Header().Name) != owner {
			return false
		}
		candidate = append(candidate, record.String())
	}
	slices.Sort(candidate)
	validator.mu.RLock()
	defer validator.mu.RUnlock()
	if _, marked := validator.deletedTrustPoints[owner]; marked != deleted {
		return false
	}
	current := make([]string, 0, len(validator.anchors[owner]))
	for _, record := range validator.anchors[owner] {
		current = append(current, record.String())
	}
	slices.Sort(current)
	return slices.Equal(candidate, current)
}

func (validator *dnssecValidator) trustAnchors(owner string) []dns.RR {
	validator.mu.RLock()
	records := append([]dns.RR(nil), validator.anchors[normalizeFQDN(owner)]...)
	validator.mu.RUnlock()
	return records
}

func (validator *dnssecValidator) deletedTrustPointFor(name string) bool {
	name = normalizeFQDN(name)
	validator.mu.RLock()
	defer validator.mu.RUnlock()
	for owner := range validator.deletedTrustPoints {
		if dns.IsSubDomain(owner, name) {
			return true
		}
	}
	return false
}

func (validator *dnssecValidator) validate(
	ctx context.Context,
	response *dns.Msg,
	question dns.Question,
	query dnssecQuery,
) (validationState, error) {
	qname := normalizeFQDN(question.Name)
	if validator.validationExempt(qname) {
		return validationInsecure, nil
	}
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return validationIndeterminate, nil
	}

	rrsets, signatures := validationRRSets(response)
	if len(rrsets) == 0 {
		return validationBogus, errors.New("DNSSEC response contains no data or denial records")
	}
	overall := validationSecure
	for key, rrset := range rrsets {
		// A CNAME synthesized from an authenticated DNAME is deliberately
		// unsigned. The covering DNAME RRset is validated independently below.
		if key.recordType == dns.TypeCNAME && len(signatures[key]) == 0 && synthesizedFromDNAME(rrset, response.Answer) {
			continue
		}
		state, err := validator.validateRRSet(ctx, rrset, signatures[key], query)
		if err != nil {
			return validationBogus, err
		}
		if state == validationInsecure {
			overall = validationInsecure
		}
	}
	if overall == validationInsecure {
		return overall, nil
	}
	if err := validateResponseProof(response, question); err != nil {
		return validationBogus, err
	}
	return validationSecure, nil
}

type validationRRSetKey struct {
	owner      string
	recordType uint16
	class      uint16
}

func validationRRSets(message *dns.Msg) (map[validationRRSetKey][]dns.RR, map[validationRRSetKey][]*dns.RRSIG) {
	rrsets := make(map[validationRRSetKey][]dns.RR)
	signatures := make(map[validationRRSetKey][]*dns.RRSIG)
	collect := func(records []dns.RR) {
		for _, record := range records {
			header := record.Header()
			if signature, ok := record.(*dns.RRSIG); ok {
				key := validationRRSetKey{owner: normalizeFQDN(header.Name), recordType: signature.TypeCovered, class: header.Class}
				signatures[key] = append(signatures[key], signature)
				continue
			}
			if header.Rrtype == dns.TypeOPT || header.Rrtype == dns.TypeTSIG {
				continue
			}
			key := validationRRSetKey{owner: normalizeFQDN(header.Name), recordType: header.Rrtype, class: header.Class}
			rrsets[key] = append(rrsets[key], record)
		}
	}
	collect(message.Answer)
	collect(message.Ns)
	return rrsets, signatures
}

func (validator *dnssecValidator) validateRRSet(
	ctx context.Context,
	rrset []dns.RR,
	signatures []*dns.RRSIG,
	query dnssecQuery,
) (validationState, error) {
	if len(signatures) == 0 {
		state, err := validator.unsignedNameState(ctx, rrset[0].Header().Name, query)
		if err != nil {
			return validationBogus, err
		}
		if state == validationSecure {
			return validationBogus, fmt.Errorf("missing RRSIG for %s %s", rrset[0].Header().Name, dns.TypeToString[rrset[0].Header().Rrtype])
		}
		return state, nil
	}
	owner := rrset[0].Header().Name
	var failures []error
	for _, signature := range signatures {
		// RFC 4035 section 5.3.1: an RRSIG's signer name must be the zone that
		// holds the RRset, i.e. equal to or an ancestor of the owner. Verify
		// enforces this, but the insecure short-circuit below runs before it, so
		// an RRSIG grouped by owner with an out-of-bailiwick signer could
		// otherwise downgrade a signed name to insecure by pointing at an
		// unsigned zone. Reject those signers before their zone state is trusted.
		if !dns.IsSubDomain(signature.SignerName, owner) {
			failures = append(failures, fmt.Errorf("RRSIG signer %s is not in bailiwick of %s", signature.SignerName, owner))
			continue
		}
		zone, err := validator.zoneKeys(ctx, signature.SignerName, query)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if zone.state == validationInsecure {
			return validationInsecure, nil
		}
		if !signature.ValidityPeriod(validator.now()) {
			failures = append(failures, fmt.Errorf("RRSIG for %s is outside its validity period", rrset[0].Header().Name))
			continue
		}
		for _, key := range zone.keys {
			if key.KeyTag() != signature.KeyTag || key.Algorithm != signature.Algorithm {
				continue
			}
			if err := signature.Verify(key, rrset); err == nil {
				return validationSecure, nil
			} else {
				failures = append(failures, err)
			}
		}
	}
	if len(failures) == 0 {
		failures = append(failures, errors.New("no DNSKEY matches an RRSIG key tag and algorithm"))
	}
	return validationBogus, fmt.Errorf("validate %s %s: %w", rrset[0].Header().Name, dns.TypeToString[rrset[0].Header().Rrtype], errors.Join(failures...))
}

func (validator *dnssecValidator) zoneKeys(ctx context.Context, zoneName string, query dnssecQuery) (validatedZone, error) {
	zoneName = normalizeFQDN(zoneName)
	if validator.validationExempt(zoneName) {
		return validatedZone{state: validationInsecure}, nil
	}
	if validator.deletedTrustPointFor(zoneName) {
		return validatedZone{state: validationInsecure}, nil
	}
	if cached, found := validator.cachedZone(zoneName); found {
		return cached, nil
	}
	if anchors := validator.trustAnchors(zoneName); len(anchors) > 0 {
		zone, err := validator.fetchAnchoredZone(ctx, zoneName, anchors, query)
		if err == nil {
			validator.cacheZone(zoneName, zone)
		}
		return zone, err
	}

	dsResponse, err := query(ctx, zoneName, dns.TypeDS)
	if err != nil {
		return validatedZone{}, fmt.Errorf("fetch DS for %s: %w", zoneName, err)
	}
	dsRRSet, dsSignatures := findRRSet(dsResponse.Answer, zoneName, dns.TypeDS)
	if len(dsRRSet) > 0 {
		parentName, err := signerForDelegation(zoneName, dsSignatures)
		if err != nil {
			return validatedZone{}, err
		}
		parent, err := validator.zoneKeys(ctx, parentName, query)
		if err != nil {
			return validatedZone{}, err
		}
		if parent.state == validationInsecure {
			zone := validatedZone{state: validationInsecure, expiresAt: validator.cacheExpiration(dsResponse)}
			validator.cacheZone(zoneName, zone)
			return zone, nil
		}
		if err := validator.verifyWithKeys(dsRRSet, dsSignatures, parent.keys); err != nil {
			return validatedZone{}, fmt.Errorf("validate DS for %s: %w", zoneName, err)
		}
		zone, err := validator.fetchDelegatedZone(ctx, zoneName, dsRRSet, query)
		if err == nil {
			zone.expiresAt = minTime(zone.expiresAt, validator.cacheExpiration(dsResponse))
			validator.cacheZone(zoneName, zone)
		}
		return zone, err
	}

	parentName, err := denialSigner(dsResponse)
	if err != nil {
		// Names below an insecure delegation carry no DNSSEC records, so a
		// resolver that already proved the ancestor unsigned answers the DS
		// query with a bare SOA. Climb to the parent before calling that a
		// failure: an insecure parent makes every zone under it insecure too.
		return validator.inheritedInsecureZone(ctx, zoneName, dsResponse, query, err)
	}
	parent, err := validator.zoneKeys(ctx, parentName, query)
	if err != nil {
		return validatedZone{}, err
	}
	if parent.state == validationInsecure {
		zone := validatedZone{state: validationInsecure, expiresAt: validator.cacheExpiration(dsResponse)}
		validator.cacheZone(zoneName, zone)
		return zone, nil
	}
	if err := validator.verifyDenialRRsets(dsResponse, parent.keys); err != nil {
		return validatedZone{}, fmt.Errorf("validate DS denial for %s: %w", zoneName, err)
	}
	if !provesInsecureDelegation(dsResponse.Ns, zoneName) {
		return validatedZone{}, fmt.Errorf("%s has no authenticated delegation", zoneName)
	}
	zone := validatedZone{state: validationInsecure, expiresAt: validator.cacheExpiration(dsResponse)}
	validator.cacheZone(zoneName, zone)
	return zone, nil
}

// inheritedInsecureZone resolves a DS denial that carries no proof of its own by
// asking whether the parent zone is insecure. Only a parent that reaches
// validationInsecure through an authenticated chain lets the child inherit that
// state, so a stripped denial under a signed parent still fails as denialErr.
func (validator *dnssecValidator) inheritedInsecureZone(
	ctx context.Context,
	zoneName string,
	dsResponse *dns.Msg,
	query dnssecQuery,
	denialErr error,
) (validatedZone, error) {
	failure := fmt.Errorf("find authenticated DS denial for %s: %w", zoneName, denialErr)
	if zoneName == "." {
		return validatedZone{}, failure
	}
	parent, err := validator.zoneKeys(ctx, parentFQDN(zoneName), query)
	if err != nil {
		return validatedZone{}, failure
	}
	if parent.state != validationInsecure {
		return validatedZone{}, failure
	}
	zone := validatedZone{
		state:     validationInsecure,
		expiresAt: minTime(parent.expiresAt, validator.cacheExpiration(dsResponse)),
	}
	validator.cacheZone(zoneName, zone)
	return zone, nil
}

func (validator *dnssecValidator) fetchAnchoredZone(
	ctx context.Context,
	zoneName string,
	anchors []dns.RR,
	query dnssecQuery,
) (validatedZone, error) {
	response, err := query(ctx, zoneName, dns.TypeDNSKEY)
	if err != nil {
		return validatedZone{}, fmt.Errorf("fetch anchored DNSKEY for %s: %w", zoneName, err)
	}
	rrset, signatures := findRRSet(response.Answer, zoneName, dns.TypeDNSKEY)
	keys := dnsKeys(rrset)
	trusted := matchingAnchorKeys(keys, anchors)
	if len(trusted) == 0 {
		return validatedZone{}, fmt.Errorf("DNSKEY for %s does not match a trust anchor", zoneName)
	}
	if err := validator.verifyWithKeys(rrset, signatures, trusted); err != nil {
		return validatedZone{}, fmt.Errorf("validate anchored DNSKEY for %s: %w", zoneName, err)
	}
	return validatedZone{state: validationSecure, keys: keys, expiresAt: validator.cacheExpiration(response)}, nil
}

func (validator *dnssecValidator) fetchDelegatedZone(
	ctx context.Context,
	zoneName string,
	dsRRSet []dns.RR,
	query dnssecQuery,
) (validatedZone, error) {
	response, err := query(ctx, zoneName, dns.TypeDNSKEY)
	if err != nil {
		return validatedZone{}, fmt.Errorf("fetch DNSKEY for %s: %w", zoneName, err)
	}
	rrset, signatures := findRRSet(response.Answer, zoneName, dns.TypeDNSKEY)
	keys := dnsKeys(rrset)
	trusted := matchingDSKeys(keys, dsRecords(dsRRSet))
	if len(trusted) == 0 {
		return validatedZone{}, fmt.Errorf("DNSKEY for %s does not match its DS RRset", zoneName)
	}
	if err := validator.verifyWithKeys(rrset, signatures, trusted); err != nil {
		return validatedZone{}, fmt.Errorf("validate DNSKEY for %s: %w", zoneName, err)
	}
	return validatedZone{state: validationSecure, keys: keys, expiresAt: validator.cacheExpiration(response)}, nil
}

func (validator *dnssecValidator) verifyWithKeys(rrset []dns.RR, signatures []*dns.RRSIG, keys []*dns.DNSKEY) error {
	if len(rrset) == 0 {
		return errors.New("RRset is empty")
	}
	if len(signatures) == 0 {
		return errors.New("RRSIG is missing")
	}
	var failures []error
	for _, signature := range signatures {
		if !signature.ValidityPeriod(validator.now()) {
			failures = append(failures, errors.New("RRSIG is outside its validity period"))
			continue
		}
		for _, key := range keys {
			if key.KeyTag() != signature.KeyTag || key.Algorithm != signature.Algorithm {
				continue
			}
			if err := signature.Verify(key, rrset); err == nil {
				return nil
			} else {
				failures = append(failures, err)
			}
		}
	}
	if len(failures) == 0 {
		return errors.New("no DNSKEY matches an RRSIG key tag and algorithm")
	}
	return errors.Join(failures...)
}

func (validator *dnssecValidator) verifyDenialRRsets(response *dns.Msg, keys []*dns.DNSKEY) error {
	rrsets, signatures := validationRRSets(&dns.Msg{Ns: response.Ns})
	validated := 0
	for key, rrset := range rrsets {
		if key.recordType != dns.TypeNSEC && key.recordType != dns.TypeNSEC3 && key.recordType != dns.TypeSOA {
			continue
		}
		if err := validator.verifyWithKeys(rrset, signatures[key], keys); err != nil {
			return err
		}
		validated++
	}
	if validated == 0 {
		return errors.New("denial response contains no signed SOA, NSEC, or NSEC3 RRset")
	}
	return nil
}

func (validator *dnssecValidator) unsignedNameState(ctx context.Context, name string, query dnssecQuery) (validationState, error) {
	name = normalizeFQDN(name)
	if validator.validationExempt(name) || validator.cachedInsecureAncestor(name) {
		return validationInsecure, nil
	}
	var soa *dns.SOA
	for candidate := name; ; candidate = parentFQDN(candidate) {
		response, err := query(ctx, candidate, dns.TypeSOA)
		if err != nil {
			return validationBogus, fmt.Errorf("discover zone for unsigned name %s: %w", name, err)
		}
		for _, section := range [][]dns.RR{response.Answer, response.Ns} {
			for _, record := range section {
				if typed, ok := record.(*dns.SOA); ok && dns.IsSubDomain(normalizeFQDN(typed.Hdr.Name), name) {
					soa = typed
					break
				}
			}
			if soa != nil {
				break
			}
		}
		if soa != nil {
			break
		}
		if candidate == "." {
			break
		}
	}
	if soa == nil {
		return validationBogus, fmt.Errorf("cannot discover authoritative zone for unsigned name %s", name)
	}
	zone, err := validator.zoneKeys(ctx, soa.Hdr.Name, query)
	if err != nil {
		return validationBogus, err
	}
	return zone.state, nil
}

// validationExempt reports whether name is out of reach of DNSSEC validation,
// either because an operator declared it insecure or because it belongs to a
// locally served zone that has no global delegation behind it.
func (validator *dnssecValidator) validationExempt(name string) bool {
	return isLocallyServedZone(name) || validator.hasNegativeTrustAnchor(name)
}

func (validator *dnssecValidator) hasNegativeTrustAnchor(name string) bool {
	name = normalizeFQDN(name)
	for _, anchor := range validator.negativeAnchors {
		anchor = normalizeFQDN(anchor)
		if dns.IsSubDomain(anchor, name) {
			return true
		}
	}
	validator.mu.RLock()
	defer validator.mu.RUnlock()
	for _, anchor := range validator.zoneInsecure {
		if dns.IsSubDomain(anchor, name) {
			return true
		}
	}
	return false
}

// setZoneInsecure replaces the zone-derived negative trust anchors. Cached zone
// keys are discarded when the set changes so a zone that was previously
// validated does not keep its old security state until the entries expire.
func (validator *dnssecValidator) setZoneInsecure(names []string) {
	normalized := make([]string, 0, len(names))
	for _, name := range names {
		normalized = append(normalized, normalizeFQDN(name))
	}
	validator.mu.Lock()
	defer validator.mu.Unlock()
	if slices.Equal(validator.zoneInsecure, normalized) {
		return
	}
	validator.zoneInsecure = normalized
	validator.zones = make(map[string]validatedZone)
}

func (validator *dnssecValidator) zoneInsecureDomains() []string {
	validator.mu.RLock()
	defer validator.mu.RUnlock()
	return append([]string(nil), validator.zoneInsecure...)
}

func (validator *dnssecValidator) cachedZone(name string) (validatedZone, bool) {
	validator.mu.RLock()
	zone, found := validator.zones[name]
	validator.mu.RUnlock()
	if !found || !validator.now().Before(zone.expiresAt) {
		return validatedZone{}, false
	}
	return zone, true
}

func (validator *dnssecValidator) cachedInsecureAncestor(name string) bool {
	validator.mu.RLock()
	defer validator.mu.RUnlock()
	now := validator.now()
	for owner, zone := range validator.zones {
		if zone.state == validationInsecure && now.Before(zone.expiresAt) && dns.IsSubDomain(owner, name) {
			return true
		}
	}
	return false
}

func (validator *dnssecValidator) cacheZone(name string, zone validatedZone) {
	if zone.expiresAt.IsZero() {
		zone.expiresAt = validator.now().Add(5 * time.Minute)
	}
	validator.mu.Lock()
	validator.zones[name] = zone
	validator.mu.Unlock()
}

func (validator *dnssecValidator) cacheExpiration(response *dns.Msg) time.Time {
	ttl := uint32(300)
	found := false
	for _, section := range [][]dns.RR{response.Answer, response.Ns} {
		for _, record := range section {
			if record.Header().Rrtype == dns.TypeOPT || record.Header().Rrtype == dns.TypeTSIG {
				continue
			}
			if !found || record.Header().Ttl < ttl {
				ttl = record.Header().Ttl
				found = true
			}
		}
	}
	if ttl == 0 {
		ttl = 1
	}
	return validator.now().Add(time.Duration(min(ttl, uint32(3600))) * time.Second)
}

func findRRSet(records []dns.RR, owner string, recordType uint16) ([]dns.RR, []*dns.RRSIG) {
	owner = normalizeFQDN(owner)
	var rrset []dns.RR
	var signatures []*dns.RRSIG
	for _, record := range records {
		if normalizeFQDN(record.Header().Name) != owner {
			continue
		}
		if record.Header().Rrtype == recordType {
			rrset = append(rrset, record)
		} else if signature, ok := record.(*dns.RRSIG); ok && signature.TypeCovered == recordType {
			signatures = append(signatures, signature)
		}
	}
	return rrset, signatures
}

func dnsKeys(records []dns.RR) []*dns.DNSKEY {
	keys := make([]*dns.DNSKEY, 0, len(records))
	for _, record := range records {
		if key, ok := record.(*dns.DNSKEY); ok && key.Protocol == 3 && key.Flags&dns.ZONE != 0 {
			keys = append(keys, key)
		}
	}
	return keys
}

func dsRecords(records []dns.RR) []*dns.DS {
	result := make([]*dns.DS, 0, len(records))
	for _, record := range records {
		if typed, ok := record.(*dns.DS); ok {
			result = append(result, typed)
		}
	}
	return result
}

func matchingAnchorKeys(keys []*dns.DNSKEY, anchors []dns.RR) []*dns.DNSKEY {
	result := make([]*dns.DNSKEY, 0)
	for _, key := range keys {
		for _, anchor := range anchors {
			switch typed := anchor.(type) {
			case *dns.DNSKEY:
				if dns.IsDuplicate(key, typed) {
					result = append(result, key)
				}
			case *dns.DS:
				if keyMatchesDS(key, typed) {
					result = append(result, key)
				}
			}
		}
	}
	return slices.Compact(result)
}

func matchingDSKeys(keys []*dns.DNSKEY, records []*dns.DS) []*dns.DNSKEY {
	result := make([]*dns.DNSKEY, 0)
	for _, key := range keys {
		for _, record := range records {
			if keyMatchesDS(key, record) {
				result = append(result, key)
			}
		}
	}
	return slices.Compact(result)
}

func keyMatchesDS(key *dns.DNSKEY, record *dns.DS) bool {
	if key.KeyTag() != record.KeyTag || key.Algorithm != record.Algorithm {
		return false
	}
	computed := key.ToDS(record.DigestType)
	return computed != nil && strings.EqualFold(computed.Digest, record.Digest)
}

func signerForDelegation(child string, signatures []*dns.RRSIG) (string, error) {
	child = normalizeFQDN(child)
	for _, signature := range signatures {
		signer := normalizeFQDN(signature.SignerName)
		if signer != child && dns.IsSubDomain(signer, child) {
			return signer, nil
		}
	}
	return "", fmt.Errorf("DS RRset for %s has no valid parent signer", child)
}

func denialSigner(response *dns.Msg) (string, error) {
	for _, record := range response.Ns {
		if signature, ok := record.(*dns.RRSIG); ok && (signature.TypeCovered == dns.TypeNSEC || signature.TypeCovered == dns.TypeNSEC3 || signature.TypeCovered == dns.TypeSOA) {
			return normalizeFQDN(signature.SignerName), nil
		}
	}
	return "", errors.New("denial response has no RRSIG signer")
}

func provesInsecureDelegation(records []dns.RR, name string) bool {
	name = normalizeFQDN(name)
	for _, record := range records {
		switch typed := record.(type) {
		case *dns.NSEC:
			if normalizeFQDN(typed.Hdr.Name) == name && hasType(typed.TypeBitMap, dns.TypeNS) && !hasType(typed.TypeBitMap, dns.TypeSOA) && !hasType(typed.TypeBitMap, dns.TypeDS) {
				return true
			}
		case *dns.NSEC3:
			if typed.Match(name) && hasType(typed.TypeBitMap, dns.TypeNS) && !hasType(typed.TypeBitMap, dns.TypeSOA) && !hasType(typed.TypeBitMap, dns.TypeDS) {
				return true
			}
			if typed.Flags&1 != 0 && typed.Cover(name) {
				return true
			}
		}
	}
	return false
}

func validateResponseProof(response *dns.Msg, question dns.Question) error {
	proofs := append([]dns.RR(nil), response.Ns...)
	terminalName, err := terminalQuestionName(response.Answer, question)
	if err != nil {
		return err
	}
	if response.Rcode == dns.RcodeNameError {
		if !provesNameError(proofs, terminalName) {
			return fmt.Errorf("NSEC/NSEC3 records do not prove NXDOMAIN for %s", terminalName)
		}
		return nil
	}
	if !hasPositiveAnswer(response.Answer, terminalName, question.Qtype) {
		if !provesNoData(proofs, terminalName, question.Qtype) {
			return fmt.Errorf("NSEC/NSEC3 records do not prove NODATA for %s %s", terminalName, dns.TypeToString[question.Qtype])
		}
		return nil
	}
	for _, record := range response.Answer {
		signature, ok := record.(*dns.RRSIG)
		if !ok || int(signature.Labels) >= dns.CountLabel(signature.Hdr.Name) {
			continue
		}
		closest := suffixDNSLabels(signature.Hdr.Name, int(signature.Labels))
		if !provesClosestEncloser(proofs, signature.Hdr.Name, closest) {
			return fmt.Errorf("NSEC/NSEC3 records do not prove wildcard expansion for %s", signature.Hdr.Name)
		}
	}
	return nil
}

func terminalQuestionName(records []dns.RR, question dns.Question) (string, error) {
	name := normalizeFQDN(question.Name)
	if question.Qtype == dns.TypeCNAME {
		return name, nil
	}
	for range len(records) + 1 {
		advanced := false
		for _, record := range records {
			alias, ok := record.(*dns.CNAME)
			if !ok || normalizeFQDN(alias.Hdr.Name) != name {
				continue
			}
			next := normalizeFQDN(alias.Target)
			if next == name {
				return "", fmt.Errorf("DNSSEC response contains a CNAME loop at %s", name)
			}
			name = next
			advanced = true
			break
		}
		if !advanced {
			return name, nil
		}
	}
	return "", errors.New("DNSSEC response contains a CNAME chain longer than its answer section")
}

func hasPositiveAnswer(records []dns.RR, owner string, recordType uint16) bool {
	owner = normalizeFQDN(owner)
	for _, record := range records {
		header := record.Header()
		if header.Rrtype == dns.TypeRRSIG || header.Rrtype == dns.TypeOPT || normalizeFQDN(header.Name) != owner {
			continue
		}
		if recordType == dns.TypeANY || header.Rrtype == recordType {
			return true
		}
	}
	return false
}

func synthesizedFromDNAME(rrset []dns.RR, answers []dns.RR) bool {
	if len(rrset) != 1 {
		return false
	}
	alias, ok := rrset[0].(*dns.CNAME)
	if !ok {
		return false
	}
	for _, record := range answers {
		delegation, ok := record.(*dns.DNAME)
		if ok && dnameSynthesizes(delegation, alias) {
			return true
		}
	}
	return false
}

func dnameSynthesizes(delegation *dns.DNAME, alias *dns.CNAME) bool {
	owner := normalizeFQDN(delegation.Hdr.Name)
	aliasOwner := normalizeFQDN(alias.Hdr.Name)
	if owner == aliasOwner || !dns.IsSubDomain(owner, aliasOwner) {
		return false
	}
	ownerLabels := dns.SplitDomainName(owner)
	aliasLabels := dns.SplitDomainName(aliasOwner)
	targetLabels := dns.SplitDomainName(normalizeFQDN(delegation.Target))
	prefixLength := len(aliasLabels) - len(ownerLabels)
	if prefixLength <= 0 {
		return false
	}
	expected := dns.Fqdn(strings.Join(append(append([]string(nil), aliasLabels[:prefixLength]...), targetLabels...), "."))
	return normalizeFQDN(alias.Target) == normalizeFQDN(expected)
}

func provesNoData(records []dns.RR, name string, recordType uint16) bool {
	name = normalizeFQDN(name)
	for _, record := range records {
		switch typed := record.(type) {
		case *dns.NSEC:
			if normalizeFQDN(typed.Hdr.Name) == name && !hasType(typed.TypeBitMap, recordType) && !hasType(typed.TypeBitMap, dns.TypeCNAME) {
				return true
			}
		case *dns.NSEC3:
			if typed.Match(name) && !hasType(typed.TypeBitMap, recordType) && !hasType(typed.TypeBitMap, dns.TypeCNAME) {
				return true
			}
		}
	}
	return false
}

func provesNameError(records []dns.RR, name string) bool {
	name = normalizeFQDN(name)
	for closest := name; ; closest = parentFQDN(closest) {
		if hasExactNSEC(records, closest) && provesClosestEncloser(records, name, closest) && coversDenialName(records, "*."+closest) {
			return true
		}
		if hasMatchingNSEC3(records, closest) && provesClosestEncloser(records, name, closest) && coversDenialName(records, "*."+closest) {
			return true
		}
		if closest == "." {
			break
		}
	}
	return false
}

func provesClosestEncloser(records []dns.RR, name, closest string) bool {
	name, closest = normalizeFQDN(name), normalizeFQDN(closest)
	next := nextCloserFQDN(name, closest)
	if hasExactNSEC(records, closest) {
		return coversNSECName(records, next)
	}
	if hasMatchingNSEC3(records, closest) {
		return coversNSEC3Name(records, next)
	}
	return false
}

func coversDenialName(records []dns.RR, name string) bool {
	return coversNSECName(records, name) || coversNSEC3Name(records, name)
}

func hasExactNSEC(records []dns.RR, name string) bool {
	name = normalizeFQDN(name)
	return slices.ContainsFunc(records, func(record dns.RR) bool {
		nsec, ok := record.(*dns.NSEC)
		return ok && normalizeFQDN(nsec.Hdr.Name) == name
	})
}

func hasMatchingNSEC3(records []dns.RR, name string) bool {
	name = normalizeFQDN(name)
	return slices.ContainsFunc(records, func(record dns.RR) bool {
		nsec3, ok := record.(*dns.NSEC3)
		return ok && nsec3.Match(name)
	})
}

func coversNSECName(records []dns.RR, name string) bool {
	return slices.ContainsFunc(records, func(record dns.RR) bool {
		nsec, ok := record.(*dns.NSEC)
		return ok && nsecCovers(nsec, name)
	})
}

func coversNSEC3Name(records []dns.RR, name string) bool {
	name = normalizeFQDN(name)
	return slices.ContainsFunc(records, func(record dns.RR) bool {
		nsec3, ok := record.(*dns.NSEC3)
		return ok && nsec3.Cover(name)
	})
}

func nsecCovers(record *dns.NSEC, name string) bool {
	owner := normalizeFQDN(record.Hdr.Name)
	next := normalizeFQDN(record.NextDomain)
	name = normalizeFQDN(name)
	if owner == name {
		return false
	}
	ownerNext := compareCanonicalNames(owner, next)
	if ownerNext < 0 {
		return compareCanonicalNames(owner, name) < 0 && compareCanonicalNames(name, next) < 0
	}
	return compareCanonicalNames(owner, name) < 0 || compareCanonicalNames(name, next) < 0
}

func compareCanonicalNames(left, right string) int {
	leftLabels := dns.SplitDomainName(strings.ToLower(left))
	rightLabels := dns.SplitDomainName(strings.ToLower(right))
	for leftIndex, rightIndex := len(leftLabels)-1, len(rightLabels)-1; leftIndex >= 0 && rightIndex >= 0; leftIndex, rightIndex = leftIndex-1, rightIndex-1 {
		if compared := strings.Compare(leftLabels[leftIndex], rightLabels[rightIndex]); compared != 0 {
			return compared
		}
	}
	return len(leftLabels) - len(rightLabels)
}

func suffixDNSLabels(name string, count int) string {
	labels := dns.SplitDomainName(name)
	if count <= 0 {
		return "."
	}
	if count > len(labels) {
		count = len(labels)
	}
	return dns.Fqdn(strings.Join(labels[len(labels)-count:], "."))
}

func nextCloserFQDN(name, closest string) string {
	name, closest = normalizeFQDN(name), normalizeFQDN(closest)
	for name != closest {
		parent := parentFQDN(name)
		if parent == closest {
			return name
		}
		name = parent
	}
	return name
}

func parentFQDN(name string) string {
	labels := dns.SplitDomainName(name)
	if len(labels) <= 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

func normalizeFQDN(name string) string {
	return strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))
}

func hasType(types []uint16, recordType uint16) bool {
	return slices.Contains(types, recordType)
}

func minTime(left, right time.Time) time.Time {
	if left.IsZero() || (!right.IsZero() && right.Before(left)) {
		return right
	}
	return left
}
