package app

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	dnssecstate "github.com/drudge/sable/internal/dnssec"
	zonemodel "github.com/drudge/sable/internal/zone"
)

const (
	dnssecGeneratedComment  = "sable:dnssec-managed"
	dnssecSignatureLifetime = 7 * 24 * time.Hour
	dnssecResignBefore      = 48 * time.Hour
	dnssecInceptionSkew     = 5 * time.Minute
)

type dnssecVault interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
}

type dnssecSigner struct {
	vault dnssecVault
	now   func() time.Time
	mu    sync.Mutex
}

type dnssecKeyMaterial struct {
	DNSKEY     string `json:"dnskey"`
	PrivateKey string `json:"private_key"`
}

func newDNSSECSigner(vault dnssecVault) *dnssecSigner {
	return &dnssecSigner{vault: vault, now: time.Now}
}

func (signer *dnssecSigner) Prepare(ctx context.Context, zones *[]zonemodel.Zone) error {
	for index := range *zones {
		zone := &(*zones)[index]
		if zone.Type != "primary" || !zone.DNSSEC {
			if zone.Type == "primary" && hasManagedDNSSECRecords(zone.Records) {
				if err := advanceDynamicSOASerial(zone); err != nil {
					return fmt.Errorf("disable DNSSEC for zone %q: %w", zone.Name, err)
				}
			}
			zone.Records = removeManagedDNSSECRecords(zone.Records)
			continue
		}
		if err := signer.signZone(ctx, zone, false); err != nil {
			return fmt.Errorf("sign zone %q: %w", zone.Name, err)
		}
	}
	return nil
}

func (signer *dnssecSigner) Rotate(ctx context.Context, zone *zonemodel.Zone) error {
	if !zone.DNSSEC || zone.Type != "primary" {
		return errors.New("DNSSEC signing is not enabled for this primary zone")
	}
	if err := signer.RequestRollover(ctx, *zone, "zsk"); err != nil {
		return err
	}
	return signer.signZone(ctx, zone, false)
}

func (signer *dnssecSigner) signZone(ctx context.Context, zone *zonemodel.Zone, _ bool) error {
	base := removeManagedDNSSECRecords(zone.Records)
	for _, record := range base {
		if !record.ExpiresAt.IsZero() {
			return errors.New("expiring records are not supported in a signed zone")
		}
	}
	if err := validateDNSSECAlgorithmTransition(*zone); err != nil {
		return err
	}
	keys, err := signer.signingKeys(ctx, *zone)
	if err != nil {
		return err
	}
	baseRRs, err := zoneRRsForSigning(*zone, base)
	if err != nil {
		return err
	}
	if signedZoneCurrent(*zone, baseRRs, keys, signer.now()) {
		return nil
	}
	if signingNeedsSOAAdvance(*zone, baseRRs) {
		if err := advanceDynamicSOASerial(zone); err != nil {
			return err
		}
		base = removeManagedDNSSECRecords(zone.Records)
		baseRRs, err = zoneRRsForSigning(*zone, base)
		if err != nil {
			return err
		}
	}
	generated, err := generateSignedZoneRecords(*zone, baseRRs, keys, signer.now())
	if err != nil {
		return err
	}
	zone.Records = append(base, generated...)
	return nil
}

func validateDNSSECAlgorithmTransition(zone zonemodel.Zone) error {
	expected, _, err := dnssecAlgorithm(zone.DNSSECAlgorithm)
	if err != nil {
		return err
	}
	for _, record := range zone.Records {
		if record.Comments != dnssecGeneratedComment || record.Type != "DNSKEY" {
			continue
		}
		rr, parseErr := configuredRecordRR(zone, record)
		if parseErr != nil {
			continue
		}
		if key, ok := rr.(*dns.DNSKEY); ok && key.Algorithm != expected {
			return errors.New("DNSSEC algorithm rollover requires a parent-coordinated multi-algorithm transition and is not supported")
		}
	}
	return nil
}

func hasManagedDNSSECRecords(records []zonemodel.Record) bool {
	return slices.ContainsFunc(records, func(record zonemodel.Record) bool {
		return record.Comments == dnssecGeneratedComment
	})
}

func signingNeedsSOAAdvance(zone zonemodel.Zone, base []dns.RR) bool {
	var soa dns.RR
	for _, record := range base {
		if record.Header().Rrtype == dns.TypeSOA {
			soa = record
			break
		}
	}
	if soa == nil {
		return false
	}
	storedKeys := make(map[uint16]*dns.DNSKEY)
	soaSignatures := make([]*dns.RRSIG, 0)
	for _, record := range zone.Records {
		if record.Comments != dnssecGeneratedComment {
			continue
		}
		rr, err := configuredRecordRR(zone, record)
		if err != nil {
			continue
		}
		switch typed := rr.(type) {
		case *dns.DNSKEY:
			storedKeys[typed.KeyTag()] = typed
		case *dns.RRSIG:
			if typed.TypeCovered == dns.TypeSOA {
				soaSignatures = append(soaSignatures, typed)
			}
		}
	}
	for _, signature := range soaSignatures {
		if key := storedKeys[signature.KeyTag]; key != nil && signature.Verify(key, []dns.RR{soa}) == nil {
			return true
		}
	}
	return false
}

func (signer *dnssecSigner) signingKey(
	ctx context.Context,
	zone zonemodel.Zone,
	rotate bool,
) (*dns.DNSKEY, crypto.Signer, error) {
	algorithm, bits, err := dnssecAlgorithm(zone.DNSSECAlgorithm)
	if err != nil {
		return nil, nil, err
	}
	secretName := dnssecSecretName(zone.Name, zone.DNSSECAlgorithm)
	if !rotate {
		encoded, getErr := signer.vault.Get(ctx, secretName)
		if getErr == nil {
			key, privateKey, decodeErr := decodeDNSSECKey(encoded)
			if decodeErr != nil {
				return nil, nil, decodeErr
			}
			key.Hdr.Name = dns.Fqdn(zone.Name)
			key.Hdr.Ttl = zone.DefaultTTL
			return key, privateKey, nil
		}
		if !errors.Is(getErr, auth.ErrNotFound) {
			return nil, nil, fmt.Errorf("load signing key: %w", getErr)
		}
	}

	key := &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: dns.Fqdn(zone.Name), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: zone.DefaultTTL},
		Flags: 257, Protocol: 3, Algorithm: algorithm,
	}
	privateValue, err := key.Generate(bits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate signing key: %w", err)
	}
	privateKey, ok := privateValue.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("generated DNSSEC key cannot sign")
	}
	material := dnssecKeyMaterial{DNSKEY: key.String(), PrivateKey: key.PrivateKeyString(privateValue)}
	encoded, err := json.Marshal(material)
	if err != nil {
		return nil, nil, fmt.Errorf("encode signing key: %w", err)
	}
	if err := signer.vault.Put(ctx, secretName, encoded); err != nil {
		return nil, nil, fmt.Errorf("store signing key: %w", err)
	}
	return key, privateKey, nil
}

func decodeDNSSECKey(encoded []byte) (*dns.DNSKEY, crypto.Signer, error) {
	var material dnssecKeyMaterial
	if err := json.Unmarshal(encoded, &material); err != nil {
		return nil, nil, errors.New("decode signing key: invalid encrypted value")
	}
	record, err := dns.NewRR(material.DNSKEY)
	if err != nil {
		return nil, nil, fmt.Errorf("decode public signing key: %w", err)
	}
	key, ok := record.(*dns.DNSKEY)
	if !ok {
		return nil, nil, errors.New("decode public signing key: record is not DNSKEY")
	}
	privateValue, err := key.NewPrivateKey(material.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decode private signing key: %w", err)
	}
	privateKey, ok := privateValue.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("decoded DNSSEC key cannot sign")
	}
	return key, privateKey, nil
}

func dnssecAlgorithm(name string) (uint8, int, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "ed25519":
		return dns.ED25519, 256, nil
	case "ecdsa-p256-sha256":
		return dns.ECDSAP256SHA256, 256, nil
	case "ecdsa-p384-sha384":
		return dns.ECDSAP384SHA384, 384, nil
	default:
		return 0, 0, fmt.Errorf("unsupported DNSSEC algorithm %q", name)
	}
}

func dnssecSecretName(zone, algorithm string) string {
	return "dnssec/" + strings.TrimSuffix(strings.ToLower(zone), ".") + "/csk/" + strings.ToLower(algorithm)
}

func removeManagedDNSSECRecords(records []zonemodel.Record) []zonemodel.Record {
	result := make([]zonemodel.Record, 0, len(records))
	for _, record := range records {
		if record.Comments == dnssecGeneratedComment {
			continue
		}
		result = append(result, record)
	}
	return result
}

func zoneRRsForSigning(zone zonemodel.Zone, records []zonemodel.Record) ([]dns.RR, error) {
	result := make([]dns.RR, 0, len(records))
	for _, record := range records {
		if record.Disabled {
			continue
		}
		recordType := strings.ToUpper(record.Type)
		if recordType == "FWD" || recordType == "ANAME" {
			return nil, fmt.Errorf("%s records are not supported in a signed zone", recordType)
		}
		if recordType == "RRSIG" || recordType == "NSEC" || recordType == "NSEC3" || recordType == "NSEC3PARAM" || recordType == "DNSKEY" {
			return nil, fmt.Errorf("user-managed %s records conflict with automatic signing", recordType)
		}
		rr, err := configuredRecordRR(zone, record)
		if err != nil {
			return nil, err
		}
		result = append(result, rr)
	}
	return result, nil
}

func generateSignedZoneRecords(
	zone zonemodel.Zone,
	base []dns.RR,
	keys []zoneSigningKey,
	now time.Time,
) ([]zonemodel.Record, error) {
	publishedKeys := publishedSigningKeys(keys, zone)
	if len(publishedKeys) == 0 {
		return nil, errors.New("signed zone has no published DNSSEC keys")
	}
	unsigned := copyRRSet(base)
	for _, key := range publishedKeys {
		unsigned = append(unsigned, key.key)
	}
	parameters, denial, err := buildDenialRecords(zone, unsigned)
	if err != nil {
		return nil, err
	}
	unsigned = append(unsigned, parameters...)
	unsigned = append(unsigned, denial...)
	rrsets := groupSigningRRSets(unsigned)

	inception := uint32(now.Add(-dnssecInceptionSkew).Unix())
	expiration := uint32(now.Add(dnssecSignatureLifetime).Unix())
	signatures := make([]dns.RR, 0, len(rrsets))
	rrsetKeys := make([]string, 0, len(rrsets))
	for rrsetKey := range rrsets {
		rrsetKeys = append(rrsetKeys, rrsetKey)
	}
	slices.Sort(rrsetKeys)
	for _, rrsetKey := range rrsetKeys {
		rrset := rrsets[rrsetKey]
		for _, signer := range signingKeysForRRSet(publishedKeys, rrset[0].Header().Rrtype) {
			signature := &dns.RRSIG{
				Hdr:       dns.RR_Header{Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: rrset[0].Header().Ttl},
				Algorithm: signer.key.Algorithm, Expiration: expiration, Inception: inception,
				KeyTag: signer.key.KeyTag(), SignerName: dns.Fqdn(zone.Name),
			}
			if err := signature.Sign(signer.privateKey, rrset); err != nil {
				return nil, fmt.Errorf("sign %s with key %d: %w", rrsetKey, signer.key.KeyTag(), err)
			}
			signatures = append(signatures, signature)
		}
	}

	generatedRRs := make([]dns.RR, 0, len(publishedKeys)+len(parameters)+len(denial)+len(signatures))
	for _, key := range publishedKeys {
		generatedRRs = append(generatedRRs, key.key)
	}
	generatedRRs = append(generatedRRs, parameters...)
	generatedRRs = append(generatedRRs, denial...)
	generatedRRs = append(generatedRRs, signatures...)
	result := make([]zonemodel.Record, 0, len(generatedRRs))
	for _, record := range generatedRRs {
		configured, err := configuredRecordFromRR(zone.Name, record)
		if err != nil {
			return nil, err
		}
		configured.Comments = dnssecGeneratedComment
		result = append(result, configured)
	}
	return result, nil
}

func publishedSigningKeys(keys []zoneSigningKey, zone zonemodel.Zone) []zoneSigningKey {
	result := make([]zoneSigningKey, 0, len(keys))
	for _, key := range keys {
		if !isPublishedKeyState(key.state) {
			continue
		}
		copy := key
		copy.key = dns.Copy(key.key).(*dns.DNSKEY)
		copy.key.Hdr.Name = dns.Fqdn(zone.Name)
		copy.key.Hdr.Ttl = zone.DefaultTTL
		result = append(result, copy)
	}
	return result
}

func isPublishedKeyState(state string) bool {
	switch state {
	case dnssecstate.StatePublished, dnssecstate.StateReady, dnssecstate.StateActive, dnssecstate.StateRetiring:
		return true
	default:
		return false
	}
}

func signingKeysForRRSet(keys []zoneSigningKey, recordType uint16) []zoneSigningKey {
	result := make([]zoneSigningKey, 0, 2)
	if recordType == dns.TypeDNSKEY {
		for _, key := range keys {
			if key.role == dnssecstate.RoleKSK {
				result = append(result, key)
			}
		}
		return result
	}
	for _, key := range keys {
		if key.role == dnssecstate.RoleZSK && key.state == dnssecstate.StateActive {
			result = append(result, key)
		}
	}
	if len(result) == 0 {
		for _, key := range keys {
			if key.role == dnssecstate.RoleKSK && key.state == dnssecstate.StateActive {
				result = append(result, key)
				break
			}
		}
	}
	return result
}

func buildDenialRecords(zone zonemodel.Zone, records []dns.RR) ([]dns.RR, []dns.RR, error) {
	if zone.DNSSECDenial != "nsec3" {
		return nil, buildNSECChain(records, zone.DefaultTTL), nil
	}
	parameter := &dns.NSEC3PARAM{
		Hdr:  dns.RR_Header{Name: dns.Fqdn(zone.Name), Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: zone.DefaultTTL},
		Hash: dns.SHA1, Iterations: zone.NSEC3Iterations,
		SaltLength: uint8(len(zone.NSEC3Salt) / 2), Salt: zone.NSEC3Salt,
	}
	withParameter := append(copyRRSet(records), parameter)
	chain, err := buildNSEC3Chain(withParameter, dns.Fqdn(zone.Name), zone.DefaultTTL, zone.NSEC3Iterations, zone.NSEC3Salt)
	if err != nil {
		return nil, nil, err
	}
	return []dns.RR{parameter}, chain, nil
}

func buildNSECChain(records []dns.RR, ttl uint32) []dns.RR {
	typesByOwner := denialTypesByOwner(records)
	owners := make([]string, 0, len(typesByOwner))
	for owner := range typesByOwner {
		owners = append(owners, owner)
	}
	slices.SortFunc(owners, compareCanonicalDNSName)
	result := make([]dns.RR, 0, len(owners))
	for index, owner := range owners {
		types := sortedDenialTypes(typesByOwner[owner], dns.TypeNSEC)
		result = append(result, &dns.NSEC{
			Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: ttl},
			NextDomain: owners[(index+1)%len(owners)], TypeBitMap: types,
		})
	}
	return result
}

func buildNSEC3Chain(records []dns.RR, zoneName string, ttl uint32, iterations uint16, salt string) ([]dns.RR, error) {
	typesByOwner := denialTypesByOwner(records)
	typesByHash := make(map[string]map[uint16]struct{}, len(typesByOwner))
	for owner, types := range typesByOwner {
		hash := dns.HashName(owner, dns.SHA1, iterations, salt)
		if hash == "" {
			return nil, fmt.Errorf("hash NSEC3 owner %q", owner)
		}
		if _, collision := typesByHash[hash]; collision {
			return nil, fmt.Errorf("NSEC3 hash collision for owner %q", owner)
		}
		typesByHash[hash] = types
	}
	hashes := make([]string, 0, len(typesByHash))
	for hash := range typesByHash {
		hashes = append(hashes, hash)
	}
	slices.Sort(hashes)
	result := make([]dns.RR, 0, len(hashes))
	for index, hash := range hashes {
		result = append(result, &dns.NSEC3{
			Hdr:  dns.RR_Header{Name: strings.ToLower(hash) + "." + dns.Fqdn(zoneName), Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: ttl},
			Hash: dns.SHA1, Flags: 0, Iterations: iterations,
			SaltLength: uint8(len(salt) / 2), Salt: salt,
			HashLength: 20, NextDomain: hashes[(index+1)%len(hashes)],
			TypeBitMap: sortedNSEC3Types(typesByHash[hash]),
		})
	}
	return result, nil
}

func denialTypesByOwner(records []dns.RR) map[string]map[uint16]struct{} {
	typesByOwner := make(map[string]map[uint16]struct{})
	zoneName := ""
	for _, record := range records {
		if record.Header().Rrtype == dns.TypeSOA {
			zoneName = strings.ToLower(dns.Fqdn(record.Header().Name))
			break
		}
	}
	for _, record := range records {
		owner := strings.ToLower(dns.Fqdn(record.Header().Name))
		if typesByOwner[owner] == nil {
			typesByOwner[owner] = make(map[uint16]struct{})
		}
		typesByOwner[owner][record.Header().Rrtype] = struct{}{}
		for ancestor := parentDNSName(owner); zoneName != "" && dns.IsSubDomain(zoneName, ancestor); ancestor = parentDNSName(ancestor) {
			if typesByOwner[ancestor] == nil {
				typesByOwner[ancestor] = make(map[uint16]struct{})
			}
			if ancestor == zoneName {
				break
			}
		}
	}
	return typesByOwner
}

func sortedDenialTypes(typesByOwner map[uint16]struct{}, additional ...uint16) []uint16 {
	types := make([]uint16, 0, len(typesByOwner)+len(additional)+1)
	for recordType := range typesByOwner {
		types = append(types, recordType)
	}
	types = append(types, additional...)
	types = append(types, dns.TypeRRSIG)
	slices.Sort(types)
	return slices.Compact(types)
}

func sortedNSEC3Types(typesByOwner map[uint16]struct{}) []uint16 {
	types := make([]uint16, 0, len(typesByOwner)+1)
	for recordType := range typesByOwner {
		types = append(types, recordType)
	}
	if len(typesByOwner) > 0 {
		types = append(types, dns.TypeRRSIG)
	}
	slices.Sort(types)
	return slices.Compact(types)
}

func parentDNSName(name string) string {
	labels := dns.SplitDomainName(name)
	if len(labels) <= 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

func compareCanonicalDNSName(left, right string) int {
	leftLabels := dns.SplitDomainName(strings.ToLower(left))
	rightLabels := dns.SplitDomainName(strings.ToLower(right))
	for leftIndex, rightIndex := len(leftLabels)-1, len(rightLabels)-1; leftIndex >= 0 && rightIndex >= 0; leftIndex, rightIndex = leftIndex-1, rightIndex-1 {
		if compared := strings.Compare(leftLabels[leftIndex], rightLabels[rightIndex]); compared != 0 {
			return compared
		}
	}
	return len(leftLabels) - len(rightLabels)
}

func groupSigningRRSets(records []dns.RR) map[string][]dns.RR {
	result := make(map[string][]dns.RR)
	for _, record := range records {
		key := signingRRSetKey(record.Header().Name, record.Header().Rrtype)
		result[key] = append(result[key], record)
	}
	return result
}

func signingRRSetKey(owner string, recordType uint16) string {
	return strings.ToLower(dns.Fqdn(owner)) + "/" + fmt.Sprint(recordType)
}

func signedZoneCurrent(zone zonemodel.Zone, base []dns.RR, keys []zoneSigningKey, now time.Time) bool {
	generatedRecords := make([]dns.RR, 0)
	for _, record := range zone.Records {
		if record.Comments != dnssecGeneratedComment {
			continue
		}
		rr, err := configuredRecordRR(zone, record)
		if err != nil {
			return false
		}
		generatedRecords = append(generatedRecords, rr)
	}
	if len(generatedRecords) == 0 {
		return false
	}

	storedKeys := make([]dns.RR, 0)
	actualDenial := make([]dns.RR, 0)
	signatures := make(map[string][]*dns.RRSIG)
	unsigned := copyRRSet(base)
	for _, record := range generatedRecords {
		switch typed := record.(type) {
		case *dns.DNSKEY:
			storedKeys = append(storedKeys, typed)
			unsigned = append(unsigned, typed)
		case *dns.NSEC, *dns.NSEC3, *dns.NSEC3PARAM:
			actualDenial = append(actualDenial, typed)
			unsigned = append(unsigned, typed)
		case *dns.RRSIG:
			signatures[signingRRSetKey(typed.Hdr.Name, typed.TypeCovered)] = append(signatures[signingRRSetKey(typed.Hdr.Name, typed.TypeCovered)], typed)
		default:
			return false
		}
	}
	expectedKeys := publishedSigningKeys(keys, zone)
	expectedKeyRecords := make([]dns.RR, 0, len(expectedKeys))
	for _, key := range expectedKeys {
		expectedKeyRecords = append(expectedKeyRecords, key.key)
	}
	if !equalUnorderedRRs(storedKeys, expectedKeyRecords) {
		return false
	}
	parameters, denial, err := buildDenialRecords(zone, append(copyRRSet(base), expectedKeyRecords...))
	if err != nil {
		return false
	}
	expectedDenial := append(parameters, denial...)
	if !equalUnorderedRRs(actualDenial, expectedDenial) {
		return false
	}
	rrsets := groupSigningRRSets(unsigned)
	if len(signatures) != len(rrsets) {
		return false
	}
	minimumExpiration := uint32(now.Add(dnssecResignBefore).Unix())
	for rrsetKey, rrset := range rrsets {
		matching := signatures[rrsetKey]
		required := signingKeysForRRSet(expectedKeys, rrset[0].Header().Rrtype)
		if len(matching) != len(required) || !signaturesMatchKeys(matching, required, rrset, minimumExpiration, now) {
			return false
		}
	}
	return true
}

func signaturesMatchKeys(signatures []*dns.RRSIG, keys []zoneSigningKey, rrset []dns.RR, minimumExpiration uint32, now time.Time) bool {
	for _, key := range keys {
		matched := false
		for _, signature := range signatures {
			if signature.KeyTag != key.key.KeyTag() || signature.Algorithm != key.key.Algorithm {
				continue
			}
			if signature.Expiration <= minimumExpiration || signature.Inception > uint32(now.Unix()) || signature.Verify(key.key, rrset) != nil {
				return false
			}
			matched = true
			break
		}
		if !matched {
			return false
		}
	}
	return true
}

func equalUnorderedRRs(left, right []dns.RR) bool {
	if len(left) != len(right) {
		return false
	}
	for _, expected := range right {
		if !slices.ContainsFunc(left, func(actual dns.RR) bool { return dns.IsDuplicate(actual, expected) }) {
			return false
		}
	}
	return true
}

func copyRRSet(records []dns.RR) []dns.RR {
	result := make([]dns.RR, len(records))
	for index, record := range records {
		result[index] = dns.Copy(record)
	}
	return result
}

func zoneDNSSECDetails(zone zonemodel.Zone) (*dns.DNSKEY, *dns.DS, time.Time) {
	var key *dns.DNSKEY
	var expiration time.Time
	for _, record := range zone.Records {
		if record.Comments != dnssecGeneratedComment {
			continue
		}
		rr, err := configuredRecordRR(zone, record)
		if err != nil {
			continue
		}
		switch typed := rr.(type) {
		case *dns.DNSKEY:
			if key == nil || typed.Flags&dns.SEP != 0 && key.Flags&dns.SEP == 0 {
				key = typed
			}
		case *dns.RRSIG:
			candidate := time.Unix(int64(typed.Expiration), 0)
			if expiration.IsZero() || candidate.Before(expiration) {
				expiration = candidate
			}
		}
	}
	if key == nil {
		return nil, nil, expiration
	}
	return key, key.ToDS(dns.SHA256), expiration
}

func (signer *dnssecSigner) ZonesNeedingRefresh(ctx context.Context, configured []zonemodel.Zone) ([]string, error) {
	threshold := signer.now().Add(dnssecResignBefore)
	zones := make([]string, 0)
	for _, zone := range configured {
		if zone.Type != "primary" || !zone.DNSSEC || zone.Disabled {
			continue
		}
		key, _, expiration := zoneDNSSECDetails(zone)
		lifecycleDue, err := signer.keyLifecycleDue(ctx, zone)
		if err != nil {
			return nil, fmt.Errorf("inspect DNSSEC key lifecycle for zone %q: %w", zone.Name, err)
		}
		if lifecycleDue || key == nil || expiration.IsZero() || !expiration.After(threshold) {
			zones = append(zones, zone.Name)
		}
	}
	return zones, nil
}
