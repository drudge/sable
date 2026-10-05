package dnsserver

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func requestWantsDNSSEC(request *dns.Msg) bool {
	option := request.IsEdns0()
	return option != nil && option.Do()
}

func signingRecordKey(owner string, recordType uint16) string {
	return strings.ToLower(dns.Fqdn(owner)) + "/" + fmt.Sprint(recordType)
}

func (zone *authoritativeZone) signaturesFor(owner string, coveredType uint16, responseOwner string, now time.Time) []dns.RR {
	owner = normalizeName(owner)
	records := zone.records[owner][dns.TypeRRSIG]
	if len(records) == 0 && responseOwner != "" {
		for current := owner; current != zone.name; {
			separator := strings.IndexByte(current, '.')
			if separator < 0 {
				break
			}
			current = current[separator+1:]
			if wildcard := zone.records["*."+current][dns.TypeRRSIG]; len(wildcard) > 0 {
				records = wildcard
				break
			}
		}
	}
	result := make([]dns.RR, 0, 1)
	for _, record := range records {
		if !record.expiresAt.IsZero() && !record.expiresAt.After(now) {
			continue
		}
		signature, ok := record.record.(*dns.RRSIG)
		if !ok || signature.TypeCovered != coveredType {
			continue
		}
		clone := dns.Copy(signature)
		if responseOwner != "" && strings.HasPrefix(clone.Header().Name, "*.") {
			clone.Header().Name = dns.Fqdn(responseOwner)
		}
		result = append(result, clone)
	}
	return result
}

func (zone *authoritativeZone) negativeProof(name string, nameExists bool, now time.Time) []dns.RR {
	if len(zone.nsec3s) > 0 {
		return zone.negativeNSEC3Proof(name, nameExists, now)
	}
	proofs := make([]dns.RR, 0, 4)
	seen := make(map[string]struct{})
	addProof := func(record dns.RR) {
		if record == nil {
			return
		}
		owner := normalizeName(record.Header().Name)
		if _, duplicate := seen[owner]; duplicate {
			return
		}
		seen[owner] = struct{}{}
		proofs = append(proofs, dns.Copy(record))
		proofs = append(proofs, zone.signaturesFor(owner, dns.TypeNSEC, "", now)...)
	}
	if nameExists {
		addProof(zone.nsecAt(name, now))
		return proofs
	}
	addProof(zone.nsecCovering(name, now))
	closest := zone.name
	for current := name; current != zone.name; {
		separator := strings.IndexByte(current, '.')
		if separator < 0 {
			break
		}
		current = current[separator+1:]
		if _, exists := zone.owners[current]; exists {
			closest = current
			break
		}
	}
	addProof(zone.nsecCovering("*."+closest, now))
	return proofs
}

func (zone *authoritativeZone) negativeNSEC3Proof(name string, nameExists bool, now time.Time) []dns.RR {
	proofs := make([]dns.RR, 0, 6)
	seen := make(map[string]struct{})
	addProof := func(record dns.RR) {
		if record == nil {
			return
		}
		owner := normalizeName(record.Header().Name)
		if _, duplicate := seen[owner]; duplicate {
			return
		}
		seen[owner] = struct{}{}
		proofs = append(proofs, dns.Copy(record))
		proofs = append(proofs, zone.signaturesFor(owner, dns.TypeNSEC3, "", now)...)
	}
	if nameExists {
		addProof(zone.nsec3At(name, now))
		return proofs
	}
	closest := zone.closestEncloser(name)
	addProof(zone.nsec3At(closest, now))
	addProof(zone.nsec3Covering(nextCloserName(name, closest), now))
	addProof(zone.nsec3Covering("*."+closest, now))
	return proofs
}

func (zone *authoritativeZone) wildcardNoDataProof(name, wildcardOwner string, now time.Time) []dns.RR {
	if len(zone.nsec3s) > 0 {
		return zone.wildcardNSEC3NoDataProof(name, wildcardOwner, now)
	}
	proofs := make([]dns.RR, 0, 4)
	for _, record := range []dns.RR{zone.nsecCovering(name, now), zone.nsecAt(wildcardOwner, now)} {
		if record == nil {
			continue
		}
		owner := normalizeName(record.Header().Name)
		if slices.ContainsFunc(proofs, func(existing dns.RR) bool { return normalizeName(existing.Header().Name) == owner }) {
			continue
		}
		proofs = append(proofs, dns.Copy(record))
		proofs = append(proofs, zone.signaturesFor(owner, dns.TypeNSEC, "", now)...)
	}
	return proofs
}

func (zone *authoritativeZone) wildcardAnswerProof(name string, now time.Time) []dns.RR {
	proofs := make([]dns.RR, 0, 4)
	addProof := func(record dns.RR, recordType uint16) {
		if record == nil {
			return
		}
		owner := normalizeName(record.Header().Name)
		if slices.ContainsFunc(proofs, func(existing dns.RR) bool { return normalizeName(existing.Header().Name) == owner }) {
			return
		}
		proofs = append(proofs, dns.Copy(record))
		proofs = append(proofs, zone.signaturesFor(owner, recordType, "", now)...)
	}
	if len(zone.nsec3s) == 0 {
		addProof(zone.nsecCovering(name, now), dns.TypeNSEC)
		return proofs
	}
	closest := zone.closestEncloser(name)
	addProof(zone.nsec3At(closest, now), dns.TypeNSEC3)
	addProof(zone.nsec3Covering(nextCloserName(name, closest), now), dns.TypeNSEC3)
	return proofs
}

func (zone *authoritativeZone) wildcardNSEC3NoDataProof(name, wildcardOwner string, now time.Time) []dns.RR {
	proofs := make([]dns.RR, 0, 4)
	seen := make(map[string]struct{})
	for _, record := range []dns.RR{zone.nsec3Covering(name, now), zone.nsec3At(wildcardOwner, now)} {
		if record == nil {
			continue
		}
		owner := normalizeName(record.Header().Name)
		if _, duplicate := seen[owner]; duplicate {
			continue
		}
		seen[owner] = struct{}{}
		proofs = append(proofs, dns.Copy(record))
		proofs = append(proofs, zone.signaturesFor(owner, dns.TypeNSEC3, "", now)...)
	}
	return proofs
}

func (zone *authoritativeZone) closestEncloser(name string) string {
	for current := normalizeName(name); ; {
		if _, exists := zone.owners[current]; exists {
			return current
		}
		if current == zone.name {
			return zone.name
		}
		separator := strings.IndexByte(current, '.')
		if separator < 0 {
			return zone.name
		}
		current = current[separator+1:]
	}
}

func nextCloserName(name, closest string) string {
	current := normalizeName(name)
	for current != closest {
		separator := strings.IndexByte(current, '.')
		if separator < 0 || current[separator+1:] == closest {
			return current
		}
		current = current[separator+1:]
	}
	return current
}

func (zone *authoritativeZone) nsec3At(name string, now time.Time) dns.RR {
	name = dns.Fqdn(normalizeName(name))
	for _, record := range zone.nsec3s {
		if !record.expiresAt.IsZero() && !record.expiresAt.After(now) {
			continue
		}
		if nsec3, ok := record.record.(*dns.NSEC3); ok && nsec3.Match(name) {
			return nsec3
		}
	}
	return nil
}

func (zone *authoritativeZone) nsec3Covering(name string, now time.Time) dns.RR {
	name = dns.Fqdn(normalizeName(name))
	for _, record := range zone.nsec3s {
		if !record.expiresAt.IsZero() && !record.expiresAt.After(now) {
			continue
		}
		if nsec3, ok := record.record.(*dns.NSEC3); ok && nsec3.Cover(name) {
			return nsec3
		}
	}
	return nil
}

func (zone *authoritativeZone) nsecAt(name string, now time.Time) dns.RR {
	for _, record := range zone.records[normalizeName(name)][dns.TypeNSEC] {
		if record.expiresAt.IsZero() || record.expiresAt.After(now) {
			return record.record
		}
	}
	return nil
}

func (zone *authoritativeZone) nsecCovering(name string, now time.Time) dns.RR {
	name = dns.Fqdn(normalizeName(name))
	for _, record := range zone.nsecs {
		if !record.expiresAt.IsZero() && !record.expiresAt.After(now) {
			continue
		}
		nsec, ok := record.record.(*dns.NSEC)
		if !ok {
			continue
		}
		ownerCompared := compareCanonicalWireName(nsec.Hdr.Name, name)
		nextCompared := compareCanonicalWireName(name, nsec.NextDomain)
		ownerToNext := compareCanonicalWireName(nsec.Hdr.Name, nsec.NextDomain)
		if (ownerToNext < 0 && ownerCompared < 0 && nextCompared < 0) ||
			(ownerToNext >= 0 && (ownerCompared < 0 || nextCompared < 0)) {
			return nsec
		}
	}
	return nil
}

func compareCanonicalWireName(left, right string) int {
	leftLabels := dns.SplitDomainName(strings.ToLower(left))
	rightLabels := dns.SplitDomainName(strings.ToLower(right))
	for leftIndex, rightIndex := len(leftLabels)-1, len(rightLabels)-1; leftIndex >= 0 && rightIndex >= 0; leftIndex, rightIndex = leftIndex-1, rightIndex-1 {
		if compared := strings.Compare(leftLabels[leftIndex], rightLabels[rightIndex]); compared != 0 {
			return compared
		}
	}
	return len(leftLabels) - len(rightLabels)
}
