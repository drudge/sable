package dnsserver

import (
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/dnsname"
	zonemodel "github.com/drudge/sable/internal/zone"
)

func authoritativeOwner(zoneName, recordName string) (string, error) {
	recordName = strings.TrimSpace(strings.ToLower(recordName))
	if recordName == "" || recordName == "@" {
		return zoneName, nil
	}
	absolute := strings.HasSuffix(recordName, ".")
	recordName = strings.TrimSuffix(recordName, ".")
	normalized, err := dnsname.NormalizeOwner(recordName)
	if err != nil {
		return "", err
	}
	if absolute {
		return normalized, nil
	}
	if normalized == zoneName || strings.HasSuffix(normalized, "."+zoneName) {
		return normalized, nil
	}
	return normalized + "." + zoneName, nil
}

func (runtime *Runtime) authoritativeResponse(request *dns.Msg) (*dns.Msg, bool) {
	return runtime.authoritativeResponseFor(request, questionName(request))
}

// authoritativeResponseFor is authoritativeResponse for a caller that already
// holds the normalized question name.
func (runtime *Runtime) authoritativeResponseFor(request *dns.Msg, queryName string) (*dns.Msg, bool) {
	if request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 {
		return nil, false
	}
	question := request.Question[0]
	if question.Qclass != dns.ClassINET && question.Qclass != dns.ClassANY {
		return nil, false
	}
	zone := runtime.authoritativeZoneFor(queryName)
	if zone == nil {
		return nil, false
	}
	if zone.kind == "catalog" {
		// A catalog zone exists only to be transferred. Answering ordinary
		// queries would hand any client the list of every zone the fleet
		// serves, so the whole subtree is refused instead.
		refusal := new(dns.Msg)
		refusal.SetReply(request)
		refusal.Rcode = dns.RcodeRefused
		return refusal, true
	}
	if zone.forwardsQuestion(queryName, question.Qtype, time.Now()) {
		return nil, false
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	response.RecursionAvailable = true
	now := time.Now()
	records, wildcardOwner, nameExists := zone.recordsAt(queryName, now)
	if !nameExists {
		response.Rcode = dns.RcodeNameError
		response.Ns = zone.nameErrorAuthority(queryName, requestWantsDNSSEC(request), now)
		return response, true
	}
	chain := runtime.authoritativeAnswer(response, records, queryName, question.Qtype, now)
	if chain.dangling != nil {
		// RFC 6604: the rcode describes the last name in the chain, and the
		// aliases that led there stay in the answer section.
		response.Rcode = dns.RcodeNameError
		response.Ns = chain.dangling.nameErrorAuthority(chain.danglingName, requestWantsDNSSEC(request), now)
	}
	if len(response.Answer) == 0 {
		response.Ns = cloneRecords(zone.soa, "", now)
		if requestWantsDNSSEC(request) && zone.signed {
			response.Ns = append(response.Ns, zone.signaturesFor(zone.name, dns.TypeSOA, "", now)...)
			if wildcardOwner != "" {
				response.Ns = append(response.Ns, zone.wildcardNoDataProof(queryName, wildcardOwner, now)...)
			} else {
				response.Ns = append(response.Ns, zone.negativeProof(queryName, true, now)...)
			}
		}
	} else if requestWantsDNSSEC(request) && zone.signed && question.Qtype != dns.TypeRRSIG && question.Qtype != dns.TypeANY {
		zone.signAnswer(response, chain, queryName, wildcardOwner, now)
	}
	return response, true
}

// authoritativeAnswer fills the answer section from the records at the
// question's name. An alias with no records of the asked type is chased, and
// the chain it followed is returned.
func (runtime *Runtime) authoritativeAnswer(response *dns.Msg, records map[uint16][]authoritativeRecord, queryName string, qtype uint16, now time.Time) cnameChain {
	if qtype == dns.TypeANY {
		for _, typed := range records {
			response.Answer = append(response.Answer, cloneRecords(typed, queryName, now)...)
		}
		return cnameChain{}
	}
	response.Answer = append(response.Answer, cloneRecords(records[qtype], queryName, now)...)
	if qtype == dns.TypeCNAME || len(response.Answer) > 0 {
		return cnameChain{}
	}
	aliases := cloneRecords(records[dns.TypeCNAME], queryName, now)
	response.Answer = append(response.Answer, aliases...)
	// RFC 1034 4.3.2 step 3a: an alias answer has to restart the lookup at
	// the canonical name so the address rides along in the same reply. A
	// stub resolver such as glibc's or Go's reads a lone CNAME as "no
	// address" and gives up instead of asking a second time.
	return runtime.chaseCNAME(response, queryName, aliases, qtype, now)
}

// nameErrorAuthority is the authority section of an NXDOMAIN for name: the
// zone's SOA and, for a signed zone and a DNSSEC client, the denial proof.
func (zone *authoritativeZone) nameErrorAuthority(name string, wantsDNSSEC bool, now time.Time) []dns.RR {
	authority := cloneRecords(zone.soa, "", now)
	if wantsDNSSEC && zone.signed {
		authority = append(authority, zone.signaturesFor(zone.name, dns.TypeSOA, "", now)...)
		authority = append(authority, zone.negativeProof(name, false, now)...)
	}
	return authority
}

// signAnswer adds the signatures for every RRset in a signed zone's answer,
// and the proofs for any wildcard the answer was expanded from.
func (zone *authoritativeZone) signAnswer(response *dns.Msg, chain cnameChain, queryName, wildcardOwner string, now time.Time) {
	covered := make(map[string]struct{})
	for _, answer := range response.Answer {
		key := signingRecordKey(answer.Header().Name, answer.Header().Rrtype)
		if _, exists := covered[key]; exists || answer.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		covered[key] = struct{}{}
		owner := normalizeName(answer.Header().Name)
		// A chased hop can live in a different zone than the question, so it
		// has to be signed with the keys of whichever zone actually owns it.
		signer := zone
		if hop := chain.zones[owner]; hop != nil {
			signer = hop
		}
		if !signer.signed {
			continue
		}
		response.Answer = append(response.Answer, signer.signaturesFor(owner, answer.Header().Rrtype, queryName, now)...)
	}
	if wildcardOwner != "" {
		response.Ns = append(response.Ns, zone.wildcardAnswerProof(queryName, now)...)
	}
	for _, hop := range chain.wildcards {
		response.Ns = append(response.Ns, hop.zone.wildcardAnswerProof(hop.name, now)...)
	}
}

// recordsAt resolves the record set an owner name serves inside the zone,
// falling back to a covering wildcard the way a lookup at that name would. It
// reports the wildcard owner it expanded from, if any, and whether the name
// exists at all so callers can tell empty-but-present (NODATA) from missing
// (NXDOMAIN).
func (zone *authoritativeZone) recordsAt(name string, now time.Time) (map[uint16][]authoritativeRecord, string, bool) {
	records := zone.records[name]
	if hasActiveRecords(records, now) {
		return records, "", true
	}
	if _, ownerExists := zone.owners[name]; ownerExists {
		return map[uint16][]authoritativeRecord{}, "", true
	}
	records, wildcardOwner := zone.wildcardRecords(name, now)
	return records, wildcardOwner, records != nil
}

// chainHop names one link of an alias chain together with the zone that owns it.
type chainHop struct {
	name string
	zone *authoritativeZone
}

// cnameChain records what following an alias chain through this node's own zones
// added to an answer: which zone owns each hop, so DNSSEC signs with the right
// keys, which hops came from a wildcard, and whether the chain dead-ended on a
// name that does not exist.
type cnameChain struct {
	zones        map[string]*authoritativeZone
	wildcards    []chainHop
	dangling     *authoritativeZone
	danglingName string
}

// chaseCNAME follows an alias chain across the zones this node is authoritative
// for, appending every hop to the answer until it reaches the requested type,
// leaves local authority, or dead-ends. A target outside those zones is left
// alone, because resolving it is the querying resolver's job, not ours.
func (runtime *Runtime) chaseCNAME(response *dns.Msg, owner string, aliases []dns.RR, qtype uint16, now time.Time) cnameChain {
	// Long enough for the alias chains real deployments build, short enough that
	// a mistyped record cannot make a single query walk an entire zone.
	const maxChainDepth = 16
	chain := cnameChain{zones: make(map[string]*authoritativeZone, 2)}
	visited := map[string]struct{}{owner: {}}
	target := firstCNAMETarget(aliases)
	for depth := 0; target != "" && depth < maxChainDepth; depth++ {
		if _, seen := visited[target]; seen {
			// A loop never reaches an address, so stop here instead of walking to
			// the depth cap on every query that touches it.
			return chain
		}
		visited[target] = struct{}{}
		zone := runtime.authoritativeZoneFor(target)
		if zone == nil || zone.kind == "catalog" || zone.forwardsQuestion(target, qtype, now) {
			return chain
		}
		records, wildcardOwner, nameExists := zone.recordsAt(target, now)
		if !nameExists {
			chain.dangling, chain.danglingName = zone, target
			return chain
		}
		answers := cloneRecords(records[qtype], target, now)
		aliased := false
		if len(answers) == 0 {
			answers = cloneRecords(records[dns.TypeCNAME], target, now)
			aliased = len(answers) > 0
		}
		if len(answers) == 0 {
			// The name exists but holds nothing of the requested type, which is a
			// NODATA answer carrying just the chain we have so far.
			return chain
		}
		response.Answer = append(response.Answer, answers...)
		chain.zones[target] = zone
		if wildcardOwner != "" {
			chain.wildcards = append(chain.wildcards, chainHop{name: target, zone: zone})
		}
		if !aliased {
			return chain
		}
		target = firstCNAMETarget(answers)
	}
	return chain
}

func firstCNAMETarget(records []dns.RR) string {
	for _, record := range records {
		if alias, ok := record.(*dns.CNAME); ok {
			return normalizeName(alias.Target)
		}
	}
	return ""
}

func (zone *authoritativeZone) forwardsQuestion(name string, qtype uint16, now time.Time) bool {
	if zonemodel.IsForwarderType(zone.kind) {
		records, _, _ := zone.recordsAt(name, now)
		if anyActive(records[qtype], now) || anyActive(records[dns.TypeCNAME], now) || qtype == dns.TypeANY && hasActiveRecords(records, now) {
			return false
		}
	}
	return zone.forwards(name)
}

func (zone *authoritativeZone) forwards(name string) bool {
	for current := name; current != ""; {
		if len(zone.forwarders[current]) != 0 {
			return true
		}
		if current == zone.name {
			return false
		}
		separator := strings.IndexByte(current, '.')
		if separator < 0 {
			return false
		}
		current = current[separator+1:]
	}
	return false
}

func (runtime *Runtime) authoritativeANAMEFor(request *dns.Msg, queryName string) (authoritativeANAME, bool) {
	if request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 {
		return authoritativeANAME{}, false
	}
	question := request.Question[0]
	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return authoritativeANAME{}, false
	}
	zone := runtime.authoritativeZoneFor(queryName)
	if zone == nil {
		return authoritativeANAME{}, false
	}
	now := time.Now()
	for _, alias := range zone.anames[queryName] {
		if alias.expiresAt.IsZero() || alias.expiresAt.After(now) {
			return alias, true
		}
	}
	return authoritativeANAME{}, false
}

func (runtime *Runtime) authoritativeZoneFor(name string) *authoritativeZone {
	for current := name; current != ""; {
		if zone := runtime.zones[current]; zone != nil {
			return zone
		}
		separator := strings.IndexByte(current, '.')
		if separator < 0 {
			return nil
		}
		current = current[separator+1:]
	}
	return nil
}

func (zone *authoritativeZone) wildcardRecords(name string, now time.Time) (map[uint16][]authoritativeRecord, string) {
	for current := name; current != zone.name; {
		separator := strings.IndexByte(current, '.')
		if separator < 0 {
			return nil, ""
		}
		current = current[separator+1:]
		if records := zone.records["*."+current]; hasActiveRecords(records, now) {
			return records, "*." + current
		}
	}
	return nil, ""
}

func hasActiveRecords(records map[uint16][]authoritativeRecord, now time.Time) bool {
	for _, typed := range records {
		if anyActive(typed, now) {
			return true
		}
	}
	return false
}

// anyActive reports whether any of records has not expired, the same test
// cloneRecords applies, without copying them.
func anyActive(records []authoritativeRecord, now time.Time) bool {
	for _, record := range records {
		if record.expiresAt.IsZero() || record.expiresAt.After(now) {
			return true
		}
	}
	return false
}

func cloneRecords(records []authoritativeRecord, owner string, now time.Time) []dns.RR {
	clones := make([]dns.RR, 0, len(records))
	for _, record := range records {
		if !record.expiresAt.IsZero() && !record.expiresAt.After(now) {
			continue
		}
		clone := dns.Copy(record.record)
		if owner != "" && strings.HasPrefix(clone.Header().Name, "*.") {
			clone.Header().Name = dns.Fqdn(owner)
		}
		clones = append(clones, clone)
	}
	return clones
}

func (runtime *Runtime) localResponse(request *dns.Msg) (*dns.Msg, bool) {
	return runtime.localResponseFor(request, questionName(request))
}

// localResponseFor is localResponse for a caller that already holds the
// normalized question name.
func (runtime *Runtime) localResponseFor(request *dns.Msg, name string) (*dns.Msg, bool) {
	if request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 {
		return nil, false
	}
	question := request.Question[0]
	if question.Qclass != dns.ClassINET {
		return nil, false
	}
	records, found := runtime.hosts[name]
	if !found {
		return nil, false
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.RecursionAvailable = true
	switch question.Qtype {
	case dns.TypeA:
		response.Answer = append(response.Answer, records.ipv4...)
	case dns.TypeAAAA:
		response.Answer = append(response.Answer, records.ipv6...)
	case dns.TypeANY:
		response.Answer = append(response.Answer, records.ipv4...)
		response.Answer = append(response.Answer, records.ipv6...)
	}
	return response, true
}

func (runtime *Runtime) localHostFor(name string) (localHostRecords, bool) {
	records, found := runtime.hosts[normalizeName(name)]
	return records, found
}
