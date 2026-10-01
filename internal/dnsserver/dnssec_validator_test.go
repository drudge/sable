package dnsserver

import (
	"context"
	"crypto"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type validatorTestKey struct {
	key     *dns.DNSKEY
	private crypto.Signer
}

func TestDNSSECValidatorAuthenticatesDelegationChain(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	root := newValidatorTestKey(t, ".")
	testZone := newValidatorTestKey(t, "demo.")
	secure := newValidatorTestKey(t, "secure.demo.")
	validator := validatorWithAnchor(t, root, now)

	queries := validatorChainQueries(t, now, root, testZone, secure)
	query := mapValidatorQuery(queries)
	answer := validatorSignedResponse(t, now, secure, "www.secure.demo.", dns.TypeA, "192.0.2.10")
	state, err := validator.validate(context.Background(), answer, answer.Question[0], query)
	if err != nil || state != validationSecure {
		t.Fatalf("validate() = %v, %v; want secure", state, err)
	}

	answer.Answer[0].(*dns.A).A[3] = 11
	state, err = validator.validate(context.Background(), answer, answer.Question[0], query)
	if err == nil || state != validationBogus {
		t.Fatalf("mutated validate() = %v, %v; want bogus", state, err)
	}
}

func TestDNSSECValidatorAuthenticatesNSECNameErrorAndWildcard(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	secure := newValidatorTestKey(t, "secure.demo.")
	validator := validatorWithAnchor(t, secure, now)
	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("secure.demo.", dns.TypeDNSKEY): validatorDNSKEYResponse(t, now, secure),
	})
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "secure.demo.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "www.secure.demo.", TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY},
	}
	soa := validatorSOA("secure.demo.")

	missing := new(dns.Msg)
	missing.SetQuestion("missing.secure.demo.", dns.TypeA)
	missing.SetRcode(missing, dns.RcodeNameError)
	missing.Authoritative = true
	missing.Ns = append(missing.Ns, soa, signValidatorRRSet(t, now, secure, []dns.RR{soa}))
	missing.Ns = append(missing.Ns, nsec, signValidatorRRSet(t, now, secure, []dns.RR{nsec}))
	state, err := validator.validate(context.Background(), missing, missing.Question[0], query)
	if err != nil || state != validationSecure {
		t.Fatalf("NXDOMAIN validate() = %v, %v; want secure", state, err)
	}

	wildcardRR := validatorA("*.secure.demo.", "192.0.2.44")
	wildcardSignature := signValidatorRRSet(t, now, secure, []dns.RR{wildcardRR})
	wildcardRR.Hdr.Name = "host.secure.demo."
	wildcardSignature.Hdr.Name = "host.secure.demo."
	wildcard := new(dns.Msg)
	wildcard.SetQuestion("host.secure.demo.", dns.TypeA)
	wildcard.SetReply(wildcard)
	wildcard.Answer = []dns.RR{wildcardRR, wildcardSignature}
	wildcard.Ns = []dns.RR{nsec, signValidatorRRSet(t, now, secure, []dns.RR{nsec})}
	state, err = validator.validate(context.Background(), wildcard, wildcard.Question[0], query)
	if err != nil || state != validationSecure {
		t.Fatalf("wildcard validate() = %v, %v; want secure", state, err)
	}
}

func TestDNSSECValidatorRecognizesAuthenticatedInsecureDelegation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	parent := newValidatorTestKey(t, "demo.")
	validator := validatorWithAnchor(t, parent, now)
	denial := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "unsigned.demo.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "z.demo.", TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	soa := validatorSOA("demo.")
	dsResponse := new(dns.Msg)
	dsResponse.SetQuestion("unsigned.demo.", dns.TypeDS)
	dsResponse.SetReply(dsResponse)
	dsResponse.Ns = []dns.RR{
		soa, signValidatorRRSet(t, now, parent, []dns.RR{soa}),
		denial, signValidatorRRSet(t, now, parent, []dns.RR{denial}),
	}
	soaResponse := new(dns.Msg)
	soaResponse.SetQuestion("www.unsigned.demo.", dns.TypeSOA)
	soaResponse.SetReply(soaResponse)
	unsignedSOA := validatorSOA("unsigned.demo.")
	soaResponse.Answer = []dns.RR{unsignedSOA}
	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("demo.", dns.TypeDNSKEY):           validatorDNSKEYResponse(t, now, parent),
		validatorQueryKey("unsigned.demo.", dns.TypeDS):      dsResponse,
		validatorQueryKey("www.unsigned.demo.", dns.TypeSOA): soaResponse,
	})
	response := new(dns.Msg)
	response.SetQuestion("www.unsigned.demo.", dns.TypeA)
	response.SetReply(response)
	response.Answer = []dns.RR{validatorA("www.unsigned.demo.", "192.0.2.20")}
	state, err := validator.validate(context.Background(), response, response.Question[0], query)
	if err != nil || state != validationInsecure {
		t.Fatalf("validate() = %v, %v; want insecure", state, err)
	}
}

// TestDNSSECValidatorInheritsInsecureStateForBareDSDenial reproduces
// api.anthropic.com: a delegation of its own that sits under an unsigned parent,
// so the forwarder answers its DS query with a bare SOA and no proof at all. The
// insecure parent has to carry the child rather than the missing proof failing
// the whole query.
func TestDNSSECValidatorInheritsInsecureStateForBareDSDenial(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	parent := newValidatorTestKey(t, "demo.")
	validator := validatorWithAnchor(t, parent, now)
	denial := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "unsigned.demo.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "z.demo.", TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	parentSOA := validatorSOA("demo.")
	parentDS := new(dns.Msg)
	parentDS.SetQuestion("unsigned.demo.", dns.TypeDS)
	parentDS.SetReply(parentDS)
	parentDS.Ns = []dns.RR{
		parentSOA, signValidatorRRSet(t, now, parent, []dns.RR{parentSOA}),
		denial, signValidatorRRSet(t, now, parent, []dns.RR{denial}),
	}

	// The upstream resolver already knows unsigned.demo. is insecure, so it
	// serves this denial without an NSEC or an RRSIG to authenticate it.
	childDS := new(dns.Msg)
	childDS.SetQuestion("api.unsigned.demo.", dns.TypeDS)
	childDS.SetReply(childDS)
	childDS.Ns = []dns.RR{validatorSOA("unsigned.demo.")}

	childSOA := new(dns.Msg)
	childSOA.SetQuestion("www.api.unsigned.demo.", dns.TypeSOA)
	childSOA.SetReply(childSOA)
	childSOA.Answer = []dns.RR{validatorSOA("api.unsigned.demo.")}

	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("demo.", dns.TypeDNSKEY):               validatorDNSKEYResponse(t, now, parent),
		validatorQueryKey("unsigned.demo.", dns.TypeDS):          parentDS,
		validatorQueryKey("api.unsigned.demo.", dns.TypeDS):      childDS,
		validatorQueryKey("www.api.unsigned.demo.", dns.TypeSOA): childSOA,
	})
	response := new(dns.Msg)
	response.SetQuestion("www.api.unsigned.demo.", dns.TypeA)
	response.SetReply(response)
	response.Answer = []dns.RR{validatorA("www.api.unsigned.demo.", "192.0.2.30")}
	state, err := validator.validate(context.Background(), response, response.Question[0], query)
	if err != nil || state != validationInsecure {
		t.Fatalf("validate() = %v, %v; want insecure", state, err)
	}
}

// TestDNSSECValidatorRejectsBareDSDenialUnderSignedParent guards the other side
// of the inheritance rule: a signed parent owes a real denial, so a stripped one
// stays bogus instead of downgrading the child to insecure.
func TestDNSSECValidatorRejectsBareDSDenialUnderSignedParent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	parent := newValidatorTestKey(t, "demo.")
	validator := validatorWithAnchor(t, parent, now)
	stripped := new(dns.Msg)
	stripped.SetQuestion("victim.demo.", dns.TypeDS)
	stripped.SetReply(stripped)
	stripped.Ns = []dns.RR{validatorSOA("demo.")}
	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("demo.", dns.TypeDNSKEY):     validatorDNSKEYResponse(t, now, parent),
		validatorQueryKey("victim.demo.", dns.TypeDS):  stripped,
		validatorQueryKey("victim.demo.", dns.TypeSOA): stripped,
	})
	if _, err := validator.zoneKeys(context.Background(), "victim.demo.", query); err == nil {
		t.Fatal("zoneKeys() accepted an unauthenticated DS denial under a signed parent")
	}
}

// TestDNSSECValidatorRejectsOutOfBailiwickInsecureSigner is the regression test
// for the signer-bailiwick bypass: an attacker attaches to a signed name an RRSIG
// whose signer points at a provably-insecure zone that does not contain the name.
// The RRSIG groups with the record by owner, so without a bailiwick check the
// validator would consult the unsigned zone's state and downgrade the forged
// record to insecure. The name is out of the signer's bailiwick, so validation
// must stay bogus rather than accept the forged answer.
func TestDNSSECValidatorRejectsOutOfBailiwickInsecureSigner(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	parent := newValidatorTestKey(t, "demo.")
	validator := validatorWithAnchor(t, parent, now)

	// unsigned.demo. is a genuinely insecure delegation, proven by an NSEC the
	// signed parent authenticates. zoneKeys("unsigned.demo.") therefore returns
	// validationInsecure, which the attacker tries to borrow for another name.
	denial := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "unsigned.demo.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "z.demo.", TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	parentSOA := validatorSOA("demo.")
	dsResponse := new(dns.Msg)
	dsResponse.SetQuestion("unsigned.demo.", dns.TypeDS)
	dsResponse.SetReply(dsResponse)
	dsResponse.Ns = []dns.RR{
		parentSOA, signValidatorRRSet(t, now, parent, []dns.RR{parentSOA}),
		denial, signValidatorRRSet(t, now, parent, []dns.RR{denial}),
	}
	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("demo.", dns.TypeDNSKEY):      validatorDNSKEYResponse(t, now, parent),
		validatorQueryKey("unsigned.demo.", dns.TypeDS): dsResponse,
	})

	// The forged answer: victim.demo. (which is NOT under unsigned.demo.) carrying
	// a bogus RRSIG whose signer is the insecure zone. The signature bytes are
	// never checked because the fix rejects the out-of-bailiwick signer first.
	forged := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "victim.demo.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeA, Algorithm: dns.ECDSAP256SHA256, Labels: 2, OrigTtl: 300,
		Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(time.Hour).Unix()),
		KeyTag: 12345, SignerName: "unsigned.demo.", Signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	response := new(dns.Msg)
	response.SetQuestion("victim.demo.", dns.TypeA)
	response.SetReply(response)
	response.Answer = []dns.RR{validatorA("victim.demo.", "192.0.2.66"), forged}

	state, err := validator.validate(context.Background(), response, response.Question[0], query)
	if state != validationBogus || err == nil {
		t.Fatalf("validate() = %v, %v; want bogus with an error", state, err)
	}
}

func TestDNSSECUnsignedZoneDiscoveryClimbsPastCNAME(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	parent := newValidatorTestKey(t, "demo.")
	validator := validatorWithAnchor(t, parent, now)
	denial := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "unsigned.demo.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "z.demo.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	parentSOA := validatorSOA("demo.")
	dsResponse := new(dns.Msg)
	dsResponse.SetQuestion("unsigned.demo.", dns.TypeDS)
	dsResponse.SetReply(dsResponse)
	dsResponse.Ns = []dns.RR{
		parentSOA, signValidatorRRSet(t, now, parent, []dns.RR{parentSOA}),
		denial, signValidatorRRSet(t, now, parent, []dns.RR{denial}),
	}
	aliasSOAResponse := new(dns.Msg)
	aliasSOAResponse.SetQuestion("alias.unsigned.demo.", dns.TypeSOA)
	aliasSOAResponse.SetReply(aliasSOAResponse)
	aliasSOAResponse.Answer = []dns.RR{&dns.CNAME{
		Hdr:    dns.RR_Header{Name: "alias.unsigned.demo.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "target.other.demo.",
	}}
	aliasSOAResponse.Ns = []dns.RR{validatorSOA("other.demo.")}
	zoneSOAResponse := new(dns.Msg)
	zoneSOAResponse.SetQuestion("unsigned.demo.", dns.TypeSOA)
	zoneSOAResponse.SetReply(zoneSOAResponse)
	zoneSOAResponse.Answer = []dns.RR{validatorSOA("unsigned.demo.")}
	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("demo.", dns.TypeDNSKEY):             validatorDNSKEYResponse(t, now, parent),
		validatorQueryKey("unsigned.demo.", dns.TypeDS):        dsResponse,
		validatorQueryKey("alias.unsigned.demo.", dns.TypeSOA): aliasSOAResponse,
		validatorQueryKey("unsigned.demo.", dns.TypeSOA):       zoneSOAResponse,
	})
	state, err := validator.unsignedNameState(context.Background(), "alias.unsigned.demo.", query, false)
	if err != nil || state != validationInsecure {
		t.Fatalf("unsignedNameState() = %v, %v; want insecure", state, err)
	}
}

// validatorDSDenial answers a DS query for name the way a signed parent does:
// its SOA and an NSEC for name listing types, both signed by the parent.
func validatorDSDenial(t *testing.T, now time.Time, parent validatorTestKey, name string, types ...uint16) *dns.Msg {
	t.Helper()
	soa := validatorSOA(parent.key.Hdr.Name)
	denial := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "zzz." + parent.key.Hdr.Name,
		TypeBitMap: append(types, dns.TypeRRSIG, dns.TypeNSEC),
	}
	response := new(dns.Msg)
	response.SetQuestion(dns.Fqdn(name), dns.TypeDS)
	response.SetReply(response)
	response.Ns = []dns.RR{
		soa, signValidatorRRSet(t, now, parent, []dns.RR{soa}),
		denial, signValidatorRRSet(t, now, parent, []dns.RR{denial}),
	}
	return response
}

// An unsigned name is proved unsigned the way BIND does it: DS at each label
// down from the trust anchor, never an SOA lookup. A label the signed parent
// proves is no delegation is passed over, and the walk ends at the first
// delegation proved to have no DS. An alias is never a zone's apex, and a DS
// query for it would follow it, so its own name is left out.
func TestDNSSECUnsignedNameWalksDownFromTheTrustAnchor(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	parent := newValidatorTestKey(t, "demo.")
	validator := validatorWithAnchor(t, parent, now)
	// No SOA and no DS for the alias or the names under the cut: asking for
	// any of them fails validation.
	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("demo.", dns.TypeDNSKEY):       validatorDNSKEYResponse(t, now, parent),
		validatorQueryKey("sub.demo.", dns.TypeDS):       validatorDSDenial(t, now, parent, "sub.demo.", dns.TypeA),
		validatorQueryKey("child.sub.demo.", dns.TypeDS): validatorDSDenial(t, now, parent, "child.sub.demo.", dns.TypeNS),
	})
	response := new(dns.Msg)
	response.SetQuestion("alias.child.sub.demo.", dns.TypeA)
	response.SetReply(response)
	response.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "alias.child.sub.demo.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "www.child.sub.demo."},
		validatorA("www.child.sub.demo.", "192.0.2.20"),
	}
	state, err := validator.validate(context.Background(), response, response.Question[0], query)
	if err != nil || state != validationInsecure {
		t.Fatalf("validate() = %v, %v; want insecure", state, err)
	}
}

// When the walk reaches the name without leaving signed zones, the name had
// to be signed, so its missing signature makes the answer bogus.
func TestDNSSECUnsignedNameInsideASignedZoneIsBogus(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	parent := newValidatorTestKey(t, "demo.")
	validator := validatorWithAnchor(t, parent, now)
	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("demo.", dns.TypeDNSKEY):     validatorDNSKEYResponse(t, now, parent),
		validatorQueryKey("sub.demo.", dns.TypeDS):     validatorDSDenial(t, now, parent, "sub.demo.", dns.TypeA),
		validatorQueryKey("www.sub.demo.", dns.TypeDS): validatorDSDenial(t, now, parent, "www.sub.demo.", dns.TypeA),
	})
	response := new(dns.Msg)
	response.SetQuestion("www.sub.demo.", dns.TypeA)
	response.SetReply(response)
	response.Answer = []dns.RR{validatorA("www.sub.demo.", "192.0.2.20")}
	state, err := validator.validate(context.Background(), response, response.Question[0], query)
	if state != validationBogus || err == nil || !strings.Contains(err.Error(), "missing RRSIG") {
		t.Fatalf("validate() = %v, %v; want bogus for a missing RRSIG", state, err)
	}
}

// A DS denial comes from the zone above the name. One signed by the zone
// itself, or by any zone not above it, is refused rather than trusted or
// followed in a loop.
func TestDNSSECRefusesDSDenialSignedFromBelow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	parent := newValidatorTestKey(t, "demo.")
	child := newValidatorTestKey(t, "unsigned.demo.")
	validator := validatorWithAnchor(t, parent, now)
	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("demo.", dns.TypeDNSKEY):          validatorDNSKEYResponse(t, now, parent),
		validatorQueryKey("unsigned.demo.", dns.TypeDS):     validatorDSDenial(t, now, child, "unsigned.demo.", dns.TypeNS),
		validatorQueryKey("unsigned.demo.", dns.TypeDNSKEY): validatorDNSKEYResponse(t, now, child),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state, err := validator.unsignedNameState(ctx, "www.unsigned.demo.", query, false)
	if state != validationBogus || err == nil || !strings.Contains(err.Error(), "not above it") {
		t.Fatalf("unsignedNameState() = %v, %v; want bogus for a denial signed from below", state, err)
	}
}

// Akamai's whoami.akamai.net answers some queries with nothing at all: no
// records and no SOA. From an unsigned zone that is a plain empty answer; from
// a signed zone, one that should have proved the denial, it is bogus.
func TestDNSSECEmptyAnswerDependsOnWhetherTheZoneIsSigned(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	parent := newValidatorTestKey(t, "demo.")
	validator := validatorWithAnchor(t, parent, now)
	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("demo.", dns.TypeDNSKEY):        validatorDNSKEYResponse(t, now, parent),
		validatorQueryKey("unsigned.demo.", dns.TypeDS):   validatorDSDenial(t, now, parent, "unsigned.demo.", dns.TypeNS),
		validatorQueryKey("signed.demo.", dns.TypeDS):     validatorDSDenial(t, now, parent, "signed.demo.", dns.TypeA),
		validatorQueryKey("www.signed.demo.", dns.TypeDS): validatorDSDenial(t, now, parent, "www.signed.demo.", dns.TypeA),
	})
	for name, want := range map[string]validationState{"whoami.unsigned.demo.": validationInsecure, "www.signed.demo.": validationBogus} {
		response := new(dns.Msg)
		response.SetQuestion(name, dns.TypeAAAA)
		response.SetReply(response)
		state, err := validator.validate(context.Background(), response, response.Question[0], query)
		if state != want || (want == validationInsecure) != (err == nil) {
			t.Errorf("validate(empty %s) = %v, %v; want %v", name, state, err, want)
		}
	}
}

func TestDNSSECResponsePresentation(t *testing.T) {
	t.Parallel()
	request := new(dns.Msg)
	request.SetQuestion("www.example.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(request)
	response.AuthenticatedData = true
	response.SetEdns0(1232, true)
	response.Answer = []dns.RR{
		validatorA("www.example.", "192.0.2.1"),
		&dns.RRSIG{Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET}},
	}
	prepareResponseForClient(response, request)
	if response.AuthenticatedData || len(response.Answer) != 1 || response.IsEdns0() != nil {
		t.Fatalf("ordinary response = %+v", response)
	}

	interested := request.Copy()
	interested.AuthenticatedData = true
	response.AuthenticatedData = true
	response.Answer = append(response.Answer, &dns.RRSIG{Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET}})
	prepareResponseForClient(response, interested)
	if !response.AuthenticatedData || len(response.Answer) != 1 {
		t.Fatalf("AD-aware response = %+v", response)
	}

	do := request.Copy()
	do.SetEdns0(1232, true)
	response.AuthenticatedData = true
	response.SetEdns0(1232, true)
	response.Answer = append(response.Answer, &dns.RRSIG{Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET}})
	prepareResponseForClient(response, do)
	if !response.AuthenticatedData || len(response.Answer) != 2 || response.IsEdns0() == nil || !response.IsEdns0().Do() {
		t.Fatalf("DO response = %+v", response)
	}
}

func TestDNSSECResponseProofFollowsCNAMEForNODATA(t *testing.T) {
	t.Parallel()
	response := new(dns.Msg)
	response.SetQuestion("alias.secure.demo.", dns.TypeAAAA)
	response.SetReply(response)
	response.Answer = []dns.RR{&dns.CNAME{
		Hdr:    dns.RR_Header{Name: "alias.secure.demo.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "target.secure.demo.",
	}}
	response.Ns = []dns.RR{&dns.NSEC{
		Hdr:        dns.RR_Header{Name: "target.secure.demo.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "z.secure.demo.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}}
	if err := validateResponseProof(response, response.Question[0]); err != nil {
		t.Fatalf("validateResponseProof() = %v", err)
	}
}

func TestDNSSECAcceptsOnlyCorrectDNAMECNAMEsAsSynthesized(t *testing.T) {
	t.Parallel()
	delegation := &dns.DNAME{
		Hdr:    dns.RR_Header{Name: "old.example.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "new.example.",
	}
	alias := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "www.old.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "www.new.example.",
	}
	if !synthesizedFromDNAME([]dns.RR{alias}, []dns.RR{delegation, alias}) {
		t.Fatal("valid DNAME synthesis was rejected")
	}
	alias.Target = "attacker.example."
	if synthesizedFromDNAME([]dns.RR{alias}, []dns.RR{delegation, alias}) {
		t.Fatal("invalid DNAME synthesis was accepted")
	}
}

func TestDNSSECVerifyWithKeysRejectsUnknownSignatureKey(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	zone := newValidatorTestKey(t, "secure.demo.")
	validator := validatorWithAnchor(t, zone, now)
	record := validatorA("www.secure.demo.", "192.0.2.10")
	signature := signValidatorRRSet(t, now, zone, []dns.RR{record})
	signature.KeyTag++
	if err := validator.verifyWithKeys([]dns.RR{record}, []*dns.RRSIG{signature}, []*dns.DNSKEY{zone.key}); err == nil {
		t.Fatal("verifyWithKeys() accepted an unknown RRSIG key tag")
	}
}

func validatorWithAnchor(t *testing.T, anchor validatorTestKey, now time.Time) *dnssecValidator {
	t.Helper()
	owner := strings.TrimSuffix(anchor.key.Hdr.Name, ".")
	if owner == "" {
		owner = "."
	}
	value := fmt.Sprintf("%s DNSKEY %d %d %d %s", owner, anchor.key.Flags, anchor.key.Protocol, anchor.key.Algorithm, anchor.key.PublicKey)
	validator, err := newDNSSECValidator([]string{value}, nil)
	if err != nil {
		t.Fatal(err)
	}
	validator.now = func() time.Time { return now }
	return validator
}

func newValidatorTestKey(t *testing.T, owner string) validatorTestKey {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256,
	}
	private, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		t.Fatalf("private key %T is not crypto.Signer", private)
	}
	return validatorTestKey{key: key, private: signer}
}

func validatorChainQueries(
	t *testing.T,
	now time.Time,
	root, testZone, secure validatorTestKey,
) map[string]*dns.Msg {
	t.Helper()
	return map[string]*dns.Msg{
		validatorQueryKey(".", dns.TypeDNSKEY):            validatorDNSKEYResponse(t, now, root),
		validatorQueryKey("demo.", dns.TypeDS):            validatorDSResponse(t, now, root, testZone),
		validatorQueryKey("demo.", dns.TypeDNSKEY):        validatorDNSKEYResponse(t, now, testZone),
		validatorQueryKey("secure.demo.", dns.TypeDS):     validatorDSResponse(t, now, testZone, secure),
		validatorQueryKey("secure.demo.", dns.TypeDNSKEY): validatorDNSKEYResponse(t, now, secure),
	}
}

func validatorDNSKEYResponse(t *testing.T, now time.Time, zone validatorTestKey) *dns.Msg {
	t.Helper()
	response := new(dns.Msg)
	response.SetQuestion(zone.key.Hdr.Name, dns.TypeDNSKEY)
	response.SetReply(response)
	response.Answer = []dns.RR{zone.key, signValidatorRRSet(t, now, zone, []dns.RR{zone.key})}
	return response
}

func validatorDSResponse(t *testing.T, now time.Time, parent, child validatorTestKey) *dns.Msg {
	t.Helper()
	record := child.key.ToDS(dns.SHA256)
	record.Hdr.Ttl = 300
	response := new(dns.Msg)
	response.SetQuestion(child.key.Hdr.Name, dns.TypeDS)
	response.SetReply(response)
	response.Answer = []dns.RR{record, signValidatorRRSet(t, now, parent, []dns.RR{record})}
	return response
}

func validatorSignedResponse(t *testing.T, now time.Time, zone validatorTestKey, owner string, recordType uint16, value string) *dns.Msg {
	t.Helper()
	response := new(dns.Msg)
	response.SetQuestion(owner, recordType)
	response.SetReply(response)
	record := validatorA(owner, value)
	response.Answer = []dns.RR{record, signValidatorRRSet(t, now, zone, []dns.RR{record})}
	return response
}

func signValidatorRRSet(t *testing.T, now time.Time, zone validatorTestKey, records []dns.RR) *dns.RRSIG {
	t.Helper()
	signature := &dns.RRSIG{
		Hdr:       dns.RR_Header{Name: records[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: records[0].Header().Ttl},
		Algorithm: zone.key.Algorithm, Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(time.Hour).Unix()),
		KeyTag: zone.key.KeyTag(), SignerName: zone.key.Hdr.Name,
	}
	if err := signature.Sign(zone.private, records); err != nil {
		t.Fatal(err)
	}
	return signature
}

func validatorA(owner, value string) *dns.A {
	record, err := dns.NewRR(fmt.Sprintf("%s 300 IN A %s", dns.Fqdn(owner), value))
	if err != nil {
		panic(err)
	}
	return record.(*dns.A)
}

func validatorSOA(owner string) *dns.SOA {
	record, err := dns.NewRR(fmt.Sprintf("%s 300 IN SOA ns1.%s hostmaster.%s 1 3600 600 1209600 300", dns.Fqdn(owner), dns.Fqdn(owner), dns.Fqdn(owner)))
	if err != nil {
		panic(err)
	}
	return record.(*dns.SOA)
}

func mapValidatorQuery(responses map[string]*dns.Msg) dnssecQuery {
	return func(_ context.Context, name string, recordType uint16) (*dns.Msg, error) {
		response := responses[validatorQueryKey(name, recordType)]
		if response == nil {
			return nil, fmt.Errorf("unexpected validation query %s %s", name, dns.TypeToString[recordType])
		}
		return response.Copy(), nil
	}
}

func validatorQueryKey(name string, recordType uint16) string {
	return normalizeFQDN(name) + "/" + fmt.Sprint(recordType)
}

// TestDNSSECValidatorZoneInsecureCoversUnsignedForwarder reproduces a private
// forwarder that answers authoritatively for a delegated name without serving
// any signatures. The validator can only call that bogus until the zone opts
// out of validation.
func TestDNSSECValidatorZoneInsecureCoversUnsignedForwarder(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	parent := newValidatorTestKey(t, "demo.")
	validator := validatorWithAnchor(t, parent, now)
	splitHorizonSOA := validatorSOA("private.demo.")
	dsResponse := new(dns.Msg)
	dsResponse.SetQuestion("private.demo.", dns.TypeDS)
	dsResponse.SetReply(dsResponse)
	dsResponse.Ns = []dns.RR{splitHorizonSOA}
	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("demo.", dns.TypeDNSKEY):     validatorDNSKEYResponse(t, now, parent),
		validatorQueryKey("private.demo.", dns.TypeDS): dsResponse,
	})
	response := new(dns.Msg)
	response.SetQuestion("host.private.demo.", dns.TypeA)
	response.SetReply(response)
	response.Answer = []dns.RR{validatorA("host.private.demo.", "10.2.0.245")}

	state, err := validator.validate(context.Background(), response, response.Question[0], query)
	if err == nil || state != validationBogus {
		t.Fatalf("validate() = %v, %v; want bogus", state, err)
	}

	validator.setZoneInsecure([]string{"private.demo"})
	state, err = validator.validate(context.Background(), response, response.Question[0], query)
	if err != nil || state != validationInsecure {
		t.Fatalf("validate() after zone opt-out = %v, %v; want insecure", state, err)
	}
}

func TestDNSSECValidatorSetZoneInsecureDropsCachedZoneState(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	validator := validatorWithAnchor(t, newValidatorTestKey(t, "demo."), now)
	validator.cacheZone("private.demo.", validatedZone{state: validationSecure, expiresAt: now.Add(time.Hour)})
	validator.setZoneInsecure([]string{"private.demo"})
	if _, found := validator.cachedZone("private.demo."); found {
		t.Fatal("cached zone state survived a validation policy change")
	}
	validator.cacheZone("private.demo.", validatedZone{state: validationInsecure, expiresAt: now.Add(time.Hour)})
	validator.setZoneInsecure([]string{"private.demo."})
	if _, found := validator.cachedZone("private.demo."); !found {
		t.Fatal("unchanged validation policy discarded cached zone state")
	}
}
