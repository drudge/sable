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
	testZone := newValidatorTestKey(t, "test.")
	secure := newValidatorTestKey(t, "secure.test.")
	validator := validatorWithAnchor(t, root, now)

	queries := validatorChainQueries(t, now, root, testZone, secure)
	query := mapValidatorQuery(queries)
	answer := validatorSignedResponse(t, now, secure, "www.secure.test.", dns.TypeA, "192.0.2.10")
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
	secure := newValidatorTestKey(t, "secure.test.")
	validator := validatorWithAnchor(t, secure, now)
	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("secure.test.", dns.TypeDNSKEY): validatorDNSKEYResponse(t, now, secure),
	})
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "secure.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "www.secure.test.", TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY},
	}
	soa := validatorSOA("secure.test.")

	missing := new(dns.Msg)
	missing.SetQuestion("missing.secure.test.", dns.TypeA)
	missing.SetRcode(missing, dns.RcodeNameError)
	missing.Authoritative = true
	missing.Ns = append(missing.Ns, soa, signValidatorRRSet(t, now, secure, []dns.RR{soa}))
	missing.Ns = append(missing.Ns, nsec, signValidatorRRSet(t, now, secure, []dns.RR{nsec}))
	state, err := validator.validate(context.Background(), missing, missing.Question[0], query)
	if err != nil || state != validationSecure {
		t.Fatalf("NXDOMAIN validate() = %v, %v; want secure", state, err)
	}

	wildcardRR := validatorA("*.secure.test.", "192.0.2.44")
	wildcardSignature := signValidatorRRSet(t, now, secure, []dns.RR{wildcardRR})
	wildcardRR.Hdr.Name = "host.secure.test."
	wildcardSignature.Hdr.Name = "host.secure.test."
	wildcard := new(dns.Msg)
	wildcard.SetQuestion("host.secure.test.", dns.TypeA)
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
	parent := newValidatorTestKey(t, "test.")
	validator := validatorWithAnchor(t, parent, now)
	denial := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "unsigned.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "z.test.", TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	soa := validatorSOA("test.")
	dsResponse := new(dns.Msg)
	dsResponse.SetQuestion("unsigned.test.", dns.TypeDS)
	dsResponse.SetReply(dsResponse)
	dsResponse.Ns = []dns.RR{
		soa, signValidatorRRSet(t, now, parent, []dns.RR{soa}),
		denial, signValidatorRRSet(t, now, parent, []dns.RR{denial}),
	}
	soaResponse := new(dns.Msg)
	soaResponse.SetQuestion("www.unsigned.test.", dns.TypeSOA)
	soaResponse.SetReply(soaResponse)
	unsignedSOA := validatorSOA("unsigned.test.")
	soaResponse.Answer = []dns.RR{unsignedSOA}
	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("test.", dns.TypeDNSKEY):           validatorDNSKEYResponse(t, now, parent),
		validatorQueryKey("unsigned.test.", dns.TypeDS):      dsResponse,
		validatorQueryKey("www.unsigned.test.", dns.TypeSOA): soaResponse,
	})
	response := new(dns.Msg)
	response.SetQuestion("www.unsigned.test.", dns.TypeA)
	response.SetReply(response)
	response.Answer = []dns.RR{validatorA("www.unsigned.test.", "192.0.2.20")}
	state, err := validator.validate(context.Background(), response, response.Question[0], query)
	if err != nil || state != validationInsecure {
		t.Fatalf("validate() = %v, %v; want insecure", state, err)
	}
}

func TestDNSSECUnsignedZoneDiscoveryClimbsPastCNAME(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	parent := newValidatorTestKey(t, "test.")
	validator := validatorWithAnchor(t, parent, now)
	denial := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "unsigned.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "z.test.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	parentSOA := validatorSOA("test.")
	dsResponse := new(dns.Msg)
	dsResponse.SetQuestion("unsigned.test.", dns.TypeDS)
	dsResponse.SetReply(dsResponse)
	dsResponse.Ns = []dns.RR{
		parentSOA, signValidatorRRSet(t, now, parent, []dns.RR{parentSOA}),
		denial, signValidatorRRSet(t, now, parent, []dns.RR{denial}),
	}
	aliasSOAResponse := new(dns.Msg)
	aliasSOAResponse.SetQuestion("alias.unsigned.test.", dns.TypeSOA)
	aliasSOAResponse.SetReply(aliasSOAResponse)
	aliasSOAResponse.Answer = []dns.RR{&dns.CNAME{
		Hdr:    dns.RR_Header{Name: "alias.unsigned.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "target.other.test.",
	}}
	aliasSOAResponse.Ns = []dns.RR{validatorSOA("other.test.")}
	zoneSOAResponse := new(dns.Msg)
	zoneSOAResponse.SetQuestion("unsigned.test.", dns.TypeSOA)
	zoneSOAResponse.SetReply(zoneSOAResponse)
	zoneSOAResponse.Answer = []dns.RR{validatorSOA("unsigned.test.")}
	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("test.", dns.TypeDNSKEY):             validatorDNSKEYResponse(t, now, parent),
		validatorQueryKey("unsigned.test.", dns.TypeDS):        dsResponse,
		validatorQueryKey("alias.unsigned.test.", dns.TypeSOA): aliasSOAResponse,
		validatorQueryKey("unsigned.test.", dns.TypeSOA):       zoneSOAResponse,
	})
	state, err := validator.unsignedNameState(context.Background(), "alias.unsigned.test.", query)
	if err != nil || state != validationInsecure {
		t.Fatalf("unsignedNameState() = %v, %v; want insecure", state, err)
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
	response.SetQuestion("alias.secure.test.", dns.TypeAAAA)
	response.SetReply(response)
	response.Answer = []dns.RR{&dns.CNAME{
		Hdr:    dns.RR_Header{Name: "alias.secure.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "target.secure.test.",
	}}
	response.Ns = []dns.RR{&dns.NSEC{
		Hdr:        dns.RR_Header{Name: "target.secure.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "z.secure.test.",
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
	zone := newValidatorTestKey(t, "secure.test.")
	validator := validatorWithAnchor(t, zone, now)
	record := validatorA("www.secure.test.", "192.0.2.10")
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
		validatorQueryKey("test.", dns.TypeDS):            validatorDSResponse(t, now, root, testZone),
		validatorQueryKey("test.", dns.TypeDNSKEY):        validatorDNSKEYResponse(t, now, testZone),
		validatorQueryKey("secure.test.", dns.TypeDS):     validatorDSResponse(t, now, testZone, secure),
		validatorQueryKey("secure.test.", dns.TypeDNSKEY): validatorDNSKEYResponse(t, now, secure),
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
	parent := newValidatorTestKey(t, "test.")
	validator := validatorWithAnchor(t, parent, now)
	splitHorizonSOA := validatorSOA("private.test.")
	dsResponse := new(dns.Msg)
	dsResponse.SetQuestion("private.test.", dns.TypeDS)
	dsResponse.SetReply(dsResponse)
	dsResponse.Ns = []dns.RR{splitHorizonSOA}
	query := mapValidatorQuery(map[string]*dns.Msg{
		validatorQueryKey("test.", dns.TypeDNSKEY):     validatorDNSKEYResponse(t, now, parent),
		validatorQueryKey("private.test.", dns.TypeDS): dsResponse,
	})
	response := new(dns.Msg)
	response.SetQuestion("host.private.test.", dns.TypeA)
	response.SetReply(response)
	response.Answer = []dns.RR{validatorA("host.private.test.", "10.2.0.245")}

	state, err := validator.validate(context.Background(), response, response.Question[0], query)
	if err == nil || state != validationBogus {
		t.Fatalf("validate() = %v, %v; want bogus", state, err)
	}

	validator.setZoneInsecure([]string{"private.test"})
	state, err = validator.validate(context.Background(), response, response.Question[0], query)
	if err != nil || state != validationInsecure {
		t.Fatalf("validate() after zone opt-out = %v, %v; want insecure", state, err)
	}
}

func TestDNSSECValidatorSetZoneInsecureDropsCachedZoneState(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	validator := validatorWithAnchor(t, newValidatorTestKey(t, "test."), now)
	validator.cacheZone("private.test.", validatedZone{state: validationSecure, expiresAt: now.Add(time.Hour)})
	validator.setZoneInsecure([]string{"private.test"})
	if _, found := validator.cachedZone("private.test."); found {
		t.Fatal("cached zone state survived a validation policy change")
	}
	validator.cacheZone("private.test.", validatedZone{state: validationInsecure, expiresAt: now.Add(time.Hour)})
	validator.setZoneInsecure([]string{"private.test."})
	if _, found := validator.cachedZone("private.test."); !found {
		t.Fatal("unchanged validation policy discarded cached zone state")
	}
}
