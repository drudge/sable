package dnsserver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The denial corpus holds real signed answers whose proofs a validating
// public resolver accepted: names that don't exist, types a name lacks, and
// wildcard answers, from zones that build those proofs in different ways.
// Sable's proof checks have broken on new shapes from real zones before
// (#36, #295, #387, #391), so every shape found in the wild belongs here.
//
// The test checks the NSEC and NSEC3 proofs only. Signatures expire, and the
// other validator tests cover them with keys of their own.
//
// To add a shape, add its name to denialCorpusQueries and recapture:
//
//	SABLE_CAPTURE_DENIAL_CORPUS=1 GOEXPERIMENT=jsonv2 go test -count=1 \
//	  -run TestDNSSECDenialCorpus ./internal/dnsserver
const denialCorpusPath = "testdata/dnssec_denial_corpus.json"

type denialCorpusCase struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Shape    string `json:"shape"`
	Secure   bool   `json:"secure"`
	Server   string `json:"server"`
	Captured string `json:"captured"`
	Response string `json:"response"`
}

// denialCorpusQueries lists the lookups to capture, each with the shape it
// was picked for. Answers without a denial proof or a wildcard, and answers
// the resolver didn't validate, are left out of the corpus, except a DS
// denial for an unsigned child, which is kept as insecure. A name missing
// from an NSEC3 opt-out span, as in com, net and org, is insecure rather
// than proved missing, so those zones appear only through their DS denials.
var denialCorpusQueries = []struct {
	name   string
	qtype  uint16
	reason string
}{
	{"sable-denial-corpus.", dns.TypeA, "NSEC NXDOMAIN at the root"},
	{"sable-denial-corpus.nl.", dns.TypeA, "NSEC3 NXDOMAIN"},
	{"sable-denial-corpus.se.", dns.TypeA, "NSEC NXDOMAIN"},
	{"sable-denial-corpus.cz.", dns.TypeA, "NSEC3 NXDOMAIN"},
	{"sable-denial-corpus.dev.", dns.TypeA, "NXDOMAIN in a Google registry"},
	{"sable-denial-corpus.gov.", dns.TypeA, "NSEC3 NXDOMAIN"},
	{"sable-denial-corpus.arpa.", dns.TypeA, "NSEC NXDOMAIN"},
	{"sable-denial-corpus.isc.org.", dns.TypeA, "NXDOMAIN in a signed second-level zone"},
	{"a.b.sable-denial-corpus.isc.org.", dns.TypeA, "NXDOMAIN two labels below the closest encloser"},
	{"sable-denial-corpus.ietf.org.", dns.TypeA, "Cloudflare black lie NODATA"},
	{"sable-denial-corpus.cloudflare.com.", dns.TypeA, "Cloudflare black lie NODATA"},
	{"sable-denial-corpus.nic.cz.", dns.TypeA, "NXDOMAIN at a registry"},
	{"sable-denial-corpus.nlnetlabs.nl.", dns.TypeA, "NXDOMAIN in a signed second-level zone"},
	{"sable-denial-corpus.sidn.nl.", dns.TypeA, "NXDOMAIN in a signed second-level zone"},
	{"sable-denial-corpus.dnssec-tools.org.", dns.TypeA, "NXDOMAIN in a signed second-level zone"},
	{"sable-denial-corpus.iana.org.", dns.TypeA, "NXDOMAIN in a signed second-level zone"},
	{"sable-denial-corpus.icann.org.", dns.TypeA, "NXDOMAIN in a signed second-level zone"},
	{"sable-denial-corpus.verisign.com.", dns.TypeA, "NXDOMAIN in a signed second-level zone"},
	{"sable-denial-corpus.nasa.gov.", dns.TypeA, "NXDOMAIN in a signed second-level zone"},
	{"254.55.207.192.in-addr.arpa.", dns.TypePTR, "NSEC NXDOMAIN below an empty non-terminal (ARIN)"},
	{"32.96.210.67.in-addr.arpa.", dns.TypePTR, "NSEC NXDOMAIN below an empty non-terminal (ARIN)"},
	{"9.9.9.203.in-addr.arpa.", dns.TypePTR, "reverse NXDOMAIN (APNIC)"},
	{"1.1.1.200.in-addr.arpa.", dns.TypePTR, "reverse NXDOMAIN (LACNIC)"},
	{"207.192.in-addr.arpa.", dns.TypeA, "NODATA at an empty non-terminal"},
	{"isc.org.", dns.TypeTLSA, "NODATA at an existing name"},
	{"ietf.org.", dns.TypeHINFO, "NODATA at an existing name"},
	{"nlnetlabs.nl.", dns.TypeHINFO, "NODATA at an existing name"},
	{"com.", dns.TypeA, "NODATA at a TLD apex"},
	{"github.com.", dns.TypeDS, "insecure delegation proved by NSEC3 opt-out"},
	{"google.com.", dns.TypeDS, "insecure delegation proved by NSEC3 opt-out"},
	{"wikipedia.org.", dns.TypeDS, "insecure delegation proved by NSEC3"},
	{"big.oisd.nl.", dns.TypeA, "NSEC3 wildcard answer"},
	{"small.oisd.nl.", dns.TypeA, "NSEC3 wildcard answer"},
	{"xmpx5.mjt.lu.", dns.TypeA, "wildcard answer"},
	{"s1kyq.mjt.lu.", dns.TypeA, "wildcard answer"},
	{"www.go-vip.net.", dns.TypeHTTPS, "wildcard NODATA"},
	{"sable-denial-corpus.go-vip.net.", dns.TypeA, "wildcard answer"},
}

func TestDNSSECDenialCorpus(t *testing.T) {
	if os.Getenv("SABLE_CAPTURE_DENIAL_CORPUS") != "" {
		captureDenialCorpus(t)
	}
	data, err := os.ReadFile(denialCorpusPath)
	if err != nil {
		t.Fatal(err)
	}
	var cases []denialCorpusCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("the denial corpus is empty")
	}
	for _, corpusCase := range cases {
		t.Run(corpusCase.Name+"/"+corpusCase.Type, func(t *testing.T) {
			t.Parallel()
			checkDenialCorpusCase(t, corpusCase)
		})
	}
}

func checkDenialCorpusCase(t *testing.T, corpusCase denialCorpusCase) {
	wire, err := base64.StdEncoding.DecodeString(corpusCase.Response)
	if err != nil {
		t.Fatal(err)
	}
	response := new(dns.Msg)
	if err := response.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	question := dns.Question{Name: dns.Fqdn(corpusCase.Name), Qtype: dns.StringToType[corpusCase.Type], Qclass: dns.ClassINET}
	stripped := response.Copy()
	stripped.Ns = slices.DeleteFunc(stripped.Ns, func(record dns.RR) bool {
		rrtype := record.Header().Rrtype
		return rrtype == dns.TypeNSEC || rrtype == dns.TypeNSEC3
	})
	if !corpusCase.Secure {
		// An unsigned child: the DS denial must prove the delegation insecure.
		if !provesInsecureDelegation(response.Ns, question.Name) {
			t.Fatalf("%s: the DS denial doesn't prove an insecure delegation", corpusCase.Shape)
		}
		if provesInsecureDelegation(stripped.Ns, question.Name) {
			t.Errorf("%s: proved insecure with its denial records removed", corpusCase.Shape)
		}
		return
	}
	if err := validateResponseProof(response, question); err != nil {
		t.Fatalf("%s: %v", corpusCase.Shape, err)
	}
	if !hasDenialRecords(response.Ns) {
		return
	}
	// Without its NSEC or NSEC3 records the answer must not validate.
	if err := validateResponseProof(stripped, question); err == nil {
		t.Errorf("%s: validated with its denial records removed", corpusCase.Shape)
	}
	// A proof that a type is missing doesn't prove the name is, and the
	// reverse: flipping the response code must not validate.
	flipped := response.Copy()
	switch {
	case flipped.Rcode == dns.RcodeNameError:
		flipped.Rcode = dns.RcodeSuccess
	case flipped.Rcode == dns.RcodeSuccess && !hasPositiveAnswer(flipped.Answer, question.Name, question.Qtype):
		flipped.Rcode = dns.RcodeNameError
	default:
		return
	}
	if err := validateResponseProof(flipped, question); err == nil {
		t.Errorf("%s: validated as %s with its response code flipped", corpusCase.Shape, dns.RcodeToString[flipped.Rcode])
	}
}

func hasDenialRecords(records []dns.RR) bool {
	return slices.ContainsFunc(records, func(record dns.RR) bool {
		rrtype := record.Header().Rrtype
		return rrtype == dns.TypeNSEC || rrtype == dns.TypeNSEC3
	})
}

// captureDenialCorpus asks validating public resolvers for every query in
// denialCorpusQueries and rewrites the corpus file with the answers they
// validated.
func captureDenialCorpus(t *testing.T) {
	t.Helper()
	client := &dns.Client{Net: "tcp", Timeout: 10 * time.Second}
	captured := time.Now().UTC().Format(time.DateOnly)
	cases := make([]denialCorpusCase, 0, len(denialCorpusQueries))
	for _, query := range denialCorpusQueries {
		corpusCase, skip, err := captureDenialCorpusCase(client, query.name, query.qtype)
		if err != nil {
			t.Fatalf("capture %s %s: %v", query.name, dns.TypeToString[query.qtype], err)
		}
		if skip != "" {
			t.Logf("skip %s %s: %s", query.name, dns.TypeToString[query.qtype], skip)
			continue
		}
		corpusCase.Shape, corpusCase.Captured = query.reason, captured
		cases = append(cases, corpusCase)
	}
	data, err := json.MarshalIndent(cases, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(denialCorpusPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(denialCorpusPath, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func captureDenialCorpusCase(client *dns.Client, name string, qtype uint16) (denialCorpusCase, string, error) {
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(name), qtype)
	request.SetEdns0(4096, true)
	var errs []string
	for _, server := range []string{"1.1.1.1:53", "9.9.9.9:53", "8.8.8.8:53"} {
		response, _, err := client.Exchange(request, server)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", server, err))
			continue
		}
		// A DS denial for an unsigned child is insecure, so it carries no AD
		// flag, but its proof still has to hold.
		secure := response.AuthenticatedData
		if !secure && (qtype != dns.TypeDS || !hasDenialRecords(response.Ns)) {
			errs = append(errs, server+" did not validate the answer")
			continue
		}
		if !hasDenialRecords(response.Ns) && !hasWildcardSignature(response.Answer) {
			return denialCorpusCase{}, "the answer has no denial proof or wildcard", nil
		}
		// The resolver's own flags and EDNS options aren't part of the proof.
		response.Id, response.AuthenticatedData, response.RecursionAvailable = 0, false, false
		response.Extra = nil
		wire, err := response.Pack()
		if err != nil {
			return denialCorpusCase{}, "", err
		}
		return denialCorpusCase{
			Name:     strings.TrimSuffix(dns.Fqdn(name), "."),
			Type:     dns.TypeToString[qtype],
			Secure:   secure,
			Server:   server,
			Response: base64.StdEncoding.EncodeToString(wire),
		}, "", nil
	}
	return denialCorpusCase{}, strings.Join(errs, "; "), nil
}

func hasWildcardSignature(records []dns.RR) bool {
	return slices.ContainsFunc(records, func(record dns.RR) bool {
		signature, ok := record.(*dns.RRSIG)
		return ok && int(signature.Labels) < dns.CountLabel(signature.Hdr.Name)
	})
}
