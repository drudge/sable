package dnsserver

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dnssecClassHandler forwards to a stub upstream inside a signed demo. zone,
// with validation on and the root as trust anchor. The upstream answers
// whoami.demo. TXT unsigned in whichever class it is asked, the way
// Cloudflare answers whoami.cloudflare CH TXT, and serves the IN chain that
// proves demo. is signed.
func dnssecClassHandler(t *testing.T) *Handler {
	t.Helper()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	root := newValidatorTestKey(t, ".")
	parent := newValidatorTestKey(t, "demo.")
	child := newValidatorTestKey(t, "secure.demo.")
	chain := validatorChainQueries(t, now, root, parent, child)
	chain[validatorQueryKey("whoami.demo.", dns.TypeDS)] = validatorDSDenial(t, now, parent, "whoami.demo.", dns.TypeTXT)

	configuration := testRuntimeConfig()
	configuration.Mode = "forward"
	configuration.DNSSECValidation = true
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	runtime.dnssec = validatorWithAnchor(t, root, now)
	handler := NewHandler(runtime)
	t.Cleanup(handler.Close)
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		question := request.Question[0]
		if question.Name == "whoami.demo." && question.Qtype == dns.TypeTXT {
			response := new(dns.Msg)
			response.SetReply(request)
			response.Answer = []dns.RR{&dns.TXT{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: question.Qclass, Ttl: 0},
				Txt: []string{"192.0.2.53"},
			}}
			return response, nil
		}
		if question.Qclass != dns.ClassINET {
			return nil, fmt.Errorf("unexpected %s query %v", dns.ClassToString[question.Qclass], question)
		}
		response := chain[validatorQueryKey(question.Name, question.Qtype)]
		if response == nil {
			return nil, fmt.Errorf("unexpected query %v", question)
		}
		response = response.Copy()
		response.Id = request.Id
		return response, nil
	}
	return handler
}

func dnssecClassQuery(class uint16) *dns.Msg {
	query := new(dns.Msg)
	query.SetQuestion("whoami.demo.", dns.TypeTXT)
	query.Question[0].Qclass = class
	query.SetEdns0(1232, true)
	return query
}

// TestForwardedChaosAnswerIsNotBogus covers a CHAOS-class query forwarded
// with validation on. Trust anchors exist only for class IN, so a CH answer
// has no chain of trust to check: RFC 4035 §4.3 calls that Indeterminate, and
// the answer passes through without AD, rather than as SERVFAIL with EDE 6
// because the IN namespace above the name happens to be signed.
func TestForwardedChaosAnswerIsNotBogus(t *testing.T) {
	t.Parallel()
	for _, class := range []uint16{dns.ClassCHAOS, dns.ClassHESIOD} {
		handler := dnssecClassHandler(t)
		client := &responseCapture{}
		handler.ServeDNS(client, dnssecClassQuery(class))
		response := client.message
		if response == nil || response.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s: response = %v", dns.ClassToString[class], response)
		}
		if response.AuthenticatedData {
			t.Fatalf("%s: an answer with no trust anchor was marked authenticated", dns.ClassToString[class])
		}
		if len(response.Answer) != 1 || response.Answer[0].Header().Class != class ||
			response.Question[0].Qclass != class {
			t.Fatalf("%s: answer = %v", dns.ClassToString[class], response)
		}
		if option := response.IsEdns0(); option != nil {
			for _, extra := range option.Option {
				if _, ede := extra.(*dns.EDNS0_EDE); ede {
					t.Fatalf("%s: response carries EDE %v", dns.ClassToString[class], extra)
				}
			}
		}
	}
}

// TestForwardedUnsignedINAnswerInSignedZoneStaysBogus is the IN regression:
// the same unsigned answer in class IN, inside the signed demo. zone, is
// still bogus.
func TestForwardedUnsignedINAnswerInSignedZoneStaysBogus(t *testing.T) {
	t.Parallel()
	handler := dnssecClassHandler(t)
	client := &responseCapture{}
	handler.ServeDNS(client, dnssecClassQuery(dns.ClassINET))
	response := client.message
	if response == nil || response.Rcode != dns.RcodeServerFailure || len(response.Answer) != 0 {
		t.Fatalf("response = %v", response)
	}
	option := response.IsEdns0()
	if option == nil || len(option.Option) == 0 {
		t.Fatalf("response has no EDE: %v", response)
	}
	ede, ok := option.Option[0].(*dns.EDNS0_EDE)
	if !ok || ede.InfoCode != dns.ExtendedErrorCodeDNSBogus || !strings.Contains(ede.ExtraText, "missing RRSIG") {
		t.Fatalf("EDE = %v, want DNSSEC Bogus for the missing RRSIG", option.Option[0])
	}
}
