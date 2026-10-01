package dnsserver

import (
	"context"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
	"github.com/miekg/dns"
)

func TestIsLocallyServedZone(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		want bool
	}{
		{"db._dns-sd._udp.0.215.168.192.in-addr.arpa.", true},
		{"1.0.16.172.in-addr.arpa.", true},
		{"1.0.31.172.in-addr.arpa.", true},
		{"1.0.100.100.in-addr.arpa.", true},
		{"_dns.resolver.arpa.", true},
		{"printer.home.arpa.", true},
		{"nas.local.", true},
		{"LOCALHOST.", true},
		{"host.internal", true},
		{"www.test.", true},
		// 172.15 and 172.32 fall outside 172.16.0.0/12, and 63.100 and 128.100
		// fall outside the shared address space, so all four are ordinary names.
		{"1.0.15.172.in-addr.arpa.", false},
		{"1.0.32.172.in-addr.arpa.", false},
		{"1.0.63.100.in-addr.arpa.", false},
		{"1.0.128.100.in-addr.arpa.", false},
		{"1.0.169.192.in-addr.arpa.", false},
		{"api.anthropic.com.", false},
		{"arpa.", false},
		{".", false},
	}
	for _, testCase := range cases {
		if got := isLocallyServedZone(testCase.name); got != testCase.want {
			t.Errorf("isLocallyServedZone(%q) = %v; want %v", testCase.name, got, testCase.want)
		}
	}
}

// TestDNSSECValidatorSkipsLocallyServedZones covers the two shapes a forwarder
// returns for a name with no global delegation: an NXDOMAIN carrying nothing at
// all, and one proven by an ancestor that never delegated the name. Neither can
// be authenticated, so both have to come back insecure rather than bogus. The
// empty query map fails any upstream lookup, proving the exemption short
// circuits before the validator reaches for a DS or DNSKEY record.
func TestDNSSECValidatorSkipsLocallyServedZones(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		recordType uint16
		authority  []dns.RR
	}{
		{"db._dns-sd._udp.0.215.168.192.in-addr.arpa.", dns.TypePTR, nil},
		{"_dns.resolver.arpa.", dns.TypeSVCB, []dns.RR{validatorSOA("arpa.")}},
	}
	for _, testCase := range cases {
		root := newValidatorTestKey(t, ".")
		validator := validatorWithAnchor(t, root, now)
		response := new(dns.Msg)
		response.SetQuestion(testCase.name, testCase.recordType)
		response.SetRcode(response, dns.RcodeNameError)
		response.Ns = testCase.authority
		state, err := validator.validate(context.Background(), response, response.Question[0], mapValidatorQuery(nil))
		if err != nil || state != validationInsecure {
			t.Errorf("validate(%s) = %v, %v; want insecure", testCase.name, state, err)
		}
	}
}

// Devices ask for service.arpa and the private reverse zones all the time.
// The IANA servers that hold some of them never answer, so in recursive mode
// each lookup used to wait out the whole timeout and end in SERVFAIL.
func TestRecursiveModeAnswersLocallyServedNamesItself(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.Mode = "recursive"
	configuration.Forwarders = nil
	configuration.RootHints = []string{"192.0.2.1:53"}
	configuration.Routes = []ForwardingRoute{{Domain: "10.in-addr.arpa", Forwarders: []string{"192.0.2.53:53"}}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	defer handler.Close()
	var asked []string
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		asked = append(asked, endpoint)
		return addressResponse(request, "192.0.2.44"), nil
	}

	for _, testCase := range []struct {
		name, zone string
		recordType uint16
	}{
		{"_matter._tcp.default.service.arpa.", "service.arpa.", dns.TypePTR},
		{"_dns-push-tls._tcp.service.arpa.", "service.arpa.", dns.TypeSRV},
		{"lb._dns-sd._udp.0.138.168.192.in-addr.arpa.", "168.192.in-addr.arpa.", dns.TypePTR},
		{"Printer.HOME.arpa.", "home.arpa.", dns.TypeA},
	} {
		request := new(dns.Msg)
		request.SetQuestion(testCase.name, testCase.recordType)
		result := handler.resolve(request, runtime)
		if result.response.Rcode != dns.RcodeNameError || result.decision.Resolver != querylog.ResolverLocallyServed {
			t.Fatalf("%s = %s via %q, want NXDOMAIN answered locally", testCase.name, dns.RcodeToString[result.response.Rcode], result.decision.Resolver)
		}
		if len(result.response.Ns) != 1 || result.response.Ns[0].Header().Name != testCase.zone || result.response.Ns[0].Header().Rrtype != dns.TypeSOA {
			t.Fatalf("%s authority = %v, want the SOA of %s", testCase.name, result.response.Ns, testCase.zone)
		}
	}
	if len(asked) != 0 {
		t.Fatalf("locally served names went to %v", asked)
	}

	// A route names a server that knows the zone, so it still wins.
	request := new(dns.Msg)
	request.SetQuestion("5.0.0.10.in-addr.arpa.", dns.TypePTR)
	if result := handler.resolve(request, runtime); result.decision.Resolver == querylog.ResolverLocallyServed || len(asked) == 0 {
		t.Fatalf("routed private reverse name answered %q, asked %v; want it forwarded", result.decision.Resolver, asked)
	}
}

func TestLocallyServedZoneLookupDoesNotAllocate(t *testing.T) {
	for _, name := range []string{"configuration-carry.ls.apple.com.", "_matter._tcp.default.service.arpa.", "118.84.231.192.in-addr.arpa."} {
		if allocations := testing.AllocsPerRun(100, func() { locallyServedZone(name) }); allocations != 0 {
			t.Errorf("locallyServedZone(%q) allocates %v times", name, allocations)
		}
	}
}

// BenchmarkLocallyServedZone measures the check every recursive cache miss now
// makes.
func BenchmarkLocallyServedZone(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		locallyServedZone("configuration-carry.ls.apple.com.")
	}
}
