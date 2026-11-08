package dnsserver

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

// nameErrorResponse is an upstream NXDOMAIN carrying the upstream's own SOA.
func nameErrorResponse(request *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetRcode(request, dns.RcodeNameError)
	response.Ns = []dns.RR{&dns.SOA{
		Hdr: dns.RR_Header{Name: "upstream.invalid.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 900},
		Ns:  "ns.upstream.invalid.", Mbox: "hostmaster.upstream.invalid.", Serial: 1, Minttl: 900,
	}}
	return response
}

func askType(t *testing.T, handler *Handler, runtime *Runtime, name string, qtype uint16) resolution {
	t.Helper()
	request := new(dns.Msg)
	request.SetQuestion(name, qtype)
	result := handler.resolveForClient(request, runtime, "192.0.2.1")
	if result.response == nil {
		t.Fatalf("resolve %s %s returned no response", name, dns.TypeToString[qtype])
	}
	return result
}

// wantNoData checks an RFC 2308 NODATA answer: NOERROR, nothing in the answer
// section, and an SOA owned by soaOwner in the authority section.
func wantNoData(t *testing.T, label string, response *dns.Msg, soaOwner string) {
	t.Helper()
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 0 {
		t.Fatalf("%s = rcode %s with %d answers, want NOERROR/NODATA\n%v", label, dns.RcodeToString[response.Rcode], len(response.Answer), response)
	}
	if len(response.Ns) != 1 {
		t.Fatalf("%s authority = %v, want exactly one SOA", label, response.Ns)
	}
	soa, ok := response.Ns[0].(*dns.SOA)
	if !ok || soa.Hdr.Name != soaOwner {
		t.Fatalf("%s authority = %v, want the SOA of %s", label, response.Ns, soaOwner)
	}
}

// A Forwarder zone answers its own records and forwards every other type. When
// the name exists only locally, the upstream answers the other types with
// NXDOMAIN. Passing that on tells the client the name it just resolved does not
// exist, so an A-only override answered AAAA with NXDOMAIN.
func TestForwarderZoneOverrideAnswersOtherTypesWithNoData(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "forward.test", Type: "forwarder",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.forward.test. hostmaster.forward.test. 1 3600 600 1209600 60"},
			{Name: "@", Type: "FWD", TTL: 300, Value: "udp 0 192.0.2.53:53"},
			{Name: "kuiper", Type: "A", TTL: 300, Value: "10.0.0.5"},
			{Name: "*.apps", Type: "A", TTL: 300, Value: "10.0.0.6"},
			{Name: "branch", Type: "FWD", TTL: 300, Value: "udp 0 192.0.2.54:53"},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	var upstreamQueries atomic.Int32
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		upstreamQueries.Add(1)
		return nameErrorResponse(request), nil
	}

	address := askType(t, handler, runtime, "kuiper.forward.test.", dns.TypeA)
	if address.source != querylog.SourceAuthoritative || len(address.response.Answer) != 1 {
		t.Fatalf("A for the override = source %q %v, want the local record", address.source, address.response)
	}

	for _, qtype := range []uint16{dns.TypeAAAA, dns.TypeHTTPS, dns.TypeTXT} {
		label := "kuiper.forward.test. " + dns.TypeToString[qtype]
		wantNoData(t, label, askType(t, handler, runtime, "kuiper.forward.test.", qtype).response, "forward.test.")
	}
	before := upstreamQueries.Load()
	cached := askType(t, handler, runtime, "kuiper.forward.test.", dns.TypeAAAA)
	if cached.source != querylog.SourceCache || upstreamQueries.Load() != before {
		t.Fatalf("repeat AAAA = source %q after %d more upstream queries, want a cache hit", cached.source, upstreamQueries.Load()-before)
	}
	wantNoData(t, "cached AAAA", cached.response, "forward.test.")
	if ttl := cached.response.Ns[0].Header().Ttl; ttl == 0 || ttl > 60 {
		t.Fatalf("cached NODATA TTL = %d, want the forwarder zone's SOA minimum of 60 or less", ttl)
	}

	// A wildcard override makes every name under it exist too.
	wantNoData(t, "wildcard AAAA", askType(t, handler, runtime, "web.apps.forward.test.", dns.TypeAAAA).response, "forward.test.")

	// A name with no local records is the upstream's to answer, and so is a
	// name whose only record is the FWD that routes it.
	for _, name := range []string{"missing.forward.test.", "branch.forward.test.", "host.branch.forward.test."} {
		result := askType(t, handler, runtime, name, dns.TypeAAAA)
		if result.response.Rcode != dns.RcodeNameError || result.source != querylog.SourceUpstream {
			t.Fatalf("AAAA for %s = source %q rcode %s, want the upstream NXDOMAIN", name, result.source, dns.RcodeToString[result.response.Rcode])
		}
	}
}

// The same holds for a prefetch refresh, which writes to the cache without a
// client waiting on it.
func TestForwarderZoneOverrideNoDataSurvivesTheCacheWrite(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "forward.test", Type: "forwarder",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.forward.test. hostmaster.forward.test. 1 3600 600 1209600 60"},
			{Name: "@", Type: "FWD", TTL: 300, Value: "udp 0 192.0.2.53:53"},
			{Name: "kuiper", Type: "A", TTL: 300, Value: "10.0.0.5"},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	request := new(dns.Msg)
	request.SetQuestion("kuiper.forward.test.", dns.TypeAAAA)
	if !runtime.cacheUpstreamAnswer(request, nameErrorResponse(request), validationIndeterminate) {
		t.Fatal("cacheUpstreamAnswer() did not store the answer")
	}
	cached, found := runtime.cache.Get(request)
	if !found {
		t.Fatal("cache missing the refreshed AAAA")
	}
	wantNoData(t, "refreshed AAAA", cached, "forward.test.")
}

// A Primary zone already answers a missing type with NODATA. This pins it next
// to the forwarder cases so the two cannot drift apart.
func TestPrimaryZoneAnswersMissingTypeWithNoData(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "example.test", Type: "primary",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 1 3600 600 1209600 60"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "kuiper", Type: "A", TTL: 300, Value: "10.0.0.5"},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	wantNoData(t, "primary AAAA", askType(t, handler, runtime, "kuiper.example.test.", dns.TypeAAAA).response, "example.test.")
	if result := askType(t, handler, runtime, "missing.example.test.", dns.TypeAAAA); result.response.Rcode != dns.RcodeNameError {
		t.Fatalf("missing name = %s, want NXDOMAIN", dns.RcodeToString[result.response.Rcode])
	}
}

// A conditional forwarding route has no local records, so its upstream's
// answers pass through untouched. The cache keys by type, so a cached NXDOMAIN
// for one type is never served for another.
func TestConditionalForwarderNegativeAnswersStayPerType(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Routes = []ForwardingRoute{{Domain: "corp.test", Forwarders: []string{"192.0.2.53:53"}}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		if request.Question[0].Qtype == dns.TypeA {
			return positiveResponse(request, 60), nil
		}
		return nameErrorResponse(request), nil
	}
	if result := askType(t, handler, runtime, "host.corp.test.", dns.TypeAAAA); result.response.Rcode != dns.RcodeNameError {
		t.Fatalf("routed AAAA = %s, want the upstream's NXDOMAIN passed through", dns.RcodeToString[result.response.Rcode])
	}
	result := askType(t, handler, runtime, "host.corp.test.", dns.TypeA)
	if result.source != querylog.SourceUpstream || result.response.Rcode != dns.RcodeSuccess || len(result.response.Answer) != 1 {
		t.Fatalf("routed A after a cached AAAA NXDOMAIN = source %q %v, want a fresh upstream answer", result.source, result.response)
	}
}

// A local host override with only an IPv4 address answers AAAA with NODATA,
// and that needs an SOA so the client can cache it (RFC 2308 section 5).
func TestHostOverrideAnswersMissingFamilyWithNoData(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Hosts = []HostOverride{{Name: "kuiper.lan", Addresses: []string{"192.0.2.2"}, TTL: 60}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	wantNoData(t, "host override AAAA", askType(t, handler, runtime, "kuiper.lan.", dns.TypeAAAA).response, "kuiper.lan.")
	if result := askType(t, handler, runtime, "kuiper.lan.", dns.TypeA); len(result.response.Answer) != 1 || len(result.response.Ns) != 0 {
		t.Fatalf("host override A = %v, want one address and no authority", result.response)
	}
}
