package dnsserver

import (
	"context"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestIterativeResolverMinimizesQNameAndFollowsReferrals(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	handler := NewHandler(runtime)
	var questions []string
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		question := request.Question[0]
		questions = append(questions, fmt.Sprintf("%s/%s@%s", question.Name, dns.TypeToString[question.Qtype], endpoint))
		switch {
		case endpoint == "udp://192.0.2.1:53" && question.Name == "com." && question.Qtype == dns.TypeNS:
			return referralResponse(request, "com.", "ns.com.", "192.0.2.2"), nil
		case endpoint == "udp://192.0.2.2:53" && question.Name == "example.com." && question.Qtype == dns.TypeNS:
			return referralResponse(request, "example.com.", "ns.example.com.", "192.0.2.3"), nil
		case endpoint == "udp://192.0.2.3:53" && question.Name == "www.example.com." && question.Qtype == dns.TypeA:
			response := new(dns.Msg)
			response.SetReply(request)
			response.Authoritative = true
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 44}}}
			return response, nil
		case endpoint == "udp://192.0.2.3:53" && question.Name == "mail.example.com." && question.Qtype == dns.TypeA:
			return addressResponse(request, "192.0.2.45"), nil
		default:
			return nil, fmt.Errorf("unexpected iterative query %s/%s to %s", question.Name, dns.TypeToString[question.Qtype], endpoint)
		}
	}

	request := new(dns.Msg)
	request.SetQuestion("www.example.com.", dns.TypeA)
	request.RecursionDesired = true
	response, err := handler.resolveNetwork(request, runtime, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Answer) != 1 || response.Answer[0].String() != "www.example.com.\t300\tIN\tA\t192.0.2.44" || !response.RecursionAvailable {
		t.Fatalf("iterative response = %+v", response)
	}
	want := []string{
		"com./NS@udp://192.0.2.1:53",
		"example.com./NS@udp://192.0.2.2:53",
		"www.example.com./A@udp://192.0.2.3:53",
	}
	if !slices.Equal(questions, want) {
		t.Fatalf("iterative questions = %v, want %v", questions, want)
	}
	second := new(dns.Msg)
	second.SetQuestion("mail.example.com.", dns.TypeA)
	if _, err := handler.resolveNetwork(second, runtime, nil); err != nil {
		t.Fatal(err)
	}
	if got := questions[len(questions)-1]; got != "mail.example.com./A@udp://192.0.2.3:53" || len(questions) != len(want)+1 {
		t.Fatalf("cached delegation did not bypass parent zones: %v", questions)
	}
}

func TestIterativeResolverRejectsOutOfBailiwickGlue(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	handler := NewHandler(runtime)
	usedMaliciousGlue := false
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		question := request.Question[0]
		if endpoint == "udp://203.0.113.66:53" {
			usedMaliciousGlue = true
			return nil, fmt.Errorf("poisoned glue was used")
		}
		switch {
		case endpoint == "udp://192.0.2.1:53" && question.Name == "com.":
			return referralResponse(request, "com.", "ns.com.", "192.0.2.2"), nil
		case endpoint == "udp://192.0.2.2:53" && question.Name == "example.com." && question.Qtype == dns.TypeNS:
			response := referralResponse(request, "example.com.", "ns.provider.net.", "")
			response.Extra = append(response.Extra, &dns.A{Hdr: dns.RR_Header{Name: "ns.provider.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{203, 0, 113, 66}})
			return response, nil
		case endpoint == "udp://192.0.2.1:53" && question.Name == "net.":
			return referralResponse(request, "net.", "ns.net.", "192.0.2.4"), nil
		case endpoint == "udp://192.0.2.4:53" && question.Name == "provider.net." && question.Qtype == dns.TypeNS:
			return referralResponse(request, "provider.net.", "ns.provider.net.", "192.0.2.5"), nil
		case endpoint == "udp://192.0.2.5:53" && question.Name == "ns.provider.net." && question.Qtype == dns.TypeA:
			return addressResponse(request, "192.0.2.5"), nil
		case endpoint == "udp://192.0.2.5:53" && question.Name == "ns.provider.net." && question.Qtype == dns.TypeAAAA:
			return noDataResponse(request, "provider.net."), nil
		case endpoint == "udp://192.0.2.5:53" && question.Name == "www.example.com." && question.Qtype == dns.TypeA:
			return addressResponse(request, "192.0.2.80"), nil
		default:
			return nil, fmt.Errorf("unexpected iterative query %s/%s to %s", question.Name, dns.TypeToString[question.Qtype], endpoint)
		}
	}
	request := new(dns.Msg)
	request.SetQuestion("www.example.com.", dns.TypeA)
	response, err := handler.resolveNetwork(request, runtime, nil)
	if err != nil {
		t.Fatal(err)
	}
	if usedMaliciousGlue || len(response.Answer) != 1 || response.Answer[0].String() != "www.example.com.\t300\tIN\tA\t192.0.2.80" {
		t.Fatalf("out-of-bailiwick result used_malicious=%t response=%+v", usedMaliciousGlue, response)
	}
}

func TestIterativeResolverFollowsCNAMEWithinCachedDelegation(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		question := request.Question[0]
		switch {
		case endpoint == "udp://192.0.2.1:53" && question.Name == "com.":
			return referralResponse(request, "com.", "ns.com.", "192.0.2.2"), nil
		case endpoint == "udp://192.0.2.2:53" && question.Name == "example.com." && question.Qtype == dns.TypeNS:
			return referralResponse(request, "example.com.", "ns.example.com.", "192.0.2.3"), nil
		case endpoint == "udp://192.0.2.3:53" && question.Name == "alias.example.com.":
			response := new(dns.Msg)
			response.SetReply(request)
			response.Authoritative = true
			response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "target.example.com."}}
			return response, nil
		case endpoint == "udp://192.0.2.3:53" && question.Name == "target.example.com.":
			return addressResponse(request, "192.0.2.90"), nil
		default:
			return nil, fmt.Errorf("unexpected iterative query %s/%s to %s", question.Name, dns.TypeToString[question.Qtype], endpoint)
		}
	}
	request := new(dns.Msg)
	request.SetQuestion("alias.example.com.", dns.TypeA)
	response, err := handler.resolveNetwork(request, runtime, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Answer) != 2 || response.Answer[0].Header().Rrtype != dns.TypeCNAME || response.Answer[1].Header().Rrtype != dns.TypeA {
		t.Fatalf("CNAME response = %+v", response.Answer)
	}
}

func TestRecursiveModeKeepsConditionalForwardingRoutes(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.Mode = "recursive"
	configuration.Forwarders = nil
	configuration.RootHints = []string{"192.0.2.1:53"}
	configuration.Routes = []ForwardingRoute{{Domain: "corp.example", Forwarders: []string{"192.0.2.53:53"}}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	forwarders, routed := runtime.forwardersFor("host.corp.example.")
	if !routed || !slices.Equal(forwarders, []string{"192.0.2.53:53"}) {
		t.Fatalf("conditional recursive-mode route = %v, %t", forwarders, routed)
	}
	forwarders, routed = runtime.forwardersFor("public.example.")
	if routed || len(forwarders) != 0 {
		t.Fatalf("recursive default unexpectedly forwarded: %v, %t", forwarders, routed)
	}
}

func TestIterativeResolverRetriesDroppedPacket(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	handler := NewHandler(runtime)
	rootAttempts := 0
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		question := request.Question[0]
		switch {
		case endpoint == "udp://192.0.2.1:53" && question.Name == "com." && question.Qtype == dns.TypeNS:
			rootAttempts++
			if rootAttempts == 1 {
				return nil, fmt.Errorf("simulated dropped packet")
			}
			return referralResponse(request, "com.", "ns.com.", "192.0.2.2"), nil
		case endpoint == "udp://192.0.2.2:53" && question.Name == "example.com." && question.Qtype == dns.TypeNS:
			return referralResponse(request, "example.com.", "ns.example.com.", "192.0.2.3"), nil
		case endpoint == "udp://192.0.2.3:53" && question.Name == "www.example.com." && question.Qtype == dns.TypeA:
			return addressResponse(request, "192.0.2.44"), nil
		default:
			return nil, fmt.Errorf("unexpected iterative query %s/%s to %s", question.Name, dns.TypeToString[question.Qtype], endpoint)
		}
	}

	// The root is the only configured hint, so without a retry the single dropped
	// packet fails the whole resolution.
	request := new(dns.Msg)
	request.SetQuestion("www.example.com.", dns.TypeA)
	response, err := handler.resolveNetwork(request, runtime, nil)
	if err != nil {
		t.Fatalf("resolveNetwork with one dropped packet: %v", err)
	}
	if len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "192.0.2.44" {
		t.Fatalf("answer = %+v", response.Answer)
	}
	if rootAttempts < 2 {
		t.Fatalf("root queried %d times, want a retry after the dropped packet", rootAttempts)
	}
}

func TestForwardExchangeRetriesDroppedPacket(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	handler := NewHandler(runtime)
	attempts := 0
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		attempts++
		if attempts == 1 {
			return nil, fmt.Errorf("simulated dropped packet")
		}
		return addressResponse(request, "192.0.2.50"), nil
	}

	request := new(dns.Msg)
	request.SetQuestion("example.net.", dns.TypeA)
	response, err := handler.exchangeContext(context.Background(), request, runtime, []string{"1.1.1.1:53"})
	if err != nil {
		t.Fatalf("exchangeContext with one dropped packet: %v", err)
	}
	if len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "192.0.2.50" {
		t.Fatalf("answer = %+v", response.Answer)
	}
	if attempts < 2 {
		t.Fatalf("forwarder queried %d times, want a retry after the dropped packet", attempts)
	}
}

func recursiveTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	configuration := testRuntimeConfig()
	configuration.Mode = "recursive"
	configuration.Forwarders = nil
	configuration.RootHints = []string{"192.0.2.1:53"}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func referralResponse(request *dns.Msg, zone, nameServer, address string) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = false
	response.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: nameServer}}
	if address != "" {
		response.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: nameServer, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: netIP(address)}}
	}
	return response
}

func addressResponse(request *dns.Msg, address string) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: netIP(address)}}
	return response
}

func noDataResponse(request *dns.Msg, zone string) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	response.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns." + zone, Mbox: "hostmaster." + zone, Serial: 1}}
	return response
}

func netIP(value string) []byte {
	parsed := net.ParseIP(value)
	if ipv4 := parsed.To4(); ipv4 != nil {
		return ipv4
	}
	return parsed
}

func BenchmarkIterativeResolverCachedDelegation(b *testing.B) {
	configuration := testRuntimeConfig()
	configuration.Mode = "recursive"
	configuration.Forwarders = nil
	configuration.RootHints = []string{"192.0.2.1:53"}
	runtime, err := Compile(configuration)
	if err != nil {
		b.Fatal(err)
	}
	runtime.delegations.set("example.com", []string{"192.0.2.3:53"}, 300, time.Now())
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		return addressResponse(request, "192.0.2.44"), nil
	}
	request := new(dns.Msg)
	request.SetQuestion("www.example.com.", dns.TypeA)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := handler.resolveNetwork(request, runtime, nil); err != nil {
			b.Fatal(err)
		}
	}
}
