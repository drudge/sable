package dnsserver

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestIterativeResolverMinimizesQNameAndFollowsReferrals(t *testing.T) {
	t.Parallel()
	for _, rootNameServer := range []string{"ns.com.", "a.gtld-servers.net."} {
		t.Run(rootNameServer, func(t *testing.T) {
			runtime := recursiveTestRuntime(t)
			handler := NewHandler(runtime)
			var questions []string
			handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
				question := request.Question[0]
				questions = append(questions, fmt.Sprintf("%s/%s@%s", question.Name, dns.TypeToString[question.Qtype], endpoint))
				switch {
				case endpoint == "udp://192.0.2.1:53" && question.Name == "com." && question.Qtype == dns.TypeNS:
					return referralResponse(request, "com.", rootNameServer, "192.0.2.2"), nil
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
		})
	}
}

// Route 53 answers an intermediate name under a wildcard with the wildcard's
// CNAME, even when the name only exists because a longer name below it does,
// and lists its own zone's name servers beside the answer. Minimizing past
// such a name must neither follow that CNAME nor take the name servers for a
// referral back into the same zone.
func TestIterativeResolverMinimizesPastWildcardAnswersWithTheirOwnNameServers(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	handler := NewHandler(runtime)
	var questions []string
	wildcard := func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "pvsty8.pivot.example.net."}}
		response.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "eu.example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800}, Ns: "ns.eu.example.com."}}
		return response
	}
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		question := request.Question[0]
		questions = append(questions, fmt.Sprintf("%s/%s@%s", question.Name, dns.TypeToString[question.Qtype], endpoint))
		switch {
		case endpoint == "udp://192.0.2.1:53" && question.Name == "com.":
			return referralResponse(request, "com.", "ns.com.", "192.0.2.2"), nil
		case endpoint == "udp://192.0.2.2:53" && question.Name == "example.com.":
			return referralResponse(request, "example.com.", "ns.example.com.", "192.0.2.3"), nil
		case endpoint == "udp://192.0.2.3:53" && question.Name == "eu.example.com.":
			return referralResponse(request, "eu.example.com.", "ns.eu.example.com.", "192.0.2.4"), nil
		case endpoint == "udp://192.0.2.4:53" && (question.Name == "tenants.eu.example.com." || question.Name == "edge.tenants.eu.example.com."):
			return wildcard(request), nil
		case endpoint == "udp://192.0.2.4:53" && question.Name == "tenant-cd.edge.tenants.eu.example.com." && question.Qtype == dns.TypeA:
			response := wildcard(request)
			response.Answer[0].(*dns.CNAME).Target = "tenant.eu.example.com."
			response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: "tenant.eu.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 99}})
			return response, nil
		default:
			return nil, fmt.Errorf("unexpected iterative query %s/%s to %s", question.Name, dns.TypeToString[question.Qtype], endpoint)
		}
	}
	request := new(dns.Msg)
	request.SetQuestion("tenant-cd.edge.tenants.eu.example.com.", dns.TypeA)
	response, err := handler.resolveNetwork(request, runtime, nil)
	if err != nil {
		t.Fatalf("resolve: %v (asked %v)", err, questions)
	}
	if len(response.Answer) != 2 || response.Answer[1].String() != "tenant.eu.example.com.\t60\tIN\tA\t192.0.2.99" {
		t.Fatalf("answer = %v", response.Answer)
	}
	if last := questions[len(questions)-1]; last != "tenant-cd.edge.tenants.eu.example.com./A@udp://192.0.2.4:53" {
		t.Fatalf("the full name was not asked last: %v", questions)
	}
	// Once the zone answered for tenants, it answers for the full name, so
	// the labels between are not asked one by one.
	if slices.Contains(questions, "edge.tenants.eu.example.com./NS@udp://192.0.2.4:53") {
		t.Fatalf("minimization went on past an answer: %v", questions)
	}
}

// With QNAME minimization off, every server is asked for the full name and
// referrals are followed as they come.
func TestIterativeResolverAsksTheFullNameWithMinimizationOff(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.Mode = "recursive"
	configuration.Forwarders = nil
	configuration.RootHints = []string{"192.0.2.1:53"}
	configuration.DisableQNAMEMinimization = true
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	var questions []string
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		question := request.Question[0]
		questions = append(questions, fmt.Sprintf("%s/%s@%s", question.Name, dns.TypeToString[question.Qtype], endpoint))
		switch endpoint {
		case "udp://192.0.2.1:53":
			return referralResponse(request, "com.", "ns.com.", "192.0.2.2"), nil
		case "udp://192.0.2.2:53":
			return referralResponse(request, "example.com.", "ns.example.com.", "192.0.2.3"), nil
		default:
			return addressResponse(request, "192.0.2.44"), nil
		}
	}
	request := new(dns.Msg)
	request.SetQuestion("www.example.com.", dns.TypeA)
	if _, err := handler.resolveNetwork(request, runtime, nil); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"www.example.com./A@udp://192.0.2.1:53",
		"www.example.com./A@udp://192.0.2.2:53",
		"www.example.com./A@udp://192.0.2.3:53",
	}
	if !slices.Equal(questions, want) {
		t.Fatalf("questions = %v, want %v", questions, want)
	}
}

// Names a zone's servers said hold no delegation are remembered, so the next
// lookup below them asks the zone for the full name straight away. Long alias
// chains, and DNSSEC validation walking the same names again, would otherwise
// repeat every step.
func TestIterativeResolverRemembersNamesInsideAZone(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	handler := NewHandler(runtime)
	var questions []string
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		question := request.Question[0]
		questions = append(questions, fmt.Sprintf("%s/%s", question.Name, dns.TypeToString[question.Qtype]))
		switch {
		case endpoint == "udp://192.0.2.1:53" && question.Name == "net.":
			return referralResponse(request, "net.", "ns.net.", "192.0.2.2"), nil
		case endpoint == "udp://192.0.2.2:53" && question.Name == "cloudflare.net.":
			return referralResponse(request, "cloudflare.net.", "ns.cloudflare.net.", "192.0.2.3"), nil
		case endpoint == "udp://192.0.2.3:53" && question.Qtype == dns.TypeNS:
			return noDataResponse(request, "cloudflare.net."), nil
		case endpoint == "udp://192.0.2.3:53" && question.Qtype == dns.TypeA:
			return addressResponse(request, "192.0.2.77"), nil
		default:
			return nil, fmt.Errorf("unexpected iterative query %s/%s to %s", question.Name, dns.TypeToString[question.Qtype], endpoint)
		}
	}
	for _, name := range []string{"ingress.eu.example.com.cdn.cloudflare.net.", "other.eu.example.com.cdn.cloudflare.net."} {
		questions = nil
		request := new(dns.Msg)
		request.SetQuestion(name, dns.TypeA)
		if _, err := handler.resolveNetwork(request, runtime, nil); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(questions, []string{"other.eu.example.com.cdn.cloudflare.net./A"}) {
		t.Fatalf("the second lookup asked %v, want only the full name", questions)
	}
}

// A server that timed out when it had time to answer is asked last for a
// while; one squeezed by the lookup's own deadline is not held against.
func TestIterativeResolverAsksServersThatJustFailedLast(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	handler := NewHandler(runtime)
	var asked []string
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		asked = append(asked, endpoint)
		if endpoint == "udp://192.0.2.10:53" {
			return nil, context.DeadlineExceeded
		}
		return addressResponse(request, "192.0.2.80"), nil
	}
	servers := []string{"192.0.2.10:53", "192.0.2.11:53"}
	firsts := make([]string, 0, 5)
	for range 5 {
		asked = nil
		budget := &iterativeBudget{remaining: maximumIterativeQueries}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if _, err := handler.exchangeIterative(ctx, iterativeQuery("www.example.com.", dns.TypeA), servers, runtime, budget); err != nil {
			t.Fatal(err)
		}
		cancel()
		firsts = append(firsts, asked[0])
	}
	// Rotation leads with each server in turn, so the failing one leads one of
	// the first two lookups; after it fails, the other leads every lookup until
	// its cooldown ends.
	failedAt := slices.Index(firsts, "udp://192.0.2.10:53")
	if failedAt < 0 || failedAt > 1 || slices.Contains(firsts[failedAt+1:], "udp://192.0.2.10:53") {
		t.Fatalf("lookups led with %v, want the failed server last once it failed", firsts)
	}
}

// Route 53 answers an alias with the next link of the chain too when both
// are in its zone. The target is looked up next and brings that link itself,
// so each alias appears in the answer once, still with its signature.
func TestIterativeResolverListsEachAliasOnce(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	handler := NewHandler(runtime)
	cname := func(owner, target string) dns.RR {
		return &dns.CNAME{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: target}
	}
	signature := func(owner string) dns.RR {
		return &dns.RRSIG{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60}, TypeCovered: dns.TypeCNAME, SignerName: "example.com."}
	}
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		question := request.Question[0]
		switch {
		case endpoint == "udp://192.0.2.1:53" && question.Name == "com.":
			return referralResponse(request, "com.", "ns.com.", "192.0.2.2"), nil
		case endpoint == "udp://192.0.2.2:53" && question.Name == "example.com.":
			return referralResponse(request, "example.com.", "ns.example.com.", "192.0.2.3"), nil
		case endpoint == "udp://192.0.2.3:53" && question.Name == "tenant-cd.example.com." && question.Qtype == dns.TypeA:
			response := new(dns.Msg)
			response.SetReply(request)
			response.Authoritative = true
			response.Answer = []dns.RR{
				cname("tenant-cd.example.com.", "tenant.example.com."), signature("tenant-cd.example.com."),
				cname("tenant.example.com.", "edge.example.net."), signature("tenant.example.com."),
			}
			return response, nil
		case endpoint == "udp://192.0.2.3:53" && question.Name == "tenant.example.com." && question.Qtype == dns.TypeA:
			response := new(dns.Msg)
			response.SetReply(request)
			response.Authoritative = true
			response.Answer = []dns.RR{cname("tenant.example.com.", "edge.example.net."), signature("tenant.example.com.")}
			return response, nil
		case endpoint == "udp://192.0.2.1:53" && question.Name == "net.":
			return referralResponse(request, "net.", "ns.net.", "192.0.2.4"), nil
		case endpoint == "udp://192.0.2.4:53" && question.Name == "example.net.":
			return referralResponse(request, "example.net.", "ns.example.net.", "192.0.2.5"), nil
		case endpoint == "udp://192.0.2.5:53" && question.Name == "edge.example.net." && question.Qtype == dns.TypeA:
			return addressResponse(request, "192.0.2.88"), nil
		default:
			return nil, fmt.Errorf("unexpected iterative query %s/%s to %s", question.Name, dns.TypeToString[question.Qtype], endpoint)
		}
	}
	request := new(dns.Msg)
	request.SetQuestion("tenant-cd.example.com.", dns.TypeA)
	response, err := handler.resolveNetwork(request, runtime, nil)
	if err != nil {
		t.Fatal(err)
	}
	owners := make([]string, 0, len(response.Answer))
	for _, record := range response.Answer {
		owners = append(owners, record.Header().Name+"/"+dns.TypeToString[record.Header().Rrtype])
	}
	want := []string{
		"tenant-cd.example.com./CNAME", "tenant-cd.example.com./RRSIG",
		"tenant.example.com./CNAME", "tenant.example.com./RRSIG",
		"edge.example.net./A",
	}
	if !slices.Equal(owners, want) {
		t.Fatalf("answer = %v, want %v", owners, want)
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

func TestForwardExchangeHonorsConfiguredRetries(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.Retries = 3
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	attempts := 0
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		attempts++
		if attempts < 3 {
			return nil, fmt.Errorf("simulated dropped packet %d", attempts)
		}
		return addressResponse(request, "192.0.2.51"), nil
	}

	request := new(dns.Msg)
	request.SetQuestion("example.net.", dns.TypeA)
	if _, err := handler.exchangeContext(context.Background(), request, runtime, []string{"1.1.1.1:53"}); err != nil {
		t.Fatalf("exchangeContext with retries=3: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("forwarder queried %d times, want 3 (two drops then success) from configured retries", attempts)
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

func TestDelegationCacheEvictsLeastRecentlyUsed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	cache := newDelegationCache(2)
	cache.set("first.example.", []string{"192.0.2.1:53"}, 3600, now)
	cache.set("second.example.", []string{"192.0.2.2:53"}, 3600, now)

	// Touching the first entry must make the second the eviction candidate.
	if _, _, found := cache.get("first.example.", now); !found {
		t.Fatal("get(first) found = false")
	}
	cache.set("third.example.", []string{"192.0.2.3:53"}, 3600, now)

	if _, _, found := cache.get("first.example.", now); !found {
		t.Error("get(first) found = false, want the recently used entry retained")
	}
	if _, _, found := cache.get("second.example.", now); found {
		t.Error("get(second) found = true, want the least recently used entry evicted")
	}
	if _, _, found := cache.get("third.example.", now); !found {
		t.Error("get(third) found = false, want the newest entry retained")
	}
}

func TestDelegationCacheExpiresOnTTL(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	cache := newDelegationCache(8)
	cache.set("example.", []string{"192.0.2.1:53"}, 30, now)

	if zone, servers, found := cache.get("www.example.", now.Add(29*time.Second)); !found || zone != "example" || len(servers) != 1 {
		t.Fatalf("get() = %q, %v, %v; want the enclosing delegation", zone, servers, found)
	}
	if _, _, found := cache.get("www.example.", now.Add(30*time.Second)); found {
		t.Error("get() found = true after the delegation TTL elapsed")
	}
}

func TestAddressCacheReusesResolvedNameServer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	cache := newAddressCache(8)
	cache.set("ns1.shared.example.", []string{"192.0.2.1:53"}, 600, now)

	// The same host serves many delegations, so a second zone pointing at it
	// must not have to resolve it again.
	addresses, found := cache.get("NS1.Shared.Example.", now.Add(time.Minute))
	if !found || len(addresses) != 1 || addresses[0] != "192.0.2.1:53" {
		t.Fatalf("get() = %v, %v; want the cached address regardless of case", addresses, found)
	}
	addresses[0] = "mutated"
	if again, _ := cache.get("ns1.shared.example.", now.Add(time.Minute)); again[0] != "192.0.2.1:53" {
		t.Fatal("caller mutated the cached slice")
	}
}

// A cold recursive lookup can outlast what a client waits. It keeps running
// after the client gives up, and a retry meanwhile waits on the same lookup
// rather than starting over, so the retry gets the answer.
func TestRecursiveLookupFinishesForARetry(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.Mode = "recursive"
	configuration.Forwarders = nil
	configuration.RootHints = []string{"192.0.2.1:53"}
	configuration.Timeout = 50 * time.Millisecond
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	defer handler.Close()
	release := make(chan struct{})
	var mu sync.Mutex
	asked, cancelledWhileAnswering := 0, false
	handler.upstreamExchange = func(ctx context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		mu.Lock()
		asked++
		mu.Unlock()
		// The authority is slow: it answers only once released.
		<-release
		mu.Lock()
		cancelledWhileAnswering = cancelledWhileAnswering || ctx.Err() != nil
		mu.Unlock()
		return addressResponse(request, "192.0.2.44"), nil
	}
	request := new(dns.Msg)
	request.SetQuestion("com.", dns.TypeA)

	if _, _, err := handler.resolveUpstream(request, runtime, nil); err == nil {
		t.Fatal("the first client got an answer before the authority gave one")
	}
	retry := make(chan *dns.Msg, 1)
	go func() {
		response, _, err := handler.resolveRecursiveWaiting(context.Background(), request, runtime, 5*time.Second)
		if err != nil {
			t.Error(err)
		}
		retry <- response
	}()
	time.Sleep(20 * time.Millisecond)
	close(release)
	response := <-retry
	if response == nil || len(response.Answer) != 1 {
		t.Fatalf("retry got %v", response)
	}
	mu.Lock()
	defer mu.Unlock()
	if asked != 1 || cancelledWhileAnswering {
		t.Fatalf("the authority was asked %d times, cancelled while answering %t; want one lookup that ran to the end", asked, cancelledWhileAnswering)
	}
}

// A referral whose name servers live in other zones, as Route 53 and Akamai
// delegate, gives no glue. Their A and AAAA records, for more than one name,
// are looked up at once rather than one after another.
func TestIterativeResolverLooksUpNameServerAddressesInParallel(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	runtime.timeout = 10 * time.Second
	handler := NewHandler(runtime)
	defer handler.Close()
	nameServers := []string{"ns1.dns-host.net.", "ns2.dns-host.org."}
	var mu sync.Mutex
	inFlight, mostAtOnce := 0, 0
	allStarted := make(chan struct{})
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		question := request.Question[0]
		switch {
		case question.Name == "com." && question.Qtype == dns.TypeNS:
			response := new(dns.Msg)
			response.SetReply(request)
			for _, nameServer := range nameServers {
				response.Ns = append(response.Ns, &dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: nameServer})
			}
			return response, nil
		case slices.Contains(nameServers, question.Name):
			// Each address lookup waits until all four are under way.
			mu.Lock()
			inFlight++
			mostAtOnce = max(mostAtOnce, inFlight)
			if inFlight == 2*len(nameServers) {
				close(allStarted)
			}
			mu.Unlock()
			select {
			case <-allStarted:
			case <-time.After(2 * time.Second):
			}
			mu.Lock()
			inFlight--
			mu.Unlock()
			if question.Qtype == dns.TypeA {
				if question.Name == nameServers[0] {
					return addressResponse(request, "192.0.2.10"), nil
				}
				return addressResponse(request, "192.0.2.11"), nil
			}
			return noDataResponse(request, "."), nil
		case question.Name == "www.example.com." && (endpoint == "udp://192.0.2.10:53" || endpoint == "udp://192.0.2.11:53"):
			return addressResponse(request, "192.0.2.44"), nil
		default:
			// Every other step of the walk finds no delegation.
			return noDataResponse(request, "."), nil
		}
	}
	request := new(dns.Msg)
	request.SetQuestion("www.example.com.", dns.TypeA)
	response, err := handler.resolveNetwork(request, runtime, nil)
	if err != nil || len(response.Answer) != 1 {
		t.Fatalf("resolveNetwork = %v, %v", response, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if mostAtOnce != 2*len(nameServers) {
		t.Fatalf("at most %d name-server address lookups ran at once, want all %d", mostAtOnce, 2*len(nameServers))
	}
	for index, name := range nameServers {
		if cached, found := runtime.nameServers.get(name, time.Now()); !found || len(cached) != 1 || cached[0] != fmt.Sprintf("192.0.2.%d:53", 10+index) {
			t.Fatalf("remembered %s at %v, want its own address", name, cached)
		}
	}
}

// When the A and AAAA lookups of one name server walk the same zones at once,
// each question goes out once and both get the answer.
func TestParallelLookupAsksASharedQuestionOnce(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	handler := NewHandler(runtime)
	defer handler.Close()
	asked := make(chan struct{}, 4)
	release := make(chan struct{})
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		asked <- struct{}{}
		<-release
		return noDataResponse(request, "net."), nil
	}
	budget := &iterativeBudget{remaining: maximumIterativeQueries}
	budget.goParallel()
	servers := []string{"192.0.2.1:53"}
	responses := make(chan *dns.Msg, 2)
	exchange := func() {
		response, err := handler.exchangeIterative(context.Background(), iterativeQuery("dns-host.net.", dns.TypeNS), servers, runtime, budget)
		if err != nil {
			t.Error(err)
		}
		responses <- response
	}
	go exchange()
	<-asked
	go exchange()
	// Wait until the second lookup is waiting on the first one's question.
	for {
		budget.mu.Lock()
		joined := len(budget.shared) == 1 && budget.shared[sharedExchangeKey{name: "dns-host.net", recordType: dns.TypeNS, server: servers[0]}].waiters == 1
		budget.mu.Unlock()
		if joined {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	first, second := <-responses, <-responses
	if first == nil || second == nil || first == second {
		t.Fatalf("responses = %p and %p, want each lookup its own copy", first, second)
	}
	if len(asked) != 0 || budget.remaining != maximumIterativeQueries-1 {
		t.Fatalf("%d more questions went out and %d were spent, want the one", len(asked), maximumIterativeQueries-budget.remaining)
	}
}

// The uk servers answer for co.uk themselves rather than delegating it.
// Remembering that saves asking them about co.uk again for every name under
// it, which a Route 53 chain does many times over.
func TestIterativeResolverRemembersAZoneItsParentServes(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	handler := NewHandler(runtime)
	defer handler.Close()
	var mu sync.Mutex
	apexAsked := 0
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		question := request.Question[0]
		switch {
		case endpoint == "udp://192.0.2.1:53" && question.Name == "uk." && question.Qtype == dns.TypeNS:
			return referralResponse(request, "uk.", "nsa.nic.uk.", "192.0.2.2"), nil
		case endpoint == "udp://192.0.2.2:53" && question.Name == "co.uk." && question.Qtype == dns.TypeNS:
			mu.Lock()
			apexAsked++
			mu.Unlock()
			response := new(dns.Msg)
			response.SetReply(request)
			response.Authoritative = true
			response.Answer = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "co.uk.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800}, Ns: "nsa.nic.uk."}}
			return response, nil
		case endpoint == "udp://192.0.2.2:53" && question.Qtype == dns.TypeNS:
			zone := question.Name
			return referralResponse(request, zone, "ns."+zone, "192.0.2.3"), nil
		case endpoint == "udp://192.0.2.3:53":
			return addressResponse(request, "192.0.2.44"), nil
		default:
			return nil, fmt.Errorf("unexpected iterative query %s/%s to %s", question.Name, dns.TypeToString[question.Qtype], endpoint)
		}
	}
	for _, name := range []string{"www.example.co.uk.", "www.other.co.uk."} {
		request := new(dns.Msg)
		request.SetQuestion(name, dns.TypeA)
		if response, err := handler.resolveNetwork(request, runtime, nil); err != nil || len(response.Answer) != 1 {
			t.Fatalf("resolveNetwork(%s) = %v, %v", name, response, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if apexAsked != 1 {
		t.Fatalf("co.uk's own NS records were asked for %d times, want once", apexAsked)
	}
	if zone, servers, found := runtime.delegations.get("www.third.co.uk.", time.Now()); !found || zone != "co.uk" || !slices.Equal(servers, []string{"192.0.2.2:53"}) {
		t.Fatalf("closest known zone for a third name = %q at %v, want co.uk at the uk servers", zone, servers)
	}
}
