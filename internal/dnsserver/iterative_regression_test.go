package dnsserver

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestIterativeDSUsesParentAuthority(t *testing.T) {
	t.Parallel()
	for _, cached := range []bool{false, true} {
		for _, name := range []string{"com.", "example.com."} {
			t.Run(fmt.Sprintf("%s/cached=%t", name, cached), func(t *testing.T) {
				runtime := recursiveTestRuntime(t)
				if cached {
					runtime.delegations.set("com", []string{"192.0.2.2:53"}, 300, time.Now())
					runtime.delegations.set("example.com", []string{"192.0.2.3:53"}, 300, time.Now())
				}
				handler := NewHandler(runtime)
				parent := "udp://192.0.2.1:53"
				if name == "example.com." {
					parent = "udp://192.0.2.2:53"
				}
				handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
					question := request.Question[0]
					if question.Qtype == dns.TypeNS && question.Name == "com." && endpoint == "udp://192.0.2.1:53" {
						return referralResponse(request, "com.", "a.gtld-servers.net.", "192.0.2.2"), nil
					}
					if question.Qtype != dns.TypeDS || question.Name != name || endpoint != parent {
						return nil, fmt.Errorf("unexpected %s/%s at %s; DS must use %s", question.Name, dns.TypeToString[question.Qtype], endpoint, parent)
					}
					response := new(dns.Msg)
					response.SetReply(request)
					response.Authoritative = true
					record, err := dns.NewRR(name + " 300 IN DS 12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
					if err != nil {
						t.Fatal(err)
					}
					response.Answer = []dns.RR{record}
					return response, nil
				}
				request := new(dns.Msg)
				request.SetQuestion(name, dns.TypeDS)
				response, err := handler.resolveNetworkWithinTimeout(request, runtime, nil)
				if err != nil {
					t.Fatal(err)
				}
				if len(response.Answer) != 1 || response.Answer[0].Header().Rrtype != dns.TypeDS {
					t.Fatalf("DS answer = %v", response)
				}
			})
		}
	}
}

func TestIterativeFailoverPreservesQueryBudget(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	runtime.timeout = 2 * time.Second
	runtime.retryTimeout = 1500 * time.Millisecond
	runtime.retries = 2
	handler := NewHandler(runtime)
	healthyTried := false
	handler.upstreamExchange = func(ctx context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		if endpoint == "udp://192.0.2.1:53" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		healthyTried = true
		return addressResponse(request, "192.0.2.44"), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), runtime.timeout)
	defer cancel()
	response, err := handler.exchangeIterative(ctx, iterativeQuery("www.example.com.", dns.TypeA), []string{"192.0.2.1:53", "192.0.2.2:53"}, runtime, &iterativeBudget{remaining: maximumIterativeQueries})
	if err != nil || !healthyTried {
		t.Fatalf("healthy server tried=%t; resolution error=%v", healthyTried, err)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("answer = %v", response)
	}
}

func TestIterativeDNSSECValidatesWithCachedChildDelegations(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	root := newValidatorTestKey(t, ".")
	parent := newValidatorTestKey(t, "demo.")
	child := newValidatorTestKey(t, "secure.demo.")
	runtime := recursiveTestRuntime(t)
	runtime.dnssec = validatorWithAnchor(t, root, now)
	runtime.delegations.set("demo", []string{"192.0.2.2:53"}, 300, time.Now())
	runtime.delegations.set("secure.demo", []string{"192.0.2.3:53"}, 300, time.Now())
	responses := validatorChainQueries(t, now, root, parent, child)
	responses[validatorQueryKey("www.secure.demo.", dns.TypeA)] = validatorSignedResponse(t, now, child, "www.secure.demo.", dns.TypeA, "192.0.2.44")
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		question := request.Question[0]
		authority := question.Name
		if question.Qtype == dns.TypeDS {
			authority = parentFQDN(authority)
		}
		expected := "udp://192.0.2.1:53"
		if dns.IsSubDomain("secure.demo.", authority) {
			expected = "udp://192.0.2.3:53"
		} else if dns.IsSubDomain("demo.", authority) {
			expected = "udp://192.0.2.2:53"
		}
		if endpoint != expected {
			return nil, fmt.Errorf("%s/%s sent to %s, want %s", question.Name, dns.TypeToString[question.Qtype], endpoint, expected)
		}
		response := responses[validatorQueryKey(question.Name, question.Qtype)]
		if response == nil {
			return nil, fmt.Errorf("unexpected query %v", question)
		}
		return response.Copy(), nil
	}
	request := new(dns.Msg)
	request.SetQuestion("www.secure.demo.", dns.TypeA)
	response, state, err := handler.resolveUpstreamWithinTimeout(request, runtime, nil)
	if err != nil || state != validationSecure {
		t.Fatalf("resolution state=%v error=%v", state, err)
	}
	if len(response.Answer) == 0 {
		t.Fatal("missing answer")
	}
}

// fye.com's servers answer www.fye.com with a CNAME to shops.myshopify.com
// and an A record for shops.myshopify.com that points at a parking page.
// They have no say over myshopify.com, so that A record is dropped and the
// target is asked of its own servers, as other resolvers do.
func TestIterativeResolverChasesACNAMEOutOfTheZone(t *testing.T) {
	t.Parallel()
	for _, minimize := range []bool{true, false} {
		t.Run(fmt.Sprintf("minimize=%t", minimize), func(t *testing.T) {
			runtime := recursiveTestRuntime(t)
			runtime.qnameMinimization = minimize
			handler := NewHandler(runtime)
			defer handler.Close()
			parked := func(name string) dns.RR {
				return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: netIP("203.0.113.129")}
			}
			handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
				question := request.Question[0]
				switch {
				case endpoint == "udp://192.0.2.1:53" && dns.IsSubDomain("com.", question.Name):
					return referralResponse(request, "com.", "a.gtld-servers.net.", "192.0.2.2"), nil
				case endpoint == "udp://192.0.2.2:53" && dns.IsSubDomain("fye.com.", question.Name):
					return referralResponse(request, "fye.com.", "ns25.worldnic.com.", "192.0.2.3"), nil
				case endpoint == "udp://192.0.2.2:53" && dns.IsSubDomain("myshopify.com.", question.Name):
					return referralResponse(request, "myshopify.com.", "ns1.myshopify.com.", "192.0.2.4"), nil
				case endpoint == "udp://192.0.2.3:53" && question.Name == "www.fye.com." && question.Qtype == dns.TypeA:
					response := new(dns.Msg)
					response.SetReply(request)
					response.Authoritative = true
					response.Answer = []dns.RR{
						&dns.CNAME{Hdr: dns.RR_Header{Name: "www.fye.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "shops.myshopify.com."},
						parked("shops.myshopify.com."),
					}
					response.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "myshopify.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns25.worldnic.com."}}
					response.Extra = []dns.RR{parked("ns25.worldnic.com.")}
					return response, nil
				case endpoint == "udp://192.0.2.4:53" && question.Name == "shops.myshopify.com." && question.Qtype == dns.TypeA:
					return addressResponse(request, "192.0.2.74"), nil
				default:
					return nil, fmt.Errorf("unexpected iterative query %s/%s to %s", question.Name, dns.TypeToString[question.Qtype], endpoint)
				}
			}
			request := new(dns.Msg)
			request.SetQuestion("www.fye.com.", dns.TypeA)
			response, err := handler.resolveNetworkWithinTimeout(request, runtime, nil)
			if err != nil {
				t.Fatal(err)
			}
			answer := make([]string, 0, len(response.Answer))
			for _, record := range response.Answer {
				answer = append(answer, record.String())
			}
			want := []string{
				"www.fye.com.\t300\tIN\tCNAME\tshops.myshopify.com.",
				"shops.myshopify.com.\t300\tIN\tA\t192.0.2.74",
			}
			if !slices.Equal(answer, want) {
				t.Fatalf("answer = %v, want %v", answer, want)
			}
			if len(response.Ns) != 0 || len(response.Extra) != 0 {
				t.Fatalf("authority %v, additional %v; want neither from fye.com's servers", response.Ns, response.Extra)
			}
		})
	}
}

// A zone's servers can only refer down, to zones below their own. One that
// claims to know com's name servers is wrong, and believing it would let it
// pick the servers for every name under com.
func TestIterativeResolverRefusesAReferralUpward(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	runtime.delegations.set("fye.com", []string{"192.0.2.3:53"}, 300, time.Now())
	handler := NewHandler(runtime)
	defer handler.Close()
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		question := request.Question[0]
		if endpoint == "udp://192.0.2.3:53" && question.Name == "www.fye.com." {
			return referralResponse(request, "com.", "ns.fye.com.", "192.0.2.3"), nil
		}
		return nil, fmt.Errorf("unexpected iterative query %s/%s to %s", question.Name, dns.TypeToString[question.Qtype], endpoint)
	}
	request := new(dns.Msg)
	request.SetQuestion("www.fye.com.", dns.TypeA)
	if _, err := handler.resolveNetworkWithinTimeout(request, runtime, nil); err == nil {
		t.Fatal("an upward referral was followed")
	}
	if zone, servers, found := runtime.delegations.get("www.example.com", time.Now()); found && zone == "com" {
		t.Fatalf("com delegation was taken from fye.com's servers: %v", servers)
	}
}

func TestInZone(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, zone string
		want       bool
	}{
		{"www.fye.com.", "fye.com", true},
		{"fye.com.", "fye.com.", true},
		{"WWW.FYE.COM.", "fye.com", true},
		{"shops.myshopify.com.", "fye.com", false},
		{"notfye.com.", "fye.com", false},
		{"com.", "fye.com", false},
		{`a\.fye.com.`, "fye.com", false},
		{`a\\.fye.com.`, "fye.com", true},
		{"anything.example.", "", true},
		{"anything.example.", ".", true},
	} {
		if got := inZone(test.name, test.zone); got != test.want {
			t.Errorf("inZone(%q, %q) = %t, want %t", test.name, test.zone, got, test.want)
		}
	}
}
