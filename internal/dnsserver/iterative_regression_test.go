package dnsserver

import (
	"context"
	"fmt"
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
				response, err := handler.resolveNetwork(request, runtime, nil)
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
	response, state, err := handler.resolveUpstream(request, runtime, nil)
	if err != nil || state != validationSecure {
		t.Fatalf("resolution state=%v error=%v", state, err)
	}
	if len(response.Answer) == 0 {
		t.Fatal("missing answer")
	}
}
