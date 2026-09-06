package dnsserver

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRecursiveAccessCoversTransportsAndWarmCache(t *testing.T) {
	configuration := testRuntimeConfig()
	configuration.Recursion = "" // the production default, including older configuration files
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	calls := 0
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		calls++
		response := new(dns.Msg)
		response.SetReply(request)
		answer, _ := dns.NewRR(request.Question[0].Name + " 60 IN A 192.0.2.80")
		response.Answer = []dns.RR{answer}
		return response, nil
	}
	query := new(dns.Msg)
	query.SetQuestion("private-cache.example.", dns.TypeA)
	trusted := &responseCapture{remoteIP: "192.168.1.2"}
	handler.ServeDNS(trusted, query)
	if trusted.message.Rcode != dns.RcodeSuccess || !trusted.message.RecursionAvailable || calls != 1 {
		t.Fatalf("trusted response=%v calls=%d", trusted.message, calls)
	}
	for _, protocol := range []string{"udp", "tcp", "dot", "doq", "doh"} {
		for _, name := range []string{"private-cache.example.", "fresh.example."} {
			t.Run(protocol+"/"+name, func(t *testing.T) {
				query := new(dns.Msg)
				query.SetQuestion(name, dns.TypeA)
				var response *dns.Msg
				if protocol == "doh" {
					wire, _ := query.Pack()
					request := dohPOSTRequest(wire)
					request.RemoteAddr = "192.0.2.9:53000"
					request.Header.Set("X-Forwarded-For", "127.0.0.1")
					recorder := httptest.NewRecorder()
					NewDoHHandler(handler).ServeHTTP(recorder, request)
					response = new(dns.Msg)
					if err := response.Unpack(recorder.Body.Bytes()); err != nil {
						t.Fatal(err)
					}
				} else {
					writer := &responseCapture{remoteIP: "192.0.2.9"}
					protocolHandler{handler: handler, protocol: protocol}.ServeDNS(writer, query)
					response = writer.message
				}
				if response.Rcode != dns.RcodeRefused || response.RecursionAvailable || len(response.Answer) != 0 {
					t.Fatalf("response=%v", response)
				}
			})
		}
	}
	if calls != 1 {
		t.Fatalf("unauthorized upstream calls: %d", calls)
	}
	configuration.Recursion = "deny"
	denied, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler.Activate(denied)
	handler.ServeDNS(trusted, query)
	if trusted.message.Rcode != dns.RcodeRefused || trusted.message.RecursionAvailable {
		t.Fatalf("reload leaked cached response: %v", trusted.message)
	}
}

func TestNonrecursiveQueriesDoNotStartUpstreamWork(t *testing.T) {
	configuration := testRuntimeConfig()
	configuration.Recursion = "private"
	configuration.Zones = []AuthoritativeZone{{Name: "example.test", Records: []ZoneRecord{
		{Name: "@", Type: "SOA", TTL: 300, Value: "ns.example.test. hostmaster.example.test. 1 3600 600 86400 300"},
		{Name: "@", Type: "NS", TTL: 300, Value: "ns.example.test."},
		{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.80"},
		{Name: "app", Type: "ANAME", TTL: 300, Value: "target.example.net."},
	}}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(context.Context, *dns.Msg, string, time.Duration) (*dns.Msg, error) {
		t.Error("RD=0 started upstream work")
		return nil, context.Canceled
	}
	for _, test := range []struct {
		name, client      string
		code              int
		authoritative, ra bool
	}{
		{"www.example.test.", "192.0.2.1", dns.RcodeSuccess, true, false},
		{"uncached.example.", "127.0.0.1", dns.RcodeRefused, false, true},
		{"uncached.example.", "192.0.2.1", dns.RcodeRefused, false, false},
	} {
		request := new(dns.Msg)
		request.SetQuestion(test.name, dns.TypeA)
		request.RecursionDesired = false
		writer := &responseCapture{remoteIP: test.client}
		handler.ServeDNS(writer, request)
		if writer.message.Rcode != test.code || writer.message.Authoritative != test.authoritative || writer.message.RecursionAvailable != test.ra {
			t.Fatalf("%s/%s: %v", test.name, test.client, writer.message)
		}
	}
	query := new(dns.Msg)
	query.SetQuestion("cached.example.", dns.TypeA)
	answer := new(dns.Msg)
	answer.SetReply(query)
	rr, _ := dns.NewRR("cached.example. 60 IN A 192.0.2.80")
	answer.Answer = []dns.RR{rr}
	runtime.cache.Set(query, answer, true)
	query.RecursionDesired = false
	writer := &responseCapture{remoteIP: "127.0.0.1"}
	handler.ServeDNS(writer, query)
	if len(writer.message.Answer) != 1 || writer.message.RecursionDesired {
		t.Fatalf("nonrecursive cache hit=%v", writer.message)
	}
}

func TestAuthoritativeANAMEWorksForPublicNonrecursiveClients(t *testing.T) {
	configuration := testRuntimeConfig()
	configuration.Recursion = "deny"
	configuration.Zones = []AuthoritativeZone{{Name: "example.test", Records: []ZoneRecord{
		{Name: "@", Type: "SOA", TTL: 300, Value: "ns.example.test. hostmaster.example.test. 1 3600 600 86400 300"},
		{Name: "@", Type: "NS", TTL: 300, Value: "ns.example.test."},
		{Name: "app", Type: "ANAME", TTL: 300, Value: "target.example.net."},
	}}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(_ context.Context, query *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		if query.Question[0].Name != "target.example.net." || !query.RecursionDesired {
			t.Errorf("unexpected ANAME target query: %v", query)
		}
		answer := new(dns.Msg)
		answer.SetReply(query)
		rr, _ := dns.NewRR("target.example.net. 60 IN A 192.0.2.80")
		answer.Answer = []dns.RR{rr}
		return answer, nil
	}
	query := new(dns.Msg)
	query.SetQuestion("app.example.test.", dns.TypeA)
	query.RecursionDesired = false
	writer := &responseCapture{remoteIP: "192.0.2.1"}
	handler.ServeDNS(writer, query)
	if writer.message.Rcode != dns.RcodeSuccess || !writer.message.Authoritative || writer.message.RecursionAvailable || len(writer.message.Answer) != 1 {
		t.Fatalf("public ANAME response=%v", writer.message)
	}
}
