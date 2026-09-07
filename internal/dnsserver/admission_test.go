package dnsserver

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func admissionQuery(name string) *dns.Msg {
	query := new(dns.Msg)
	query.SetQuestion(name, dns.TypeA)
	return query
}
func admissionAnswer(query *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(query)
	answer, _ := dns.NewRR(query.Question[0].Name + " 60 IN A 192.0.2.80")
	response.Answer = []dns.RR{answer}
	return response
}
func waitForAdmission(t *testing.T, handler *Handler, count int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if handler.Stats().ResolutionInflight == count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("admitted=%d want %d", handler.Stats().ResolutionInflight, count)
}

func TestResolutionAdmissionBoundsMissesWaitersAndClients(t *testing.T) {
	configuration := testRuntimeConfig()
	configuration.MaxConcurrent = 3
	configuration.MaxConcurrentPerClient = 2
	configuration.Zones = []AuthoritativeZone{{Name: "example.test", Records: []ZoneRecord{
		{Name: "@", Type: "SOA", TTL: 300, Value: "ns.example.test. hostmaster.example.test. 1 3600 600 86400 300"},
		{Name: "@", Type: "NS", TTL: 300, Value: "ns.example.test."},
		{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.80"},
		{Name: "app", Type: "ANAME", TTL: 300, Value: "origin.example.net."},
	}}}
	configuration.Hosts = []HostOverride{{Name: "local.example", Addresses: []string{"192.0.2.2"}, TTL: 60}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var calls atomic.Int32
	handler.upstreamExchange = func(_ context.Context, query *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		calls.Add(1)
		<-release
		return admissionAnswer(query), nil
	}
	done := make(chan resolution, 3)
	go func() { done <- handler.resolveForClient(admissionQuery("shared.example."), runtime, "192.0.2.1") }()
	waitForAdmission(t, handler, 1)
	go func() {
		done <- handler.resolveForClient(admissionQuery("shared.example."), runtime, "::ffff:192.0.2.1")
	}()
	waitForAdmission(t, handler, 2)
	// A duplicate waiter consumes client capacity just like a unique miss.
	if got := handler.resolveForClient(admissionQuery("other.example."), runtime, "192.0.2.1"); got.response.Rcode != dns.RcodeRefused {
		t.Fatalf("per-client overload=%v", got.response)
	}
	go func() { done <- handler.resolveForClient(admissionQuery("second.example."), runtime, "192.0.2.2") }()
	waitForAdmission(t, handler, 3)
	for i := 0; i < 100; i++ {
		got := handler.resolveForClient(admissionQuery(fmt.Sprintf("random-%d.example.", i)), runtime, fmt.Sprintf("198.51.100.%d", i+1))
		if got.response.Rcode != dns.RcodeRefused {
			t.Fatalf("global overload=%v", got.response)
		}
	}
	// Cache and local paths bypass admission even for the exhausted client.
	cached := admissionQuery("cached.example.")
	runtime.cache.Set(cached, admissionAnswer(cached), true)
	for _, name := range []string{"cached.example.", "local.example.", "www.example.test."} {
		got := handler.resolveForClient(admissionQuery(name), runtime, "192.0.2.1")
		if got.response.Rcode != dns.RcodeSuccess || len(got.response.Answer) != 1 {
			t.Fatalf("fast path under load=%v", got.response)
		}
	}
	stats := handler.Stats()
	if stats.ResolutionClients != 2 || stats.ResolutionRejectedGlobal != 100 || stats.ResolutionRejectedClient != 1 {
		t.Fatalf("admission stats=%+v", stats)
	}
	if got := handler.resolveForClient(admissionQuery("app.example.test."), runtime, "192.0.2.3"); got.response.Rcode != dns.RcodeRefused {
		t.Fatalf("ANAME bypassed capacity: %v", got.response)
	}
	// A reload must not create a fresh capacity pool while old requests remain.
	configuration.MaxConcurrent = 2
	configuration.MaxConcurrentPerClient = 1
	next, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler.Activate(next)
	if got := handler.resolveForClient(admissionQuery("reload.example."), next, "192.0.2.3"); got.response.Rcode != dns.RcodeRefused {
		t.Fatalf("reload bypass=%v", got.response)
	}
	close(release)
	for i := 0; i < 3; i++ {
		select {
		case got := <-done:
			if got.response.Rcode != dns.RcodeSuccess {
				t.Fatalf("admitted result=%v", got.response)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("admitted work did not finish")
		}
	}
	waitForAdmission(t, handler, 0)
	if handler.Stats().ResolutionClients != 0 || calls.Load() != 2 {
		t.Fatalf("leaked clients or duplicate upstream: clients=%d calls=%d", handler.Stats().ResolutionClients, calls.Load())
	}
	if got := handler.resolveForClient(admissionQuery("recovered.example."), next, "192.0.2.1"); got.response.Rcode != dns.RcodeSuccess {
		t.Fatalf("recovery=%v", got.response)
	}
}

func TestAdmissionReleasesFailedAndBackgroundWork(t *testing.T) {
	configuration := testRuntimeConfig()
	configuration.MaxConcurrent = 1
	configuration.MaxConcurrentPerClient = 1
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(context.Context, *dns.Msg, string, time.Duration) (*dns.Msg, error) {
		return nil, context.DeadlineExceeded
	}
	got := handler.resolveForClient(admissionQuery("failure.example."), runtime, "192.0.2.1")
	if got.response.Rcode != dns.RcodeServerFailure || handler.Stats().ResolutionInflight != 0 || handler.Stats().ResolutionClients != 0 {
		t.Fatalf("failed resolution leaked permit: %v", got.response)
	}
	hold := make(chan struct{})
	defer func() {
		select {
		case <-hold:
		default:
			close(hold)
		}
	}()
	handler.upstreamExchange = func(_ context.Context, query *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		<-hold
		return admissionAnswer(query), nil
	}
	handler.prefetch(admissionQuery("refresh.example."), runtime)
	waitForAdmission(t, handler, 1)
	handler.prefetch(admissionQuery("another-refresh.example."), runtime)
	if got := handler.resolveForClient(admissionQuery("foreground.example."), runtime, "192.0.2.2"); got.response.Rcode != dns.RcodeRefused {
		t.Fatalf("prefetch bypassed global capacity: %v", got.response)
	}
	if handler.Stats().ResolutionInflight != 1 || handler.Stats().ResolutionRejectedGlobal != 2 {
		t.Fatalf("background admission=%+v", handler.Stats())
	}
	close(hold)
	waitForAdmission(t, handler, 0)
}

func TestStaleAnswerHoldsAdmissionUntilRefreshFinishes(t *testing.T) {
	configuration := testRuntimeConfig()
	configuration.MaxConcurrent = 1
	configuration.MaxConcurrentPerClient = 1
	configuration.ServeStale = true
	configuration.CacheStaleTTL = 300
	configuration.CacheStaleAnswerTTL = 30
	configuration.CacheStaleMaxWait = time.Millisecond
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	now := time.Now()
	runtime.cache.now = func() time.Time { return now }
	query := admissionQuery("stale.example.")
	runtime.cache.Set(query, admissionAnswer(query), true)
	now = now.Add(61 * time.Second)
	hold := make(chan struct{})
	defer func() {
		select {
		case <-hold:
		default:
			close(hold)
		}
	}()
	handler.upstreamExchange = func(_ context.Context, query *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		<-hold
		return admissionAnswer(query), nil
	}
	got := handler.resolveForClient(query, runtime, "192.0.2.1")
	if got.response.Rcode != dns.RcodeSuccess || handler.Stats().ResolutionInflight != 1 {
		t.Fatalf("stale refresh lost capacity: %v", got.response)
	}
	if other := handler.resolveForClient(admissionQuery("other.example."), runtime, "192.0.2.2"); other.response.Rcode != dns.RcodeRefused {
		t.Fatalf("stale refresh bypass: %v", other.response)
	}
	close(hold)
	waitForAdmission(t, handler, 0)
}
