package dnsserver

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestActivateZonesRouteChangeDropsRecursiveCacheAndKeepsOptions(t *testing.T) {
	configuration := testRuntimeConfig()
	configuration.CacheSize = 16
	configuration.CacheMinimumTTL = 7
	configuration.CacheMaximumTTL = 90
	active, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	request := cacheRequest("route-change.example.", 1)
	active.cache.Set(request, positiveResponse(request, 60), true)
	oldCache := active.cache
	oldOptions := oldCache.options
	handler := NewHandler(active)
	if err := handler.ActivateZones([]AuthoritativeZone{{
		Name: "example", Type: "forwarder",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example. hostmaster.example. 1 3600 600 1209600 300"},
			{Name: "@", Type: "FWD", TTL: 300, Value: "udp 0 192.0.2.53:53"},
		},
	}}, nil); err != nil {
		t.Fatal(err)
	}
	current := handler.runtime.Load()
	if current.cache == oldCache {
		t.Fatal("route-changing zone activation reused the recursive cache")
	}
	if current.cache.Capacity() != oldCache.Capacity() || current.cache.options != oldOptions {
		t.Fatalf("replacement cache = capacity %d options %+v, want capacity %d options %+v", current.cache.Capacity(), current.cache.options, oldCache.Capacity(), oldOptions)
	}
	if current.cache.Len() != 0 {
		t.Fatalf("replacement cache entries = %d, want empty", current.cache.Len())
	}
	var upstreamCalls int
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		upstreamCalls++
		if endpoint != "udp://192.0.2.53:53" {
			t.Errorf("upstream endpoint = %q, want new zone forwarder", endpoint)
		}
		return answerWithAddress(request, "192.0.2.53"), nil
	}
	result := handler.resolveForClient(request.Copy(), current, "192.0.2.44")
	if result.response == nil || len(result.response.Answer) != 1 || result.response.Answer[0].(*dns.A).A.String() != "192.0.2.53" || upstreamCalls != 1 {
		t.Fatalf("route-changing ActivateZones reused stale answer: calls=%d answer=%v", upstreamCalls, result.response)
	}
}

func TestActivateZonesUnchangedRoutesPreserveRecursiveCache(t *testing.T) {
	configuration := testRuntimeConfig()
	active, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	request := cacheRequest("preserved.example.", 1)
	active.cache.Set(request, positiveResponse(request, 60), true)
	handler := NewHandler(active)
	if err := handler.ActivateZones([]AuthoritativeZone{testAuthoritativeZone("new.example", "192.0.2.20")}, nil); err != nil {
		t.Fatal(err)
	}
	if current := handler.runtime.Load(); current.cache != active.cache || current.cache.Len() != 1 {
		t.Fatal("authoritative-only zone activation did not preserve the recursive cache")
	}
}

func TestActivateZonesDNSSECPolicyChangeDropsRecursiveCache(t *testing.T) {
	configuration := testRuntimeConfig()
	configuration.DNSSECValidation = true
	zone := AuthoritativeZone{
		Name: "private.example", Type: "forwarder",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.private.example. hostmaster.private.example. 1 3600 600 1209600 300"},
			{Name: "@", Type: "FWD", TTL: 300, Value: "udp 0 192.0.2.53:53"},
		},
	}
	configuration.Zones = []AuthoritativeZone{zone}
	active, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	request := cacheRequest("private.example.", 1)
	active.cache.Set(request, positiveResponse(request, 60), true)
	handler := NewHandler(active)
	zone.DNSSECValidationDisabled = true
	if err := handler.ActivateZones([]AuthoritativeZone{zone}, nil); err != nil {
		t.Fatal(err)
	}
	if current := handler.runtime.Load(); current.cache == active.cache || current.cache.Len() != 0 {
		t.Fatal("DNSSEC policy-changing zone activation preserved recursive cache")
	}
}

func TestResolveCoalescingDoesNotCrossRuntimeActivation(t *testing.T) {
	oldConfiguration := testRuntimeConfig()
	oldConfiguration.Forwarders = []string{"old.forwarder:53"}
	oldRuntime, err := Compile(oldConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	newConfiguration := oldConfiguration
	newConfiguration.Forwarders = []string{"new.forwarder:53"}
	newRuntime, err := Compile(newConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(oldRuntime)
	oldEntered := make(chan struct{})
	oldRelease := make(chan struct{})
	var once sync.Once
	var releaseOnce sync.Once
	releaseOld := func() { releaseOnce.Do(func() { close(oldRelease) }) }
	t.Cleanup(releaseOld)
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		if endpoint == "old.forwarder:53" {
			once.Do(func() { close(oldEntered) })
			<-oldRelease
			return answerWithAddress(request, "192.0.2.1"), nil
		}
		return answerWithAddress(request, "192.0.2.2"), nil
	}
	request := cacheRequest("activation.example.", 1)
	oldResult := make(chan resolution, 1)
	go func() { oldResult <- handler.resolveForClient(request.Copy(), oldRuntime, "192.0.2.44") }()
	select {
	case <-oldEntered:
	case <-time.After(time.Second):
		t.Fatal("old runtime resolution did not start")
	}
	handler.Activate(newRuntime)
	newResult := make(chan resolution, 1)
	go func() { newResult <- handler.resolveForClient(request.Copy(), newRuntime, "192.0.2.44") }()
	select {
	case result := <-newResult:
		if got := result.response.Answer[0].(*dns.A).A.String(); got != "192.0.2.2" {
			t.Fatalf("new runtime answer = %s, want new upstream answer", got)
		}
	case <-time.After(time.Second):
		t.Fatal("new runtime joined the blocked old in-flight resolution")
	}
	releaseOld()
	select {
	case result := <-oldResult:
		if got := result.response.Answer[0].(*dns.A).A.String(); got != "192.0.2.1" {
			t.Fatalf("old runtime answer = %s, want old upstream answer", got)
		}
	case <-time.After(time.Second):
		t.Fatal("old runtime resolution did not finish")
	}
}

func answerWithAddress(request *dns.Msg, address string) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = append(response.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP(address),
	})
	return response
}
