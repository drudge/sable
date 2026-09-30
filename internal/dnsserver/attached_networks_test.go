package dnsserver

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A LAN device with a global IPv6 address is refused under private recursion
// until the handler knows the network it's on.
func TestPrivateRecursionAdmitsAttachedNetworks(t *testing.T) {
	configuration := testRuntimeConfig()
	configuration.Recursion = "private"
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		response := new(dns.Msg)
		response.SetReply(request)
		answer, _ := dns.NewRR(request.Question[0].Name + " 60 IN A 192.0.2.80")
		response.Answer = []dns.RR{answer}
		return response, nil
	}
	query := new(dns.Msg)
	query.SetQuestion("eu.tectonic.example.", dns.TypeA)
	device := &responseCapture{remoteIP: "2001:db8:1234:1500:4b53:1028:c3bd:115b"}

	handler.ServeDNS(device, query)
	if device.message.Rcode != dns.RcodeRefused || device.message.RecursionAvailable {
		t.Fatalf("response before the network was known = %v", device.message)
	}
	handler.SetAttachedNetworks([]netip.Prefix{netip.MustParsePrefix("2001:db8:1234:1500::/64")})
	handler.ServeDNS(device, query)
	if device.message.Rcode != dns.RcodeSuccess || !device.message.RecursionAvailable {
		t.Fatalf("response once the network was known = %v", device.message)
	}
	outsider := &responseCapture{remoteIP: "2001:db8:9999::1"}
	handler.ServeDNS(outsider, query)
	if outsider.message.Rcode != dns.RcodeRefused {
		t.Fatalf("a client off the network got %v", outsider.message)
	}
}

// attachedWriter answers from a LAN device with a global IPv6 address.
type attachedWriter struct{ discardWriter }

var attachedClient = &net.UDPAddr{IP: net.ParseIP("2001:db8:1234:1500:4b53:1028:c3bd:115b"), Port: 53000}

func (attachedWriter) RemoteAddr() net.Addr { return attachedClient }

// BenchmarkServeDNSCacheHitFromAttachedNetwork is a cache hit under private
// recursion from a device admitted only by the network it's on. It must cost
// no more allocations than BenchmarkServeDNSCacheHit.
func BenchmarkServeDNSCacheHitFromAttachedNetwork(b *testing.B) {
	configuration := testRuntimeConfig()
	configuration.Recursion = "private"
	configuration.CacheSize = 10_000
	runtime, err := Compile(configuration)
	if err != nil {
		b.Fatal(err)
	}
	handler := NewHandler(runtime)
	handler.SetAttachedNetworks([]netip.Prefix{
		netip.MustParsePrefix("2001:db8:1234:1400::/64"), netip.MustParsePrefix("2001:db8:1234:1500::/64"),
	})
	request := cacheRequest("example.com.", 1)
	if !runtime.cache.Set(request, positiveResponse(request, 300), true) {
		b.Fatal("failed to seed the response cache")
	}
	b.ReportAllocs()
	for b.Loop() {
		handler.ServeDNS(attachedWriter{}, request)
	}
}
