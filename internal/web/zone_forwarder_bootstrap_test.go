package web

import (
	"strings"
	"testing"

	zonemodel "github.com/drudge/sable/internal/zone"
)

// TestNewForwardersNeedBootstrapAddress covers FWD records and forwarder
// zones: a new encrypted forwarder named by host name is refused, a saved one
// still loads, and one with a bootstrap address is stored canonically.
func TestNewForwardersNeedBootstrapAddress(t *testing.T) {
	t.Parallel()
	zone := zonemodel.Zone{Name: "forward.test", Type: "forwarder", DefaultTTL: 300}
	for _, value := range []string{"tls 0 dns.example", "quic 0 dns.example:853", "https 0 https://dns.quad9.net/dns-query"} {
		if _, err := newRecord(zone, recordInput{Name: "@", Type: "FWD", Value: value}); err == nil ||
			!strings.Contains(err.Error(), "in parentheses") {
			t.Errorf("new FWD %q: %v", value, err)
		}
	}
	for _, value := range []string{"udp 0 dns.example", "tls 0 1.1.1.1", "https 0 https://dns.quad9.net/dns-query (9.9.9.9)"} {
		if _, err := newRecord(zone, recordInput{Name: "@", Type: "FWD", Value: value}); err != nil {
			t.Errorf("new FWD %q: %v", value, err)
		}
	}
	saved := zonemodel.Record{Name: "@", Type: "FWD", TTL: 300, Value: "tls 0 dns.example:853"}
	if _, err := zonemodel.ParseRecord(zone, saved); err != nil {
		t.Fatalf("a saved DoT record named by host name must still load: %v", err)
	}
	if _, err := newZoneForwarder(zoneCreate{ForwarderProtocol: "https", ForwarderAddress: "https://dns.quad9.net/dns-query"}); err == nil {
		t.Fatal("a forwarder zone was created with a DoH forwarder and no bootstrap address")
	}
	forwarder, err := newZoneForwarder(zoneCreate{ForwarderProtocol: "https", ForwarderAddress: "dns.quad9.net (9.9.9.9)"})
	if err != nil || forwarder.String() != "https 0 https://dns.quad9.net/dns-query (9.9.9.9)" {
		t.Fatalf("newZoneForwarder() = %q, %v", forwarder.String(), err)
	}
}
