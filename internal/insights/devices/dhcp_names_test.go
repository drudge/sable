package devices

import (
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

// A device with a DHCP lease is named from it, like Pi-hole and Technitium
// do, when neither the operator nor UniFi named it. The lease's name follows
// the hardware address, so the newer nameless neighbor sighting doesn't hide
// it, and it outranks reverse DNS for one address.
func TestDevicesAreNamedFromTheirDHCPLease(t *testing.T) {
	t.Parallel()
	given := NewGivenNames([]querylog.ClientIdentity{
		{Address: "10.0.0.100", MAC: "3c:22:fb:01:02:03", Source: "dhcp", Hostname: "georges-macbook", LastSeen: testNow.Add(-5 * time.Minute)},
		{Address: "10.0.0.100", MAC: "3c:22:fb:01:02:03", Source: "neighbor", LastSeen: testNow},
		{Address: "10.0.0.101", MAC: "da:a1:19:00:00:01", Source: "dhcp", Hostname: "ipad", LastSeen: testNow},
		{Address: "10.0.0.101", MAC: "da:a1:19:00:00:01", Source: "unifi", Hostname: "Kids iPad", LastSeen: testNow.Add(-5 * time.Minute)},
	}, nil)
	discovered := map[string]DiscoveredName{"10.0.0.100": {Name: "old.lan", Source: SourceReverse}}
	laptop := Device{MAC: "3c:22:fb:01:02:03", Addresses: []Address{{Address: "10.0.0.100"}}}
	if name, source, _ := chooseName(laptop, given, discovered); name != "georges-macbook" || source != SourceDHCP {
		t.Fatalf("laptop named %q from %q", name, source)
	}
	ipad := Device{MAC: "da:a1:19:00:00:01", Addresses: []Address{{Address: "10.0.0.101"}}}
	if name, source, _ := chooseName(ipad, given, nil); name != "Kids iPad" || source != SourceUniFi {
		t.Fatalf("iPad named %q from %q", name, source)
	}
}
