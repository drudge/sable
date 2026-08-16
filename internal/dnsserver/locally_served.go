package dnsserver

import (
	"fmt"

	"github.com/miekg/dns"
)

// locallyServedZones names the zones that RFC 6303 and RFC 6761 and its
// successors set aside for local use. None of them are delegated in the global
// DNS, so there is nothing for a validator to authenticate: a forwarder either
// answers them from a blackhole zone with an empty authority section, or the
// root proves the name does not exist at all. Validating either shape turns
// ordinary local traffic into SERVFAIL, so these names stay outside DNSSEC.
var locallyServedZones = buildLocallyServedZones()

func buildLocallyServedZones() []string {
	zones := []string{
		// RFC 6303 section 4, IPv4 reverse zones with no global delegation.
		"10.in-addr.arpa.",
		"168.192.in-addr.arpa.",
		"0.in-addr.arpa.",
		"127.in-addr.arpa.",
		"254.169.in-addr.arpa.",
		"255.in-addr.arpa.",
		// RFC 5737 documentation ranges.
		"2.0.192.in-addr.arpa.",
		"100.51.198.in-addr.arpa.",
		"113.0.203.in-addr.arpa.",

		// RFC 6303 section 5, IPv6 reverse zones.
		"d.f.ip6.arpa.", // fd00::/8 unique local
		// fe80::/10 link local, which spans four nibble boundaries.
		"8.e.f.ip6.arpa.",
		"9.e.f.ip6.arpa.",
		"a.e.f.ip6.arpa.",
		"b.e.f.ip6.arpa.",
		"8.b.d.0.1.0.0.2.ip6.arpa.", // 2001:db8::/32 documentation
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.", // ::1 loopback

		// Special-use domain names that resolve only inside a local network.
		"home.arpa.",     // RFC 8375
		"resolver.arpa.", // RFC 9462, used by DDR probes
		"service.arpa.",  // RFC 9665
		"local.",         // RFC 6762 multicast DNS
		"localhost.",     // RFC 6761
		"invalid.",       // RFC 6761
		"onion.",         // RFC 7686
		"alt.",           // RFC 9476
		"internal.",      // ICANN reserved for private use, 2024
		"test.",          // RFC 6761
	}
	// 172.16.0.0/12 and the RFC 6598 shared address space each cover a run of
	// reverse zones that is clearer to generate than to spell out.
	for octet := 16; octet <= 31; octet++ {
		zones = append(zones, fmt.Sprintf("%d.172.in-addr.arpa.", octet))
	}
	for octet := 64; octet <= 127; octet++ {
		zones = append(zones, fmt.Sprintf("%d.100.in-addr.arpa.", octet))
	}
	return zones
}

// isLocallyServedZone reports whether name sits inside a zone that is only ever
// answered locally.
func isLocallyServedZone(name string) bool {
	name = normalizeFQDN(name)
	for _, zone := range locallyServedZones {
		if dns.IsSubDomain(zone, name) {
			return true
		}
	}
	return false
}
