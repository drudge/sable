package dnsserver

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// locallyServedZones names the zones that RFC 6303 and RFC 6761 and its
// successors set aside for local use. None of them are delegated in the global
// DNS, so there is nothing for a validator to authenticate: a forwarder either
// answers them from a blackhole zone with an empty authority section, or the
// root proves the name does not exist at all. Validating either shape turns
// ordinary local traffic into SERVFAIL, so these names stay outside DNSSEC.
var locallyServedZones = buildLocallyServedZones()

// locallyServedSet holds the same zones for a lookup by name.
var locallyServedSet = func() map[string]struct{} {
	set := make(map[string]struct{}, len(locallyServedZones))
	for _, zone := range locallyServedZones {
		set[zone] = struct{}{}
	}
	return set
}()

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
	_, found := locallyServedZone(name)
	return found
}

// locallyServedZone returns the locally served zone that holds name. It runs
// for every recursive cache miss, so a lowercase name with its final dot, as
// clients send, is checked without allocating.
func locallyServedZone(name string) (string, bool) {
	name = strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))
	for current := name; current != "."; {
		if _, found := locallyServedSet[current]; found {
			return current, true
		}
		separator := strings.IndexByte(current, '.')
		if separator < 0 || separator == len(current)-1 {
			break
		}
		current = current[separator+1:]
	}
	return "", false
}

// locallyServedResponse answers a name in a locally served zone the way RFC
// 6303 asks a recursive resolver to: the name does not exist, with the zone's
// SOA so the client caches that. Nothing on the internet can answer these
// names. The IANA blackhole servers that hold some of them, such as
// service.arpa and the private reverse zones, often never reply at all, so
// asking them costs the client the whole timeout and then a SERVFAIL.
func locallyServedResponse(request *dns.Msg, zone string) *dns.Msg {
	response := new(dns.Msg)
	response.SetRcode(request, dns.RcodeNameError)
	response.Authoritative = true
	response.RecursionAvailable = true
	response.Ns = []dns.RR{&dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: locallyServedNegativeTTL},
		Ns:      "localhost.",
		Mbox:    "nobody.invalid.",
		Serial:  1,
		Refresh: 3600,
		Retry:   1200,
		Expire:  604800,
		Minttl:  locallyServedNegativeTTL,
	}}
	return response
}

// locallyServedNegativeTTL is the SOA minimum RFC 6303 section 3 gives these
// zones.
const locallyServedNegativeTTL = 10800
