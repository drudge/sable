package dnsname

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// ReverseZone returns the reverse zone that covers a prefix. Reverse
// delegation happens on octet boundaries for IPv4 and nibble boundaries for
// IPv6, so a prefix is rounded down to the nearest boundary: a 192.168.10.0/26
// still lives inside 10.168.192.in-addr.arpa.
func ReverseZone(prefix netip.Prefix) (string, error) {
	if !prefix.IsValid() {
		return "", fmt.Errorf("invalid prefix %q", prefix)
	}
	prefix = prefix.Masked()
	address := prefix.Addr()
	if address.Is4() {
		octets := address.As4()
		significant := prefix.Bits() / 8
		if significant == 0 {
			return "", fmt.Errorf("prefix %s is too broad for a reverse zone", prefix)
		}
		labels := make([]string, 0, significant+2)
		for index := significant - 1; index >= 0; index-- {
			labels = append(labels, fmt.Sprint(octets[index]))
		}
		return strings.Join(append(labels, "in-addr", "arpa"), "."), nil
	}
	nibbles := prefix.Bits() / 4
	if nibbles == 0 {
		return "", fmt.Errorf("prefix %s is too broad for a reverse zone", prefix)
	}
	full := address.As16()
	labels := make([]string, 0, nibbles+2)
	for index := nibbles - 1; index >= 0; index-- {
		octet := full[index/2]
		if index%2 == 0 {
			octet >>= 4
		}
		labels = append(labels, fmt.Sprintf("%x", octet&0x0f))
	}
	return strings.Join(append(labels, "ip6", "arpa"), "."), nil
}

// ReverseName returns the full reverse name for one address, such as
// 50.1.168.192.in-addr.arpa.
func ReverseName(address netip.Addr) (string, error) {
	if !address.IsValid() {
		return "", fmt.Errorf("invalid address %q", address)
	}
	reverse, err := dns.ReverseAddr(address.Unmap().String())
	if err != nil {
		return "", fmt.Errorf("reverse name for %s: %w", address, err)
	}
	return strings.TrimSuffix(reverse, "."), nil
}
