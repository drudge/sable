// Package clientaccess compiles source-address policies shared by configuration
// validation and DNS runtime activation.
package clientaccess

import (
	"fmt"
	"net/netip"
	"strings"
)

type Policy struct {
	mode     string
	networks []netip.Prefix
}

func Compile(mode string, clients []string) (Policy, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "private"
	}
	switch mode {
	case "private", "acl", "deny", "allow":
	default:
		return Policy{}, fmt.Errorf("recursion must be private, acl, deny, or allow")
	}
	policy := Policy{mode: mode}
	for _, client := range clients {
		client = strings.TrimSpace(client)
		prefix, err := netip.ParsePrefix(client)
		if err != nil {
			address, addressErr := netip.ParseAddr(client)
			if addressErr != nil || address.Zone() != "" {
				return Policy{}, fmt.Errorf("recursion client %q must be an IP address or CIDR network", client)
			}
			address = address.Unmap()
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return Policy{}, fmt.Errorf("recursion client %q has an ambiguous mapped IPv4 prefix", client)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		policy.networks = append(policy.networks, prefix.Masked())
	}
	return policy, nil
}

func (policy Policy) Allows(client string) bool {
	address, err := netip.ParseAddr(client)
	if err != nil {
		return false
	}
	address = address.Unmap().WithZone("")
	switch policy.mode {
	case "allow":
		return true
	case "private":
		return address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast()
	case "acl":
		for _, network := range policy.networks {
			if network.Contains(address) {
				return true
			}
		}
	}
	return false
}
