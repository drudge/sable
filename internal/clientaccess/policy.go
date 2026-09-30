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

// Allows reports whether a client may use recursion, counting only the
// fixed private ranges in private mode.
func (policy Policy) Allows(client string) bool {
	return policy.AllowsFrom(client, nil)
}

// AllowsFrom reports whether a client may use recursion. In private mode it
// also admits the networks Sable is attached to, which the caller keeps
// current. It runs for every lookup and allocates nothing.
func (policy Policy) AllowsFrom(client string, attached []netip.Prefix) bool {
	address, err := netip.ParseAddr(client)
	if err != nil {
		return false
	}
	address = address.Unmap().WithZone("")
	switch policy.mode {
	case "allow":
		return true
	case "private":
		if address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return true
		}
		for _, network := range attached {
			if network.Contains(address) {
				return true
			}
		}
	case "acl":
		for _, network := range policy.networks {
			if network.Contains(address) {
				return true
			}
		}
	}
	return false
}

// Private reports whether the policy is private mode, the one that counts
// the networks Sable is attached to.
func (policy Policy) Private() bool {
	return policy.mode == "private"
}
