// Package unifi reads networks, DHCP reservations, and connected clients from
// a UniFi controller so Sable can publish them as authoritative DNS records.
package unifi

import (
	"net/netip"
	"slices"
	"strings"
)

// Network is a UniFi LAN or VLAN. The identifier is stable across renames, so
// Sable keys zone mappings on it rather than on the display name.
type Network struct {
	ID      string
	Name    string
	Slug    string
	Purpose string
	Subnets []netip.Prefix
}

// IPv4Subnets returns only the IPv4 prefixes, which are the ones that produce
// in-addr.arpa reverse zones.
func (network Network) IPv4Subnets() []netip.Prefix {
	subnets := make([]netip.Prefix, 0, len(network.Subnets))
	for _, subnet := range network.Subnets {
		if subnet.Addr().Is4() {
			subnets = append(subnets, subnet)
		}
	}
	return subnets
}

// Contains reports whether one of the network's subnets covers an address.
func (network Network) Contains(address netip.Addr) bool {
	for _, subnet := range network.Subnets {
		if subnet.Contains(address) {
			return true
		}
	}
	return false
}

// Addressable reports whether the network covers a range Sable can name. A
// network without a subnet has no addresses to publish, and a single-host
// prefix is how the controller describes a VPN client tunnel rather than a LAN,
// so neither belongs in the inventory the console offers to synchronize.
func (network Network) Addressable() bool {
	for _, subnet := range network.Subnets {
		if subnet.Bits() < subnet.Addr().BitLen() {
			return true
		}
	}
	return false
}

// Host is one address the controller knows about. Reserved marks a
// configured fixed-IP reservation rather than an observed lease. IPv6 lists
// the global and unique-local addresses the controller has observed on the
// host; SLAAC privacy rotation changes that set between reads, so consumers
// republish it wholesale rather than tracking any one address.
type Host struct {
	MAC       string
	Hostname  string
	Address   netip.Addr
	IPv6      []netip.Addr
	NetworkID string
	Reserved  bool
}

// Inventory is one complete read of the controller.
type Inventory struct {
	Networks []Network
	Hosts    []Host
}

// NetworkByID returns the named network, if the controller reported it.
func (inventory Inventory) NetworkByID(id string) (Network, bool) {
	for _, network := range inventory.Networks {
		if network.ID == id {
			return network, true
		}
	}
	return Network{}, false
}

// HostCounts totals the hosts belonging to each network, which the setup
// wizard shows next to each candidate network.
func (inventory Inventory) HostCounts() map[string]int {
	counts := make(map[string]int, len(inventory.Networks))
	for _, host := range inventory.Hosts {
		counts[host.NetworkID]++
	}
	return counts
}

// mergeHosts collapses reservations and active clients into one host per MAC.
// A reservation always wins over an observed lease because it is the address
// the operator chose, and an entry without a usable hostname loses to one that
// has a name so a nameless active client cannot mask a named reservation. The
// winner inherits a network the loser knew about, because the reservation that
// carries the right address often does not say which network it is on, and it
// inherits the loser's observed IPv6 addresses for the same reason: only the
// active lease reports them.
func mergeHosts(reserved, active []Host) []Host {
	byMAC := make(map[string]Host, len(reserved)+len(active))
	for _, host := range slices.Concat(active, reserved) {
		if host.Hostname == "" || !host.Address.IsValid() {
			continue
		}
		existing, found := byMAC[host.MAC]
		if found && existing.Reserved && !host.Reserved {
			if len(existing.IPv6) == 0 {
				existing.IPv6 = host.IPv6
				byMAC[host.MAC] = existing
			}
			continue
		}
		if found && host.NetworkID == "" {
			host.NetworkID = existing.NetworkID
		}
		if found && len(host.IPv6) == 0 {
			host.IPv6 = existing.IPv6
		}
		byMAC[host.MAC] = host
	}
	hosts := make([]Host, 0, len(byMAC))
	for _, host := range byMAC {
		hosts = append(hosts, host)
	}
	slices.SortFunc(hosts, func(left, right Host) int {
		if compared := strings.Compare(left.Hostname, right.Hostname); compared != 0 {
			return compared
		}
		return left.Address.Compare(right.Address)
	})
	return hosts
}

// placeHosts settles which network each host belongs to. What the controller
// says comes first, but it says nothing at all on most reservations, and it can
// name a network that does not hold the address being published, so the network
// whose subnet covers the address stands in for it. A host that matches no
// subnet keeps whatever the controller said, which may be nothing, so it is
// counted nowhere rather than counted wrongly.
func placeHosts(networks []Network, hosts []Host) []Host {
	byID := make(map[string]Network, len(networks))
	for _, network := range networks {
		byID[network.ID] = network
	}
	for index, host := range hosts {
		if declared, known := byID[host.NetworkID]; known && declared.Contains(host.Address) {
			continue
		}
		if id, found := networkForAddress(networks, host.Address); found {
			hosts[index].NetworkID = id
		}
	}
	return hosts
}

// networkForAddress finds the network covering an address, preferring the most
// specific subnet so a wider network cannot claim a host from a narrower one.
func networkForAddress(networks []Network, address netip.Addr) (string, bool) {
	best, bestBits, found := "", -1, false
	for _, network := range networks {
		for _, subnet := range network.Subnets {
			if subnet.Contains(address) && subnet.Bits() > bestBits {
				best, bestBits, found = network.ID, subnet.Bits(), true
			}
		}
	}
	return best, found
}
