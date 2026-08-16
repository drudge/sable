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
// configured fixed-IP reservation rather than an observed lease.
type Host struct {
	MAC       string
	Hostname  string
	Address   netip.Addr
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
// has a name so a nameless active client cannot mask a named reservation.
func mergeHosts(reserved, active []Host) []Host {
	byMAC := make(map[string]Host, len(reserved)+len(active))
	for _, host := range slices.Concat(active, reserved) {
		if host.Hostname == "" || !host.Address.IsValid() {
			continue
		}
		existing, found := byMAC[host.MAC]
		if found && existing.Reserved && !host.Reserved {
			continue
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
