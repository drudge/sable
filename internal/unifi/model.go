// Package unifi reads networks, DHCP reservations, and connected clients from
// a UniFi controller so Sable can publish them as authoritative DNS records.
// It also reads the controller's own devices, which name hardware in Insights
// but are never published.
package unifi

import (
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Network is a UniFi LAN or VLAN. The identifier is stable across renames, so
// Sable keys zone mappings on it rather than on the display name.
type Network struct {
	ID      string
	Name    string
	Slug    string
	Purpose string
	Subnets []netip.Prefix
	// Gateway is the gateway's own address on the network, which is where
	// the controller's DHCP points devices for DNS unless told otherwise.
	Gateway netip.Addr
	// DHCP reports whether the controller runs the network's DHCP server,
	// and DHCPDNS the DNS servers the operator set it to hand out. With none
	// set, it hands out the gateway.
	DHCP    bool
	DHCPDNS []netip.Addr
}

// HandedOutDNS lists the DNS servers devices on the network are told to use.
// Known is false when the controller does not run the network's DHCP, so what
// devices are told is decided elsewhere.
func (network Network) HandedOutDNS() (servers []netip.Addr, known bool) {
	if !network.DHCP {
		return nil, false
	}
	if len(network.DHCPDNS) > 0 {
		return network.DHCPDNS, true
	}
	if network.Gateway.IsValid() {
		return []netip.Addr{network.Gateway}, true
	}
	return nil, false
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
	// Kind is what a piece of Ubiquiti hardware is: "gateway", "switch",
	// "access point", or "ups" for the controller's own devices, and "storage"
	// for a UniFi Drive, which the controller lists as a client. Other hosts
	// have none.
	Kind string
	// Fingerprint is the device type the controller's fingerprinting
	// suggests for a client, with FingerprintConfidence from 0 to 100.
	// FingerprintSet marks a type the operator chose by hand in UniFi.
	Fingerprint           string
	FingerprintConfidence int
	FingerprintSet        bool
}

// DeviceType is the Insights device type the controller vouches for:
// "network" for its gateways, switches, and access points, "ups" for its UPS
// units, which carry power rather than traffic, and "storage" for a UniFi
// Drive.
func (host Host) DeviceType() string {
	switch host.Kind {
	case "gateway", "switch", "access point":
		return "network"
	case "ups", "storage":
		return host.Kind
	}
	return ""
}

// Station is one client connected to the controller right now, with or without
// a name, and the traffic the controller has seen from it since it connected.
// Unlike a Host it is never published; it is how Insights tells a device that
// is online and busy from one that only holds a lease.
type Station struct {
	MAC  string
	Name string
	// Address is the IPv4 or IPv6 address the controller lists for the
	// client, and IPv6 every global and unique-local address it has seen on
	// it, privacy addresses included.
	Address   netip.Addr
	IPv6      []netip.Addr
	NetworkID string
	Wired     bool
	// LastSeen is when the controller last heard from the client, and
	// Uptime how long it has been connected this time.
	LastSeen time.Time
	Uptime   time.Duration
	// Bytes is what the client sent and received since it connected.
	Bytes uint64
}

// Addresses lists every address the controller ties to the station.
func (station Station) Addresses() []netip.Addr {
	addresses := make([]netip.Addr, 0, 1+len(station.IPv6))
	if station.Address.IsValid() {
		addresses = append(addresses, station.Address)
	}
	for _, address := range station.IPv6 {
		if address != station.Address {
			addresses = append(addresses, address)
		}
	}
	return addresses
}

// Inventory is one complete read of the controller. Gear is the controller's
// own adopted devices: its gateway, switches, and access points. It is kept
// apart from Hosts because hosts are what the sync publishes as DNS records,
// and naming the network's own hardware must not quietly add records.
// Stations is every connected client, named or not, which is never published.
type Inventory struct {
	Networks []Network
	Hosts    []Host
	Gear     []Host
	Stations []Station
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
			}
			if existing.Kind == "" {
				existing.Kind = host.Kind
			}
			if existing.Fingerprint == "" {
				existing.Fingerprint, existing.FingerprintConfidence, existing.FingerprintSet = host.Fingerprint, host.FingerprintConfidence, host.FingerprintSet
			}
			byMAC[host.MAC] = existing
			continue
		}
		if found && host.NetworkID == "" {
			host.NetworkID = existing.NetworkID
		}
		if found && len(host.IPv6) == 0 {
			host.IPv6 = existing.IPv6
		}
		if found && host.Kind == "" {
			host.Kind = existing.Kind
		}
		if found && host.Fingerprint == "" {
			host.Fingerprint, host.FingerprintConfidence, host.FingerprintSet = existing.Fingerprint, existing.FingerprintConfidence, existing.FingerprintSet
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

// withoutDisplacedReservations drops a reservation for a device that is not
// connected while another connected device holds its address. A reservation
// left behind for a retired machine would otherwise publish the old name at
// the new machine's address, and tie that address to the old hardware.
func withoutDisplacedReservations(hosts []Host, connected []Station) []Host {
	online := make(map[string]bool, len(connected))
	holder := make(map[netip.Addr]string, len(connected))
	for _, station := range connected {
		online[station.MAC] = true
		holder[station.Address] = station.MAC
	}
	return slices.DeleteFunc(hosts, func(host Host) bool {
		mac, held := holder[host.Address]
		return host.Reserved && !online[host.MAC] && held && mac != host.MAC
	})
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

// placeStations settles which network each connected client is on, the way
// placeHosts does for hosts.
func placeStations(networks []Network, stations []Station) []Station {
	byID := make(map[string]Network, len(networks))
	for _, network := range networks {
		byID[network.ID] = network
	}
	for index, station := range stations {
		if declared, known := byID[station.NetworkID]; known && declared.Contains(station.Address) {
			continue
		}
		if id, found := networkForAddress(networks, station.Address); found {
			stations[index].NetworkID = id
		}
	}
	return stations
}
