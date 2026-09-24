// Package devices turns client addresses into devices and reports what changed
// about them. An address is tied to a device through the names an operator
// gave it, a UniFi controller's inventory, or the host's neighbor table, so a
// laptop's IPv4 and rotating IPv6 addresses count as one device. When nothing
// ties an address to hardware, the address stands on its own and every
// sentence about it says "address" rather than claiming a device.
package devices

import (
	"cmp"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights/vendors"
	"github.com/drudge/sable/internal/querylog"
)

// Name sources, in the order a device's name is chosen.
const (
	SourceOperator = "Your name"
	SourceUniFi    = "UniFi"
	SourceLocal    = "Local host"
	SourceReverse  = "Reverse DNS"
)

// Identity sources recorded by the store.
const (
	identityUniFi    = "unifi"
	identityNeighbor = "neighbor"
)

// Device is one piece of hardware, or one address that could not be tied to
// hardware, with its traffic in a window.
type Device struct {
	// Key is "mac:<address>" for hardware Sable identified and "ip:<address>"
	// otherwise. It is stable for as long as that identity holds.
	Key        string
	Name       string
	NameSource string
	MAC        string
	// PrivateMAC marks a randomized per-network hardware address.
	PrivateMAC bool
	// Named is set when the operator named this device in Sable.
	Named bool
	// NameNetwork is the network the operator's name was given to, when it
	// names a whole network rather than this device.
	NameNetwork string
	// Server is set when the device runs Sable: "This server" for the one
	// that counted the queries, "Sable node" for the rest of its cluster.
	Server string
	// Vendor is the maker of the device's network interface, from its
	// hardware address.
	Vendor string
	// Type is the kind of device the operator said this device is, if they
	// did. NetworkType is the kind they said every device on TypeNetwork is,
	// which applies when the device has no type of its own.
	Type        string
	NetworkType string
	TypeNetwork string
	// Guess is what kind of device this is, filled in by Identify once the
	// services the device uses are known.
	Guess Guess
	// Addresses are the client addresses that sent traffic, busiest first.
	Addresses []Address
	Queries   uint64
	Blocked   uint64
	// NewDomains counts names first queried in the window; it is exact for a
	// single-address device and filled in by the caller for the rest.
	NewDomains uint64
	FirstSeen  time.Time
	LastSeen   time.Time
	Recent     uint64
	Baseline   uint64
	// RecentNewDomains and BaselineNewDomains count first-time names in the
	// last 24 hours and the week before, summed over the device's addresses.
	RecentNewDomains   uint64
	BaselineNewDomains uint64
}

// Address is one client address of a device and its own traffic, which is
// what a query log link for that address reproduces.
type Address struct {
	Address string
	Queries uint64
	Blocked uint64
}

// Identified reports whether the device is tied to hardware or to a name the
// operator gave, rather than to a bare address.
func (device Device) Identified() bool { return device.MAC != "" || device.Named }

// ClientAddresses lists the device's addresses.
func (device Device) ClientAddresses() []string {
	addresses := make([]string, 0, len(device.Addresses))
	for _, address := range device.Addresses {
		addresses = append(addresses, address.Address)
	}
	return addresses
}

// Input is everything devices are built from. Names holds names discovered
// for individual addresses, such as local host entries and PTR records, with
// the source of each. Servers marks the client addresses of Sable servers
// with what each one is to the server that counted the queries.
type Input struct {
	Activity   querylog.ClientActivityReport
	Identities []querylog.ClientIdentity
	Clients    []config.Client
	Names      map[string]DiscoveredName
	Servers    map[string]string
}

// DiscoveredName is a name found for one address and where it came from.
type DiscoveredName struct {
	Name   string
	Source string
}

// GivenNames are the names a device was given rather than discovered: the one
// the operator set in Sable, then the one its UniFi controller reports. Both
// follow the device's hardware address, so they hold while its IP addresses
// change and outrank any name discovered for one address.
type GivenNames struct {
	identities map[string]querylog.ClientIdentity
	operator   operatorNames
	unifi      map[string]string
}

// NewGivenNames reads the operator's names and the UniFi names among the
// hardware sightings.
func NewGivenNames(identities []querylog.ClientIdentity, clients []config.Client) GivenNames {
	return GivenNames{
		identities: latestIdentities(identities),
		operator:   newOperatorNames(clients),
		unifi:      unifiNames(identities),
	}
}

// Address returns the given name of the device behind one client address, or
// nothing when only a discovered name could label it.
func (given GivenNames) Address(address string) string {
	device := Device{MAC: given.identities[address].MAC, Addresses: []Address{{Address: address}}}
	name, _, _ := chooseName(device, given, nil)
	return name
}

// Build groups client activity into devices, busiest first.
func Build(input Input) []Device {
	given := NewGivenNames(input.Identities, input.Clients)
	devices := make(map[string]*Device)
	order := make([]string, 0)
	for _, activity := range input.Activity.Clients {
		address := activity.Client
		identity, identified := given.identities[address]
		key := "ip:" + address
		if identified {
			key = "mac:" + identity.MAC
		}
		device, found := devices[key]
		if !found {
			device = &Device{Key: key}
			if identified {
				device.MAC = identity.MAC
				if parsed, err := net.ParseMAC(identity.MAC); err == nil {
					device.PrivateMAC = len(parsed) > 0 && parsed[0]&0x02 != 0
				}
			}
			devices[key] = device
			order = append(order, key)
		}
		device.Addresses = append(device.Addresses, Address{Address: address, Queries: activity.Queries, Blocked: activity.Blocked})
		device.Queries += activity.Queries
		device.Blocked += activity.Blocked
		device.NewDomains += activity.NewDomains
		device.Recent += activity.Recent
		device.Baseline += activity.Baseline
		device.RecentNewDomains += activity.RecentNewDomains
		device.BaselineNewDomains += activity.BaselineNewDomains
		if !activity.FirstSeen.IsZero() && (device.FirstSeen.IsZero() || activity.FirstSeen.Before(device.FirstSeen)) {
			device.FirstSeen = activity.FirstSeen
		}
		if activity.LastSeen.After(device.LastSeen) {
			device.LastSeen = activity.LastSeen
		}
	}

	result := make([]Device, 0, len(order))
	for _, key := range order {
		device := devices[key]
		slices.SortFunc(device.Addresses, func(left, right Address) int {
			if order := cmp.Compare(right.Queries, left.Queries); order != 0 {
				return order
			}
			return cmp.Compare(left.Address, right.Address)
		})
		device.Name, device.NameSource, device.NameNetwork = chooseName(*device, given, input.Names)
		device.Named = device.NameSource == SourceOperator
		device.Type = given.operator.own(*device, clientType)
		device.NetworkType, device.TypeNetwork = given.operator.network(*device, clientType)
		for _, address := range device.Addresses {
			if server := input.Servers[address.Address]; server != "" {
				device.Server = server
				break
			}
		}
		if device.MAC != "" {
			device.Vendor, _ = vendors.Lookup(device.MAC)
		}
		result = append(result, *device)
	}
	slices.SortFunc(result, func(left, right Device) int {
		if order := cmp.Compare(right.Queries, left.Queries); order != 0 {
			return order
		}
		return cmp.Compare(left.Key, right.Key)
	})
	return result
}

// latestIdentities keeps each address's most recent hardware sighting. A UniFi
// sighting wins a tie so the answer does not depend on the order sightings
// were read in.
func latestIdentities(identities []querylog.ClientIdentity) map[string]querylog.ClientIdentity {
	latest := make(map[string]querylog.ClientIdentity, len(identities))
	for _, identity := range identities {
		current, found := latest[identity.Address]
		if !found || identity.LastSeen.After(current.LastSeen) ||
			(identity.LastSeen.Equal(current.LastSeen) && identity.Source == identityUniFi && current.Source != identityUniFi) {
			latest[identity.Address] = identity
		}
	}
	return latest
}

// AddressesOf lists, in order, the client addresses whose most recent hardware
// sighting is mac: the addresses Sable ties to that device now.
func AddressesOf(identities []querylog.ClientIdentity, mac string) []string {
	addresses := make([]string, 0)
	for address, identity := range latestIdentities(identities) {
		if identity.MAC == mac {
			addresses = append(addresses, address)
		}
	}
	slices.Sort(addresses)
	return addresses
}

// unifiNames keeps the name each hardware address had in its most recent UniFi
// sighting. It is keyed by hardware address rather than read from an
// address's latest sighting because the neighbor table is sampled more often
// than the controller and carries no name, so the latest sighting is usually
// one without it.
func unifiNames(identities []querylog.ClientIdentity) map[string]string {
	names := make(map[string]string)
	seen := make(map[string]time.Time)
	for _, identity := range identities {
		if identity.Source != identityUniFi || identity.MAC == "" || identity.Hostname == "" {
			continue
		}
		if last, found := seen[identity.MAC]; found && !identity.LastSeen.After(last) {
			continue
		}
		names[identity.MAC], seen[identity.MAC] = identity.Hostname, identity.LastSeen
	}
	return names
}

// operatorNames resolves what an operator said about devices: by hardware
// address, by exact address, and by the most specific network containing an
// address.
type operatorNames struct {
	byMAC     map[string]config.Client
	byAddress map[string]config.Client
	networks  []namedNetwork
}

type namedNetwork struct {
	prefix netip.Prefix
	client config.Client
}

func newOperatorNames(clients []config.Client) operatorNames {
	names := operatorNames{byMAC: map[string]config.Client{}, byAddress: map[string]config.Client{}}
	for _, client := range clients {
		switch {
		case client.MAC != "":
			names.byMAC[strings.ToLower(client.MAC)] = client
		case strings.Contains(client.Address, "/"):
			if prefix, err := netip.ParsePrefix(client.Address); err == nil {
				names.networks = append(names.networks, namedNetwork{prefix: prefix.Masked(), client: client})
			}
		default:
			if address, err := netip.ParseAddr(client.Address); err == nil {
				names.byAddress[address.Unmap().String()] = client
			}
		}
	}
	slices.SortFunc(names.networks, func(left, right namedNetwork) int {
		return cmp.Compare(right.prefix.Bits(), left.prefix.Bits())
	})
	return names
}

// forDevice returns the most specific value the operator set for a device,
// read from each matching entry with pick, and the network it was set for
// when it came from a whole network rather than the device's own entry.
func (names operatorNames) forDevice(device Device, pick func(config.Client) string) (string, string) {
	if value := names.own(device, pick); value != "" {
		return value, ""
	}
	return names.network(device, pick)
}

// own returns the value the operator set for the device itself: by its
// hardware address, then by one of its addresses.
func (names operatorNames) own(device Device, pick func(config.Client) string) string {
	if device.MAC != "" {
		if value := pick(names.byMAC[device.MAC]); value != "" {
			return value
		}
	}
	for _, address := range device.Addresses {
		if value := pick(names.byAddress[address.Address]); value != "" {
			return value
		}
	}
	return ""
}

// network returns the value the operator set for the most specific network
// containing one of the device's addresses, and that network.
func (names operatorNames) network(device Device, pick func(config.Client) string) (string, string) {
	for _, address := range device.Addresses {
		parsed, err := netip.ParseAddr(address.Address)
		if err != nil {
			continue
		}
		for _, network := range names.networks {
			if value := pick(network.client); value != "" && network.prefix.Contains(parsed.Unmap()) {
				return value, network.prefix.String()
			}
		}
	}
	return "", ""
}

func clientName(client config.Client) string { return client.Name }
func clientType(client config.Client) string { return client.Type }

// chooseName returns a device's name, where it came from, and the network an
// operator's name was given to when it names a whole network.
func chooseName(device Device, given GivenNames, discovered map[string]DiscoveredName) (string, string, string) {
	if name, network := given.operator.forDevice(device, clientName); name != "" {
		return name, SourceOperator, network
	}
	if name := given.unifi[device.MAC]; name != "" {
		return name, SourceUniFi, ""
	}
	for _, address := range device.Addresses {
		if name := discovered[address.Address]; name.Name != "" {
			return name.Name, name.Source, ""
		}
	}
	return "", "", ""
}

// Find returns the device with a key.
func Find(devices []Device, key string) (Device, bool) {
	for _, device := range devices {
		if device.Key == key {
			return device, true
		}
	}
	return Device{}, false
}
