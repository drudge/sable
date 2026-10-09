package dnsserver

import (
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"slices"
)

// DeviceAddresses maps the addresses Sable has tied to a device to the
// device's hardware address, in net.HardwareAddr's form.
type DeviceAddresses map[netip.Addr]string

// SetDeviceAddresses replaces the addresses of devices named by hardware
// address. The table lives beside the runtime rather than in it, so a new
// lease or IPv6 address doesn't recompile the block lists.
func (handler *Handler) SetDeviceAddresses(addresses DeviceAddresses) {
	handler.deviceAddresses.Store(&addresses)
}

// DeviceAddressTable returns the current table. It is shared; don't change it.
func (handler *Handler) DeviceAddressTable() DeviceAddresses {
	if addresses := handler.deviceAddresses.Load(); addresses != nil {
		return *addresses
	}
	return nil
}

// policyClient is the client of a query as policy sees it: its address, and
// the hardware address of the device behind it when Sable knows it.
type policyClient struct {
	address netip.Addr
	mac     string
}

// identifyClient parses a query's client address. A query without a valid
// one, such as a check from the console, has no client.
func identifyClient(clientIP string, devices DeviceAddresses) (policyClient, bool) {
	if clientIP == "" {
		return policyClient{}, false
	}
	address, err := netip.ParseAddr(clientIP)
	if err != nil {
		return policyClient{}, false
	}
	address = address.Unmap().WithZone("")
	return policyClient{address: address, mac: devices[address]}, true
}

// MatchClient returns the entry of clients that a client at address, behind
// hardware address mac, uses, the way rule sets and holds pick one. The first
// entry naming a client keeps it. Entries Sable cannot read are skipped.
func MatchClient(clients []string, address, mac string) (string, bool) {
	client, ok := identifyClient(address, nil)
	if !ok {
		return "", false
	}
	if parsed, err := net.ParseMAC(mac); err == nil {
		client.mac = parsed.String()
	}
	var table clientTable[string]
	for _, entry := range clients {
		_ = table.add(entry, entry)
	}
	table.sort()
	return table.lookup(client)
}

// clientTable finds the entry for a client: by its exact address, then by the
// hardware address of the device behind it, then by the most specific
// network. Lookups run on every query, so they must not allocate.
type clientTable[V any] struct {
	exact    map[netip.Addr]V
	macs     map[string]V
	prefixes []clientPrefix[V]
}

type clientPrefix[V any] struct {
	prefix netip.Prefix
	value  V
}

// add puts value in the table for client, an IP address, CIDR network, or
// hardware address. The first value added for an address or hardware address
// keeps it. Call sort once everything is added.
func (table *clientTable[V]) add(client string, value V) error {
	if mac, err := net.ParseMAC(client); err == nil {
		if table.macs == nil {
			table.macs = make(map[string]V)
		}
		if _, taken := table.macs[mac.String()]; !taken {
			table.macs[mac.String()] = value
		}
		return nil
	}
	prefix, err := parseClientPrefix(client)
	if err != nil {
		return err
	}
	if !prefix.IsSingleIP() {
		table.prefixes = append(table.prefixes, clientPrefix[V]{prefix: prefix, value: value})
		return nil
	}
	if table.exact == nil {
		table.exact = make(map[netip.Addr]V)
	}
	if _, taken := table.exact[prefix.Addr()]; !taken {
		table.exact[prefix.Addr()] = value
	}
	return nil
}

// sort puts the most specific network first; among equals, the one added
// first.
func (table *clientTable[V]) sort() {
	slices.SortStableFunc(table.prefixes, func(left, right clientPrefix[V]) int {
		return cmp.Compare(right.prefix.Bits(), left.prefix.Bits())
	})
}

func (table *clientTable[V]) empty() bool {
	return len(table.exact) == 0 && len(table.macs) == 0 && len(table.prefixes) == 0
}

func (table *clientTable[V]) lookup(client policyClient) (V, bool) {
	if value, found := table.exact[client.address]; found {
		return value, true
	}
	if client.mac != "" {
		if value, found := table.macs[client.mac]; found {
			return value, true
		}
	}
	for _, entry := range table.prefixes {
		if entry.prefix.Contains(client.address) {
			return entry.value, true
		}
	}
	var zero V
	return zero, false
}

func parseClientPrefix(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid client %q", value)
	}
	address = address.Unmap()
	return netip.PrefixFrom(address, address.BitLen()), nil
}
