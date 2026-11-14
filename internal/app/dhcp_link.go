package app

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/drudge/sable/internal/dhcp"
)

// dhcpLink is the interface a request came in on, with its IPv4 prefixes:
// the engine serves the scope whose subnet holds one of them. Interfaces
// come and go (a VLAN brought up, a DHCP-assigned host address renewed), so
// it's read for each request; at DHCP's rate that costs nothing.
func dhcpLink(ifIndex int) (dhcp.Meta, error) {
	device, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		return dhcp.Meta{}, fmt.Errorf("interface %d: %w", ifIndex, err)
	}
	addresses, err := device.Addrs()
	if err != nil {
		return dhcp.Meta{}, fmt.Errorf("addresses of %s: %w", device.Name, err)
	}
	meta := dhcp.Meta{Interface: device.Name}
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(network.IP)
		if !ok || !ip.Unmap().Is4() {
			continue
		}
		bits, _ := network.Mask.Size()
		if len(network.Mask) == net.IPv6len {
			bits -= 96
		}
		meta.Addrs = append(meta.Addrs, netip.PrefixFrom(ip.Unmap(), bits))
	}
	return meta, nil
}
