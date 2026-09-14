package web

import (
	"net"
	"net/netip"
	"slices"
	"strings"
)

func localClusterDNSAddresses(listeners []string) string {
	var addresses []netip.Addr
	interfaces, _ := net.Interfaces()
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 || networkInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		assigned, _ := networkInterface.Addrs()
		for _, address := range assigned {
			if prefix, err := netip.ParsePrefix(address.String()); err == nil && prefix.Addr().IsGlobalUnicast() {
				addresses = append(addresses, prefix.Addr().Unmap())
			}
		}
	}
	return strings.Join(clusterDNSAddressDefaults(listeners, addresses), "\n")
}

func clusterDNSAddressDefaults(listeners []string, local []netip.Addr) []string {
	var result []string
	for _, listener := range listeners {
		endpoint, err := netip.ParseAddrPort(listener)
		if err != nil || endpoint.Port() == 0 {
			continue
		}
		addresses := []netip.Addr{endpoint.Addr().Unmap()}
		if endpoint.Addr().IsUnspecified() {
			addresses = nil
			for _, address := range local {
				if address.IsGlobalUnicast() && address.Is4() == endpoint.Addr().Is4() {
					addresses = append(addresses, address)
				}
			}
		}
		for _, address := range addresses {
			if address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() {
				continue
			}
			value := address.String()
			if endpoint.Port() != 53 {
				value = netip.AddrPortFrom(address, endpoint.Port()).String()
			}
			result = append(result, value)
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}
