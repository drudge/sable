//go:build darwin

package neighbors

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

func read() ([]Entry, error) {
	entries := make([]Entry, 0)
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		raw, err := route.FetchRIB(family, route.RIBTypeRoute, 0)
		if err != nil {
			return nil, err
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, raw)
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			routeMessage, ok := message.(*route.RouteMessage)
			if !ok || routeMessage.Flags&syscall.RTF_LLINFO == 0 || len(routeMessage.Addrs) <= syscall.RTAX_GATEWAY {
				continue
			}
			var address netip.Addr
			switch destination := routeMessage.Addrs[syscall.RTAX_DST].(type) {
			case *route.Inet4Addr:
				address = netip.AddrFrom4(destination.IP)
			case *route.Inet6Addr:
				address = netip.AddrFrom16(destination.IP)
			}
			link, ok := routeMessage.Addrs[syscall.RTAX_GATEWAY].(*route.LinkAddr)
			if !ok {
				continue
			}
			mac := append(net.HardwareAddr(nil), link.Addr...)
			if usable(address, mac) {
				entries = append(entries, Entry{Address: address, MAC: mac})
			}
		}
	}
	return entries, nil
}
