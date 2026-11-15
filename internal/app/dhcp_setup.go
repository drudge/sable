package app

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web"
)

// Networks lists the IPv4 networks this host has an address on, for the
// console's setup flow. A /31 or /32 has no room for a pool.
func (service *dhcpService) Networks() ([]web.DHCPNetwork, error) {
	links, err := service.links()
	if err != nil {
		return nil, err
	}
	gateways := service.gateways()
	var networks []web.DHCPNetwork
	for _, link := range links {
		for _, prefix := range link.Meta.Addrs {
			if prefix.Addr().Is4() && prefix.Bits() <= 30 && !prefix.Addr().IsLinkLocalUnicast() {
				networks = append(networks, web.DHCPNetwork{Interface: link.Meta.Interface, Prefix: prefix, Gateway: gateways[link.Meta.Interface]})
			}
		}
	}
	return networks, nil
}

// FindOthers runs the other-server probe now, for Turn On: the same probe
// the running server repeats every five minutes.
func (service *dhcpService) FindOthers(ctx context.Context, settings config.DHCP) ([]web.DHCPOtherServer, error) {
	found, failed := service.findOthers(ctx, settings)
	others := make([]web.DHCPOtherServer, 0, len(found))
	for _, other := range found {
		others = append(others, web.DHCPOtherServer{Interface: other.Interface, Server: other.Server, Offered: other.Offered})
	}
	var problems []error
	for _, name := range slices.Sorted(maps.Keys(failed)) {
		if name == "" {
			problems = append(problems, failed[name])
		} else {
			problems = append(problems, fmt.Errorf("%s: %w", name, failed[name]))
		}
	}
	return others, errors.Join(problems...)
}

// dhcpDefaultGateways reads each interface's default route from
// /proc/net/route. Off Linux, or when it can't be read, there are none and
// setup leaves the router for the operator to fill in.
func dhcpDefaultGateways() map[string]netip.Addr {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil
	}
	defer file.Close()
	return parseDefaultGateways(bufio.NewScanner(file))
}

// parseDefaultGateways reads /proc/net/route's table: Iface, Destination,
// Gateway, in hex in host byte order, which is little-endian on every
// platform Sable ships for.
func parseDefaultGateways(lines *bufio.Scanner) map[string]netip.Addr {
	gateways := map[string]netip.Addr{}
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		var address [4]byte
		binary.BigEndian.PutUint32(address[:], binary.LittleEndian.Uint32(raw))
		if gateway := netip.AddrFrom4(address); !gateway.IsUnspecified() {
			if _, ok := gateways[fields[0]]; !ok {
				gateways[fields[0]] = gateway
			}
		}
	}
	return gateways
}
