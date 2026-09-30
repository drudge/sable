package app

import (
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/drudge/sable/internal/localnet"
)

// devDemoAttachedNetworksEnv names the IPv6 networks the Vandelay demo's nodes
// act as if they were attached to, comma-separated, in place of the host's
// own. Set but empty, a node is attached to none. It keeps the demo's pages
// and screenshots from showing the developer's real network.
const devDemoAttachedNetworksEnv = "SABLE_DEV_DEMO_ATTACHED_NETWORKS"

// attachedInterfaceReader reads this host's interfaces, or the demo's
// stand-in LAN when the demo names one.
func attachedInterfaceReader() func() ([]localnet.Interface, error) {
	configured, found := os.LookupEnv(devDemoAttachedNetworksEnv)
	if !found {
		return localnet.ReadInterfaces
	}
	lan := localnet.Interface{Name: "eth0", Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast}
	for value := range strings.SplitSeq(configured, ",") {
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(value)); err == nil {
			lan.Addresses = append(lan.Addresses, prefix)
		}
	}
	if len(lan.Addresses) > 0 {
		// The stand-in LAN also has a private IPv4 address, like a real one.
		lan.Addresses = append(lan.Addresses, netip.MustParsePrefix("10.0.0.2/24"))
	}
	return func() ([]localnet.Interface, error) { return []localnet.Interface{lan}, nil }
}
