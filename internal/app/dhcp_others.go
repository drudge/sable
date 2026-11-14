package app

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dhcp"
)

const (
	// dhcpOthersInterval is how often a serving node looks for another DHCP
	// server on its networks (docs/design/dhcp.md §4). Two servers on one
	// link hand out conflicting leases, and a router whose DHCP came back on
	// after cutover is the usual cause.
	dhcpOthersInterval = 5 * time.Minute
	// dhcpOthersWait is how long a probe listens after each DISCOVER: a
	// client's first retransmit interval (RFC 2131 §4.1). dnsmasq, ISC dhcpd
	// and Windows ping an address before offering it, so the OFFER to a first
	// DISCOVER can come 3 s later; the design's 3 s wait missed dnsmasq about
	// one time in six in the namespace harness.
	dhcpOthersWait = 4 * time.Second
	// dhcpOthersTries is how many DISCOVERs a probe sends while nothing
	// answers. The retransmit is answered with the offer the first one made.
	dhcpOthersTries = 2
)

// dhcpOtherServer is a DHCP server other than this one that answered a
// probe's DISCOVER with an OFFER.
type dhcpOtherServer struct {
	Interface string
	// Server is the OFFER's server identifier (RFC 2132 §9.7).
	Server  netip.Addr
	Offered netip.Addr
}

// dhcpProbeLink is an interface a probe can go out of.
type dhcpProbeLink struct {
	Index int
	MAC   net.HardwareAddr
	Meta  dhcp.Meta
}

// dhcpDefaultSeek is the seek a new service gets. The package's tests replace
// it, so no test broadcasts a DISCOVER on the network it runs on.
var dhcpDefaultSeek dhcpSeek = seekDHCP

// dhcpSeek broadcasts discover out of link from port 68 and returns every
// datagram that came back to port 68 on that link within wait.
type dhcpSeek func(ctx context.Context, link dhcpProbeLink, discover []byte, wait time.Duration) ([][]byte, error)

// watchOthers probes for other DHCP servers when the server starts and every
// service.othersEvery after, until ctx ends.
func (service *dhcpService) watchOthers(ctx context.Context, settings config.DHCP) {
	for {
		found := service.findOthers(ctx, settings)
		if ctx.Err() != nil {
			return
		}
		service.setOthers(found)
		select {
		case <-ctx.Done():
			return
		case <-time.After(service.othersEvery):
		}
	}
}

// findOthers probes every interface that holds an address in a serving
// scope. Relayed scopes have no local link; their relay agent sees what's
// there.
func (service *dhcpService) findOthers(ctx context.Context, settings config.DHCP) []dhcpOtherServer {
	links, err := service.links()
	if err != nil {
		service.logger.Debug("list interfaces for the DHCP server probe", "error", err)
		return nil
	}
	own := map[netip.Addr]bool{}
	for _, link := range links {
		for _, prefix := range link.Meta.Addrs {
			own[prefix.Addr()] = true
		}
	}
	var found []dhcpOtherServer
	for _, link := range links {
		if dhcpServesLink(settings, link.Meta) {
			found = append(found, service.probeLink(ctx, link, own)...)
		}
	}
	return found
}

// dhcpServesLink reports whether a serving scope's subnet holds one of the
// link's addresses.
func dhcpServesLink(settings config.DHCP, meta dhcp.Meta) bool {
	for _, scope := range settings.Scopes {
		subnet, err := netip.ParsePrefix(scope.Subnet)
		if err != nil || !scope.Serves() {
			continue
		}
		for _, prefix := range meta.Addrs {
			if subnet.Contains(prefix.Addr()) {
				return true
			}
		}
	}
	return false
}

// probeLink sends a DISCOVER with the broadcast flag set, so a server
// answers to the limited broadcast and not to an address the probe doesn't
// hold (RFC 2131 §4.1), retransmits it with the same transaction ID while no
// other server has answered, and returns the servers other than this node's
// own addresses that offered a lease. Nothing is requested, so an offered
// address is only held until that server's offer times out.
func (service *dhcpService) probeLink(ctx context.Context, link dhcpProbeLink, own map[netip.Addr]bool) []dhcpOtherServer {
	discover := dhcpProbeDiscover(link.MAC)
	var found []dhcpOtherServer
	for try := range dhcpOthersTries {
		discover.Secs = uint16(try) * uint16(dhcpOthersWait/time.Second)
		replies, err := service.seek(ctx, link, discover.Marshal(), dhcpOthersWait)
		if err != nil {
			service.logger.Debug("probe for another DHCP server", "interface", link.Meta.Interface, "error", err)
			return nil
		}
		if found = dhcpOtherOffers(link, discover, replies, own); len(found) > 0 || ctx.Err() != nil {
			break
		}
	}
	return found
}

// dhcpOtherOffers is the servers other than own that answered discover with
// an OFFER, each once.
func dhcpOtherOffers(link dhcpProbeLink, discover dhcp.Packet, replies [][]byte, own map[netip.Addr]bool) []dhcpOtherServer {
	var found []dhcpOtherServer
	for _, reply := range replies {
		offer, err := dhcp.ParseReply(reply)
		if err != nil || offer.Op != 2 || offer.XID != discover.XID || offer.MessageType() != dhcp.Offer {
			continue
		}
		identifier, ok := offer.Option(54)
		server, valid := netip.AddrFromSlice(identifier)
		if !ok || !valid || own[server] {
			continue
		}
		other := dhcpOtherServer{Interface: link.Meta.Interface, Server: server, Offered: offer.YIAddr}
		if !slices.ContainsFunc(found, func(seen dhcpOtherServer) bool { return seen.Server == server }) {
			found = append(found, other)
		}
	}
	return found
}

// dhcpProbeDiscover is a DISCOVER from mac with a random transaction ID and
// the broadcast flag.
func dhcpProbeDiscover(mac net.HardwareAddr) dhcp.Packet {
	packet := dhcp.Packet{
		Op: 1, HType: 1, Flags: 0x8000, CHAddr: mac,
		CIAddr: netip.IPv4Unspecified(), YIAddr: netip.IPv4Unspecified(),
		SIAddr: netip.IPv4Unspecified(), GIAddr: netip.IPv4Unspecified(),
		Options: []dhcp.Option{{Code: 53, Data: []byte{byte(dhcp.Discover)}}},
	}
	_, _ = rand.Read(packet.XID[:])
	return packet
}

// setOthers records what the latest probe found and logs each server it
// hadn't seen the time before.
func (service *dhcpService) setOthers(found []dhcpOtherServer) {
	service.othersMutex.Lock()
	defer service.othersMutex.Unlock()
	for _, other := range found {
		if !slices.Contains(service.others, other) {
			service.logger.Warn("another DHCP server answers on this network; clients may get conflicting leases",
				"interface", other.Interface, "server", other.Server, "offered", other.Offered)
		}
	}
	service.others = found
}

// otherServers is what the latest probe found: none while the server isn't
// running.
func (service *dhcpService) otherServers() []dhcpOtherServer {
	if service == nil {
		return nil
	}
	service.othersMutex.Lock()
	defer service.othersMutex.Unlock()
	return slices.Clone(service.others)
}

// dhcpProbeLinks lists the interfaces that are up, with their IPv4
// prefixes, skipping loopback.
func dhcpProbeLinks() ([]dhcpProbeLink, error) {
	devices, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var links []dhcpProbeLink
	for _, device := range devices {
		if device.Flags&net.FlagUp == 0 || device.Flags&net.FlagLoopback != 0 || len(device.HardwareAddr) != 6 {
			continue
		}
		meta, err := dhcpLink(device.Index)
		if err != nil || len(meta.Addrs) == 0 {
			continue
		}
		links = append(links, dhcpProbeLink{Index: device.Index, MAC: device.HardwareAddr, Meta: meta})
	}
	return links, nil
}
