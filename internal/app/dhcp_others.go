package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dhcp"
)

const (
	// dhcpOptionVendorClass is the vendor class identifier (RFC 2132 §9.13).
	dhcpOptionVendorClass = 60
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
	failing := map[string]bool{}
	for {
		found, failed := service.findOthers(ctx, settings)
		if ctx.Err() != nil {
			return
		}
		service.setOthers(found)
		service.noteProbeFailures(failing, failed)
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
// Failed maps each interface the probe couldn't go out of to why.
func (service *dhcpService) findOthers(ctx context.Context, settings config.DHCP) (found []dhcpOtherServer, failed map[string]error) {
	failed = map[string]error{}
	links, err := service.links()
	if err != nil {
		failed[""] = err
		return nil, failed
	}
	own := service.ownAddresses(links)
	for _, link := range links {
		if !dhcpServesLink(settings, link.Meta) {
			continue
		}
		others, err := service.probeLink(ctx, link, own)
		if err != nil {
			failed[link.Meta.Interface] = err
		}
		found = append(found, others...)
	}
	return found, failed
}

// ownAddresses is the server identifiers that aren't another server: this
// node's interface addresses and its cluster peers' addresses, since a peer
// serves its own ranges of the same scopes (D36).
func (service *dhcpService) ownAddresses(links []dhcpProbeLink) map[netip.Addr]bool {
	own := map[netip.Addr]bool{}
	for _, link := range links {
		for _, prefix := range link.Meta.Addrs {
			own[prefix.Addr()] = true
		}
	}
	for _, node := range service.clusterState().Nodes {
		for _, text := range node.Addresses {
			if address, err := netip.ParseAddr(text); err == nil {
				own[address.Unmap()] = true
			}
		}
	}
	return own
}

// noteProbeFailures logs when the probe stops being able to go out of an
// interface, and when it can again, rather than at every probe: a probe that
// can't run never sees another server, so its silence isn't an all-clear.
// Failing is the interfaces failing after the last probe; it's updated.
func (service *dhcpService) noteProbeFailures(failing map[string]bool, failed map[string]error) {
	for name, err := range failed {
		if !failing[name] {
			failing[name] = true
			service.logger.Warn("can't probe for another DHCP server; conflicting servers go unnoticed",
				"interface", name, "error", err)
		}
	}
	for name := range failing {
		if _, still := failed[name]; !still {
			delete(failing, name)
			service.logger.Warn("probing for another DHCP server again", "interface", name)
		}
	}
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
func (service *dhcpService) probeLink(ctx context.Context, link dhcpProbeLink, own map[netip.Addr]bool) ([]dhcpOtherServer, error) {
	discover := dhcpProbeDiscover(link.MAC, service.ownProbes.tag())
	defer service.ownProbes.add(discover.XID)()
	var found []dhcpOtherServer
	for try := range dhcpOthersTries {
		discover.Secs = uint16(try) * uint16(dhcpOthersWait/time.Second)
		replies, err := service.seek(ctx, link, discover.Marshal(), dhcpOthersWait)
		if err != nil {
			return nil, err
		}
		if found = dhcpOtherOffers(link, discover, replies, own); len(found) > 0 || ctx.Err() != nil {
			break
		}
	}
	return found, nil
}

// dhcpOwnProbes is the transaction IDs of this node's probe DISCOVERs in
// flight. A probe's broadcast loops back to this node's own port 67 socket,
// and answering it would hold a pool address on offer to the node itself at
// every probe (F32, D36). Only this process's IDs are dropped, so two
// standalone servers on one link still find each other. On a cluster a probe
// also carries the cluster's tag (dhcpProbeVendorPrefix), and every node of
// the cluster drops it the same way.
type dhcpOwnProbes struct {
	mutex sync.Mutex
	xids  map[[4]byte]int
	// cluster is this node's cluster ID, empty outside a cluster. Nil is
	// outside a cluster.
	cluster func() string
}

// dhcpProbeVendorPrefix starts the vendor class identifier (option 60, RFC
// 2132 §9.13) of a cluster node's probe; the cluster ID follows it.
const dhcpProbeVendorPrefix = "sable-probe/"

// tag is the vendor class this node's probes carry: nil outside a cluster.
func (probes *dhcpOwnProbes) tag() []byte {
	if probes == nil || probes.cluster == nil {
		return nil
	}
	id := probes.cluster()
	if id == "" {
		return nil
	}
	return []byte(dhcpProbeVendorPrefix + id)
}

// add marks xid in flight until the returned func is called.
func (probes *dhcpOwnProbes) add(xid [4]byte) func() {
	probes.mutex.Lock()
	defer probes.mutex.Unlock()
	if probes.xids == nil {
		probes.xids = map[[4]byte]int{}
	}
	probes.xids[xid]++
	return func() {
		probes.mutex.Lock()
		defer probes.mutex.Unlock()
		if probes.xids[xid]--; probes.xids[xid] <= 0 {
			delete(probes.xids, xid)
		}
	}
}

// sent reports whether datagram is a client message (op BOOTREQUEST, RFC 2131
// §2) carrying the transaction ID of a probe in flight.
func (probes *dhcpOwnProbes) sent(datagram []byte) bool {
	if probes == nil || len(datagram) < 8 || datagram[0] != 1 {
		return false
	}
	probes.mutex.Lock()
	_, found := probes.xids[[4]byte(datagram[4:8])]
	probes.mutex.Unlock()
	return found || probes.fromPeer(datagram)
}

// fromPeer reports whether datagram is a probe from a node of this node's
// cluster: it carries the cluster's tag.
func (probes *dhcpOwnProbes) fromPeer(datagram []byte) bool {
	tag := probes.tag()
	if tag == nil {
		return false
	}
	request, err := dhcp.Parse(datagram)
	if err != nil {
		return false
	}
	vendor, found := request.Option(dhcpOptionVendorClass)
	return found && bytes.Equal(vendor, tag)
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

// dhcpProbeDiscover is a DISCOVER from mac with a random transaction ID, the
// broadcast flag, and the cluster's tag as its vendor class when it has one.
func dhcpProbeDiscover(mac net.HardwareAddr, tag []byte) dhcp.Packet {
	packet := dhcp.Packet{
		Op: 1, HType: 1, Flags: 0x8000, CHAddr: mac,
		CIAddr: netip.IPv4Unspecified(), YIAddr: netip.IPv4Unspecified(),
		SIAddr: netip.IPv4Unspecified(), GIAddr: netip.IPv4Unspecified(),
		Options: []dhcp.Option{{Code: 53, Data: []byte{byte(dhcp.Discover)}}},
	}
	if tag != nil {
		packet.Options = append(packet.Options, dhcp.Option{Code: dhcpOptionVendorClass, Data: tag})
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
