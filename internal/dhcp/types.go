// Package dhcp is the DHCPv4 server's state machine (RFC 2131). It has no
// sockets and no store: Handle takes a parsed request, the arrival link, and
// the time, and returns the reply and what the caller must do around it.
package dhcp

import (
	"net"
	"net/netip"
	"time"
)

// MessageType is option 53 (RFC 2132 §9.6).
type MessageType uint8

// Message types from RFC 2132 §9.6.
const (
	Discover MessageType = 1
	Offer    MessageType = 2
	Request  MessageType = 3
	Decline  MessageType = 4
	Ack      MessageType = 5
	Nak      MessageType = 6
	Release  MessageType = 7
	Inform   MessageType = 8
)

// String is the message type's name as RFC 2132 §9.6 writes it, without the
// DHCP prefix.
func (kind MessageType) String() string {
	names := [...]string{"", "DISCOVER", "OFFER", "REQUEST", "DECLINE", "ACK", "NAK", "RELEASE", "INFORM"}
	if int(kind) < len(names) && kind != 0 {
		return names[kind]
	}
	return "unknown"
}

// Option codes the engine reads or writes itself (RFC 2132, RFC 3046,
// RFC 3397, RFC 3442, RFC 5859, RFC 6842, RFC 8925).
const (
	optionSubnetMask    = 1
	optionRouter        = 3
	optionDNS           = 6
	optionHostname      = 12
	optionDomain        = 15
	optionBroadcast     = 28
	optionNTP           = 42
	optionRequestedIP   = 50
	optionLeaseTime     = 51
	optionMessageType   = 53
	optionServerID      = 54
	optionParameters    = 55
	optionMessage       = 56
	optionMaxSize       = 57
	optionRenewal       = 58
	optionRebinding     = 59
	optionVendorClass   = 60
	optionClientID      = 61
	optionTFTPServer    = 66
	optionBootFile      = 67
	optionClientFQDN    = 81
	optionRelayInfo     = 82
	optionV6OnlyPrefer  = 108
	optionSubnetSelect  = 118
	optionSearch        = 119
	optionRoutes        = 121
	optionTFTPAddresses = 150
	optionMSRoutes      = 249
)

// Packet is one DHCP message, client's or server's (RFC 2131 §2), with its
// options in the order they go on the wire.
type Packet struct {
	Op      uint8 // 1 BOOTREQUEST, 2 BOOTREPLY
	HType   uint8
	Hops    uint8
	XID     [4]byte
	Secs    uint16
	Flags   uint16
	CIAddr  netip.Addr
	YIAddr  netip.Addr
	SIAddr  netip.Addr
	GIAddr  netip.Addr
	CHAddr  net.HardwareAddr
	SName   string
	File    string
	Options []Option
}

// Option is one option's code and payload.
type Option struct {
	Code uint8
	Data []byte
}

// broadcastFlag is the B bit of flags (RFC 2131 §2, Figure 2).
const broadcastFlag = 0x8000

// Option returns the payload of the first option with code, if any.
func (packet Packet) Option(code uint8) ([]byte, bool) {
	for _, option := range packet.Options {
		if option.Code == code {
			return option.Data, true
		}
	}
	return nil, false
}

// MessageType returns option 53, or 0 when it's missing or malformed.
func (packet Packet) MessageType() MessageType {
	data, found := packet.Option(optionMessageType)
	if !found || len(data) != 1 {
		return 0
	}
	return MessageType(data[0])
}

// Meta is where a request arrived: the interface's addresses with their
// prefixes, and the datagram's destination address. A scope is served on the
// link whose subnet holds one of them.
type Meta struct {
	Interface string
	Addrs     []netip.Prefix
	// To is the datagram's destination: a broadcast, or this node's own
	// address for a client that renews by unicast. Unset when the socket
	// couldn't say, which counts as a broadcast.
	To netip.Addr
}

// unicast reports the address a request was sent to when it came to this
// node by unicast: not the limited broadcast, nor a directed broadcast of the
// arrival link (RFC 919 §7, RFC 922 §7). A /31 or /32 has no directed
// broadcast (RFC 3021): its last address is a host, often this node.
func (meta Meta) unicast() (netip.Addr, bool) {
	to := meta.To.Unmap()
	if !to.Is4() || to.IsUnspecified() || to.IsMulticast() || to == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, false
	}
	for _, local := range meta.Addrs {
		if local.Addr().Unmap().Is4() && local.Bits() < 31 && to == lastAddress(local) {
			return netip.Addr{}, false
		}
	}
	return to, true
}

// lastAddress is the all-ones host address of an IPv4 prefix, its directed
// broadcast.
func lastAddress(prefix netip.Prefix) netip.Addr {
	octets := prefix.Masked().Addr().Unmap().As4()
	host := uint32(1)<<(32-prefix.Bits()) - 1
	value := uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3]) | host
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

// Destination is where a reply goes (RFC 2131 §4.1).
type Destination int

// Reply destinations, in the order RFC 2131 §4.1 checks them.
const (
	ToRelay     Destination = iota + 1 // giaddr, port 67
	ToClient                           // ciaddr, port 68
	ToBroadcast                        // 255.255.255.255, port 68
	ToHardware                         // yiaddr at chaddr, port 68
)

// Result is what Handle decided. Reply is nil when nothing is sent; Drop then
// says why, for the stats.
type Result struct {
	Reply       *Packet
	Destination Destination
	// Save is the leases to write, in order, before the reply goes out, so
	// a client is never told it holds a lease the store doesn't have. An ACK
	// that moves a client carries its old lease, released, first.
	Save []Lease
	// Delay holds an OFFER back (offer_delay).
	Delay time.Duration
	// Probe is an address to check for another holder, for up to
	// ProbeTimeout, before the OFFER goes (RFC 2131 §4.4.1). If something
	// answers, call Conflict and send nothing.
	Probe        netip.Addr
	ProbeTimeout time.Duration
	Drop         string
}

// DropRelayNoScope is the Drop for a relayed request whose giaddr is in no
// scope. Unlike a broadcast on a link with no scope, it is always a setup
// mistake: the relay was pointed at this server.
const DropRelayNoScope = "relay address is in no scope"

// LeaseState is where a lease stands.
type LeaseState string

// Lease states. Only active leases hold their address.
const (
	LeaseActive   LeaseState = "active"
	LeaseReleased LeaseState = "released"
	LeaseExpired  LeaseState = "expired"
	LeaseDeclined LeaseState = "declined"
)

// Lease is one address bound to a client, by the node that wrote it.
type Lease struct {
	NodeID      string
	Address     netip.Addr
	ScopeID     string
	ClientKey   string
	MAC         string
	ClientID    string
	Hostname    string
	State       LeaseState
	BoundAt     time.Time
	ExpiresAt   time.Time
	Relay       string
	VendorClass string
}

// holds reports whether the lease keeps its address from other clients at now.
func (lease *Lease) holds(now time.Time) bool {
	switch lease.State {
	case LeaseActive, LeaseDeclined:
		return now.Before(lease.ExpiresAt)
	}
	return false
}
