package dhcp

import (
	"errors"
	"net"
	"net/netip"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"
)

// This file is the only one that knows the packet library: it reads and
// writes the wire format and nothing else.

// Parse reads a DHCP message off the wire. It rejects anything that isn't a
// BOOTREQUEST carrying a message type, since the engine answers nothing else.
func Parse(data []byte) (Packet, error) {
	message, err := dhcpv4.FromBytes(data)
	if err != nil {
		return Packet{}, err
	}
	if message.OpCode != dhcpv4.OpcodeBootRequest {
		return Packet{}, errors.New("not a BOOTREQUEST")
	}
	packet := Packet{
		Op: uint8(message.OpCode), HType: uint8(message.HWType), Hops: message.HopCount,
		XID: message.TransactionID, Secs: message.NumSeconds, Flags: message.Flags,
		CIAddr: addr4(message.ClientIPAddr), YIAddr: addr4(message.YourIPAddr),
		SIAddr: addr4(message.ServerIPAddr), GIAddr: addr4(message.GatewayIPAddr),
		CHAddr: message.ClientHWAddr, SName: message.ServerHostName, File: message.BootFileName,
	}
	for code, payload := range message.Options {
		packet.Options = append(packet.Options, Option{Code: code, Data: payload})
	}
	if packet.MessageType() == 0 {
		return Packet{}, errors.New("no DHCP message type")
	}
	return packet, nil
}

// Marshal writes the packet in wire format. Option 82 goes last, as
// RFC 3046 §2.1 requires; long options are split (RFC 3396); the message is
// padded to BOOTP's 300 bytes.
func (packet Packet) Marshal() []byte {
	message := dhcpv4.DHCPv4{
		OpCode: dhcpv4.OpcodeType(packet.Op), HWType: iana.HWType(packet.HType), HopCount: packet.Hops,
		TransactionID: packet.XID, NumSeconds: packet.Secs, Flags: packet.Flags,
		ClientIPAddr: ip4(packet.CIAddr), YourIPAddr: ip4(packet.YIAddr),
		ServerIPAddr: ip4(packet.SIAddr), GatewayIPAddr: ip4(packet.GIAddr),
		ClientHWAddr: packet.CHAddr, ServerHostName: packet.SName, BootFileName: packet.File,
		Options: dhcpv4.Options{},
	}
	for _, option := range packet.Options {
		message.Options[option.Code] = option.Data
	}
	return message.ToBytes()
}

func addr4(ip net.IP) netip.Addr {
	address, ok := netip.AddrFromSlice(ip.To4())
	if !ok {
		return netip.IPv4Unspecified()
	}
	return address
}

func ip4(address netip.Addr) net.IP {
	if !address.Is4() {
		return net.IPv4zero.To4()
	}
	octets := address.As4()
	return net.IP(octets[:])
}
