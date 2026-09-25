package neighbors

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// Netlink values from linux/netlink.h, linux/rtnetlink.h, and
// linux/neighbour.h. The parser is platform neutral so it can be tested
// anywhere; only the socket read is Linux specific.
const (
	netlinkHeaderLength = 16
	netlinkNewNeighbor  = 28 // RTM_NEWNEIGH

	ndMessageLength = 12
	ndaDestination  = 1
	ndaLinkAddress  = 2

	nudIncomplete = 0x01
	nudFailed     = 0x20
	nudNoARP      = 0x40
)

// parseNeighborMessages decodes an RTM_GETNEIGH dump into usable entries.
func parseNeighborMessages(raw []byte) []Entry {
	entries := make([]Entry, 0)
	for len(raw) >= netlinkHeaderLength {
		length := int(binary.NativeEndian.Uint32(raw[0:4]))
		kind := binary.NativeEndian.Uint16(raw[4:6])
		if length < netlinkHeaderLength || length > len(raw) {
			break
		}
		if kind == netlinkNewNeighbor {
			if entry, ok := parseNeighbor(raw[netlinkHeaderLength:length]); ok {
				entries = append(entries, entry)
			}
		}
		aligned := (length + 3) &^ 3
		if aligned > len(raw) {
			break
		}
		raw = raw[aligned:]
	}
	return entries
}

func parseNeighbor(data []byte) (Entry, bool) {
	if len(data) < ndMessageLength {
		return Entry{}, false
	}
	state := binary.NativeEndian.Uint16(data[8:10])
	if state&(nudIncomplete|nudFailed|nudNoARP) != 0 {
		return Entry{}, false
	}
	var address netip.Addr
	var mac net.HardwareAddr
	for attributes := data[ndMessageLength:]; len(attributes) >= 4; {
		length := int(binary.NativeEndian.Uint16(attributes[0:2]))
		kind := binary.NativeEndian.Uint16(attributes[2:4])
		if length < 4 || length > len(attributes) {
			break
		}
		value := attributes[4:length]
		switch kind {
		case ndaDestination:
			if parsed, ok := netip.AddrFromSlice(value); ok {
				address = parsed.Unmap()
			}
		case ndaLinkAddress:
			mac = append(net.HardwareAddr(nil), value...)
		}
		aligned := (length + 3) &^ 3
		if aligned >= len(attributes) {
			break
		}
		attributes = attributes[aligned:]
	}
	if !usable(address, mac) {
		return Entry{}, false
	}
	return Entry{Address: address, MAC: mac}, true
}
