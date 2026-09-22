// Package neighbors reads the host's neighbor table: the IP-to-hardware
// address mappings the kernel learned from ARP and IPv6 neighbor discovery.
// When Sable shares a network with its clients, this is how a device keeps one
// identity while its addresses change. It only sees clients on directly
// attached networks, and nothing inside an isolated container network.
package neighbors

import (
	"errors"
	"net"
	"net/netip"
)

// ErrUnsupported reports a platform with no neighbor table reader.
var ErrUnsupported = errors.New("neighbor table is not available on this platform")

// Entry is one resolved neighbor.
type Entry struct {
	Address netip.Addr
	MAC     net.HardwareAddr
}

// Read returns the current resolved neighbors, skipping entries that are
// incomplete, failed, or carry no usable hardware address.
func Read() ([]Entry, error) { return read() }

// PrivateMAC reports a locally administered hardware address. Phones and
// laptops use these as per-network "private Wi-Fi addresses", so one is stable
// on a network but says nothing about the maker.
func PrivateMAC(mac net.HardwareAddr) bool {
	return len(mac) > 0 && mac[0]&0x02 != 0
}

// usable filters out addresses that cannot identify a client device.
func usable(address netip.Addr, mac net.HardwareAddr) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalMulticast() {
		return false
	}
	if len(mac) != 6 && len(mac) != 8 && len(mac) != 20 {
		return false
	}
	zero, broadcast := true, true
	for _, octet := range mac {
		zero = zero && octet == 0
		broadcast = broadcast && octet == 0xff
	}
	// A multicast bit in the first octet is never a single device.
	return !zero && !broadcast && mac[0]&0x01 == 0
}
