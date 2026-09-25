package devices

import (
	"net"
	"net/netip"
)

// hardwareFromAddress reads the hardware address an IPv6 address was built
// from. A device that forms its addresses the original SLAAC way (RFC 4291)
// puts its hardware address in the interface identifier, with ff:fe in the
// middle and the universal/local bit flipped, so such an address names its
// device without a neighbor table or a controller.
func hardwareFromAddress(address string) (string, bool) {
	parsed, err := netip.ParseAddr(address)
	if err != nil || !parsed.Is6() || parsed.Is4In6() || parsed.IsUnspecified() || parsed.IsLoopback() || parsed.IsMulticast() {
		return "", false
	}
	octets := parsed.As16()
	if octets[11] != 0xff || octets[12] != 0xfe {
		return "", false
	}
	mac := net.HardwareAddr{octets[8] ^ 0x02, octets[9], octets[10], octets[13], octets[14], octets[15]}
	// A multicast hardware address is never one device, and no device has an
	// all-zero one.
	if mac[0]&0x01 != 0 || mac[0]|mac[1]|mac[2]|mac[3]|mac[4]|mac[5] == 0 {
		return "", false
	}
	return mac.String(), true
}

// privacyAddress reports an IPv6 address with a random interface identifier:
// a temporary address phones and computers make for themselves and replace
// about once a day (RFC 8981), or a stable random one they keep for each
// network (RFC 7217). Neither says which device made it, and a temporary one
// turning up or falling silent is routine. An identifier built from a hardware
// address, or a small assigned one such as ::1a, is not random.
func privacyAddress(address string) bool {
	parsed, err := netip.ParseAddr(address)
	if err != nil || !parsed.Is6() || parsed.Is4In6() || !parsed.IsGlobalUnicast() {
		return false
	}
	if _, built := hardwareFromAddress(address); built {
		return false
	}
	octets := parsed.As16()
	// An assigned identifier leaves the top half of the interface identifier
	// zero, which a random one all but never does.
	return octets[8]|octets[9]|octets[10]|octets[11] != 0
}

// PrivacyAddressesOnly reports a device Sable knows only by IPv6 privacy
// addresses it could not tie to hardware or a name. Such an address arriving
// or going quiet is a device replacing its address, not a device joining or
// leaving; the device itself is still reported by its other addresses.
func (device Device) PrivacyAddressesOnly() bool {
	if device.Identified() || len(device.Addresses) == 0 {
		return false
	}
	for _, address := range device.Addresses {
		if !privacyAddress(address.Address) {
			return false
		}
	}
	return true
}
