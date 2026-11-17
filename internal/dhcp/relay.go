package dhcp

import "net/netip"

// relayLinkSelection is the link selection sub-option of option 82
// (RFC 3527 §3).
const relayLinkSelection = 5

// LinkHint is the client's subnet as a relay names it apart from giaddr:
// option 82's link selection sub-option (RFC 3527) or the subnet selection
// option (RFC 3011). Relays that send one may set giaddr to an address
// outside the client's subnet. Sable picks the scope from giaddr alone, so
// this is reported, not used. Source names the option; it is empty when the
// request carries neither.
func LinkHint(request Packet) (address netip.Addr, source string) {
	if info, found := request.Option(optionRelayInfo); found {
		for rest := info; len(rest) >= 2 && len(rest) >= 2+int(rest[1]); rest = rest[2+int(rest[1]):] {
			if rest[0] == relayLinkSelection && rest[1] == 4 {
				return netip.AddrFrom4([4]byte(rest[2:6])), "link selection (RFC 3527)"
			}
		}
	}
	if data, found := request.Option(optionSubnetSelect); found && len(data) == 4 {
		return netip.AddrFrom4([4]byte(data)), "subnet selection (RFC 3011)"
	}
	return netip.Addr{}, ""
}
