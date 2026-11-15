package web

import (
	"net/netip"
	"testing"
)

// Review of #633: the scope setup suggests must not hand out the router's own
// address. 10.0.0.138 is the stock gateway of a whole family of ISP modems,
// and .100-.199 is the suggested pool on a /24.
func TestReview633SuggestedRangeLeavesOutTheRouter(t *testing.T) {
	t.Parallel()
	for _, network := range []DHCPNetwork{
		{Interface: "eth0", Prefix: netip.MustParsePrefix("10.0.0.2/24"), Gateway: netip.MustParseAddr("10.0.0.138")},
		{Interface: "eth0", Prefix: netip.MustParsePrefix("10.0.0.2/24"), Gateway: netip.MustParseAddr("10.0.0.100")},
		{Interface: "eth0", Prefix: netip.MustParsePrefix("10.0.0.2/24"), Gateway: netip.MustParseAddr("10.0.0.199")},
		{Interface: "eth0", Prefix: netip.MustParsePrefix("10.0.0.2/27"), Gateway: netip.MustParseAddr("10.0.0.30")},
	} {
		scope := dhcpSuggestedScope(network, "lan")
		if scope.Router != network.Gateway.String() {
			t.Fatalf("%v via %v: suggested router %q", network.Prefix, network.Gateway, scope.Router)
		}
		for _, pool := range scope.Ranges {
			start, end := netip.MustParseAddr(pool.Start), netip.MustParseAddr(pool.End)
			if start.Compare(end) > 0 {
				t.Errorf("%v via %v: suggested range %s - %s is inverted", network.Prefix, network.Gateway, start, end)
			}
			if network.Gateway.Compare(start) >= 0 && network.Gateway.Compare(end) <= 0 {
				t.Errorf("%v via %v: suggested range %s - %s hands out the router's own address", network.Prefix, network.Gateway, start, end)
			}
		}
	}
}
