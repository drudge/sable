package web

import (
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
)

// A member removed while a range is still pinned to it leaves that range
// with no node (D65). Every DHCP edit is then refused ("... is not a cluster
// member") until the range is moved, and the scope dialog kept it as it was
// when the range's ends hadn't changed. Saving the scope splits the range
// across the nodes there are.
func TestDHCPConsoleSplitsARangeWhoseNodeLeft(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPClusterConsoleServer(t, "node-a", "")
	configuration.snapshot.Config.DHCP.Scopes[0].Ranges = []config.DHCPRange{
		{Start: "192.0.2.100", End: "192.0.2.149", Node: "node-a"}, {Start: "192.0.2.150", End: "192.0.2.199", Node: "node-gone"}}
	scope := configuration.snapshot.Config.DHCP.Scopes[0]
	form := url.Values{"id": {scope.ID}, "name": {scope.Name}, "subnet": {scope.Subnet}, "router": {scope.Router}, "domain": {scope.Domain},
		"range_start": {"192.0.2.100"}, "range_end": {"192.0.2.199"}}
	response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/scopes", form)
	for _, pool := range configuration.snapshot.Config.DHCP.Scopes[0].Ranges {
		if pool.Node != "node-a" && pool.Node != "node-b" {
			t.Fatalf("saving the scope = %d and left %s-%s pinned to %q, which isn't a member", response.Code, pool.Start, pool.End, pool.Node)
		}
	}
}

// A hand-set gap (D90) outlives the member a range was pinned to: saving the
// same range pins the orphaned range to a member, and the gap stays out of
// the pool.
func TestDHCPConsoleAdoptsAnOrphanedRangeAndKeepsTheGap(t *testing.T) {
	t.Parallel()
	nodes := []cluster.Node{{ID: "node-a", Name: "ns1"}, {ID: "node-b", Name: "ns2"}}
	ranges := []config.DHCPRange{
		{Start: "192.0.2.100", End: "192.0.2.109", Node: "node-a"},
		{Start: "192.0.2.120", End: "192.0.2.129", Node: "node-gone"}}
	got, err := dhcpFormRanges(ranges, "192.0.2.100", "192.0.2.129", nodes)
	want := []config.DHCPRange{
		{Start: "192.0.2.100", End: "192.0.2.109", Node: "node-a"},
		{Start: "192.0.2.120", End: "192.0.2.129", Node: "node-b"}}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("dhcpFormRanges with node-gone = %v, %v; want %v", got, err, want)
	}
	if ranges[1].Node != "node-gone" {
		t.Fatalf("dhcpFormRanges changed the ranges it was given: %v", ranges)
	}
	got, err = dhcpFormRanges([]config.DHCPRange{
		{Start: "192.0.2.100", End: "192.0.2.109", Node: "node-gone"},
		{Start: "192.0.2.120", End: "192.0.2.129", Node: "node-a"},
		{Start: "192.0.2.140", End: "192.0.2.149", Node: "node-a"}}, "192.0.2.100", "192.0.2.149", nodes)
	if err != nil || got[0].Node != "node-b" {
		t.Fatalf("dhcpFormRanges = %v, %v; want the orphaned range on node-b, the member holding none", got, err)
	}
}
