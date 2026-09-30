package localnet

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func prefixes(values ...string) []netip.Prefix {
	parsed := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		parsed = append(parsed, netip.MustParsePrefix(value))
	}
	return parsed
}

// A LAN interface counts its global IPv6 networks. Loopback, tunnels, down
// interfaces, and a server with only public addresses don't.
func TestDetectCountsOnlyLANInterfaces(t *testing.T) {
	up := net.FlagUp | net.FlagBroadcast | net.FlagMulticast
	found := Detect([]Interface{
		{Name: "lo", Flags: net.FlagUp | net.FlagLoopback, Addresses: prefixes("127.0.0.1/8", "::1/128")},
		{Name: "eth0", Flags: up, Addresses: prefixes("10.0.7.12/24", "2001:db8:1234:1500:be24:11ff:fe5c:59c5/64", "fe80::be24:11ff:fe5c:59c5/64")},
		// A DHCPv6 address stands for the /64 it sits in.
		{Name: "eth1", Flags: up, Addresses: prefixes("fd00:1::2/64", "2001:db8:1234:1600::25/128")},
		{Name: "wg0", Flags: net.FlagUp | net.FlagPointToPoint, Addresses: prefixes("10.8.0.1/24", "2001:db8:9::1/64")},
		{Name: "eth2", Flags: net.FlagBroadcast, Addresses: prefixes("192.168.1.2/24", "2001:db8:1234:1700::1/64")},
		// A VPS: a public IPv4 and a provider's shared on-link prefix.
		{Name: "ens3", Flags: up, Addresses: prefixes("203.0.113.8/24", "2001:db8:ffff::8/64")},
		// Broader than any LAN.
		{Name: "eth3", Flags: up, Addresses: prefixes("100.64.0.2/10", "2001:db8::1/32", "2001:db8:1234:1800::1/64")},
	})
	want := []Network{
		{Prefix: netip.MustParsePrefix("2001:db8:1234:1500::/64"), Interface: "eth0"},
		{Prefix: netip.MustParsePrefix("2001:db8:1234:1600::/64"), Interface: "eth1"},
		{Prefix: netip.MustParsePrefix("2001:db8:1234:1800::/64"), Interface: "eth3"},
	}
	if !slices.Equal(found, want) {
		t.Fatalf("Detect = %+v, want %+v", found, want)
	}
}

// The watcher publishes only changes, keeps what it knew through a failed
// read, and joins the lead's networks with its own while they are fresh.
func TestWatcherPublishesChangesAndTheLeadsNetworks(t *testing.T) {
	var published [][]netip.Prefix
	watcher := NewWatcher(func(current []netip.Prefix) { published = append(published, current) })
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	watcher.now = func() time.Time { return now }
	lan := []Interface{{Name: "eth0", Flags: net.FlagUp, Addresses: prefixes("10.0.7.12/24", "2001:db8:1234:1500::12/64")}}
	read := func() ([]Interface, error) { return lan, nil }

	if err := watcher.Refresh(read); err != nil {
		t.Fatal(err)
	}
	if err := watcher.Refresh(read); err != nil {
		t.Fatal(err)
	}
	if len(published) != 1 || !slices.Equal(published[0], prefixes("2001:db8:1234:1500::/64")) {
		t.Fatalf("published %v, want the LAN once", published)
	}
	if err := watcher.Refresh(func() ([]Interface, error) { return nil, errors.New("no interfaces") }); err == nil {
		t.Fatal("a failed read reported no error")
	}
	if got := watcher.Prefixes(); !slices.Equal(got, prefixes("2001:db8:1234:1500::/64")) {
		t.Fatalf("a failed read dropped the networks: %v", got)
	}

	watcher.SetLead("ns1", prefixes("2001:db8:1234:1500::/64", "2001:db8:1234:1600::/64"))
	networks := watcher.Networks()
	if len(networks) != 2 || networks[0].Interface != "eth0" || networks[1].Node != "ns1" ||
		networks[1].Prefix != netip.MustParsePrefix("2001:db8:1234:1600::/64") {
		t.Fatalf("networks with the lead's = %+v", networks)
	}
	if got := published[len(published)-1]; !slices.Equal(got, prefixes("2001:db8:1234:1500::/64", "2001:db8:1234:1600::/64")) {
		t.Fatalf("published %v after the lead shared", got)
	}
	if got := watcher.Own(); !slices.Equal(got, prefixes("2001:db8:1234:1500::/64")) {
		t.Fatalf("own networks %v include the lead's", got)
	}

	// A node that stops hearing from the lead, because it leads now or left
	// the cluster, drops the lead's networks on its next read.
	now = now.Add(leadFreshness + time.Second)
	if err := watcher.Refresh(read); err != nil {
		t.Fatal(err)
	}
	if got := published[len(published)-1]; !slices.Equal(got, prefixes("2001:db8:1234:1500::/64")) {
		t.Fatalf("published %v after the lead's networks went stale", got)
	}
}
