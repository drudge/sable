package cluster

import (
	"net/netip"
	"slices"
	"sync"
	"testing"
)

// leadNetworks records what a replica was handed.
type leadNetworks struct {
	mu       sync.Mutex
	node     string
	prefixes []netip.Prefix
	calls    int
}

func (received *leadNetworks) take(node string, prefixes []netip.Prefix) {
	received.mu.Lock()
	defer received.mu.Unlock()
	received.node, received.prefixes, received.calls = node, prefixes, received.calls+1
}

func (received *leadNetworks) read() (string, []netip.Prefix, int) {
	received.mu.Lock()
	defer received.mu.Unlock()
	return received.node, received.prefixes, received.calls
}

// A replica is handed the lead's networks in every synchronization, named for
// the lead, and an emptied list reaches it too.
func TestReplicaTakesTheLeadsAttachedNetworks(t *testing.T) {
	t.Parallel()
	primary, replica := joinedClusterServices(t)
	var mu sync.Mutex
	own := []netip.Prefix{netip.MustParsePrefix("2001:db8:1234:1500::/64")}
	primary.SetAttachedNetworks(AttachedNetworks{Own: func() []netip.Prefix {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(own)
	}})
	received := &leadNetworks{}
	replica.SetAttachedNetworks(AttachedNetworks{Lead: received.take})

	synchronize(t, replica, 1)
	node, prefixes, calls := received.read()
	if calls != 1 || node != primary.nodeName || !slices.Equal(prefixes, own) {
		t.Fatalf("replica took %v from %q in %d calls, want %v from %q", prefixes, node, calls, own, primary.nodeName)
	}

	mu.Lock()
	own = nil
	mu.Unlock()
	synchronize(t, replica, 1)
	if _, prefixes, calls := received.read(); calls != 2 || len(prefixes) != 0 {
		t.Fatalf("after the lead lost its network the replica took %v in %d calls", prefixes, calls)
	}
}

// A lead too old to share networks sends none, and a replica keeps only its
// own. Anything that isn't a global IPv6 network of a LAN's size is dropped.
func TestReplicaIgnoresMissingOrUnusableNetworks(t *testing.T) {
	t.Parallel()
	primary, replica := joinedClusterServices(t)
	received := &leadNetworks{}
	replica.SetAttachedNetworks(AttachedNetworks{Lead: received.take})
	synchronize(t, replica, 1)
	if _, prefixes, calls := received.read(); calls != 1 || len(prefixes) != 0 {
		t.Fatalf("a lead that shares nothing handed %v in %d calls", prefixes, calls)
	}

	replica.receiveAttachedNetworks(primary.nodeName, []byte(`["2001:db8:1234:1500::7/64","10.0.7.0/24","fd00::/64","2001:db8::/32","nonsense"]`))
	if _, prefixes, _ := received.read(); !slices.Equal(prefixes, []netip.Prefix{netip.MustParsePrefix("2001:db8:1234:1500::/64")}) {
		t.Fatalf("kept %v, want only the global /64", prefixes)
	}
}
