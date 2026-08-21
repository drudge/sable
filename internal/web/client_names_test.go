package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drudge/sable/internal/web/pages"
)

type stubReverseResolver struct {
	names  map[string]string
	fail   map[string]bool
	calls  atomic.Int64
	block  chan struct{}
	slowIP string
}

func (stub *stubReverseResolver) ReverseLookup(ctx context.Context, address netip.Addr) (string, error) {
	stub.calls.Add(1)
	if stub.slowIP == address.String() && stub.block != nil {
		select {
		case <-stub.block:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if stub.fail[address.String()] {
		return "", errors.New("no such name")
	}
	return stub.names[address.String()], nil
}

func newTestNameCache(resolver reverseResolver) *reverseNameCache {
	return newReverseNameCache(resolver, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestReverseNameCacheResolvesAndRemembers(t *testing.T) {
	t.Parallel()

	resolver := &stubReverseResolver{names: map[string]string{"10.0.7.16": "laptop.home.arpa"}}
	cache := newTestNameCache(resolver)

	names := cache.names([]string{"10.0.7.16"})
	if names["10.0.7.16"] != "laptop.home.arpa" {
		t.Fatalf("names = %+v", names)
	}
	// A second render must not repeat the query.
	if again := cache.names([]string{"10.0.7.16"}); again["10.0.7.16"] != "laptop.home.arpa" {
		t.Fatalf("cached names = %+v", again)
	}
	if calls := resolver.calls.Load(); calls != 1 {
		t.Fatalf("reverse lookups = %d, want 1", calls)
	}
}

// A client with no PTR is the common case, so the miss has to be remembered
// too or every render would re-ask for every unnamed client on the network.
func TestReverseNameCacheRemembersMisses(t *testing.T) {
	t.Parallel()

	resolver := &stubReverseResolver{fail: map[string]bool{"10.0.7.99": true}}
	cache := newTestNameCache(resolver)

	if names := cache.names([]string{"10.0.7.99"}); len(names) != 0 {
		t.Fatalf("names = %+v, want none", names)
	}
	cache.names([]string{"10.0.7.99"})
	if calls := resolver.calls.Load(); calls != 1 {
		t.Fatalf("reverse lookups = %d, want 1", calls)
	}

	// Once the miss expires the address is asked about again.
	cache.now = func() time.Time { return time.Now().Add(reverseNameMissLifetime + time.Minute) }
	cache.names([]string{"10.0.7.99"})
	if calls := resolver.calls.Load(); calls != 2 {
		t.Fatalf("reverse lookups after expiry = %d, want 2", calls)
	}
}

// A slow reverse zone must not hold the dashboard open. The render gives up on
// the budget and the answer is still there for the render after it.
func TestReverseNameCacheGivesUpOnBudget(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	resolver := &stubReverseResolver{
		names:  map[string]string{"10.0.7.16": "laptop.home.arpa"},
		block:  release,
		slowIP: "10.0.7.16",
	}
	cache := newTestNameCache(resolver)

	startedAt := time.Now()
	names := cache.names([]string{"10.0.7.16"})
	elapsed := time.Since(startedAt)
	if len(names) != 0 {
		t.Fatalf("names = %+v, want none while the lookup is still running", names)
	}
	if elapsed > 3*reverseNameBudget {
		t.Fatalf("render waited %s, want about %s", elapsed, reverseNameBudget)
	}
	close(release)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if name, found := cache.cached("10.0.7.16"); found && name == "laptop.home.arpa" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the late answer never reached the cache")
}

func TestReverseNameCacheCapsLookupsPerRender(t *testing.T) {
	t.Parallel()

	resolver := &stubReverseResolver{}
	cache := newTestNameCache(resolver)
	addresses := make([]string, 0, reverseNameLimit+25)
	for index := range reverseNameLimit + 25 {
		addresses = append(addresses, netip.AddrFrom4([4]byte{10, 0, byte(index / 256), byte(index % 256)}).String())
	}
	cache.names(addresses)
	if calls := resolver.calls.Load(); calls != reverseNameLimit {
		t.Fatalf("reverse lookups = %d, want %d", calls, reverseNameLimit)
	}
}

func TestNameRankedClientsLeavesExistingNamesAlone(t *testing.T) {
	t.Parallel()

	server := &Server{reverseNames: newTestNameCache(&stubReverseResolver{
		names: map[string]string{"10.0.7.42": "printer.home.arpa", "10.0.7.16": "wrong.example"},
	})}
	clients := []pages.RankedStatView{
		{Name: "10.0.7.16", Secondary: "laptop.home.arpa", Value: 10},
		{Name: "10.0.7.42", Value: 5},
		{Name: "10.0.7.99", Value: 1},
	}
	server.nameRankedClients(clients)

	if clients[0].Secondary != "laptop.home.arpa" {
		t.Fatalf("host override was overwritten: %+v", clients[0])
	}
	if clients[1].Secondary != "printer.home.arpa" {
		t.Fatalf("resolver name missing: %+v", clients[1])
	}
	if clients[2].Secondary != "" {
		t.Fatalf("unnamed client gained a name: %+v", clients[2])
	}
}

// A server whose DNS handler cannot resolve still renders; the rankings simply
// fall back to whatever the local zones and host overrides knew.
func TestNameRankedClientsWithoutAResolver(t *testing.T) {
	t.Parallel()

	server := &Server{}
	clients := []pages.RankedStatView{{Name: "10.0.7.16", Value: 3}}
	server.nameRankedClients(clients)
	if clients[0].Secondary != "" {
		t.Fatalf("client view = %+v", clients[0])
	}
}
