package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drudge/sable/internal/web/pages"
)

type stubReverseResolver struct {
	names     map[string]string
	fail      map[string]bool
	calls     atomic.Int64
	active    atomic.Int64
	maxActive atomic.Int64
	block     chan struct{}
	blockAll  bool
	slowIP    string
}

func (stub *stubReverseResolver) ReverseLookup(ctx context.Context, address netip.Addr) (string, error) {
	stub.calls.Add(1)
	active := stub.active.Add(1)
	defer stub.active.Add(-1)
	for {
		maximum := stub.maxActive.Load()
		if active <= maximum || stub.maxActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	if (stub.blockAll || stub.slowIP == address.String()) && stub.block != nil {
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

func TestReverseNameCacheLimitsWorkersAcrossConcurrentRenders(t *testing.T) {
	resolver := &stubReverseResolver{block: make(chan struct{}), blockAll: true}
	cache := newTestNameCache(resolver)
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(10)
	for index := range 10 {
		go func(index int) {
			defer wait.Done()
			<-start
			cache.names([]string{netip.AddrFrom4([4]byte{10, 1, 0, byte(index)}).String()})
		}(index)
	}
	close(start)
	deadline := time.Now().Add(time.Second)
	for resolver.maxActive.Load() < reverseNameWorkers && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := resolver.maxActive.Load(); got > reverseNameWorkers {
		t.Fatalf("maximum concurrent reverse lookups = %d, want at most %d", got, reverseNameWorkers)
	}
	close(resolver.block)
	wait.Wait()
	if got := resolver.maxActive.Load(); got != reverseNameWorkers {
		t.Fatalf("peak active lookups = %d, want %d", got, reverseNameWorkers)
	}
	if calls := resolver.calls.Load(); calls != 10 {
		t.Fatalf("reverse lookups = %d, want 10", calls)
	}
}

func TestReverseNameCacheCapsInflightClaimsAcrossRenders(t *testing.T) {
	resolver := &stubReverseResolver{block: make(chan struct{}), blockAll: true}
	cache := newTestNameCache(resolver)
	addresses := make([]string, 0, reverseNameCacheCapacity+1)
	for index := range reverseNameCacheCapacity + 1 {
		addresses = append(addresses, netip.AddrFrom4([4]byte{10, byte(index / 256), byte(index / 256), byte(index % 256)}).String())
	}
	done := make(chan struct{})
	go func() {
		cache.names(addresses)
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		cache.mutex.Lock()
		claims := len(cache.inflight)
		cache.mutex.Unlock()
		if claims == reverseNameInflightLimit || !time.Now().Before(deadline) {
			if claims != reverseNameInflightLimit {
				t.Fatalf("inflight claims = %d, want %d", claims, reverseNameInflightLimit)
			}
			break
		}
		time.Sleep(time.Millisecond)
	}
	const extraAddress = "192.0.2.250"
	if _, extra := cache.partition([]string{extraAddress}); len(extra) != 0 {
		t.Fatal("another render exceeded the cache-wide claim cap")
	}
	close(resolver.block)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cache render did not finish")
	}
	if calls := resolver.calls.Load(); calls != reverseNameInflightLimit {
		t.Fatalf("reverse lookups = %d, want %d", calls, reverseNameInflightLimit)
	}
	if _, retry := cache.partition([]string{extraAddress}); len(retry) != 1 {
		t.Fatal("declined address was not available for retry after capacity freed")
	}
	cache.unclaim(extraAddress)
}

func TestReverseNameCacheCanceledQueuedClaimsDoNotResolveOrCache(t *testing.T) {
	resolver := &stubReverseResolver{block: make(chan struct{}), blockAll: true}
	cache := newTestNameCache(resolver)
	addresses := make([]string, 0, reverseNameWorkers+1)
	for index := range reverseNameWorkers + 1 {
		addresses = append(addresses, netip.AddrFrom4([4]byte{10, 2, 0, byte(index)}).String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, pending := cache.partition(addresses)
	if len(pending) != len(addresses) {
		t.Fatalf("pending claims = %d, want %d", len(pending), len(addresses))
	}
	done := make(chan struct{})
	go func() {
		cache.resolve(ctx, cancel, pending)
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for resolver.calls.Load() < reverseNameWorkers && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls := resolver.calls.Load(); calls != reverseNameWorkers {
		t.Fatalf("started reverse lookups = %d, want %d", calls, reverseNameWorkers)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled cache resolve did not finish")
	}
	if calls := resolver.calls.Load(); calls != reverseNameWorkers {
		t.Fatalf("reverse lookups after cancellation = %d, want %d", calls, reverseNameWorkers)
	}
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if len(cache.inflight) != 0 || len(cache.entries) != 0 {
		t.Fatalf("canceled claims left cache state: inflight=%d entries=%d", len(cache.inflight), len(cache.entries))
	}
}

func TestReverseNameCachePrunesExpiredAndEvictsSoonestExpiry(t *testing.T) {
	moment := time.Unix(100, 0)
	cache := newTestNameCache(&stubReverseResolver{})
	cache.now = func() time.Time { return moment }
	for index := range reverseNameCacheCapacity {
		cache.entries[fmt.Sprintf("address-%d", index)] = reverseNameEntry{
			name: fmt.Sprintf("name-%d", index), expiresAt: moment.Add(time.Duration(index+1) * time.Second),
		}
	}
	cache.store("new-address", "new-name")
	if len(cache.entries) != reverseNameCacheCapacity {
		t.Fatalf("cache size after eviction = %d, want %d", len(cache.entries), reverseNameCacheCapacity)
	}
	if _, found := cache.entries["address-0"]; found {
		t.Fatal("earliest-expiring entry was not evicted")
	}
	moment = moment.Add(2 * time.Hour)
	cache.store("fresh-address", "fresh-name")
	if len(cache.entries) != 1 {
		t.Fatalf("cache size after expiry prune = %d, want 1", len(cache.entries))
	}
}

func BenchmarkReverseNameCacheStoreAtCapacity(b *testing.B) {
	cache := newTestNameCache(&stubReverseResolver{})
	moment := time.Unix(100, 0)
	cache.now = func() time.Time { return moment }
	for index := range reverseNameCacheCapacity {
		cache.entries[fmt.Sprintf("address-%d", index)] = reverseNameEntry{
			name: "name", expiresAt: moment.Add(time.Hour),
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	index := 0
	for b.Loop() {
		cache.store(fmt.Sprintf("new-address-%d", index), "new-name")
		index++
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
