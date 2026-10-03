package dnsserver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/trustanchor"
)

// panickingObserver panics the first time the handler asks whether it is
// enabled, which happens before any response is written.
type panickingObserver struct{ fired atomic.Bool }

func (observer *panickingObserver) Enabled() bool {
	if observer.fired.CompareAndSwap(false, true) {
		panic("observer exploded")
	}
	return false
}

func (*panickingObserver) Record(querylog.Event) {}

func TestServeDNSRecoversPanicWithServfailAndKeepsServing(t *testing.T) {
	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	request := cacheRequest("panic.example.", 1)
	if !runtime.cache.Set(request, positiveResponse(request, 300), true) {
		t.Fatal("failed to seed the response cache")
	}
	handler.SetQueryObserver(&panickingObserver{})

	first := &responseCapture{}
	handler.ServeDNS(first, request)
	if first.message == nil || first.message.Rcode != dns.RcodeServerFailure {
		t.Fatalf("panicking query answered %+v, want SERVFAIL", first.message)
	}
	if first.message.Id != request.Id {
		t.Fatalf("SERVFAIL Id = %d, want %d", first.message.Id, request.Id)
	}
	if stats := handler.Stats(); stats.Panics != 1 || stats.ServerFailures != 1 {
		t.Fatalf("Panics = %d, ServerFailures = %d; want 1 and 1", stats.Panics, stats.ServerFailures)
	}

	second := &responseCapture{}
	handler.ServeDNS(second, cacheRequest("panic.example.", 2))
	if second.message == nil || second.message.Rcode != dns.RcodeSuccess || len(second.message.Answer) != 1 {
		t.Fatalf("query after the panic answered %+v, want the cached answer", second.message)
	}
}

func TestInflightPanicReleasesWaiters(t *testing.T) {
	group := newInflightGroup()
	key := inflightKey{name: "panic-leader.example."}
	started := make(chan struct{})
	release := make(chan struct{})
	leaderDone := make(chan any, 1)
	go func() {
		defer func() { leaderDone <- recover() }()
		group.doContext(context.Background(), key, func() resolution {
			close(started)
			<-release
			panic("leader exploded")
		})
	}()
	<-started

	followerDone := make(chan struct{})
	go func() {
		group.doContext(context.Background(), key, func() resolution { return resolution{} })
		close(followerDone)
	}()
	// Give the follower a moment to join the leader's call before it panics.
	// There is no hook to observe that, so a follower that arrives late just
	// runs its own call; the later identical call below still proves the fix.
	time.Sleep(20 * time.Millisecond)
	close(release)

	if value := <-leaderDone; value == nil {
		t.Fatal("leader panic was swallowed")
	}
	select {
	case <-followerDone:
	case <-time.After(time.Second):
		t.Fatal("follower still waiting after the leader panicked")
	}

	next := make(chan resolution, 1)
	go func() {
		result, _, _ := group.doContext(context.Background(), key, func() resolution {
			return resolution{response: new(dns.Msg)}
		})
		next <- result
	}()
	select {
	case result := <-next:
		if result.response == nil {
			t.Fatal("later identical call did not run its own lookup")
		}
	case <-time.After(time.Second):
		t.Fatal("later identical call hung on the panicked leader")
	}
}

func TestPrefetchWithCheckingDisabledKeepsSharedEntryWhenValidationIsOff(t *testing.T) {
	for _, tc := range []struct {
		name             string
		checkingDisabled bool
		want             string
	}{
		{name: "CD prefetch leaves the entry", checkingDisabled: true, want: "192.0.2.1"},
		{name: "plain prefetch refreshes the entry", checkingDisabled: false, want: "198.51.100.9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configuration := testRuntimeConfig()
			configuration.Forwarders = []string{"192.0.2.1:53"}
			runtime, err := Compile(configuration)
			if err != nil {
				t.Fatal(err)
			}
			handler := NewHandler(runtime)
			handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
				response := positiveResponse(request, 300)
				response.Answer[0].(*dns.A).A = net.ParseIP("198.51.100.9")
				return response, nil
			}
			seed := cacheRequest("prefetch-cd.example.", 1)
			if !runtime.cache.Set(seed, positiveResponse(seed, 300), true) {
				t.Fatal("failed to seed the response cache")
			}

			prefetch := cacheRequest("prefetch-cd.example.", 2)
			prefetch.CheckingDisabled = tc.checkingDisabled
			handler.prefetch(prefetch, runtime)
			// Shutdown would cancel the prefetch, so wait for it to finish.
			handler.backgroundWG.Wait()

			cached, found := runtime.cache.Get(cacheRequest("prefetch-cd.example.", 3))
			if !found || len(cached.Answer) != 1 {
				t.Fatalf("shared entry = %+v, found=%v", cached, found)
			}
			if got := cached.Answer[0].(*dns.A).A.String(); got != tc.want {
				t.Fatalf("shared entry answers %s, want %s", got, tc.want)
			}
		})
	}
}

func TestApplyManagedTrustAnchorsKeepsCacheOptions(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.DNSSECValidation = true
	configuration.DNSSECTrustAnchorUpdates = true
	configuration.ServeStale = true
	configuration.CacheStaleTTL = 86_400
	configuration.CacheMinimumTTL = 30
	configuration.CacheMaximumTTL = 3_600
	configuration.CachePrefetchTriggerTTL = 10
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	want := runtime.cache.options
	if !want.ServeStale {
		t.Fatal("test configuration did not enable serve-stale")
	}

	handler.ApplyManagedTrustAnchors([]string{trustanchor.DefaultRootKSK2024}, false)
	active := handler.runtime.Load()
	if active.cache == runtime.cache {
		t.Fatal("a changed anchor set kept the old cache")
	}
	if active.cache.options != want {
		t.Fatalf("cache options after rollover = %+v, want %+v", active.cache.options, want)
	}
	if active.cache.Capacity() != runtime.cache.Capacity() {
		t.Fatalf("cache capacity after rollover = %d, want %d", active.cache.Capacity(), runtime.cache.Capacity())
	}
}
