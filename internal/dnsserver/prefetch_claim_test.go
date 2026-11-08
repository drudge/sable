package dnsserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// electedCache returns a cache holding one popular entry inside the prefetch
// trigger window, with its clock, and the claim a client hit just won on it.
func electedCache(t *testing.T, name string) (*ResponseCache, *time.Time, PrefetchClaim) {
	t.Helper()
	clock := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	cache := NewResponseCacheWithOptions(4, CacheOptions{
		PrefetchMinTTL: 30, PrefetchAtTTL: 10, PrefetchSample: 5 * time.Minute, PrefetchHits: 24,
	})
	cache.now = func() time.Time { return clock }
	request := cacheRequest(name, 1)
	cache.Set(request, positiveResponse(request, 60), true)
	clock = clock.Add(51 * time.Second)
	if _, _, claim := cache.GetWithPrefetch(request); claim.Held() {
		t.Fatal("first hit elected before the entry was popular")
	}
	_, found, claim := cache.GetWithPrefetch(request)
	if !found || !claim.Held() {
		t.Fatalf("second hit found = %v, held = %v; want an election", found, claim.Held())
	}
	return cache, &clock, claim
}

func electable(cache *ResponseCache, name string) bool {
	_, _, claim := cache.GetWithPrefetch(cacheRequest(name, 9))
	defer claim.Release()
	return claim.Held()
}

func TestPrefetchClaimReleaseIsIdempotent(t *testing.T) {
	t.Parallel()

	cache, _, claim := electedCache(t, "popular.example.")
	var empty PrefetchClaim
	empty.Release()
	if empty.Held() {
		t.Fatal("zero claim reports held")
	}
	if electable(cache, "popular.example.") {
		t.Fatal("entry elected twice while the first claim is held")
	}
	claim.Release()
	if claim.Held() {
		t.Fatal("claim still held after Release()")
	}
	_, _, second := cache.GetWithPrefetch(cacheRequest("popular.example.", 2))
	if !second.Held() {
		t.Fatal("hit after Release() did not re-elect")
	}
	claim.Release()
	if electable(cache, "popular.example.") {
		t.Fatal("releasing a spent claim freed the next holder's election")
	}
	second.Release()
}

// A claim frees only the entry it won. When a fresh answer has replaced that
// entry and somebody has elected the replacement, a late release of the old
// claim must leave the new election alone.
func TestPrefetchClaimReleaseLeavesReplacementAlone(t *testing.T) {
	t.Parallel()

	cache, clock, stale := electedCache(t, "popular.example.")
	request := cacheRequest("popular.example.", 3)
	cache.Set(request, positiveResponse(request, 60), true)
	*clock = clock.Add(51 * time.Second)
	_, _, current := cache.GetWithPrefetch(request)
	if !current.Held() {
		t.Fatal("replacement inside the trigger window was not elected")
	}
	stale.Release()
	if electable(cache, "popular.example.") {
		t.Fatal("releasing the replaced entry's claim freed the replacement's election")
	}
	current.Release()
	if !electable(cache, "popular.example.") {
		t.Fatal("replacement not electable after its own claim was released")
	}
}

func TestPrefetchGivesBackItsClaimOnEveryPath(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*Handler, *Runtime)
		answer  func(*dns.Msg) (*dns.Msg, error)
	}{
		{name: "handler shut down", prepare: func(handler *Handler, _ *Runtime) {
			if err := handler.Shutdown(context.Background()); err != nil {
				panic(err)
			}
		}},
		{name: "admission refused", prepare: func(handler *Handler, runtime *Runtime) {
			runtime.maxConcurrent = 1
			if _, admitted := handler.admission.acquire("held", 1, 1); !admitted {
				panic("could not fill admission")
			}
		}},
		{name: "upstream fails", answer: func(*dns.Msg) (*dns.Msg, error) {
			return nil, errors.New("upstream down")
		}},
		{name: "answer not cacheable", answer: func(query *dns.Msg) (*dns.Msg, error) {
			response := new(dns.Msg)
			response.SetRcode(query, dns.RcodeRefused)
			return response, nil
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runtime, err := Compile(testRuntimeConfig())
			if err != nil {
				t.Fatal(err)
			}
			cache, _, claim := electedCache(t, "refresh.example.")
			runtime.cache = cache
			handler := NewHandler(runtime)
			defer handler.Shutdown(context.Background())
			handler.upstreamExchange = func(_ context.Context, query *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
				if tc.answer == nil {
					t.Error("prefetch reached the upstream")
					return nil, errors.New("unexpected")
				}
				return tc.answer(query)
			}
			if tc.prepare != nil {
				tc.prepare(handler, runtime)
			}
			handler.prefetch(cacheRequest("refresh.example.", 4), runtime, claim)
			handler.backgroundWG.Wait()
			if !electable(cache, "refresh.example.") {
				t.Fatal("entry still marked refreshing after the prefetch gave up")
			}
		})
	}
}
