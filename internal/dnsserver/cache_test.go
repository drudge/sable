package dnsserver

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

func TestResponseCacheReturnsIndependentResponseWithAdjustedIDAndTTL(t *testing.T) {
	t.Parallel()

	clock := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	cache := NewResponseCache(16)
	cache.now = func() time.Time { return clock }
	request := cacheRequest("Example.COM.", 100)
	response := positiveResponse(request, 60)

	if !cache.Set(request, response) {
		t.Fatal("Set() = false, want response cached")
	}
	clock = clock.Add(7 * time.Second)
	lookup := cacheRequest("example.com.", 900)
	cached, found := cache.Get(lookup)
	if !found {
		t.Fatal("Get() found = false, want true")
	}
	if cached.Id != lookup.Id {
		t.Fatalf("response ID = %d, want %d", cached.Id, lookup.Id)
	}
	if cached.Answer[0].Header().Ttl != 53 {
		t.Fatalf("cached TTL = %d, want 53", cached.Answer[0].Header().Ttl)
	}
	if response.Answer[0].Header().Ttl != 60 {
		t.Fatalf("source response TTL = %d, want unchanged 60", response.Answer[0].Header().Ttl)
	}
}

func TestResponseCacheExpiresEntryAtMinimumTTL(t *testing.T) {
	t.Parallel()

	clock := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	cache := NewResponseCache(4)
	cache.now = func() time.Time { return clock }
	request := cacheRequest("example.com.", 1)
	response := positiveResponse(request, 10)
	response.Extra = append(response.Extra, &dns.A{
		Hdr: dns.RR_Header{Name: "ns.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3},
		A:   net.ParseIP("192.0.2.2"),
	})
	cache.Set(request, response)

	clock = clock.Add(3 * time.Second)
	if _, found := cache.Get(request); found {
		t.Fatal("Get() found = true after minimum TTL elapsed")
	}
	if cache.Len() != 0 {
		t.Fatalf("Len() = %d, want expired entry removed", cache.Len())
	}
}

func TestResponseCacheUsesSOAMinimumForNegativeResponse(t *testing.T) {
	t.Parallel()

	clock := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	cache := NewResponseCache(4)
	cache.now = func() time.Time { return clock }
	request := cacheRequest("missing.example.", 1)
	response := new(dns.Msg)
	response.SetRcode(request, dns.RcodeNameError)
	response.Ns = append(response.Ns, &dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 30},
		Ns:     "ns.example.",
		Mbox:   "hostmaster.example.",
		Minttl: 5,
	})
	if !cache.Set(request, response) {
		t.Fatal("Set() = false, want negative response cached")
	}

	clock = clock.Add(5 * time.Second)
	if _, found := cache.Get(request); found {
		t.Fatal("Get() found = true after SOA minimum elapsed")
	}
}

func TestResponseCacheAppliesConfiguredTTLLimits(t *testing.T) {
	t.Parallel()

	cache := NewResponseCacheWithOptions(4, CacheOptions{MinimumTTL: 10, MaximumTTL: 60})
	shortRequest := cacheRequest("short.example.", 1)
	longRequest := cacheRequest("long.example.", 2)
	if !cache.Set(shortRequest, positiveResponse(shortRequest, 3)) {
		t.Fatal("Set(short) = false, want true")
	}
	if !cache.Set(longRequest, positiveResponse(longRequest, 600)) {
		t.Fatal("Set(long) = false, want true")
	}

	shortResponse, found := cache.Get(shortRequest)
	if !found || shortResponse.Answer[0].Header().Ttl != 10 {
		t.Fatalf("short cached TTL = %v, want 10", cachedAnswerTTL(shortResponse, found))
	}
	longResponse, found := cache.Get(longRequest)
	if !found || longResponse.Answer[0].Header().Ttl != 60 {
		t.Fatalf("long cached TTL = %v, want 60", cachedAnswerTTL(longResponse, found))
	}
}

func TestResponseCacheAppliesConfiguredNegativeAndFailureTTLs(t *testing.T) {
	t.Parallel()

	clock := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	cache := NewResponseCacheWithOptions(4, CacheOptions{NegativeTTL: 45, FailureTTL: 7})
	cache.now = func() time.Time { return clock }

	negativeRequest := cacheRequest("missing.example.", 1)
	negative := new(dns.Msg)
	negative.SetRcode(negativeRequest, dns.RcodeNameError)
	negative.Ns = append(negative.Ns, &dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 5},
		Ns:     "ns.example.",
		Mbox:   "hostmaster.example.",
		Minttl: 5,
	})
	if !cache.Set(negativeRequest, negative) {
		t.Fatal("Set(negative) = false, want true")
	}
	if cached, found := cache.Get(negativeRequest); !found || cached.Ns[0].Header().Ttl != 45 {
		t.Fatalf("negative cached TTL = %v, want 45", cachedAuthorityTTL(cached, found))
	}

	failureRequest := cacheRequest("failure.example.", 2)
	failure := new(dns.Msg)
	failure.SetRcode(failureRequest, dns.RcodeServerFailure)
	if !cache.Set(failureRequest, failure) {
		t.Fatal("Set(SERVFAIL) = false, want failure cached")
	}
	clock = clock.Add(6 * time.Second)
	if cached, found := cache.Get(failureRequest); !found || cached.Rcode != dns.RcodeServerFailure {
		t.Fatal("Get(SERVFAIL) found = false before configured expiration")
	}
	clock = clock.Add(time.Second)
	if _, found := cache.Get(failureRequest); found {
		t.Fatal("Get(SERVFAIL) found = true at configured expiration")
	}
}

func TestResponseCacheServesExpiredResponseOnlyAsStaleFallback(t *testing.T) {
	t.Parallel()

	clock := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	cache := NewResponseCacheWithOptions(4, CacheOptions{
		ServeStale: true, StaleTTL: 30, StaleAnswerTTL: 12,
	})
	cache.now = func() time.Time { return clock }
	request := cacheRequest("stale.example.", 1)
	if !cache.Set(request, positiveResponse(request, 5)) {
		t.Fatal("Set() = false, want true")
	}

	if _, found := cache.GetStale(request); found {
		t.Fatal("GetStale() found fresh response")
	}
	clock = clock.Add(5 * time.Second)
	if _, found := cache.Get(request); found {
		t.Fatal("Get() found expired response")
	}
	stale, found := cache.GetStale(request)
	if !found {
		t.Fatal("GetStale() found = false inside stale window")
	}
	if stale.Answer[0].Header().Ttl != 12 {
		t.Fatalf("stale response TTL = %d, want 12", stale.Answer[0].Header().Ttl)
	}
	clock = clock.Add(30 * time.Second)
	if _, found := cache.GetStale(request); found {
		t.Fatal("GetStale() found = true after stale window")
	}
}

func TestResponseCacheUsesStaleRetryWindowAfterFailedRefresh(t *testing.T) {
	t.Parallel()

	clock := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	cache := NewResponseCacheWithOptions(4, CacheOptions{
		ServeStale: true, StaleTTL: 60, StaleAnswerTTL: 12, StaleResetTTL: 10,
	})
	cache.now = func() time.Time { return clock }
	request := cacheRequest("retry-stale.example.", 1)
	cache.Set(request, positiveResponse(request, 5))
	clock = clock.Add(5 * time.Second)
	if _, found := cache.GetStale(request); !found {
		t.Fatal("GetStale() found = false")
	}
	if response, found := cache.Get(request); !found || response.Answer[0].Header().Ttl != 12 {
		t.Fatalf("Get() during stale retry window found = %v, response = %+v", found, response)
	}
	clock = clock.Add(10 * time.Second)
	if _, found := cache.Get(request); found {
		t.Fatal("Get() found stale response after retry window")
	}
}

func TestResponseCacheElectsSinglePopularPrefetch(t *testing.T) {
	t.Parallel()

	clock := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	cache := NewResponseCacheWithOptions(4, CacheOptions{
		PrefetchMinTTL: 30, PrefetchAtTTL: 10, PrefetchSample: 5 * time.Minute, PrefetchHits: 24,
	})
	cache.now = func() time.Time { return clock }
	request := cacheRequest("popular.example.", 1)
	cache.Set(request, positiveResponse(request, 60))
	clock = clock.Add(51 * time.Second)

	if _, found, prefetch := cache.GetWithPrefetch(request); !found || prefetch {
		t.Fatalf("first hit found = %v, prefetch = %v; want found without election", found, prefetch)
	}
	if _, found, prefetch := cache.GetWithPrefetch(request); !found || !prefetch {
		t.Fatalf("second hit found = %v, prefetch = %v; want one election", found, prefetch)
	}
	if _, _, prefetch := cache.GetWithPrefetch(request); prefetch {
		t.Fatal("third hit elected duplicate refresh")
	}
	cache.CancelPrefetch(request)
	if _, _, prefetch := cache.GetWithPrefetch(request); !prefetch {
		t.Fatal("hit after CancelPrefetch() did not re-elect refresh")
	}
}

func TestResponseCacheExportRestoreRoundTrip(t *testing.T) {
	t.Parallel()

	clock := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	options := CacheOptions{ServeStale: true, StaleTTL: 60, StaleAnswerTTL: 10, StaleResetTTL: 5}
	source := NewResponseCacheWithOptions(4, options)
	source.now = func() time.Time { return clock }
	request := cacheRequest("persisted.example.", 1)
	source.Set(request, positiveResponse(request, 60))
	clock = clock.Add(7 * time.Second)
	entries, err := source.Export()
	if err != nil || len(entries) != 1 {
		t.Fatalf("Export() = %d entries, %v; want 1, nil", len(entries), err)
	}

	restored := NewResponseCacheWithOptions(4, options)
	restored.now = func() time.Time { return clock }
	count, err := restored.Restore(entries)
	if err != nil || count != 1 {
		t.Fatalf("Restore() = %d, %v; want 1, nil", count, err)
	}
	response, found := restored.Get(request)
	if !found || response.Answer[0].Header().Ttl != 53 {
		t.Fatalf("restored response found = %v, TTL = %v; want true, 53", found, cachedAnswerTTL(response, found))
	}
}

func TestHandlerReturnsStaleAfterConfiguredMaximumWait(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.CacheSize = 4
	configuration.ServeStale = true
	configuration.CacheStaleTTL = 60
	configuration.CacheStaleAnswerTTL = 12
	configuration.CacheStaleResetTTL = 10
	configuration.CacheStaleMaxWait = time.Millisecond
	configuration.Timeout = 20 * time.Millisecond
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	runtime.cache.now = func() time.Time { return clock }
	request := cacheRequest("slow-upstream.example.", 1)
	runtime.cache.Set(request, positiveResponse(request, 5))
	clock = clock.Add(5 * time.Second)
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(ctx context.Context, _ *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	started := time.Now()
	result := handler.resolve(request, runtime)
	if elapsed := time.Since(started); elapsed >= configuration.Timeout {
		t.Fatalf("stale resolution took %s, want less than upstream timeout %s", elapsed, configuration.Timeout)
	}
	if result.source != querylog.SourceCache || len(result.response.Answer) != 1 || result.response.Answer[0].Header().Ttl != 12 {
		t.Fatalf("stale resolution = source %q response %+v", result.source, result.response)
	}
}

func TestResponseCacheRemainsBounded(t *testing.T) {
	t.Parallel()

	const capacity = 8
	cache := NewResponseCache(capacity)
	for index := range 100 {
		request := cacheRequest(fmt.Sprintf("host-%d.example.", index), uint16(index))
		cache.Set(request, positiveResponse(request, 60))
	}
	if cache.Len() > capacity {
		t.Fatalf("Len() = %d, want at most %d", cache.Len(), capacity)
	}
}

func TestResponseCacheClearReturnsRemovedEntries(t *testing.T) {
	t.Parallel()

	cache := NewResponseCache(4)
	for index := range 3 {
		request := cacheRequest(fmt.Sprintf("clear-%d.example.", index), uint16(index))
		cache.Set(request, positiveResponse(request, 60))
	}
	if removed := cache.Clear(); removed != 3 {
		t.Fatalf("Clear() = %d, want 3", removed)
	}
	if cache.Len() != 0 {
		t.Fatalf("Len() = %d after Clear(), want 0", cache.Len())
	}
}

func TestResponseCacheSnapshotIsSortedAndAdjustsTTLs(t *testing.T) {
	t.Parallel()

	clock := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	cache := NewResponseCache(8)
	cache.now = func() time.Time { return clock }
	for _, name := range []string{"z.example.", "a.example."} {
		request := cacheRequest(name, 1)
		cache.Set(request, positiveResponse(request, 60))
	}
	clock = clock.Add(7 * time.Second)

	snapshot := cache.Snapshot()
	if len(snapshot) != 2 {
		t.Fatalf("Snapshot() length = %d, want 2", len(snapshot))
	}
	if snapshot[0].Name != "a.example." || snapshot[1].Name != "z.example." {
		t.Fatalf("Snapshot() names = %q, %q, want sorted", snapshot[0].Name, snapshot[1].Name)
	}
	if snapshot[0].RemainingTTL != 53 || snapshot[0].Records[0].TTL != 53 {
		t.Fatalf("Snapshot() TTLs = remaining %d record %d, want 53", snapshot[0].RemainingTTL, snapshot[0].Records[0].TTL)
	}
}

func TestHandlerActivationPreservesCompatibleCache(t *testing.T) {
	t.Parallel()

	activeConfiguration := testRuntimeConfig()
	activeConfiguration.CacheSize = 16
	active, err := Compile(activeConfiguration)
	if err != nil {
		t.Fatalf("Compile(active) error = %v", err)
	}
	request := cacheRequest("preserved.example.", 1)
	active.cache.Set(request, positiveResponse(request, 60))
	handler := NewHandler(active)
	candidateConfiguration := activeConfiguration
	candidateConfiguration.Timeout = 2 * time.Second
	candidateConfiguration.Blocking = true
	candidateConfiguration.BlockedDomains = []string{"ads.example"}
	candidate, err := Compile(candidateConfiguration)
	if err != nil {
		t.Fatalf("Compile(candidate) error = %v", err)
	}

	handler.Activate(candidate)
	if handler.Stats().CacheEntries != 1 {
		t.Fatalf("CacheEntries = %d, want compatible cache preserved", handler.Stats().CacheEntries)
	}
}

func TestHandlerActivationClearsCacheWhenForwardingPolicyChanges(t *testing.T) {
	t.Parallel()

	activeConfiguration := testRuntimeConfig()
	activeConfiguration.CacheSize = 16
	active, err := Compile(activeConfiguration)
	if err != nil {
		t.Fatalf("Compile(active) error = %v", err)
	}
	request := cacheRequest("route-change.example.", 1)
	active.cache.Set(request, positiveResponse(request, 60))
	handler := NewHandler(active)
	candidateConfiguration := activeConfiguration
	candidateConfiguration.Routes = []ForwardingRoute{{
		Domain: "example", Forwarders: []string{"192.0.2.53:53"},
	}}
	candidate, err := Compile(candidateConfiguration)
	if err != nil {
		t.Fatalf("Compile(candidate) error = %v", err)
	}

	handler.Activate(candidate)
	if handler.Stats().CacheEntries != 0 {
		t.Fatalf("CacheEntries = %d, want route change to clear cache", handler.Stats().CacheEntries)
	}
}

func TestResponseCacheSkipsEDNSOptionsAndTransientFailures(t *testing.T) {
	t.Parallel()

	cache := NewResponseCache(4)
	request := cacheRequest("example.com.", 1)
	request.IsEdns0().Option = append(request.IsEdns0().Option, &dns.EDNS0_SUBNET{})
	if cache.Set(request, positiveResponse(request, 60)) {
		t.Fatal("Set() = true for request with response-varying EDNS options")
	}

	request = cacheRequest("example.com.", 2)
	response := new(dns.Msg)
	response.SetRcode(request, dns.RcodeServerFailure)
	if cache.Set(request, response) {
		t.Fatal("Set() = true for SERVFAIL response")
	}
}

func TestResponseCacheIgnoresHopByHopEDNSOptions(t *testing.T) {
	t.Parallel()

	cache := NewResponseCache(4)
	padded := cacheRequest("example.com.", 1)
	padded.IsEdns0().Option = append(padded.IsEdns0().Option,
		&dns.EDNS0_PADDING{Padding: make([]byte, 32)},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "2436313a4d7a5f21"},
	)
	response := positiveResponse(padded, 60)
	response.SetEdns0(dns.DefaultMsgSize, true)
	response.IsEdns0().Option = append(response.IsEdns0().Option,
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "2436313a4d7a5f215365727665724330"},
	)

	if !cache.Set(padded, response) {
		t.Fatal("Set() = false for a padded request, want it cached")
	}
	cached, found := cache.Get(padded)
	if !found {
		t.Fatal("Get() found = false for a padded request, want a cache hit")
	}
	if option := cached.IsEdns0(); option != nil && len(option.Option) != 0 {
		t.Fatalf("cached response carries hop-scoped options %v, want them stripped", option.Option)
	}

	plain := cacheRequest("example.com.", 2)
	if _, found := cache.Get(plain); !found {
		t.Fatal("Get() found = false for a plain request, want the padded entry to serve it")
	}
	cookied := cacheRequest("example.com.", 3)
	cookied.IsEdns0().Option = append(cookied.IsEdns0().Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "1111111111111111"})
	if _, found := cache.Get(cookied); !found {
		t.Fatal("Get() found = false for a differently cookied request, want a cache hit")
	}
}

func BenchmarkResponseCacheHit(b *testing.B) {
	cache := NewResponseCache(65_536)
	request := cacheRequest("example.com.", 1)
	cache.Set(request, positiveResponse(request, 300))
	b.ReportAllocs()
	for b.Loop() {
		_, _ = cache.Get(request)
	}
}

func cacheRequest(name string, id uint16) *dns.Msg {
	request := new(dns.Msg)
	request.Id = id
	request.SetQuestion(name, dns.TypeA)
	request.SetEdns0(dns.DefaultMsgSize, true)
	return request
}

func positiveResponse(request *dns.Msg, ttl uint32) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = append(response.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP("192.0.2.1"),
	})
	return response
}

func cachedAnswerTTL(message *dns.Msg, found bool) any {
	if !found || message == nil || len(message.Answer) == 0 {
		return "missing"
	}
	return message.Answer[0].Header().Ttl
}

func cachedAuthorityTTL(message *dns.Msg, found bool) any {
	if !found || message == nil || len(message.Ns) == 0 {
		return "missing"
	}
	return message.Ns[0].Header().Ttl
}
