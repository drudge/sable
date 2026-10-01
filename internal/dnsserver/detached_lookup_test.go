package dnsserver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
	"github.com/miekg/dns"
)

// A device that hears nothing sends the same question again a second or two
// later. That retry joins the lookup the first question started, and it used
// to end at the first question's deadline, so all three answers came back as
// one SERVFAIL at the same moment.
func TestRetryJoiningARunningLookupWaitsItsOwnTime(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.Mode = "recursive"
	configuration.Forwarders = nil
	configuration.RootHints = []string{"192.0.2.1:53"}
	configuration.Timeout = 600 * time.Millisecond
	configuration.CacheFailureTTL = 10
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	defer handler.Close()
	release := make(chan struct{})
	var mu sync.Mutex
	asked := 0
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		mu.Lock()
		asked++
		mu.Unlock()
		// The authority answers only once released, like a long alias
		// chain still being followed.
		<-release
		return addressResponse(request, "192.0.2.44"), nil
	}
	request := new(dns.Msg)
	request.SetQuestion("com.", dns.TypeA)

	started := time.Now()
	first := make(chan resolution, 1)
	go func() { first <- handler.resolveForClient(request.Copy(), runtime, "192.0.2.100") }()
	time.Sleep(200 * time.Millisecond)
	retry := make(chan resolution, 1)
	go func() { retry <- handler.resolveForClient(request.Copy(), runtime, "192.0.2.100") }()

	// The first client stops waiting at 600ms, while the lookup still runs.
	result := <-first
	if result.response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("first client got %s, want SERVFAIL once its wait ran out", dns.RcodeToString[result.response.Rcode])
	}
	// Its failure is not cached, or the retry would find it there.
	if cached, found := runtime.cache.Get(request); found {
		t.Fatalf("a lookup still running left %s in the cache", dns.RcodeToString[cached.Rcode])
	}
	// The lookup finishes after the first client's wait and inside the
	// retry's, which started 200ms later.
	time.Sleep(time.Until(started.Add(700 * time.Millisecond)))
	close(release)
	result = <-retry
	if result.response.Rcode != dns.RcodeSuccess || len(result.response.Answer) != 1 {
		t.Fatalf("retry got %s with %v, want the answer the lookup finished with", dns.RcodeToString[result.response.Rcode], result.response.Answer)
	}
	mu.Lock()
	defer mu.Unlock()
	if asked != 1 {
		t.Fatalf("the authority was asked %d times, want one lookup shared by both clients", asked)
	}
}

// A retry that comes just after the lookup finished gets its answer rather
// than starting the whole chain again.
func TestFinishedRecursiveLookupAnswersALateRetry(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	handler := NewHandler(runtime)
	defer handler.Close()
	var mu sync.Mutex
	asked := 0
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		mu.Lock()
		asked++
		mu.Unlock()
		return addressResponse(request, "192.0.2.44"), nil
	}
	request := new(dns.Msg)
	request.SetQuestion("com.", dns.TypeA)
	for range 2 {
		response, _, err := handler.resolveRecursiveWaiting(context.Background(), request, runtime, time.Second)
		if err != nil || response == nil || len(response.Answer) != 1 {
			t.Fatalf("lookup = %v, %v", response, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if asked != 1 {
		t.Fatalf("the authority was asked %d times, want the finished lookup to answer the retry", asked)
	}
}

func TestStillRunningFailureIsNotCached(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.Mode = "recursive"
	configuration.Forwarders = nil
	configuration.RootHints = []string{"192.0.2.1:53"}
	configuration.Timeout = 50 * time.Millisecond
	configuration.CacheFailureTTL = 10
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	defer handler.Close()
	release := make(chan struct{})
	defer close(release)
	handler.upstreamExchange = func(ctx context.Context, _ *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, errors.New("not answering")
	}
	request := new(dns.Msg)
	request.SetQuestion("com.", dns.TypeA)
	result := handler.resolveForClient(request, runtime, "192.0.2.100")
	if result.response.Rcode != dns.RcodeServerFailure || !result.stillRunning {
		t.Fatalf("got %s, still running %t; want an uncached SERVFAIL", dns.RcodeToString[result.response.Rcode], result.stillRunning)
	}
	if _, found := runtime.cache.Get(request); found {
		t.Fatal("the failure of a lookup still running was cached")
	}
}

// When every client stopped waiting, the lookup caches its own answer as it
// finishes, so the device's next retry is a cache hit and skips both the
// network and DNSSEC validation.
func TestAbandonedRecursiveLookupCachesItsAnswer(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.Mode = "recursive"
	configuration.Forwarders = nil
	configuration.RootHints = []string{"192.0.2.1:53"}
	configuration.Timeout = 50 * time.Millisecond
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	defer handler.Close()
	release := make(chan struct{})
	var mu sync.Mutex
	asked := 0
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		mu.Lock()
		asked++
		mu.Unlock()
		<-release
		return addressResponse(request, "192.0.2.44"), nil
	}
	request := new(dns.Msg)
	request.SetQuestion("com.", dns.TypeA)
	if result := handler.resolveForClient(request.Copy(), runtime, "192.0.2.100"); result.response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("first client got %s, want SERVFAIL once its wait ran out", dns.RcodeToString[result.response.Rcode])
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, found := runtime.cache.Get(request); found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the lookup finished with no client waiting and left nothing in the cache")
		}
		time.Sleep(5 * time.Millisecond)
	}
	result := handler.resolveForClient(request.Copy(), runtime, "192.0.2.100")
	if result.source != querylog.SourceCache || len(result.response.Answer) != 1 {
		t.Fatalf("retry came from %q with %v, want the cached answer", result.source, result.response.Answer)
	}
	mu.Lock()
	defer mu.Unlock()
	if asked != 1 {
		t.Fatalf("the authority was asked %d times, want once", asked)
	}
}
