package dnsserver

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestHandlerCloseRepeatedlyWithoutMaintenanceDoesNotBlock(t *testing.T) {
	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	done := make(chan struct{})
	go func() {
		handler.Close()
		handler.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("repeated Close() blocked without a maintenance goroutine")
	}
}

func TestHandlerStartMaintenanceAfterCloseDoesNotRestart(t *testing.T) {
	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	handler.Close()
	handler.StartMaintenance()
	done := make(chan struct{})
	go func() {
		handler.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close() blocked after StartMaintenance() followed an earlier close")
	}
}

func TestHandlerCloseAndStartMaintenanceConcurrently(t *testing.T) {
	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	started := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		handler.StartMaintenance()
		close(started)
	}()
	go func() {
		handler.Close()
		close(closed)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("StartMaintenance() did not return")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("concurrent Close() did not return")
	}
}

func TestHandlerShutdownCancelsAndJoinsPrefetch(t *testing.T) {
	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	started := make(chan struct{})
	handler.upstreamExchange = func(ctx context.Context, _ *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	request := new(dns.Msg)
	request.SetQuestion("prefetch.example.", dns.TypeA)
	handler.prefetch(request, runtime)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("prefetch did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handler.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if err := handler.Shutdown(context.Background()); err != nil {
		t.Fatalf("repeated Shutdown() error = %v", err)
	}
}

func TestResolveUpstreamRetainsRuntimeTimeout(t *testing.T) {
	configuration := testRuntimeConfig()
	configuration.Timeout = 10 * time.Millisecond
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	deadlineSeen := make(chan bool, 1)
	handler.upstreamExchange = func(ctx context.Context, _ *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		_, bounded := ctx.Deadline()
		deadlineSeen <- bounded
		<-ctx.Done()
		return nil, ctx.Err()
	}
	request := new(dns.Msg)
	request.SetQuestion("timeout.example.", dns.TypeA)
	_, _, _ = handler.resolveUpstream(request, runtime, runtime.forwarders)
	select {
	case bounded := <-deadlineSeen:
		if !bounded {
			t.Fatal("upstream context has no runtime timeout")
		}
	case <-time.After(time.Second):
		t.Fatal("upstream exchange did not start")
	}
}

func TestHandlerShutdownDeadlineReportsUndrainedPrefetch(t *testing.T) {
	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	started := make(chan struct{})
	release := make(chan struct{})
	handler.upstreamExchange = func(_ context.Context, _ *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		close(started)
		<-release
		return nil, errors.New("released")
	}
	request := new(dns.Msg)
	request.SetQuestion("prefetch.example.", dns.TypeA)
	handler.prefetch(request, runtime)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("prefetch did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := handler.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown() error = %v, want deadline exceeded", err)
	}
	close(release)
	if err := handler.Shutdown(context.Background()); err != nil {
		t.Fatalf("draining repeated Shutdown() error = %v", err)
	}
}

func staleRefreshRuntime(t *testing.T) (*Runtime, *Handler, *dns.Msg) {
	t.Helper()
	configuration := testRuntimeConfig()
	configuration.ServeStale = true
	configuration.CacheStaleTTL = 300
	configuration.CacheStaleAnswerTTL = 30
	configuration.CacheStaleMaxWait = time.Millisecond
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := handler.Shutdown(ctx); err != nil {
			t.Errorf("cleanup Shutdown() error = %v", err)
		}
	})
	now := time.Now()
	runtime.cache.now = func() time.Time { return now }
	query := admissionQuery("stale-lifecycle.example.")
	runtime.cache.Set(query, admissionAnswer(query), true)
	now = now.Add(61 * time.Second)
	return runtime, handler, query
}

func TestHandlerShutdownJoinsStaleRefresh(t *testing.T) {
	runtime, handler, query := staleRefreshRuntime(t)
	started := make(chan context.Context, 1)
	hold := make(chan struct{})
	defer close(hold)
	handler.upstreamExchange = func(ctx context.Context, query *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		started <- ctx
		select {
		case <-hold:
			return admissionAnswer(query), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	result := handler.resolveForClient(query, runtime, "192.0.2.1")
	if result.response == nil || result.response.Rcode != dns.RcodeSuccess {
		t.Fatalf("stale answer = %v", result.response)
	}
	var workerContext context.Context
	select {
	case workerContext = <-started:
	case <-time.After(time.Second):
		t.Fatal("stale refresh did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handler.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if workerContext.Err() == nil {
		t.Fatal("Shutdown() did not cancel stale refresh context")
	}
	waitForAdmission(t, handler, 0)
}

func TestHandlerShutdownDeadlineReportsUndrainedStaleRefresh(t *testing.T) {
	runtime, handler, query := staleRefreshRuntime(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseWorker := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseWorker)
	handler.upstreamExchange = func(_ context.Context, query *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		close(started)
		<-release
		return admissionAnswer(query), nil
	}
	result := handler.resolveForClient(query, runtime, "192.0.2.1")
	if result.response == nil || result.response.Rcode != dns.RcodeSuccess {
		t.Fatalf("stale answer = %v", result.response)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("stale refresh did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := handler.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown() error = %v, want deadline exceeded", err)
	}
	releaseWorker()
	if err := handler.Shutdown(context.Background()); err != nil {
		t.Fatalf("draining repeated Shutdown() error = %v", err)
	}
	waitForAdmission(t, handler, 0)
}

func TestStaleRefreshRejectedAfterShutdown(t *testing.T) {
	runtime, handler, query := staleRefreshRuntime(t)
	var calls atomic.Int32
	handler.upstreamExchange = func(_ context.Context, query *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		calls.Add(1)
		return admissionAnswer(query), nil
	}
	if err := handler.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	result := handler.resolveForClient(query, runtime, "192.0.2.1")
	if result.response == nil || result.response.Rcode != dns.RcodeSuccess {
		t.Fatalf("post-shutdown stale answer = %v", result.response)
	}
	if calls.Load() != 0 {
		t.Fatalf("post-shutdown stale refresh started %d upstream calls", calls.Load())
	}
	waitForAdmission(t, handler, 0)
}

func TestInflightFollowerCancellationPreservesLeaderResult(t *testing.T) {
	group := newInflightGroup()
	key := inflightKey{name: "cancel-follower.example."}
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseLeader := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseLeader)
	leaderDone := make(chan resolution, 1)
	go func() {
		result, shared := group.doContext(context.Background(), key, func() resolution {
			close(started)
			<-release
			return resolution{response: new(dns.Msg)}
		})
		if shared {
			t.Errorf("leader shared = true, want false")
		}
		leaderDone <- result
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("leader did not start")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	followerDone := make(chan struct{}, 1)
	go func() {
		follower, shared := group.doContext(ctx, key, func() resolution {
			t.Error("canceled follower became leader")
			return resolution{}
		})
		if !shared || follower.response != nil {
			t.Errorf("canceled follower = %+v, shared=%v; want no response and shared", follower, shared)
		}
		followerDone <- struct{}{}
	}()
	select {
	case <-followerDone:
	case <-time.After(time.Second):
		t.Fatal("canceled follower did not detach from leader")
	}

	releaseLeader()
	select {
	case result := <-leaderDone:
		if result.response == nil {
			t.Fatal("leader result was lost after follower cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("leader did not finish")
	}
}

func TestConcurrentStaleRefreshAdmissionAndShutdown(t *testing.T) {
	configuration := testRuntimeConfig()
	configuration.MaxConcurrent = 64
	configuration.MaxConcurrentPerClient = 64
	configuration.ServeStale = true
	configuration.CacheStaleTTL = 300
	configuration.CacheStaleAnswerTTL = 30
	configuration.CacheStaleMaxWait = time.Millisecond
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := handler.Shutdown(ctx); err != nil {
			t.Errorf("cleanup Shutdown() error = %v", err)
		}
	})
	now := time.Now()
	runtime.cache.now = func() time.Time { return now }
	query := admissionQuery("concurrent-stale-lifecycle.example.")
	runtime.cache.Set(query, admissionAnswer(query), true)
	now = now.Add(61 * time.Second)

	started := make(chan struct{}, 1)
	handler.upstreamExchange = func(ctx context.Context, _ *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	const callers = 32
	start := make(chan struct{})
	responses := make(chan *dns.Msg, callers)
	var callersWG sync.WaitGroup
	callersWG.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer callersWG.Done()
			<-start
			responses <- handler.resolveForClient(query.Copy(), runtime, "192.0.2.1").response
		}()
	}
	close(start)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("concurrent stale refresh did not start")
	}
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- handler.Shutdown(context.Background()) }()
	callersDone := make(chan struct{})
	go func() {
		callersWG.Wait()
		close(callersDone)
	}()
	select {
	case <-callersDone:
	case <-time.After(time.Second):
		t.Fatal("concurrent stale callers did not finish")
	}
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent Shutdown() did not finish")
	}
	for i := 0; i < callers; i++ {
		select {
		case response := <-responses:
			if response == nil || response.Rcode != dns.RcodeSuccess {
				t.Fatalf("stale caller %d response = %v", i, response)
			}
		case <-time.After(time.Second):
			t.Fatalf("stale caller %d did not finish", i)
		}
	}
	waitForAdmission(t, handler, 0)
}
