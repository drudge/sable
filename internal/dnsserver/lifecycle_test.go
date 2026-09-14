package dnsserver

import (
	"context"
	"errors"
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
