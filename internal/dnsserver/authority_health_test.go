package dnsserver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// An authority that never answers, as some of Apple's do over IPv6, cost each
// lookup a full retry timeout. The zone's other servers are its retries.
func TestIterativeResolverPassesOverASilentServerQuickly(t *testing.T) {
	t.Parallel()
	runtime := recursiveTestRuntime(t)
	runtime.retryTimeout = 1500 * time.Millisecond
	runtime.retries = 2
	handler := NewHandler(runtime)
	defer handler.Close()
	type attempt struct {
		endpoint string
		timeout  time.Duration
	}
	var attempts []attempt
	handler.upstreamExchange = func(_ context.Context, _ *dns.Msg, endpoint string, timeout time.Duration) (*dns.Msg, error) {
		attempts = append(attempts, attempt{endpoint, timeout})
		return nil, context.DeadlineExceeded
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	servers := []string{"192.0.2.10:53", "192.0.2.11:53", "192.0.2.12:53"}
	if _, err := handler.exchangeIterative(ctx, iterativeQuery("www.example.com.", dns.TypeA), servers, runtime, &iterativeBudget{remaining: maximumIterativeQueries}); err == nil {
		t.Fatal("every server failed, but the exchange succeeded")
	}
	if len(attempts) != 4 {
		t.Fatalf("attempts = %v, want one each for the first two servers and two for the last", attempts)
	}
	for index, current := range attempts {
		want := authorityAttemptTimeout
		if index >= 2 {
			want = runtime.retryTimeout
		}
		if current.timeout != want {
			t.Fatalf("attempt %d to %s waited %v, want %v", index, current.endpoint, current.timeout, want)
		}
	}
	if attempts[2].endpoint != attempts[3].endpoint {
		t.Fatalf("attempts = %v, want the last server retried", attempts)
	}
}

func TestAuthorityCooldownGrowsWhileAServerKeepsFailing(t *testing.T) {
	t.Parallel()
	now := time.Now()
	authorities := newAuthorityHealthTracker()
	authorities.now = func() time.Time { return now }
	forwarders := newUpstreamHealthTracker()
	forwarders.now = func() time.Time { return now }

	for failure, want := range []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second} {
		authorities.markUnhealthy("[2620:149:ae7::53]:53")
		if got := authorities.retryAfter["[2620:149:ae7::53]:53"].Sub(now); got != want {
			t.Fatalf("authority cooldown after failure %d = %v, want %v", failure+1, got, want)
		}
		forwarders.markUnhealthy("192.0.2.53:53")
		if got := forwarders.retryAfter["192.0.2.53:53"].Sub(now); got != upstreamUnhealthyCooldown {
			t.Fatalf("forwarder cooldown after failure %d = %v, want %v", failure+1, got, upstreamUnhealthyCooldown)
		}
	}
	for range 20 {
		authorities.markUnhealthy("[2620:149:ae7::53]:53")
	}
	if got := authorities.retryAfter["[2620:149:ae7::53]:53"].Sub(now); got != authorityUnhealthyCooldownLimit {
		t.Fatalf("authority cooldown = %v, want it capped at %v", got, authorityUnhealthyCooldownLimit)
	}
	authorities.markHealthy("[2620:149:ae7::53]:53")
	authorities.markUnhealthy("[2620:149:ae7::53]:53")
	if got := authorities.retryAfter["[2620:149:ae7::53]:53"].Sub(now); got != upstreamUnhealthyCooldown {
		t.Fatalf("cooldown after an answer and a new failure = %v, want it back at %v", got, upstreamUnhealthyCooldown)
	}
}
