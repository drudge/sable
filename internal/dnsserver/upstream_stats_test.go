package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/forwarding"
)

func TestForwarderStatsCountAttemptsAndPercentiles(t *testing.T) {
	t.Parallel()
	table := newForwarderStatsTable()
	answer := new(dns.Msg)
	for index := 1; index <= 100; index++ {
		table.observe("a", time.Duration(index)*time.Millisecond, answer, nil, false)
	}
	table.observe("a", 0, &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}, nil, false)
	table.observe("a", time.Second, nil, context.DeadlineExceeded, false)
	table.observe("a", time.Millisecond, nil, errors.New("tls: handshake failure"), false)

	stats := table.snapshot("a")
	if stats.Attempts != 103 || stats.Answers != 101 || stats.FailedAnswers != 1 || stats.Timeouts != 1 || stats.Errors != 1 {
		t.Fatalf("counts = %+v", stats)
	}
	// The SERVFAIL answer took under a microsecond and counts as one.
	if stats.Samples != 101 || stats.Median != 50*time.Millisecond || stats.P95 != 95*time.Millisecond {
		t.Fatalf("samples %d median %v p95 %v, want 101, 50ms, 95ms", stats.Samples, stats.Median, stats.P95)
	}
	if stats.LastError != "tls: handshake failure" || stats.LastErrorAt.IsZero() {
		t.Fatalf("last error = %q at %v", stats.LastError, stats.LastErrorAt)
	}
}

func TestForwarderStatsKeepOnlyRecentSamples(t *testing.T) {
	t.Parallel()
	table := newForwarderStatsTable()
	for range recentForwarderSamples {
		table.observe("a", time.Second, new(dns.Msg), nil, false)
	}
	for range recentForwarderSamples {
		table.observe("a", time.Millisecond, new(dns.Msg), nil, false)
	}
	if stats := table.snapshot("a"); stats.P95 != time.Millisecond {
		t.Fatalf("p95 = %v, want only the latest %d answers counted", stats.P95, recentForwarderSamples)
	}
}

func TestForwarderStatsSmoothResponseTimes(t *testing.T) {
	t.Parallel()
	table := newForwarderStatsTable()
	table.observe("a", 80*time.Millisecond, new(dns.Msg), nil, false)
	table.observe("a", 160*time.Millisecond, new(dns.Msg), nil, false)
	// The first answers are averaged, so a slow first answer that carried
	// a handshake washes out quickly.
	if got := table.orderingRTT("a"); got != 120*time.Millisecond {
		t.Fatalf("smoothed after two answers = %v, want their average, 120ms", got)
	}
	for range 6 {
		table.observe("a", 120*time.Millisecond, new(dns.Msg), nil, false)
	}
	// From the ninth answer on, RFC 6298 §2.3: SRTT = 7/8 SRTT + 1/8 R'.
	table.observe("a", 200*time.Millisecond, new(dns.Msg), nil, false)
	if got := table.orderingRTT("a"); got != 130*time.Millisecond {
		t.Fatalf("smoothed = %v, want 130ms", got)
	}
}

func TestForwarderStatsTableStaysBounded(t *testing.T) {
	t.Parallel()
	table := newForwarderStatsTable()
	for index := range maximumTrackedForwarders + 10 {
		table.observe(fmt.Sprintf("udp://192.0.2.%d:%d", index%250, index), time.Millisecond, new(dns.Msg), nil, false)
	}
	table.mu.RLock()
	size := len(table.byForwarder)
	table.mu.RUnlock()
	if size > maximumTrackedForwarders {
		t.Fatalf("table holds %d forwarders, want at most %d", size, maximumTrackedForwarders)
	}
}

// statsHandler builds a handler whose forwarders answer after the delay set
// for each, or fail when the delay is negative.
func statsHandler(t *testing.T, order string, forwarders ...string) (*Handler, *Runtime, func(map[string]time.Duration)) {
	t.Helper()
	configuration := testRuntimeConfig()
	configuration.Forwarders = forwarders
	configuration.ForwarderOrder = order
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	var mu sync.Mutex
	delays := map[string]time.Duration{}
	handler.upstreamExchange = func(_ context.Context, query *dns.Msg, forwarder string, _ time.Duration) (*dns.Msg, error) {
		mu.Lock()
		delay := delays[forwarder]
		mu.Unlock()
		if delay < 0 {
			return nil, errors.New("connection refused")
		}
		response := new(dns.Msg)
		response.SetReply(query)
		return response, nil
	}
	setDelays := func(next map[string]time.Duration) {
		mu.Lock()
		delays = next
		mu.Unlock()
	}
	return handler, runtime, setDelays
}

func firstForwarders(handler *Handler, runtime *Runtime, queries int) map[string]int {
	counts := map[string]int{}
	for range queries {
		counts[handler.orderForwarders(runtime, forwardersOf(runtime.forwarders))[0]]++
	}
	return counts
}

func TestForwarderOrderInOrderAlwaysStartsAtTheFirst(t *testing.T) {
	t.Parallel()
	handler, runtime, _ := statsHandler(t, forwarding.OrderInOrder, "udp://192.0.2.1:53", "udp://192.0.2.2:53", "udp://192.0.2.3:53")
	if counts := firstForwarders(handler, runtime, 30); counts["udp://192.0.2.1:53"] != 30 {
		t.Fatalf("first forwarder counts = %v, want the first listed every time", counts)
	}
	handler.upstreamHealth.markUnhealthy("udp://192.0.2.1:53")
	if got := handler.orderForwarders(runtime, forwardersOf(runtime.forwarders)); !slices.Equal(got, []string{"udp://192.0.2.2:53", "udp://192.0.2.3:53", "udp://192.0.2.1:53"}) {
		t.Fatalf("order with the first failing = %v, want the next in line first", got)
	}
}

func TestForwarderOrderRoundRobinIsTheDefault(t *testing.T) {
	t.Parallel()
	handler, runtime, _ := statsHandler(t, "", "udp://192.0.2.1:53", "udp://192.0.2.2:53", "udp://192.0.2.3:53")
	if runtime.forwarderOrder != forwarding.OrderRoundRobin {
		t.Fatalf("default order = %q", runtime.forwarderOrder)
	}
	counts := firstForwarders(handler, runtime, 30)
	for _, forwarder := range runtime.forwarders {
		if counts[forwarder] != 10 {
			t.Fatalf("first forwarder counts = %v, want an even share", counts)
		}
	}
}

func TestForwarderOrderFastestFirst(t *testing.T) {
	t.Parallel()
	slow, fast, dead, fresh := "udp://192.0.2.1:53", "udp://192.0.2.2:53", "udp://192.0.2.3:53", "udp://192.0.2.4:53"
	handler, runtime, _ := statsHandler(t, forwarding.OrderFastest, slow, fast, dead, fresh)
	for range 4 {
		handler.forwarderStats.observe(slow, 60*time.Millisecond, new(dns.Msg), nil, false)
		handler.forwarderStats.observe(fast, 8*time.Millisecond, new(dns.Msg), nil, false)
		handler.forwarderStats.observe(dead, time.Millisecond, nil, errors.New("connection refused"), false)
	}
	handler.upstreamIndex.Store(1)
	// fresh has never been asked, so it goes first to be measured; a
	// forwarder that has only ever failed goes last.
	if got := handler.orderForwarders(runtime, forwardersOf(runtime.forwarders)); !slices.Equal(got, []string{fresh, fast, slow, dead}) {
		t.Fatalf("fastest order = %v", got)
	}
	handler.forwarderStats.observe(fresh, 30*time.Millisecond, new(dns.Msg), nil, false)
	speeds := map[string]time.Duration{slow: 60 * time.Millisecond, fast: 8 * time.Millisecond, fresh: 30 * time.Millisecond}
	counts := map[string]int{}
	clock := time.Now()
	for range 10 * fastestExploreEvery {
		chosen := handler.orderForwarders(runtime, forwardersOf(runtime.forwarders))[0]
		counts[chosen]++
		clock = clock.Add(time.Millisecond)
		handler.forwarderStats.now = func() time.Time { return clock }
		if speed, answers := speeds[chosen]; answers {
			handler.forwarderStats.observe(chosen, speed, new(dns.Msg), nil, false)
		} else {
			handler.forwarderStats.observe(chosen, time.Millisecond, nil, errors.New("connection refused"), false)
		}
	}
	if counts[fast] < 9*fastestExploreEvery {
		t.Fatalf("first forwarder counts = %v, want the fastest nearly every time", counts)
	}
	if counts[slow] < 2 || counts[fresh] < 2 || counts[dead] < 2 {
		t.Fatalf("first forwarder counts = %v, want every other forwarder explored in its turn", counts)
	}
	// Health still comes first.
	handler.upstreamHealth.markUnhealthy(fast)
	handler.upstreamIndex.Store(1)
	if got := handler.orderForwarders(runtime, forwardersOf(runtime.forwarders)); got[0] != fresh || got[len(got)-1] != fast {
		t.Fatalf("fastest order with the fastest failing = %v, want it last", got)
	}
}

func TestForwarderOrderFastestKeepsFWDPriority(t *testing.T) {
	t.Parallel()
	handler, runtime, _ := statsHandler(t, forwarding.OrderFastest, "udp://192.0.2.1:53")
	backup := forwarderList{endpoints: []string{"udp://192.0.2.10:53", "udp://192.0.2.11:53", "udp://192.0.2.20:53"}, ranks: []int{10, 10, 20}}
	handler.forwarderStats.observe("udp://192.0.2.10:53", 50*time.Millisecond, new(dns.Msg), nil, false)
	handler.forwarderStats.observe("udp://192.0.2.11:53", 40*time.Millisecond, new(dns.Msg), nil, false)
	handler.forwarderStats.observe("udp://192.0.2.20:53", time.Millisecond, new(dns.Msg), nil, false)
	handler.upstreamIndex.Store(1)
	if got := handler.orderForwarders(runtime, backup); !slices.Equal(got, []string{"udp://192.0.2.11:53", "udp://192.0.2.10:53", "udp://192.0.2.20:53"}) {
		t.Fatalf("order = %v, want speed to decide only within a priority", got)
	}
}

func TestCompileRefusesUnknownForwarderOrder(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.ForwarderOrder = "random"
	if _, err := Compile(configuration); err == nil {
		t.Fatal("Compile() accepted an unknown forwarder order")
	}
}

// Every attempt a query makes is counted against its forwarder, and the
// stats list the configured forwarders in order with their health.
func TestForwardedQueriesFillForwarderStats(t *testing.T) {
	t.Parallel()
	good, bad := "udp://192.0.2.1:53", "udp://192.0.2.2:53"
	handler, runtime, setDelays := statsHandler(t, forwarding.OrderInOrder, bad, good)
	setDelays(map[string]time.Duration{bad: -1})
	request := new(dns.Msg)
	request.SetQuestion("host.example.", dns.TypeA)
	if result := handler.resolve(request, runtime); result.response == nil || result.response.Rcode != dns.RcodeSuccess {
		t.Fatalf("resolve = %+v", result.response)
	}
	stats := handler.ForwarderStats()
	if len(stats) != 2 || stats[0].Forwarder != bad || stats[1].Forwarder != good {
		t.Fatalf("stats = %+v, want the configured forwarders in order", stats)
	}
	if stats[0].Errors != uint64(runtime.retries) || stats[0].CoolingUntil.IsZero() || stats[0].LastError == "" {
		t.Fatalf("failing forwarder stats = %+v, want every retry counted and a cooldown", stats[0])
	}
	if stats[1].Answers != 1 || stats[1].Samples != 1 || !stats[1].CoolingUntil.IsZero() {
		t.Fatalf("answering forwarder stats = %+v", stats[1])
	}
}

func TestTestForwardersReportsValidation(t *testing.T) {
	t.Parallel()
	validating, plain, broken := "udp://192.0.2.1:53", "tls://dns.example (192.0.2.2)", "udp://192.0.2.3:53"
	configuration := testRuntimeConfig()
	configuration.Forwarders = []string{validating, plain, broken}
	configuration.Routes = []ForwardingRoute{{Domain: "corp.example", Forwarders: []string{validating}}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	var mu sync.Mutex
	asked := map[string]int{}
	handler.upstreamExchange = func(_ context.Context, query *dns.Msg, forwarder string, _ time.Duration) (*dns.Msg, error) {
		mu.Lock()
		asked[forwarder]++
		mu.Unlock()
		if !query.RecursionDesired || !query.AuthenticatedData || query.IsEdns0() == nil || !query.IsEdns0().Do() {
			t.Errorf("probe to %s lacks RD, AD, or DO: %v", forwarder, query)
		}
		if forwarder == broken {
			return nil, context.DeadlineExceeded
		}
		response := new(dns.Msg)
		response.SetReply(query)
		validates := forwarder == validating
		if query.Question[0].Name == forwarderProbeBogus && validates {
			response.Rcode = dns.RcodeServerFailure
		}
		response.AuthenticatedData = validates && query.Question[0].Name == forwarderProbeSigned
		return response, nil
	}
	results := handler.TestForwarders(context.Background())
	if len(results) != 4 {
		t.Fatalf("results = %+v, want the three forwarders and the route", results)
	}
	byKey := map[string]ForwarderTest{}
	for _, result := range results {
		byKey[result.Route+"|"+result.Forwarder] = result
	}
	if result := byKey["|"+validating]; !result.OK || !result.AuthenticatedData || result.Validates != "yes" || result.ResponseCode != "NOERROR" {
		t.Fatalf("validating forwarder = %+v", result)
	}
	if result := byKey["|"+plain]; !result.OK || result.AuthenticatedData || result.Validates != "no" {
		t.Fatalf("plain forwarder = %+v", result)
	}
	if result := byKey["|"+broken]; result.OK || result.Error != "no answer in time" {
		t.Fatalf("broken forwarder = %+v", result)
	}
	if result := byKey["corp.example|"+validating]; result.Validates != "yes" {
		t.Fatalf("route forwarder = %+v, want the shared forwarder's result", result)
	}
	// The validating forwarder is shared with the route but asked once:
	// the signed name three times and the bogus name once.
	if asked[validating] != forwarderProbeRepeats+1 {
		t.Fatalf("validating forwarder asked %d times, want %d", asked[validating], forwarderProbeRepeats+1)
	}
	if stats := handler.ForwarderStats(); stats[0].Attempts != 0 {
		t.Fatalf("test queries counted in the stats: %+v", stats[0])
	}
}

// An answer that waited for a new connection counts, but its time measures
// the handshake, so it stays out of the response times. A forwarder that has
// only answered that way gets the next turn, to be timed.
func TestForwarderStatsLeaveOutConnectionSetup(t *testing.T) {
	t.Parallel()
	table := newForwarderStatsTable()
	table.observe("tls://dns.example (192.0.2.1)", 150*time.Millisecond, new(dns.Msg), nil, true)
	stats := table.snapshot("tls://dns.example (192.0.2.1)")
	if stats.Answers != 1 || stats.Connections != 1 || stats.Samples != 0 || stats.Smoothed != 0 {
		t.Fatalf("stats = %+v, want the answer counted and its time left out", stats)
	}
	if got := table.orderingRTT("tls://dns.example (192.0.2.1)"); got != 0 {
		t.Fatalf("orderingRTT = %v, want 0 so it is timed next", got)
	}
	table.observe("tls://dns.example (192.0.2.1)", 20*time.Millisecond, new(dns.Msg), nil, false)
	if stats := table.snapshot("tls://dns.example (192.0.2.1)"); stats.Median != 20*time.Millisecond || stats.Smoothed != 20*time.Millisecond {
		t.Fatalf("stats = %+v, want only the warm answer timed", stats)
	}
}

// The pool marks an exchange that opened a connection, over each encrypted
// transport, and not one that reused it.
func TestForwarderPoolMarksNewConnections(t *testing.T) {
	t.Parallel()
	dot, _, dotRoots := startTestDoTServer(t)
	doq, _, doqRoots := startTestDoQForwarder(t)
	doh := startTestDoHServer(t)
	for _, test := range []struct {
		name, forwarder string
		pool            *forwarderPool
	}{
		{"DoT", dot, trustingPool(dotRoots)},
		{"DoQ", doq, trustingPool(doqRoots)},
		{"DoH", doh.forwarder("/dns-query"), func() *forwarderPool { pool := newForwarderPool(); trustDoH(pool, doh.roots()); return pool }()},
	} {
		t.Cleanup(test.pool.Close)
		for index, want := range []bool{true, false} {
			ctx, opened := withConnectionMark(context.Background())
			if _, err := test.pool.exchange(ctx, testForwarderRequest(), test.forwarder, 2*time.Second); err != nil {
				t.Fatalf("%s exchange %d: %v", test.name, index, err)
			}
			if opened.Load() != want {
				t.Errorf("%s exchange %d marked a new connection = %v, want %v", test.name, index, opened.Load(), want)
			}
		}
	}
}
