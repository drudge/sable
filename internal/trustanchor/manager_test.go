package trustanchor

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type memoryStore struct {
	mu       sync.Mutex
	snapshot Snapshot
}

func (store *memoryStore) LoadTrustAnchorSnapshot(_ context.Context, owner string) (Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.snapshot.Status.Owner == "" {
		return Snapshot{Status: Status{Owner: owner}}, nil
	}
	return cloneSnapshot(store.snapshot), nil
}

func (store *memoryStore) SaveTrustAnchorSnapshot(_ context.Context, snapshot Snapshot) error {
	store.mu.Lock()
	store.snapshot = cloneSnapshot(snapshot)
	store.mu.Unlock()
	return nil
}

type testKey struct {
	key     *dns.DNSKEY
	private crypto.Signer
}

func TestManagerAddsNewKeyOnlyAfterHoldDownAndPersistsIt(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	clock := now
	active := newTestKey(t, ".")
	standby := newTestKey(t, ".")
	response := signedDNSKEYResponse(t, now, []*testKey{active, standby}, active)
	store := &memoryStore{}
	query := func(context.Context, string, uint16) (*dns.Msg, error) { return response.Copy(), nil }
	manager, err := New(context.Background(), store, query, Options{
		Bootstrap: []string{dnskeyAnchor(active.key)},
		Now:       func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := manager.Status()
	if status.Active != 1 || status.Pending != 1 || status.NextRefresh.Sub(now) != time.Hour {
		t.Fatalf("initial status = %+v", status)
	}

	clock = now.Add(30*24*time.Hour + time.Minute)
	response = signedDNSKEYResponse(t, clock, []*testKey{active, standby}, active)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	anchors, initialized := manager.ActiveAnchors()
	if !initialized || len(anchors) != 2 || manager.Status().Pending != 0 {
		t.Fatalf("accepted anchors = %v, status = %+v", anchors, manager.Status())
	}
	clock = clock.Add(time.Hour)
	response = signedDNSKEYResponse(t, clock, []*testKey{active}, active)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	anchors, _ = manager.ActiveAnchors()
	if len(anchors) != 2 || manager.Status().Missing != 1 || manager.Status().Active != 2 {
		t.Fatalf("missing anchor status = %+v, anchors = %v", manager.Status(), anchors)
	}

	restarted, err := New(context.Background(), store, query, Options{Bootstrap: []string{dnskeyAnchor(active.key)}})
	if err != nil {
		t.Fatal(err)
	}
	restored, initialized := restarted.ActiveAnchors()
	if !initialized || len(restored) != 2 {
		t.Fatalf("restored anchors = %v, initialized = %t", restored, initialized)
	}
}

func TestManagerResetsPendingKeyWhenItDisappears(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	clock := now
	active := newTestKey(t, ".")
	pending := newTestKey(t, ".")
	response := signedDNSKEYResponse(t, now, []*testKey{active, pending}, active)
	manager, err := New(context.Background(), &memoryStore{}, func(context.Context, string, uint16) (*dns.Msg, error) {
		return response.Copy(), nil
	}, Options{Bootstrap: []string{dnskeyAnchor(active.key)}, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(time.Hour)
	response = signedDNSKEYResponse(t, clock, []*testKey{active}, active)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if manager.Status().Pending != 0 || len(manager.ActiveAnchorStatesForTest()) != 1 {
		t.Fatalf("status after disappearance = %+v", manager.Status())
	}
	clock = now.Add(2 * time.Hour)
	response = signedDNSKEYResponse(t, clock, []*testKey{active, pending}, active)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	restartedAt := time.Time{}
	for _, anchor := range manager.snapshot.Anchors {
		if anchor.State == StateAddPending {
			restartedAt = anchor.FirstSeen
		}
	}
	if manager.snapshot.Status.Pending != 1 || len(manager.snapshot.Anchors) != 2 || !restartedAt.Equal(clock) {
		t.Fatalf("restarted pending state = %+v", manager.snapshot)
	}
}

func TestManagerImmediatelyRevokesOnlySelfSignedKey(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	clock := now
	active := newTestKey(t, ".")
	response := signedDNSKEYResponse(t, now, []*testKey{active}, active)
	store := &memoryStore{}
	manager, err := New(context.Background(), store, func(context.Context, string, uint16) (*dns.Msg, error) {
		return response.Copy(), nil
	}, Options{Bootstrap: []string{dnskeyAnchor(active.key)}, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	clock = now.Add(time.Hour)
	revoked := *active.key
	revoked.Flags |= revokeFlag
	revokedKey := &testKey{key: &revoked, private: active.private}
	response = signedDNSKEYResponse(t, clock, []*testKey{revokedKey}, revokedKey)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	anchors, _ := manager.ActiveAnchors()
	status := manager.Status()
	if len(anchors) != 0 || status.Revoked != 1 || status.Active != 0 {
		t.Fatalf("revocation status = %+v, anchors = %v", status, anchors)
	}
}

func TestManagerRejectsRevocationWithoutRevokedKeySelfSignature(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	clock := now
	first := newTestKey(t, ".")
	second := newTestKey(t, ".")
	response := signedDNSKEYResponse(t, now, []*testKey{first, second}, second)
	manager, err := New(context.Background(), &memoryStore{}, func(context.Context, string, uint16) (*dns.Msg, error) {
		return response.Copy(), nil
	}, Options{
		Bootstrap: []string{dnskeyAnchor(first.key), dnskeyAnchor(second.key)},
		Now:       func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(time.Hour)
	revoked := *first.key
	revoked.Flags |= revokeFlag
	response = signedDNSKEYResponse(t, clock, []*testKey{{key: &revoked, private: first.private}, second}, second)
	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := manager.Status()
	if status.Revoked != 0 || status.Active != 2 {
		t.Fatalf("unauthenticated revocation changed state: %+v", status)
	}
}

func TestManagerFailureUsesRFC5011RetryFloor(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	manager, err := New(context.Background(), &memoryStore{}, func(context.Context, string, uint16) (*dns.Msg, error) {
		return nil, context.DeadlineExceeded
	}, Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh() error = nil")
	}
	status := manager.Status()
	if status.LastError == "" || status.NextRefresh.Sub(now) != 24*time.Hour {
		t.Fatalf("failure status = %+v", status)
	}
}

func TestManagerRefreshIntervalFollowsTheLastKeySetSeen(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t, ".")
	for _, testCase := range []struct {
		name    string
		refresh bool
		want    time.Duration
	}{
		{name: "never refreshed waits the longest interval", want: 15 * 24 * time.Hour},
		// The key set's TTL is two hours and its signature has four hours
		// left, so half the TTL comes first.
		{name: "refreshed waits half the key set's TTL", refresh: true, want: time.Hour},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			response := signedDNSKEYResponse(t, now, []*testKey{key}, key)
			manager, err := New(context.Background(), &memoryStore{}, func(context.Context, string, uint16) (*dns.Msg, error) {
				return response.Copy(), nil
			}, Options{
				Bootstrap:      []string{dnskeyAnchor(key.key)},
				MinimumRefresh: time.Minute,
				Now:            func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			if testCase.refresh {
				if err := manager.Refresh(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if got := manager.RefreshInterval(); got != testCase.want {
				t.Fatalf("RefreshInterval() = %s, want %s", got, testCase.want)
			}
		})
	}
}

func newTestKey(t *testing.T, owner string) *testKey {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 7200},
		Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256,
	}
	private, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		t.Fatalf("private key %T is not crypto.Signer", private)
	}
	return &testKey{key: key, private: signer}
}

func signedDNSKEYResponse(t *testing.T, now time.Time, keys []*testKey, signer *testKey) *dns.Msg {
	t.Helper()
	rrset := make([]dns.RR, 0, len(keys))
	for _, key := range keys {
		rrset = append(rrset, key.key)
	}
	signature := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: ".", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 7200},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   signer.key.Algorithm,
		Labels:      0,
		OrigTtl:     7200,
		Expiration:  uint32(now.Add(4 * time.Hour).Unix()),
		Inception:   uint32(now.Add(-time.Hour).Unix()),
		KeyTag:      signer.key.KeyTag(),
		SignerName:  ".",
	}
	if err := signature.Sign(signer.private, rrset); err != nil {
		t.Fatal(err)
	}
	request := new(dns.Msg)
	request.SetQuestion(".", dns.TypeDNSKEY)
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = append(rrset, signature)
	return response
}

func dnskeyAnchor(key *dns.DNSKEY) string {
	return fmt.Sprintf(". DNSKEY %d %d %d %s", key.Flags, key.Protocol, key.Algorithm, key.PublicKey)
}

// ActiveAnchorStatesForTest returns non-removed state count without exposing
// mutable manager state to the tests.
func (manager *Manager) ActiveAnchorStatesForTest() []Anchor {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	var states []Anchor
	for _, anchor := range manager.snapshot.Anchors {
		if anchor.State != StateRemoved {
			states = append(states, anchor)
		}
	}
	return states
}

// fakeRun drives Run against a fake clock: each wait advances the clock at
// once, and Run stops once the clock passes until.
type fakeRun struct {
	mu       sync.Mutex
	clock    time.Time
	until    time.Time
	attempts []time.Time
	cancel   context.CancelFunc
}

func (run *fakeRun) now() time.Time {
	run.mu.Lock()
	defer run.mu.Unlock()
	return run.clock
}

func (run *fakeRun) wait(_ context.Context, duration time.Duration) bool {
	run.mu.Lock()
	defer run.mu.Unlock()
	run.clock = run.clock.Add(duration)
	if !run.clock.Before(run.until) {
		run.cancel()
		return false
	}
	return true
}

func (run *fakeRun) attemptsBefore(limit time.Time) int {
	run.mu.Lock()
	defer run.mu.Unlock()
	count := 0
	for _, attempt := range run.attempts {
		if attempt.Before(limit) {
			count++
		}
	}
	return count
}

func TestRunBacksOffWhileTheTrustPointHasNeverRefreshed(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &fakeRun{clock: start, until: start.Add(time.Hour), cancel: cancel}
	manager, err := New(ctx, &memoryStore{}, func(context.Context, string, uint16) (*dns.Msg, error) {
		run.mu.Lock()
		run.attempts = append(run.attempts, run.clock)
		run.mu.Unlock()
		return nil, fmt.Errorf("dial udp: connect: network is unreachable")
	}, Options{Now: run.now})
	if err != nil {
		t.Fatal(err)
	}
	manager.wait = run.wait
	manager.Run(ctx, slog.New(slog.DiscardHandler))

	// Tries at 0s, 5s, 15s and 35s, then 75s, 155s, 315s and every five
	// minutes after that.
	if got := run.attemptsBefore(start.Add(time.Minute)); got != 4 {
		t.Fatalf("attempts in the first minute = %d, want 4 (%v)", got, run.attempts)
	}
	if got := run.attemptsBefore(start.Add(time.Hour)); got > 20 {
		t.Fatalf("attempts in the first hour = %d, want at most 20", got)
	}
	if manager.Status().Initialized {
		t.Fatal("trust point initialized without a successful refresh")
	}
}

func TestRunWaitsForTheRetryIntervalAfterAnInitializedFailure(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	key := newTestKey(t, ".")
	response := signedDNSKEYResponse(t, start, []*testKey{key}, key)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &fakeRun{clock: start, until: start.Add(24 * time.Hour), cancel: cancel}
	manager, err := New(ctx, &memoryStore{}, func(context.Context, string, uint16) (*dns.Msg, error) {
		run.mu.Lock()
		run.attempts = append(run.attempts, run.clock)
		first := len(run.attempts) == 1
		run.mu.Unlock()
		if first {
			return response.Copy(), nil
		}
		return nil, context.DeadlineExceeded
	}, Options{Bootstrap: []string{dnskeyAnchor(key.key)}, Now: run.now})
	if err != nil {
		t.Fatal(err)
	}
	manager.wait = run.wait
	manager.Run(ctx, slog.New(slog.DiscardHandler))

	// The key set's TTL is two hours, so refreshes are due hourly and a
	// failure waits the one-hour RFC 5011 retry floor: no more than one try
	// an hour.
	if got := run.attemptsBefore(start.Add(24 * time.Hour)); got < 2 || got > 25 {
		t.Fatalf("attempts in a day = %d, want 2 to 25 (%v)", got, run.attempts)
	}
	if !manager.Status().Initialized {
		t.Fatal("first refresh did not initialize the trust point")
	}
}

func TestRunReturnsPromptlyWhenCancelled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	calls := 0
	manager, err := New(ctx, &memoryStore{}, func(ctx context.Context, _ string, _ uint16) (*dns.Msg, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		// Like a forwarder that only times out: hold until cancelled.
		<-ctx.Done()
		return nil, ctx.Err()
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		manager.Run(ctx, slog.New(slog.DiscardHandler))
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return within a second of cancel")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("refresh attempts = %d, want 1", calls)
	}
}

func TestRetryBackoffDoublesUpToTheCap(t *testing.T) {
	t.Parallel()
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 5 * time.Minute, 5 * time.Minute}
	for index, expected := range want {
		if got := retryBackoff(index + 1); got != expected {
			t.Fatalf("retryBackoff(%d) = %s, want %s", index+1, got, expected)
		}
	}
	if got := retryBackoff(1 << 20); got != retryBackoffMax {
		t.Fatalf("retryBackoff(large) = %s, want %s", got, retryBackoffMax)
	}
}
