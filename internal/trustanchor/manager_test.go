package trustanchor

import (
	"context"
	"crypto"
	"fmt"
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
