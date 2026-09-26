package alerts

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/webpush"
)

var testNow = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

// memorySent is the store's record of what was sent, in memory.
type memorySent struct {
	mu    sync.Mutex
	sent  map[string]map[string]time.Time
	known map[string]bool
}

func newMemorySent() *memorySent {
	return &memorySent{sent: map[string]map[string]time.Time{}, known: map[string]bool{}}
}

func (store *memorySent) AlertsSent(_ context.Context, target string) (map[string]time.Time, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	copied := make(map[string]time.Time, len(store.sent[target]))
	for id, at := range store.sent[target] {
		copied[id] = at
	}
	return copied, store.known[target] || len(copied) > 0, nil
}

func (store *memorySent) MarkAlertsSent(_ context.Context, target string, ids []string, at time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.sent[target] == nil {
		store.sent[target] = map[string]time.Time{}
	}
	for _, id := range ids {
		store.sent[target][id] = at
	}
	store.known[target] = true
	return nil
}

func (store *memorySent) ForgetAlertsSent(_ context.Context, target string, ids []string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, id := range ids {
		delete(store.sent[target], id)
	}
	return nil
}

func (store *memorySent) has(target, id string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, found := store.sent[target][id]
	return found
}

// memoryVault is the encrypted vault, without the encryption.
type memoryVault struct {
	mu      sync.Mutex
	entries map[string][]byte
}

func newMemoryVault() *memoryVault { return &memoryVault{entries: map[string][]byte{}} }

func (vault *memoryVault) Put(_ context.Context, name string, plaintext []byte) error {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	vault.entries[name] = slices.Clone(plaintext)
	return nil
}

func (vault *memoryVault) Get(_ context.Context, name string) ([]byte, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	entry, found := vault.entries[name]
	if !found {
		return nil, auth.ErrNotFound
	}
	return slices.Clone(entry), nil
}

func (vault *memoryVault) Delete(_ context.Context, name string) error {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	delete(vault.entries, name)
	return nil
}

// staticSource reports whatever alerts it is told to, or an error.
type staticSource struct {
	mu     sync.Mutex
	alerts []Alert
	err    error
}

func (source *staticSource) set(alerts ...Alert) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.alerts, source.err = alerts, nil
}

func (source *staticSource) fail(err error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.err = err
}

func (source *staticSource) Alerts(context.Context, time.Time) ([]Alert, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	return slices.Clone(source.alerts), source.err
}

// recordingHook is a webhook that records what it receives and answers with a
// status it can be told to change.
type recordingHook struct {
	*httptest.Server
	mu       sync.Mutex
	requests []recordedRequest
	status   int
}

type recordedRequest struct {
	header http.Header
	body   string
}

func newRecordingHook(t *testing.T) *recordingHook {
	t.Helper()
	hook := &recordingHook{status: http.StatusNoContent}
	hook.Server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		hook.mu.Lock()
		hook.requests = append(hook.requests, recordedRequest{header: request.Header.Clone(), body: string(body)})
		status := hook.status
		hook.mu.Unlock()
		writer.WriteHeader(status)
	}))
	t.Cleanup(hook.Close)
	return hook
}

func (hook *recordingHook) received() []recordedRequest {
	hook.mu.Lock()
	defer hook.mu.Unlock()
	return slices.Clone(hook.requests)
}

func (hook *recordingHook) answer(status int) {
	hook.mu.Lock()
	defer hook.mu.Unlock()
	hook.status = status
}

// fixedPushKeys stands in for the vault-backed key store.
type fixedPushKeys struct{ key *ecdsa.PrivateKey }

func (keys fixedPushKeys) PushKey(context.Context) (*ecdsa.PrivateKey, error) { return keys.key, nil }

// memorySubscriptions keeps browser subscriptions in memory.
type memorySubscriptions struct {
	mu            sync.Mutex
	subscriptions []webpush.Subscription
}

func (store *memorySubscriptions) PushSubscriptions(context.Context) ([]webpush.Subscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return slices.Clone(store.subscriptions), nil
}

func (store *memorySubscriptions) DeletePushSubscription(_ context.Context, endpoint string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.subscriptions = slices.DeleteFunc(store.subscriptions, func(subscription webpush.Subscription) bool {
		return subscription.Endpoint == endpoint
	})
	return nil
}

// browserSubscriptionFor is a subscription a browser would hand the page.
func browserSubscriptionFor(t *testing.T, endpoint string) webpush.Subscription {
	t.Helper()
	browser, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return webpush.Subscription{
		Endpoint: endpoint, Label: "Chrome on macOS", CreatedAt: testNow,
		P256DH: base64.RawURLEncoding.EncodeToString(browser.PublicKey().Bytes()),
		Auth:   base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")),
	}
}

// newTestDispatcher sends to the given destinations, whose secrets are kept in
// memory, from the given sources.
func newTestDispatcher(t *testing.T, destinations []config.AlertDestination, sources ...Source) (*Dispatcher, *memorySent, *config.Config) {
	t.Helper()
	configuration := config.Defaults()
	configuration.Alerts.Destinations = destinations
	secrets := NewSecretStore(newMemoryVault())
	for index, destination := range configuration.Alerts.Destinations {
		if err := secrets.Put(context.Background(), destination.ID, SecretsOf(destination)); err != nil {
			t.Fatal(err)
		}
		configuration.Alerts.Destinations[index] = Strip(destination)
	}
	sent := newMemorySent()
	dispatcher := &Dispatcher{
		Config:  func() config.Config { return configuration },
		Secrets: secrets,
		Sent:    sent,
	}
	dispatcher.Add(sources...)
	return dispatcher, sent, &configuration
}

var errTestSource = errors.New("source failed")

// pushService is a browser's push service: it records each push and can be
// told the subscription is gone.
type pushService struct {
	*httptest.Server
	mu     sync.Mutex
	pushes []*http.Request
	gone   bool
}

func newPushService(t *testing.T) *pushService {
	t.Helper()
	service := &pushService{}
	service.Server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		service.mu.Lock()
		defer service.mu.Unlock()
		service.pushes = append(service.pushes, request)
		if service.gone {
			writer.WriteHeader(http.StatusGone)
			return
		}
		writer.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(service.Close)
	return service
}

func (service *pushService) received() []*http.Request {
	service.mu.Lock()
	defer service.mu.Unlock()
	return slices.Clone(service.pushes)
}

func (service *pushService) goAway() {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.gone = true
}
