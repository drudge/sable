package web

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/drudge/sable/internal/oidc"
)

const (
	ssoStateBytes = 32
	// ssoStateTTL bounds how long a half-finished sign-in stays redeemable.
	// Ten minutes is long enough to approve a passkey prompt or type a
	// one-time code, and short enough that an abandoned attempt is not left
	// lying around.
	ssoStateTTL = 10 * time.Minute
	maxSSOState = 2048
)

// ssoStateStore holds the per-sign-in secrets between the redirect out to the
// provider and the callback that comes back.
//
// It is deliberately in memory rather than in the browser. The PKCE verifier
// is what proves the callback belongs to the browser that started, so handing
// it to that browser and trusting it to hand it back would defeat the point.
// The browser only carries a lookup key. A restart loses in-flight sign-ins,
// which is the same behaviour the sign-in form already has.
type ssoStateStore struct {
	mutex   sync.Mutex
	entries map[string]ssoStateEntry
	now     func() time.Time
}

type ssoStateEntry struct {
	request oidc.Request
	expires time.Time
}

func newSSOStateStore() *ssoStateStore {
	return &ssoStateStore{entries: make(map[string]ssoStateEntry), now: time.Now}
}

// issue stores a started sign-in and returns the key the browser carries.
func (store *ssoStateStore) issue(request oidc.Request) (string, error) {
	random := make([]byte, ssoStateBytes)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	key := base64.RawURLEncoding.EncodeToString(random)

	store.mutex.Lock()
	defer store.mutex.Unlock()
	now := store.now()
	store.pruneExpired(now)
	if len(store.entries) >= maxSSOState {
		store.evictOldest()
	}
	store.entries[key] = ssoStateEntry{request: request, expires: now.Add(ssoStateTTL)}
	return key, nil
}

// consume redeems a started sign-in exactly once. A second callback carrying
// the same key finds nothing, which is what makes an intercepted callback URL
// useless after the browser has already used it.
func (store *ssoStateStore) consume(key string) (oidc.Request, bool) {
	if key == "" {
		return oidc.Request{}, false
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	entry, found := store.entries[key]
	if !found {
		return oidc.Request{}, false
	}
	delete(store.entries, key)
	if !store.now().Before(entry.expires) {
		return oidc.Request{}, false
	}
	return entry.request, true
}

func (store *ssoStateStore) pruneExpired(now time.Time) {
	for key, entry := range store.entries {
		if !now.Before(entry.expires) {
			delete(store.entries, key)
		}
	}
}

func (store *ssoStateStore) evictOldest() {
	var oldestKey string
	var oldestExpiry time.Time
	for key, entry := range store.entries {
		if oldestKey == "" || entry.expires.Before(oldestExpiry) {
			oldestKey, oldestExpiry = key, entry.expires
		}
	}
	delete(store.entries, oldestKey)
}
