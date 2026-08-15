package web

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

const (
	preAuthTokenBytes = 32
	preAuthTokenTTL   = 10 * time.Minute
	maxPreAuthTokens  = 2048
)

type preAuthTokenStore struct {
	mu     sync.Mutex
	tokens map[string]time.Time
	now    func() time.Time
}

func newPreAuthTokenStore() *preAuthTokenStore {
	return &preAuthTokenStore{
		tokens: make(map[string]time.Time),
		now:    time.Now,
	}
}

func (store *preAuthTokenStore) issue() (string, error) {
	random := make([]byte, preAuthTokenBytes)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(random)

	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.now()
	store.pruneExpired(now)
	if len(store.tokens) >= maxPreAuthTokens {
		store.evictOldest()
	}
	store.tokens[token] = now.Add(preAuthTokenTTL)
	return token, nil
}

func (store *preAuthTokenStore) consume(token string) bool {
	if token == "" {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	expires, found := store.tokens[token]
	if !found {
		return false
	}
	delete(store.tokens, token)
	return store.now().Before(expires)
}

func (store *preAuthTokenStore) pruneExpired(now time.Time) {
	for token, expires := range store.tokens {
		if !now.Before(expires) {
			delete(store.tokens, token)
		}
	}
}

func (store *preAuthTokenStore) evictOldest() {
	var oldestToken string
	var oldestExpiry time.Time
	for token, expires := range store.tokens {
		if oldestToken == "" || expires.Before(oldestExpiry) {
			oldestToken = token
			oldestExpiry = expires
		}
	}
	delete(store.tokens, oldestToken)
}
