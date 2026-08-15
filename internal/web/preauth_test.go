package web

import (
	"testing"
	"time"
)

func TestPreAuthTokensAreOneTimeAndExpire(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	store := newPreAuthTokenStore()
	store.now = func() time.Time { return now }

	oneTimeToken, err := store.issue()
	if err != nil {
		t.Fatalf("issue() error = %v", err)
	}
	if !store.consume(oneTimeToken) {
		t.Fatal("first token consumption failed")
	}
	if store.consume(oneTimeToken) {
		t.Fatal("token was accepted more than once")
	}

	expiringToken, err := store.issue()
	if err != nil {
		t.Fatalf("issue() error = %v", err)
	}
	now = now.Add(preAuthTokenTTL)
	if store.consume(expiringToken) {
		t.Fatal("expired token was accepted")
	}
}
