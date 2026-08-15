package auth

import (
	"testing"
	"time"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	t.Parallel()

	encoded, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !VerifyPassword(encoded, "correct horse battery staple") {
		t.Fatal("VerifyPassword() = false for correct password")
	}
	if VerifyPassword(encoded, "incorrect password") {
		t.Fatal("VerifyPassword() = true for incorrect password")
	}
}

func TestPasswordValidationRejectsShortAndOversizedValues(t *testing.T) {
	t.Parallel()

	if _, err := HashPassword("too-short"); err == nil {
		t.Fatal("HashPassword() error = nil for short password")
	}
	oversized := make([]byte, maximumPassword+1)
	if _, err := HashPassword(string(oversized)); err == nil {
		t.Fatal("HashPassword() error = nil for oversized password")
	}
}

func TestLoginLimiterResetsAfterWindowAndSuccess(t *testing.T) {
	t.Parallel()

	limiter := newLoginLimiter(2, 10*time.Second)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !limiter.allow("user", now) {
		t.Fatal("first attempt was rejected")
	}
	limiter.failure("user", now)
	limiter.failure("user", now)
	if limiter.allow("user", now) {
		t.Fatal("limited attempt was allowed")
	}
	if !limiter.allow("user", now.Add(10*time.Second)) {
		t.Fatal("attempt after window was rejected")
	}
	limiter.failure("user", now)
	limiter.success("user")
	if !limiter.allow("user", now) {
		t.Fatal("attempt after success was rejected")
	}
}
