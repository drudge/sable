package auth

import (
	"sync"
	"time"
)

type attemptWindow struct {
	started time.Time
	count   int
	// refused marks a window that has already turned an attempt away.
	refused bool
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]attemptWindow
	limit    int
	window   time.Duration
}

const maximumTrackedLoginKeys = 10_000

func newLoginLimiter(limit int, window time.Duration) *loginLimiter {
	return &loginLimiter{attempts: make(map[string]attemptWindow), limit: limit, window: window}
}

func (limiter *loginLimiter) allow(key string, now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if _, tracked := limiter.attempts[key]; !tracked && len(limiter.attempts) >= maximumTrackedLoginKeys {
		limiter.prune(now)
		if len(limiter.attempts) >= maximumTrackedLoginKeys {
			return false
		}
	}
	attempt := limiter.attempts[key]
	if attempt.started.IsZero() || now.Sub(attempt.started) >= limiter.window {
		limiter.attempts[key] = attemptWindow{started: now}
		return true
	}
	return attempt.count < limiter.limit
}

func (limiter *loginLimiter) prune(now time.Time) {
	for key, attempt := range limiter.attempts {
		if now.Sub(attempt.started) >= limiter.window {
			delete(limiter.attempts, key)
		}
	}
}

func (limiter *loginLimiter) failure(key string, now time.Time) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	attempt := limiter.attempts[key]
	if attempt.started.IsZero() || now.Sub(attempt.started) >= limiter.window {
		attempt = attemptWindow{started: now}
	}
	attempt.count++
	limiter.attempts[key] = attempt
}

// refuse notes that an attempt under key was turned away, and reports whether
// it is the first its window has turned away. That makes a lockout one event,
// however many requests arrive while it lasts. A key the limiter is not
// tracking was turned away because too many keys are, which is no lockout.
func (limiter *loginLimiter) refuse(key string, now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	attempt, tracked := limiter.attempts[key]
	if !tracked || attempt.refused || now.Sub(attempt.started) >= limiter.window {
		return false
	}
	attempt.refused = true
	limiter.attempts[key] = attempt
	return true
}

func (limiter *loginLimiter) success(key string) {
	limiter.mu.Lock()
	delete(limiter.attempts, key)
	limiter.mu.Unlock()
}
