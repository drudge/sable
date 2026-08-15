package auth

import (
	"sync"
	"time"
)

type attemptWindow struct {
	started time.Time
	count   int
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

func (limiter *loginLimiter) success(key string) {
	limiter.mu.Lock()
	delete(limiter.attempts, key)
	limiter.mu.Unlock()
}
