package web

import (
	"sync"
	"time"
)

// shortCache keeps values for a few seconds, for reads that every open
// console tab repeats on its poll. A load runs under the lock, so callers that
// miss together share one read. Errors are never kept. The zero value is
// ready to use.
type shortCache[K comparable, V any] struct {
	mu      sync.Mutex
	entries map[K]shortCacheEntry[V]
}

type shortCacheEntry[V any] struct {
	value   V
	expires time.Time
}

func (cache *shortCache[K, V]) get(key K, now time.Time, ttl time.Duration, load func() (V, error)) (V, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if entry, found := cache.entries[key]; found && now.Before(entry.expires) {
		return entry.value, nil
	}
	value, err := load()
	if err != nil {
		return value, err
	}
	if cache.entries == nil {
		cache.entries = make(map[K]shortCacheEntry[V])
	}
	for stale, entry := range cache.entries {
		if !now.Before(entry.expires) {
			delete(cache.entries, stale)
		}
	}
	cache.entries[key] = shortCacheEntry[V]{value: value, expires: now.Add(ttl)}
	return value, nil
}

// clear drops every value, for a write that makes them out of date.
func (cache *shortCache[K, V]) clear() {
	cache.mu.Lock()
	clear(cache.entries)
	cache.mu.Unlock()
}
