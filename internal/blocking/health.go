package blocking

import (
	"slices"
	"sync"
	"time"
)

// Retry backoff for a block-list source that fails to download. The delay
// doubles per consecutive failure so a dead or rate-limiting host is not
// hammered, and it is capped well below a typical daily update interval so a
// source that recovers is picked up the same day.
const (
	retryBaseDelay    = 5 * time.Minute
	retryMaximumDelay = 6 * time.Hour
)

// SourceHealth is the observable state of one remote block list. It answers
// the operational questions a stale list raises: did the last refresh reach
// this source, how long has it been failing, why, and when is the next try.
type SourceHealth struct {
	Name                string        `json:"name"`
	URL                 string        `json:"url"`
	LastAttempt         time.Time     `json:"last_attempt"`
	LastSuccess         time.Time     `json:"last_success"`
	LastFailure         time.Time     `json:"last_failure"`
	LastError           string        `json:"last_error"`
	ConsecutiveFailures int           `json:"consecutive_failures"`
	Downloads           uint64        `json:"downloads"`
	Failures            uint64        `json:"failures"`
	RetryAfter          time.Time     `json:"retry_after"`
	LastBytes           int64         `json:"last_bytes"`
	LastDuration        time.Duration `json:"last_duration"`
}

// Healthy reports whether the most recent attempt for this source succeeded.
// A source that has never been attempted is reported healthy so a freshly
// started server does not show a wall of warnings.
func (health SourceHealth) Healthy() bool { return health.ConsecutiveFailures == 0 }

// InBackoff reports whether the source is waiting out a retry delay.
func (health SourceHealth) InBackoff(now time.Time) bool {
	return !health.RetryAfter.IsZero() && now.Before(health.RetryAfter)
}

// healthTracker keeps per-source download history keyed by URL. The URL is the
// stable identity: an operator can rename a list without resetting its health,
// and two lists cannot share a URL because they would share a cache file.
type healthTracker struct {
	mu      sync.Mutex
	sources map[string]SourceHealth
}

func newHealthTracker() *healthTracker {
	return &healthTracker{sources: make(map[string]SourceHealth)}
}

func (tracker *healthTracker) recordAttempt(source RemoteSource, now time.Time) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	health := tracker.sources[source.URL]
	health.Name = source.Name
	health.URL = source.URL
	health.LastAttempt = now
	tracker.sources[source.URL] = health
}

func (tracker *healthTracker) recordSuccess(source RemoteSource, now time.Time, bytes int64, elapsed time.Duration) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	health := tracker.sources[source.URL]
	health.Name = source.Name
	health.URL = source.URL
	health.LastAttempt = now
	health.LastSuccess = now
	health.LastError = ""
	health.ConsecutiveFailures = 0
	health.RetryAfter = time.Time{}
	health.Downloads++
	health.LastBytes = bytes
	health.LastDuration = elapsed
	tracker.sources[source.URL] = health
}

func (tracker *healthTracker) recordFailure(source RemoteSource, now time.Time, cause error) SourceHealth {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	health := tracker.sources[source.URL]
	health.Name = source.Name
	health.URL = source.URL
	health.LastAttempt = now
	health.LastFailure = now
	if cause != nil {
		health.LastError = cause.Error()
	}
	health.ConsecutiveFailures++
	health.Failures++
	health.RetryAfter = now.Add(retryDelay(health.ConsecutiveFailures))
	tracker.sources[source.URL] = health
	return health
}

// clearBackoff drops every pending retry delay so an operator-triggered
// refresh attempts each source immediately.
func (tracker *healthTracker) clearBackoff() {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	for url, health := range tracker.sources {
		health.RetryAfter = time.Time{}
		tracker.sources[url] = health
	}
}

// retain drops health for sources that are no longer configured.
func (tracker *healthTracker) retain(sources []RemoteSource) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	configured := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		configured[source.URL] = struct{}{}
	}
	for url := range tracker.sources {
		if _, keep := configured[url]; !keep {
			delete(tracker.sources, url)
		}
	}
}

func (tracker *healthTracker) get(url string) (SourceHealth, bool) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	health, found := tracker.sources[url]
	return health, found
}

// snapshot returns every tracked source ordered by name so the console and the
// metrics endpoint render in a stable order.
func (tracker *healthTracker) snapshot() []SourceHealth {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	snapshot := make([]SourceHealth, 0, len(tracker.sources))
	for _, health := range tracker.sources {
		snapshot = append(snapshot, health)
	}
	slices.SortFunc(snapshot, func(first, second SourceHealth) int {
		if first.Name != second.Name {
			if first.Name < second.Name {
				return -1
			}
			return 1
		}
		if first.URL < second.URL {
			return -1
		}
		if first.URL > second.URL {
			return 1
		}
		return 0
	})
	return snapshot
}

// earliestRetry returns the soonest pending retry across failing sources, or
// the zero time when every source is healthy.
func (tracker *healthTracker) earliestRetry(now time.Time) time.Time {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	earliest := time.Time{}
	for _, health := range tracker.sources {
		if health.ConsecutiveFailures == 0 || health.RetryAfter.IsZero() {
			continue
		}
		if health.RetryAfter.Before(now) {
			return now
		}
		if earliest.IsZero() || health.RetryAfter.Before(earliest) {
			earliest = health.RetryAfter
		}
	}
	return earliest
}

func retryDelay(consecutiveFailures int) time.Duration {
	if consecutiveFailures <= 1 {
		return retryBaseDelay
	}
	delay := retryBaseDelay
	for attempt := 1; attempt < consecutiveFailures; attempt++ {
		delay *= 2
		if delay >= retryMaximumDelay {
			return retryMaximumDelay
		}
	}
	return delay
}
