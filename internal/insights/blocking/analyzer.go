package blocking

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	blockcompiler "github.com/drudge/sable/internal/blocking"
)

// analysisTimeout bounds one comparison of the cached lists. It runs detached
// from the request that started it, so an operator who navigates away does not
// throw away work the next page view can use.
const analysisTimeout = 2 * time.Minute

// Analyzer keeps the most recent list comparison and recomputes it only when
// the configured lists or their cached files change. Concurrent requests for
// the same lists share one computation.
type ContributionCache struct {
	mu     sync.Mutex
	key    string
	lists  string
	result Contribution
	valid  bool
	flight *analysisFlight
	now    func() time.Time
}

type analysisFlight struct {
	key    string
	lists  string
	done   chan struct{}
	result Contribution
	err    error
}

// Contribution returns the comparison for the given lists, reusing the cached
// result while every list's configuration and cached file are unchanged. When
// only the files changed, as a scheduled update rewrites them, the last
// comparison answers while the new one runs; a change to which lists are
// compared waits for the new comparison.
func (analyzer *ContributionCache) Contribution(ctx context.Context, baseDirectory string, lists []List) (Contribution, error) {
	key, configured := fingerprint(baseDirectory, lists), listsKey(baseDirectory, lists)
	analyzer.mu.Lock()
	if analyzer.valid && analyzer.key == key {
		result := analyzer.result
		analyzer.mu.Unlock()
		return result, nil
	}
	flight := analyzer.flight
	if flight == nil || flight.key != key {
		flight = &analysisFlight{key: key, lists: configured, done: make(chan struct{})}
		analyzer.flight = flight
		now := time.Now
		if analyzer.now != nil {
			now = analyzer.now
		}
		go analyzer.run(flight, baseDirectory, append([]List(nil), lists...), now())
	}
	if analyzer.valid && analyzer.lists == configured {
		result := analyzer.result
		analyzer.mu.Unlock()
		return result, nil
	}
	analyzer.mu.Unlock()

	select {
	case <-flight.done:
		return flight.result, flight.err
	case <-ctx.Done():
		return Contribution{}, ctx.Err()
	}
}

func (analyzer *ContributionCache) run(flight *analysisFlight, baseDirectory string, lists []List, started time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), analysisTimeout)
	defer cancel()
	flight.result, flight.err = Analyze(ctx, baseDirectory, lists, started)

	analyzer.mu.Lock()
	if flight.err == nil {
		analyzer.key, analyzer.lists, analyzer.result, analyzer.valid = flight.key, flight.lists, flight.result, true
	}
	if analyzer.flight == flight {
		analyzer.flight = nil
	}
	analyzer.mu.Unlock()
	close(flight.done)
}

// listsKey identifies a set of lists by their configuration alone.
func listsKey(baseDirectory string, lists []List) string {
	var key strings.Builder
	for _, list := range lists {
		key.WriteString(list.Name)
		key.WriteByte(0)
		key.WriteString(blockcompiler.SourcePath(baseDirectory, list.Path))
		key.WriteByte(0)
		key.WriteString(list.Format)
		key.WriteByte('\n')
	}
	return key.String()
}

// fingerprint identifies a set of lists by their configuration and by the size
// and modification time of each cached file. A block-list update rewrites the
// file, which changes the fingerprint and invalidates the comparison.
func fingerprint(baseDirectory string, lists []List) string {
	var key strings.Builder
	for _, list := range lists {
		path := blockcompiler.SourcePath(baseDirectory, list.Path)
		key.WriteString(list.Name)
		key.WriteByte(0)
		key.WriteString(path)
		key.WriteByte(0)
		key.WriteString(list.Format)
		key.WriteByte(0)
		if info, err := os.Stat(path); err == nil {
			key.WriteString(strconv.FormatInt(info.Size(), 10))
			key.WriteByte(':')
			key.WriteString(strconv.FormatInt(info.ModTime().UnixNano(), 10))
		} else {
			key.WriteString("missing")
		}
		key.WriteByte('\n')
	}
	return key.String()
}
