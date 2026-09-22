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
type Analyzer struct {
	mu     sync.Mutex
	key    string
	result Contribution
	valid  bool
	flight *analysisFlight
	now    func() time.Time
}

type analysisFlight struct {
	key    string
	done   chan struct{}
	result Contribution
	err    error
}

// Contribution returns the comparison for the given lists, reusing the cached
// result while every list's configuration and cached file are unchanged.
func (analyzer *Analyzer) Contribution(ctx context.Context, baseDirectory string, lists []List) (Contribution, error) {
	key := fingerprint(baseDirectory, lists)
	analyzer.mu.Lock()
	if analyzer.valid && analyzer.key == key {
		result := analyzer.result
		analyzer.mu.Unlock()
		return result, nil
	}
	flight := analyzer.flight
	if flight == nil || flight.key != key {
		flight = &analysisFlight{key: key, done: make(chan struct{})}
		analyzer.flight = flight
		now := time.Now
		if analyzer.now != nil {
			now = analyzer.now
		}
		go analyzer.run(flight, baseDirectory, append([]List(nil), lists...), now())
	}
	analyzer.mu.Unlock()

	select {
	case <-flight.done:
		return flight.result, flight.err
	case <-ctx.Done():
		return Contribution{}, ctx.Err()
	}
}

func (analyzer *Analyzer) run(flight *analysisFlight, baseDirectory string, lists []List, started time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), analysisTimeout)
	defer cancel()
	flight.result, flight.err = Analyze(ctx, baseDirectory, lists, started)

	analyzer.mu.Lock()
	if flight.err == nil {
		analyzer.key, analyzer.result, analyzer.valid = flight.key, flight.result, true
	}
	if analyzer.flight == flight {
		analyzer.flight = nil
	}
	analyzer.mu.Unlock()
	close(flight.done)
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
