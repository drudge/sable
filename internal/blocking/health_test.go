package blocking

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// fixedClock advances only when a test asks it to, so backoff deadlines are
// exact instead of racing real time.
type fixedClock struct{ current atomic.Pointer[time.Time] }

func newFixedClock(start time.Time) *fixedClock {
	clock := new(fixedClock)
	clock.current.Store(&start)
	return clock
}

func (clock *fixedClock) now() time.Time { return *clock.current.Load() }

func (clock *fixedClock) advance(delta time.Duration) {
	next := clock.now().Add(delta)
	clock.current.Store(&next)
}

func writeCachedList(t *testing.T, root string, source RemoteSource, contents string) {
	t.Helper()

	path := filepath.Join(root, source.Path)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRetryDelayDoublesAndCaps(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		failures int
		want     time.Duration
	}{
		{failures: 1, want: retryBaseDelay},
		{failures: 2, want: 2 * retryBaseDelay},
		{failures: 3, want: 4 * retryBaseDelay},
		{failures: 8, want: retryMaximumDelay},
		{failures: 40, want: retryMaximumDelay},
	} {
		if got := retryDelay(test.failures); got != test.want {
			t.Errorf("retryDelay(%d) = %s, want %s", test.failures, got, test.want)
		}
	}
}

func TestRefreshBacksOffAFailingSourceAndKeepsUpdatingTheRest(t *testing.T) {
	t.Parallel()

	var failing atomic.Bool
	failing.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/broken" && failing.Load() {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = writer.Write([]byte("fresh " + request.URL.Path))
	}))
	defer server.Close()

	root := t.TempDir()
	healthy := RemoteSource{Name: "healthy", URL: server.URL + "/healthy", Path: "lists/healthy.txt"}
	broken := RemoteSource{Name: "broken", URL: server.URL + "/broken", Path: "lists/broken.txt"}
	writeCachedList(t, root, healthy, "cached healthy")
	writeCachedList(t, root, broken, "cached broken")

	clock := newFixedClock(time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC))
	updater := NewUpdater(root)
	updater.now = clock.now

	activations := 0
	err := updater.Refresh(context.Background(), []RemoteSource{healthy, broken}, func(context.Context) error {
		activations++
		return nil
	})
	if err == nil {
		t.Fatal("Refresh() error = nil, want the broken source reported")
	}
	if activations != 1 {
		t.Fatalf("activations = %d, want the healthy source to still be compiled", activations)
	}
	contents, readErr := os.ReadFile(filepath.Join(root, healthy.Path))
	if readErr != nil || string(contents) != "fresh /healthy" {
		t.Fatalf("healthy list = %q, %v", contents, readErr)
	}
	contents, readErr = os.ReadFile(filepath.Join(root, broken.Path))
	if readErr != nil || string(contents) != "cached broken" {
		t.Fatalf("broken list = %q, %v; want the cached copy preserved", contents, readErr)
	}

	status := updater.Status()
	if status.Degraded != 1 || len(status.Sources) != 2 {
		t.Fatalf("status = %+v", status)
	}
	brokenHealth, found := updater.health.get(broken.URL)
	if !found || brokenHealth.Healthy() || brokenHealth.ConsecutiveFailures != 1 {
		t.Fatalf("broken health = %+v", brokenHealth)
	}
	if want := clock.now().Add(retryBaseDelay); !brokenHealth.RetryAfter.Equal(want) {
		t.Fatalf("retry after = %s, want %s", brokenHealth.RetryAfter, want)
	}
	if got := updater.RetryAt(); !got.Equal(brokenHealth.RetryAfter) {
		t.Fatalf("RetryAt() = %s, want %s", got, brokenHealth.RetryAfter)
	}

	// While the backoff window is open the failing source is not re-fetched,
	// so a second refresh does not touch it at all.
	failing.Store(false)
	clock.advance(retryBaseDelay / 2)
	if err := updater.Refresh(context.Background(), []RemoteSource{healthy, broken}, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("Refresh() during backoff error = %v", err)
	}
	contents, _ = os.ReadFile(filepath.Join(root, broken.Path))
	if string(contents) != "cached broken" {
		t.Fatalf("broken list during backoff = %q, want the cached copy", contents)
	}

	// Once the deadline passes the source is retried and recovers.
	clock.advance(retryBaseDelay)
	if err := updater.Refresh(context.Background(), []RemoteSource{healthy, broken}, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("Refresh() after backoff error = %v", err)
	}
	contents, _ = os.ReadFile(filepath.Join(root, broken.Path))
	if string(contents) != "fresh /broken" {
		t.Fatalf("broken list after recovery = %q", contents)
	}
	if status := updater.Status(); status.Degraded != 0 {
		t.Fatalf("degraded after recovery = %d, want 0", status.Degraded)
	}
	if got := updater.RetryAt(); !got.IsZero() {
		t.Fatalf("RetryAt() after recovery = %s, want zero", got)
	}
}

func TestRefreshAbortsWhenAFailingSourceHasNoCachedCopy(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	root := t.TempDir()
	source := RemoteSource{Name: "missing", URL: server.URL + "/missing", Path: "lists/missing.txt"}
	updater := NewUpdater(root)
	activations := 0
	err := updater.Refresh(context.Background(), []RemoteSource{source}, func(context.Context) error {
		activations++
		return nil
	})
	if err == nil {
		t.Fatal("Refresh() error = nil, want an abort for a source with no cache")
	}
	if activations != 0 {
		t.Fatalf("activations = %d, want 0", activations)
	}
}

func TestClearBackoffForcesAnImmediateRetry(t *testing.T) {
	t.Parallel()

	var failing atomic.Bool
	failing.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if failing.Load() {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = writer.Write([]byte("fresh " + request.URL.Path))
	}))
	defer server.Close()

	root := t.TempDir()
	source := RemoteSource{Name: "flaky", URL: server.URL + "/flaky", Path: "lists/flaky.txt"}
	writeCachedList(t, root, source, "cached flaky")

	clock := newFixedClock(time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC))
	updater := NewUpdater(root)
	updater.now = clock.now
	if err := updater.Refresh(context.Background(), []RemoteSource{source}, func(context.Context) error { return nil }); err == nil {
		t.Fatal("Refresh() error = nil, want a download failure")
	}

	failing.Store(false)
	updater.ClearBackoff()
	if err := updater.Refresh(context.Background(), []RemoteSource{source}, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("Refresh() after ClearBackoff() error = %v", err)
	}
	contents, _ := os.ReadFile(filepath.Join(root, source.Path))
	if string(contents) != "fresh /flaky" {
		t.Fatalf("list after forced retry = %q", contents)
	}
}

func TestRefreshDropsHealthForRemovedSources(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("fresh " + request.URL.Path))
	}))
	defer server.Close()

	root := t.TempDir()
	first := RemoteSource{Name: "first", URL: server.URL + "/first", Path: "lists/first.txt"}
	second := RemoteSource{Name: "second", URL: server.URL + "/second", Path: "lists/second.txt"}
	updater := NewUpdater(root)
	if err := updater.Refresh(context.Background(), []RemoteSource{first, second}, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := len(updater.Status().Sources); got != 2 {
		t.Fatalf("tracked sources = %d, want 2", got)
	}
	if err := updater.Refresh(context.Background(), []RemoteSource{first}, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	sources := updater.Status().Sources
	if len(sources) != 1 || sources[0].Name != "first" {
		t.Fatalf("tracked sources after removal = %+v", sources)
	}
}

func TestStatusReportsSuccessfulDownloadTelemetry(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("0.0.0.0 ads.example\n"))
	}))
	defer server.Close()

	root := t.TempDir()
	source := RemoteSource{Name: "test", URL: server.URL + "/hosts", Path: "lists/test.txt"}
	updater := NewUpdater(root)
	if err := updater.Download(context.Background(), source); err != nil {
		t.Fatalf("Download() error = %v", err)
	}
	sources := updater.Status().Sources
	if len(sources) != 1 {
		t.Fatalf("tracked sources = %+v", sources)
	}
	health := sources[0]
	if !health.Healthy() || health.Downloads != 1 || health.Failures != 0 {
		t.Fatalf("health = %+v", health)
	}
	if health.LastBytes != int64(len("0.0.0.0 ads.example\n")) {
		t.Fatalf("last bytes = %d", health.LastBytes)
	}
	if health.LastSuccess.IsZero() || !health.RetryAfter.IsZero() {
		t.Fatalf("health timestamps = %+v", health)
	}
}

func TestDownloadRecordsFailureHealth(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	updater := NewUpdater(root)
	source := RemoteSource{Name: "invalid", URL: "https://127.0.0.1:1/blocked", Path: "lists/invalid.txt"}
	if err := updater.Download(context.Background(), source); err == nil {
		t.Fatal("Download() error = nil, want a connection failure")
	}
	sources := updater.Status().Sources
	if len(sources) != 1 || sources[0].Healthy() || sources[0].Failures != 1 || sources[0].LastError == "" {
		t.Fatalf("health after failed download = %+v", sources)
	}
}
