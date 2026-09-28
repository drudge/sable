package web

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

// watchedTestConfiguration adds config.Manager's change signal to the test
// configuration and guards it, since a stream reads it while a test changes it.
type watchedTestConfiguration struct {
	*editableTestConfiguration
	mu      sync.Mutex
	changed chan struct{}
}

func watchConfiguration(server *Server, configuration *editableTestConfiguration) *watchedTestConfiguration {
	watched := &watchedTestConfiguration{editableTestConfiguration: configuration, changed: make(chan struct{})}
	server.config = watched
	return watched
}

func (configuration *watchedTestConfiguration) Current() config.Snapshot {
	configuration.mu.Lock()
	defer configuration.mu.Unlock()
	return configuration.editableTestConfiguration.Current()
}

func (configuration *watchedTestConfiguration) Update(ctx context.Context, mutate func(*config.Config) error) error {
	configuration.mu.Lock()
	err := configuration.editableTestConfiguration.Update(ctx, mutate)
	if err == nil {
		close(configuration.changed)
		configuration.changed = make(chan struct{})
	}
	configuration.mu.Unlock()
	return err
}

func (configuration *watchedTestConfiguration) Changed() <-chan struct{} {
	configuration.mu.Lock()
	defer configuration.mu.Unlock()
	return configuration.changed
}

// openMCPStream opens a GET stream and delivers its events, one string per
// blank-line-separated block, until the stream ends.
func openMCPStream(t *testing.T, address, token string) (<-chan string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address+mcpPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		cancel()
		t.Fatalf("open stream: %v", err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		cancel()
		t.Fatalf("open stream = %d %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	events := make(chan string, 16)
	go func() {
		defer close(events)
		defer response.Body.Close()
		reader := bufio.NewReader(response.Body)
		var event strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\n" {
				events <- event.String()
				event.Reset()
				continue
			}
			event.WriteString(line)
		}
	}()
	return events, cancel
}

func nextMCPEvent(t *testing.T, events <-chan string, wait time.Duration) (string, bool) {
	t.Helper()
	select {
	case event, open := <-events:
		return event, open
	case <-time.After(wait):
		return "", true
	}
}

const mcpToolsChangedData = `data: {"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`

func TestMCPStreamAnnouncesToolChanges(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	watched := watchConfiguration(server, configuration)
	listener := httptest.NewServer(server.httpServer.Handler)
	defer listener.Close()

	events, stop := openMCPStream(t, listener.URL, "sable_pat_admin")
	defer stop()

	// A new stream asks for a new list at once, so an assistant that
	// reconnects after an upgrade sees the new build's tools.
	if event, _ := nextMCPEvent(t, events, 2*time.Second); !strings.HasPrefix(event, "retry: 30000\n") {
		t.Fatalf("first event = %q, want the retry hint", event)
	}
	if event, _ := nextMCPEvent(t, events, 2*time.Second); !strings.Contains(event, mcpToolsChangedData) {
		t.Fatalf("opening event = %q, want tools/list_changed", event)
	}

	update := func(change func(*config.Config)) {
		t.Helper()
		if err := watched.Update(context.Background(), func(candidate *config.Config) error {
			change(candidate)
			return nil
		}); err != nil {
			t.Fatalf("Update() error = %v", err)
		}
	}
	quiet := func(reason string) {
		t.Helper()
		if event, _ := nextMCPEvent(t, events, 300*time.Millisecond); event != "" {
			t.Fatalf("%s: got %q, want nothing", reason, event)
		}
	}
	announced := func(reason string) {
		t.Helper()
		if event, _ := nextMCPEvent(t, events, 2*time.Second); !strings.Contains(event, mcpToolsChangedData) {
			t.Fatalf("%s: got %q, want tools/list_changed", reason, event)
		}
	}

	update(func(candidate *config.Config) { candidate.Blocking.Enabled = !candidate.Blocking.Enabled })
	quiet("a change that leaves the tools alone")

	update(func(candidate *config.Config) {
		candidate.MCP.Tools = slices.DeleteFunc(slices.Clone(candidate.MCP.Tools), func(tool string) bool { return tool == "lookup" })
	})
	announced("turning a tool off")

	update(func(candidate *config.Config) { candidate.MCP.Enabled = false })
	quiet("pausing the server")
	update(func(candidate *config.Config) { candidate.MCP.Enabled = true })
	announced("resuming the server")
}

func TestMCPStreamRefusals(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	get := func(token, accept string) int {
		request := httptest.NewRequest(http.MethodGet, mcpPath, nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		if accept != "" {
			request.Header.Set("Accept", accept)
		}
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response.Code
	}
	if status := get("", "text/event-stream"); status != http.StatusUnauthorized {
		t.Fatalf("no token status = %d", status)
	}
	if status := get("sable_pat_admin", "application/json"); status != http.StatusNotAcceptable {
		t.Fatalf("JSON-only Accept status = %d", status)
	}
	configuration.snapshot.Config.MCP.Enabled = false
	if status := get("sable_pat_admin", "text/event-stream"); status != http.StatusNotFound {
		t.Fatalf("paused server status = %d", status)
	}
}

func TestMCPStreamEndsOnShutdown(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	watchConfiguration(server, configuration)
	listener := httptest.NewServer(server.httpServer.Handler)
	defer listener.Close()

	events, stop := openMCPStream(t, listener.URL, "sable_pat_admin")
	defer stop()
	nextMCPEvent(t, events, 2*time.Second)
	nextMCPEvent(t, events, 2*time.Second)

	server.runtimeCancel()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, open := <-events:
			if !open {
				if count := server.mcpStreams.count(); count != 0 {
					t.Fatalf("%d streams still registered after shutdown", count)
				}
				return
			}
		case <-deadline:
			t.Fatal("stream still open after shutdown")
		}
	}
}

func TestMCPStreamLimits(t *testing.T) {
	t.Parallel()
	var registry mcpStreams

	var desktop []*mcpStream
	for range mcpStreamsPerToken {
		desktop = append(desktop, registry.open("desktop"))
	}
	other := registry.open("other")
	// One more stream for the same token closes that token's oldest only.
	newest := registry.open("desktop")
	select {
	case <-desktop[0].evicted:
	default:
		t.Fatal("oldest stream for the token stayed open")
	}
	for _, stream := range append(desktop[1:], other, newest) {
		select {
		case <-stream.evicted:
			t.Fatal("a stream within the limits was closed")
		default:
		}
	}

	var last *mcpStream
	for index := range mcpStreamsTotal {
		last = registry.open("token-" + string(rune('a'+index%26)) + string(rune('a'+index/26)))
	}
	if count := registry.count(); count != mcpStreamsTotal {
		t.Fatalf("count = %d, want the server limit %d", count, mcpStreamsTotal)
	}
	select {
	case <-desktop[1].evicted:
	default:
		t.Fatal("the server limit did not close the oldest stream")
	}

	registry.close(last)
	registry.close(last)
	if count := registry.count(); count != mcpStreamsTotal-1 {
		t.Fatalf("count after close = %d", count)
	}
}

func TestAcceptsEventStream(t *testing.T) {
	t.Parallel()
	for accept, want := range map[string]bool{
		"text/event-stream":                   true,
		"application/json, text/event-stream": true,
		"text/event-stream;q=0.9":             true,
		"*/*":                                 true,
		"application/json":                    false,
		"":                                    false,
	} {
		if got := acceptsEventStream([]string{accept}); got != want {
			t.Errorf("acceptsEventStream(%q) = %v, want %v", accept, got, want)
		}
	}
}
