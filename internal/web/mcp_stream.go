package web

import (
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/config"
)

// An assistant may hold a GET stream open on /mcp to hear from Sable between
// requests. Sable only ever sends one message on it: that the tool list
// changed, so the assistant should ask for it again. Requests and replies
// still travel as single POSTs, so the stream carries no session.
const (
	// mcpStreamRetry is the reconnect delay Sable asks for. mcp-remote tries
	// twice before giving up on the stream for good, so this covers a restart
	// of about a minute, such as an upgrade.
	mcpStreamRetry = 30 * time.Second
	// mcpStreamKeepAlive keeps proxies and NAT from dropping an idle stream.
	mcpStreamKeepAlive = 25 * time.Second
	// mcpStreamLifetime makes a client reconnect now and then, which checks
	// its token again.
	mcpStreamLifetime = time.Hour
	// Claude Desktop runs two mcp-remote helpers per server, and each opens
	// a stream, so one token commonly holds several. A new stream past
	// either limit closes the oldest one it competes with.
	mcpStreamsPerToken = 8
	mcpStreamsTotal    = 64
)

const mcpToolsChangedEvent = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n"

type mcpStreams struct {
	mu      sync.Mutex
	streams []*mcpStream // oldest first
}

type mcpStream struct {
	token     string
	evicted   chan struct{}
	evictOnce sync.Once
}

func (stream *mcpStream) evict() {
	stream.evictOnce.Do(func() { close(stream.evicted) })
}

// open registers a stream for the token, closing the oldest stream in its way
// when the token or the server is at its limit.
func (registry *mcpStreams) open(token string) *mcpStream {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	sameToken := func(stream *mcpStream) bool { return stream.token == token }
	count := 0
	for _, stream := range registry.streams {
		if sameToken(stream) {
			count++
		}
	}
	if count >= mcpStreamsPerToken {
		registry.evictLocked(slices.IndexFunc(registry.streams, sameToken))
	}
	if len(registry.streams) >= mcpStreamsTotal {
		registry.evictLocked(0)
	}
	stream := &mcpStream{token: token, evicted: make(chan struct{})}
	registry.streams = append(registry.streams, stream)
	return stream
}

func (registry *mcpStreams) evictLocked(index int) {
	registry.streams[index].evict()
	registry.streams = slices.Delete(registry.streams, index, index+1)
}

func (registry *mcpStreams) close(stream *mcpStream) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if index := slices.Index(registry.streams, stream); index >= 0 {
		registry.streams = slices.Delete(registry.streams, index, index+1)
	}
}

func (registry *mcpStreams) count() int {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return len(registry.streams)
}

type configurationWatcher interface {
	Changed() <-chan struct{}
}

var _ configurationWatcher = (*config.Manager)(nil)

// mcpEvents holds the stream open. It says the tools changed as soon as it
// opens, so an assistant reconnecting after an upgrade lists the new tools,
// and again whenever a configuration change, local or replicated from the
// primary, changes what tools/list returns.
func (server *Server) mcpEvents(writer http.ResponseWriter, request *http.Request) {
	if !server.config.Current().Config.MCP.Enabled {
		apiError(writer, http.StatusNotFound, mcpDisabledMessage)
		return
	}
	if requested := request.Header.Get(mcpProtocolHeader); requested != "" && !slices.Contains(mcpProtocols, requested) {
		writeMCPError(writer, http.StatusBadRequest, nil, mcpInvalidRequest, "unsupported MCP protocol version "+requested)
		return
	}
	if !acceptsEventStream(request.Header.Values("Accept")) {
		writeMCPError(writer, http.StatusNotAcceptable, nil, mcpInvalidRequest, "Accept must include text/event-stream")
		return
	}
	// The stream outlives the server's request deadlines by design. A read
	// deadline passing would also cancel the request, so clear both.
	controller := http.NewResponseController(writer)
	_ = controller.SetReadDeadline(time.Time{})
	_ = controller.SetWriteDeadline(time.Time{})

	stream := server.mcpStreams.open(mcpStreamToken(request))
	defer server.mcpStreams.close(stream)

	header := writer.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Accel-Buffering", "no")
	writer.WriteHeader(http.StatusOK)

	var changed <-chan struct{}
	watcher, watching := server.config.(configurationWatcher)
	if watching {
		changed = watcher.Changed()
	}
	sent := mcpToolsFingerprint(server.config.Current().Config.MCP)
	send := func(event string) bool {
		if _, err := writer.Write([]byte(event)); err != nil {
			return false
		}
		return controller.Flush() == nil
	}
	if !send("retry: " + strconv.FormatInt(mcpStreamRetry.Milliseconds(), 10) + "\n\n" + mcpToolsChangedEvent) {
		return
	}

	keepAlive := time.NewTicker(mcpStreamKeepAlive)
	defer keepAlive.Stop()
	lifetime := time.NewTimer(mcpStreamLifetime)
	defer lifetime.Stop()
	for {
		select {
		case <-request.Context().Done():
			return
		case <-server.runtimeContext.Done():
			return
		case <-stream.evicted:
			return
		case <-lifetime.C:
			return
		case <-changed:
			changed = watcher.Changed()
			current := mcpToolsFingerprint(server.config.Current().Config.MCP)
			if current == sent {
				continue
			}
			sent = current
			// While the server is paused there is no list to fetch. Resuming
			// differs from the paused state, so it is announced.
			if current == "" {
				continue
			}
			if !send(mcpToolsChangedEvent) {
				return
			}
		case <-keepAlive.C:
			if !send(": keep-alive\n\n") {
				return
			}
		}
	}
}

// mcpToolsFingerprint names the tools tools/list offers with these settings,
// or nothing while the server is off. Descriptions change only with a new
// build, which reconnects every stream anyway.
func mcpToolsFingerprint(settings config.MCP) string {
	if !settings.Enabled {
		return ""
	}
	var names strings.Builder
	for _, tool := range mcpToolList(settings) {
		names.WriteString(tool.Name)
		names.WriteByte('\n')
	}
	return names.String()
}

// mcpStreamToken groups streams by the credential that opened them without
// keeping the credential itself.
func mcpStreamToken(request *http.Request) string {
	sum := sha256.Sum256([]byte(request.Header.Get("Authorization")))
	return hex.EncodeToString(sum[:])
}

func acceptsEventStream(values []string) bool {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(part)); err == nil && (mediaType == "text/event-stream" || mediaType == "*/*") {
				return true
			}
		}
	}
	return false
}
