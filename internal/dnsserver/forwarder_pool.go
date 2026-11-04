package dnsserver

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/drudge/sable/internal/dnsclient"
	"github.com/drudge/sable/internal/forwarding"
)

// forwarderPool exchanges queries with upstream forwarders and keeps encrypted
// and TCP connections alive between queries. Dialing a fresh TCP+TLS or QUIC
// connection per query costs one or more extra round trips plus an asymmetric
// handshake, which dominates the cost of forwarding to an encrypted upstream.
//
// TCP and DoT connections are held in a small idle pool per endpoint and handed
// out for exclusive use, so one query ever owns a connection at a time and no
// response demultiplexing is needed. DoQ keeps one connection per endpoint and
// opens a stream per query, allowing concurrent exchanges without additional
// handshakes. DoH sends concurrent queries as streams on a shared HTTP/2
// connection (RFC 8484 §5.2 recommends HTTP/2), opening up to a few more per
// endpoint only when enough queries are in flight; see dohStreamsPerConnection. DoT, DoQ, and DoH share a TLS client session cache for re-dials.
type forwarderPool struct {
	mu             sync.Mutex
	idle           map[string][]idleConnection
	doqConnections map[string]*pooledDoQConnection
	dohClients     map[string]*dohEndpoint
	sessions       tls.ClientSessionCache
	closed         bool

	// upstreams caches each forwarder string's parse, so the query path does
	// not parse the same few configured strings on every query.
	upstreams     sync.Map
	upstreamCount atomic.Int64

	maxIdlePerHost int
	idleTimeout    time.Duration

	// tlsConfig builds the client TLS configuration for a DoT dial. It is a field
	// so tests can trust a self-signed upstream; production uses defaultTLSConfig.
	tlsConfig    func(host string) *tls.Config
	doqTLSConfig func(host string) *tls.Config
	dohTLSConfig func(host string) *tls.Config
}

type idleConnection struct {
	connection *dns.Conn
	expiry     time.Time
}

type pooledDoQConnection struct {
	connection *quic.Conn
	ready      chan struct{}
}

var errForwarderPoolClosed = errors.New("forwarder connection pool is closed")

func newForwarderPool() *forwarderPool {
	pool := &forwarderPool{
		idle:           make(map[string][]idleConnection),
		doqConnections: make(map[string]*pooledDoQConnection),
		dohClients:     make(map[string]*dohEndpoint),
		sessions:       tls.NewLRUClientSessionCache(0),
		maxIdlePerHost: 8,
		idleTimeout:    30 * time.Second,
	}
	pool.tlsConfig = pool.defaultTLSConfig
	pool.doqTLSConfig = pool.defaultDoQTLSConfig
	pool.dohTLSConfig = pool.defaultTLSConfig
	return pool
}

func (pool *forwarderPool) defaultDoQTLSConfig(host string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         host,
		NextProtos:         []string{"doq"},
		ClientSessionCache: pool.sessions,
	}
}

func (pool *forwarderPool) defaultTLSConfig(host string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         host,
		ClientSessionCache: pool.sessions,
	}
}

// exchange satisfies upstreamExchangeFunc.
func (pool *forwarderPool) exchange(ctx context.Context, request *dns.Msg, forwarder string, timeout time.Duration) (*dns.Msg, error) {
	if pool.isClosed() {
		return nil, errForwarderPoolClosed
	}
	upstream, err := pool.upstream(forwarder)
	if err != nil {
		return nil, err
	}
	switch upstream.Protocol {
	case "quic":
		return pool.exchangeQUIC(ctx, request, upstream, timeout)
	case "https":
		return pool.exchangeHTTPS(ctx, request, upstream, timeout)
	case "udp":
		return pool.exchangeUDP(ctx, request, upstream.Address, timeout)
	default: // tcp, tls
		return pool.exchangeStream(ctx, request, upstream, timeout)
	}
}

// maximumCachedUpstreams bounds the parse cache. Forwarders come from the
// configuration and FWD records, so a long-running server that keeps
// changing them starts the cache over rather than growing it forever.
const maximumCachedUpstreams = 4096

func (pool *forwarderPool) upstream(forwarder string) (forwarding.Upstream, error) {
	if cached, found := pool.upstreams.Load(forwarder); found {
		return cached.(forwarding.Upstream), nil
	}
	upstream, err := forwarding.Parse(forwarder)
	if err != nil {
		return forwarding.Upstream{}, err
	}
	if pool.upstreamCount.Add(1) > maximumCachedUpstreams {
		pool.upstreams.Clear()
		pool.upstreamCount.Store(1)
	}
	pool.upstreams.Store(forwarder, upstream)
	return upstream, nil
}

func (pool *forwarderPool) exchangeQUIC(
	ctx context.Context,
	request *dns.Msg,
	upstream forwarding.Upstream,
	timeout time.Duration,
) (*dns.Msg, error) {
	address, host := upstream.DialAddress(), upstream.Host()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	key := "quic|" + address + "|" + host
	var exchangeErr error
	for attempt := 0; attempt < 2; attempt++ {
		connection, err := pool.doqConnection(ctx, key, address, host, timeout)
		if err != nil {
			return nil, err
		}
		response, err := dnsclient.ExchangeQUICConnection(ctx, request, connection)
		if err == nil {
			return response, nil
		}
		exchangeErr = err
		if ctx.Err() != nil || connection.Context().Err() == nil {
			return nil, err
		}
		pool.discardDoQConnection(key, connection)
	}
	return nil, exchangeErr
}

// doqConnection returns the live connection for an endpoint. The ready channel
// makes concurrent first queries share one dial instead of creating a handshake
// stampede, while established QUIC streams remain fully concurrent.
func (pool *forwarderPool) doqConnection(
	ctx context.Context,
	key, address, host string,
	timeout time.Duration,
) (*quic.Conn, error) {
	for {
		pool.mu.Lock()
		if pool.closed {
			pool.mu.Unlock()
			return nil, errForwarderPoolClosed
		}
		if state := pool.doqConnections[key]; state != nil {
			if state.connection != nil {
				if state.connection.Context().Err() == nil {
					connection := state.connection
					pool.mu.Unlock()
					return connection, nil
				}
				delete(pool.doqConnections, key)
				pool.mu.Unlock()
				continue
			}
			ready := state.ready
			pool.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ready:
				continue
			}
		}

		state := &pooledDoQConnection{ready: make(chan struct{})}
		pool.doqConnections[key] = state
		pool.mu.Unlock()

		connection, err := pool.dialDoQ(ctx, address, host, timeout)
		pool.mu.Lock()
		current, owned := pool.doqConnections[key]
		if owned && current == state && !pool.closed {
			if err == nil {
				state.connection = connection
			} else {
				delete(pool.doqConnections, key)
			}
			ready := state.ready
			state.ready = nil
			close(ready)
			pool.mu.Unlock()
			return connection, err
		}
		pool.mu.Unlock()
		if connection != nil {
			_ = connection.CloseWithError(0, "")
		}
		return nil, errForwarderPoolClosed
	}
}

func (pool *forwarderPool) dialDoQ(ctx context.Context, address, host string, timeout time.Duration) (*quic.Conn, error) {
	configuration := pool.doqTLSConfig(host)
	if configuration == nil {
		configuration = new(tls.Config)
	} else {
		configuration = configuration.Clone()
	}
	configuration.MinVersion = tls.VersionTLS13
	configuration.ServerName = host
	configuration.NextProtos = []string{"doq"}
	if configuration.ClientSessionCache == nil {
		configuration.ClientSessionCache = pool.sessions
	}
	return quic.DialAddr(ctx, address, configuration, &quic.Config{
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       pool.idleTimeout,
	})
}

func (pool *forwarderPool) discardDoQConnection(key string, connection *quic.Conn) {
	pool.mu.Lock()
	if current := pool.doqConnections[key]; current != nil && current.connection == connection {
		delete(pool.doqConnections, key)
	}
	pool.mu.Unlock()
	_ = connection.CloseWithError(0, "")
}

func (pool *forwarderPool) exchangeUDP(ctx context.Context, request *dns.Msg, address string, timeout time.Duration) (*dns.Msg, error) {
	client := &dns.Client{Net: "udp", Timeout: timeout}
	response, _, err := client.ExchangeContext(ctx, request, address)
	if err != nil {
		return nil, err
	}
	if !response.Truncated {
		return response, nil
	}
	// A truncated UDP answer is retried over a pooled TCP connection.
	return pool.exchangeStream(ctx, request, forwarding.Upstream{Protocol: "tcp", Address: address}, timeout)
}

// exchangeStream runs a TCP or DoT exchange, reusing a pooled connection when one
// is available. A reused connection may have been closed by the upstream while
// idle, so a failure on a pooled connection is retried once on a fresh dial.
func (pool *forwarderPool) exchangeStream(ctx context.Context, request *dns.Msg, upstream forwarding.Upstream, timeout time.Duration) (*dns.Msg, error) {
	protocol, address, host := upstream.Protocol, upstream.DialAddress(), upstream.Host()
	key := protocol + "|" + address + "|" + host
	if connection := pool.take(key); connection != nil {
		response, err := roundTrip(ctx, connection, request, timeout)
		if err == nil {
			pool.put(key, connection)
			return response, nil
		}
		_ = connection.Close()
	}

	connection, err := pool.dial(protocol, address, host, timeout)
	if err != nil {
		return nil, err
	}
	response, err := roundTrip(ctx, connection, request, timeout)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	pool.put(key, connection)
	return response, nil
}

// dial connects to address. A DoT server is authenticated as host, which
// differs from address when the forwarder has a bootstrap address
// (RFC 7858 §4.2).
func (pool *forwarderPool) dial(protocol, address, host string, timeout time.Duration) (*dns.Conn, error) {
	client := &dns.Client{Timeout: timeout, DialTimeout: timeout}
	if protocol == "tls" {
		client.Net = "tcp-tls"
		client.TLSConfig = pool.tlsConfig(host)
	} else {
		client.Net = "tcp"
	}
	return client.Dial(address)
}

// roundTrip writes the request and reads the matching response on an exclusively
// held connection. An id mismatch means a stale message was left on the wire, so
// the connection is reported as failed and the caller discards it.
func roundTrip(ctx context.Context, connection *dns.Conn, request *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	if err := connection.WriteMsg(request); err != nil {
		return nil, err
	}
	response, err := connection.ReadMsg()
	if err != nil {
		return nil, err
	}
	if response.Id != request.Id {
		return nil, errors.New("forwarder response id does not match the request")
	}
	return response, nil
}

// take removes a usable idle connection for the endpoint, discarding any that
// have passed their idle deadline.
func (pool *forwarderPool) take(key string) *dns.Conn {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	connections := pool.idle[key]
	now := time.Now()
	for len(connections) > 0 {
		candidate := connections[len(connections)-1]
		connections = connections[:len(connections)-1]
		if now.Before(candidate.expiry) {
			pool.store(key, connections)
			return candidate.connection
		}
		_ = candidate.connection.Close()
	}
	pool.store(key, nil)
	return nil
}

// reapIdle closes idle connections that have passed their deadline. take only
// discards expired connections for the endpoint it is asked about, so without
// this an endpoint that stops being used holds its sockets open indefinitely.
func (pool *forwarderPool) reapIdle(now time.Time) {
	var expired []*dns.Conn
	pool.mu.Lock()
	for key, connections := range pool.idle {
		kept := connections[:0]
		for _, connection := range connections {
			if now.Before(connection.expiry) {
				kept = append(kept, connection)
			} else {
				expired = append(expired, connection.connection)
			}
		}
		clear(connections[len(kept):])
		pool.store(key, kept)
	}
	pool.mu.Unlock()
	for _, connection := range expired {
		_ = connection.Close()
	}
}

// put returns a healthy connection to the idle pool, or closes it when the pool
// for that endpoint is already full.
func (pool *forwarderPool) put(key string, connection *dns.Conn) {
	pool.mu.Lock()
	connections := pool.idle[key]
	if len(connections) >= pool.maxIdlePerHost {
		pool.mu.Unlock()
		_ = connection.Close()
		return
	}
	pool.idle[key] = append(connections, idleConnection{connection: connection, expiry: time.Now().Add(pool.idleTimeout)})
	pool.mu.Unlock()
}

// store records the remaining idle connections for an endpoint, dropping the map
// entry entirely when none remain. The caller holds pool.mu.
func (pool *forwarderPool) store(key string, connections []idleConnection) {
	if len(connections) == 0 {
		delete(pool.idle, key)
		return
	}
	pool.idle[key] = connections
}

func (pool *forwarderPool) isClosed() bool {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.closed
}

func (pool *forwarderPool) Close() {
	pool.mu.Lock()
	if pool.closed {
		pool.mu.Unlock()
		return
	}
	pool.closed = true
	streams := make([]*dns.Conn, 0)
	for _, connections := range pool.idle {
		for _, connection := range connections {
			streams = append(streams, connection.connection)
		}
	}
	doq := make([]*quic.Conn, 0, len(pool.doqConnections))
	for _, state := range pool.doqConnections {
		if state.connection != nil {
			doq = append(doq, state.connection)
		}
		if state.ready != nil {
			close(state.ready)
			state.ready = nil
		}
	}
	doh := make([]*dohEndpoint, 0, len(pool.dohClients))
	for _, endpoint := range pool.dohClients {
		doh = append(doh, endpoint)
	}
	clear(pool.idle)
	clear(pool.doqConnections)
	clear(pool.dohClients)
	pool.mu.Unlock()

	for _, endpoint := range doh {
		endpoint.close()
	}

	for _, connection := range streams {
		_ = connection.Close()
	}
	for _, connection := range doq {
		_ = connection.CloseWithError(0, "")
	}
}
