package dnsserver

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
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
// handshakes. DoT and DoQ also share a TLS client session cache for re-dials.
type forwarderPool struct {
	mu             sync.Mutex
	idle           map[string][]idleConnection
	doqConnections map[string]*pooledDoQConnection
	sessions       tls.ClientSessionCache
	closed         bool

	maxIdlePerHost int
	idleTimeout    time.Duration

	// tlsConfig builds the client TLS configuration for a DoT dial. It is a field
	// so tests can trust a self-signed upstream; production uses defaultTLSConfig.
	tlsConfig    func(host string) *tls.Config
	doqTLSConfig func(host string) *tls.Config
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
		sessions:       tls.NewLRUClientSessionCache(0),
		maxIdlePerHost: 8,
		idleTimeout:    30 * time.Second,
	}
	pool.tlsConfig = pool.defaultTLSConfig
	pool.doqTLSConfig = pool.defaultDoQTLSConfig
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
	protocol, address, err := forwarding.ParseEndpoint(forwarder)
	if err != nil {
		return nil, err
	}
	switch protocol {
	case "quic":
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, splitErr
		}
		return pool.exchangeQUIC(ctx, request, address, host, timeout)
	case "udp":
		return pool.exchangeUDP(ctx, request, address, timeout)
	default: // tcp, tls
		return pool.exchangeStream(ctx, request, protocol, address, timeout)
	}
}

func (pool *forwarderPool) exchangeQUIC(
	ctx context.Context,
	request *dns.Msg,
	address, host string,
	timeout time.Duration,
) (*dns.Msg, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	key := "quic|" + address
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
	return pool.exchangeStream(ctx, request, "tcp", address, timeout)
}

// exchangeStream runs a TCP or DoT exchange, reusing a pooled connection when one
// is available. A reused connection may have been closed by the upstream while
// idle, so a failure on a pooled connection is retried once on a fresh dial.
func (pool *forwarderPool) exchangeStream(ctx context.Context, request *dns.Msg, protocol, address string, timeout time.Duration) (*dns.Msg, error) {
	key := protocol + "|" + address
	if connection := pool.take(key); connection != nil {
		response, err := roundTrip(ctx, connection, request, timeout)
		if err == nil {
			pool.put(key, connection)
			return response, nil
		}
		_ = connection.Close()
	}

	connection, err := pool.dial(protocol, address, timeout)
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

func (pool *forwarderPool) dial(protocol, address string, timeout time.Duration) (*dns.Conn, error) {
	client := &dns.Client{Timeout: timeout, DialTimeout: timeout}
	if protocol == "tls" {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
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
	clear(pool.idle)
	clear(pool.doqConnections)
	pool.mu.Unlock()

	for _, connection := range streams {
		_ = connection.Close()
	}
	for _, connection := range doq {
		_ = connection.CloseWithError(0, "")
	}
}
