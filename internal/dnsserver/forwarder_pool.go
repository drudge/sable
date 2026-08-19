package dnsserver

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"

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
// response demultiplexing is needed. DoT and DoQ additionally share a TLS client
// session cache, so even a fresh dial resumes the session instead of running a
// full handshake.
type forwarderPool struct {
	mu       sync.Mutex
	idle     map[string][]idleConnection
	sessions tls.ClientSessionCache

	maxIdlePerHost int
	idleTimeout    time.Duration

	// tlsConfig builds the client TLS configuration for a DoT dial. It is a field
	// so tests can trust a self-signed upstream; production uses defaultTLSConfig.
	tlsConfig func(host string) *tls.Config
}

type idleConnection struct {
	connection *dns.Conn
	expiry     time.Time
}

func newForwarderPool() *forwarderPool {
	pool := &forwarderPool{
		idle:           make(map[string][]idleConnection),
		sessions:       tls.NewLRUClientSessionCache(0),
		maxIdlePerHost: 8,
		idleTimeout:    30 * time.Second,
	}
	pool.tlsConfig = pool.defaultTLSConfig
	return pool
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
		response, _, exchangeErr := dnsclient.ExchangeQUICWithSessions(ctx, request, address, host, timeout, pool.sessions)
		return response, exchangeErr
	case "udp":
		return pool.exchangeUDP(ctx, request, address, timeout)
	default: // tcp, tls
		return pool.exchangeStream(ctx, request, protocol, address, timeout)
	}
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
