package dnsserver

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/dnsclient"
	"github.com/drudge/sable/internal/forwarding"
)

// maxDoHConnections is the most HTTP/2 connections Sable opens to one DoH
// forwarder. A busy DoT forwarder holds a connection per query in flight, so
// this keeps DoH within the same order of connections.
const maxDoHConnections = 16

// dohStreamsPerConnection is how many queries in flight justify one more
// connection. Public DoH services throttle a single busy connection well below
// its stream limit: Cloudflare stalls and then refuses streams (REFUSED_STREAM)
// on one connection past about 150 queries a second, though it advertises 256
// concurrent streams. A quiet forwarder uses one connection; a busy one spreads
// its queries the way the DoT pool spreads them over its connections.
const dohStreamsPerConnection = 4

// dohEndpoint is one DoH forwarder's connections. Each has its own transport,
// so it is one HTTP/2 connection reused by every query sent on it and closed
// with the pool.
type dohEndpoint struct {
	upstream forwarding.Upstream
	timeout  time.Duration

	mu          sync.Mutex
	connections [maxDoHConnections]*dohConnection
	next        atomic.Uint64
	inflight    atomic.Int64
}

// dohConnection is one HTTP/2 connection. Until a query has been answered on
// it, queries take turns through first, so a burst shares the connection the
// first query opens instead of each dialing its own (net/http does not
// combine concurrent dials).
type dohConnection struct {
	client *http.Client
	first  chan struct{}
	warm   atomic.Bool
}

// exchangeHTTPS sends a query to an RFC 8484 DNS over HTTPS forwarder.
//
// The answer comes whole, up to 65535 octets, and is never truncated, so
// unlike UDP there is no retry over TCP (RFC 8484 §6). Failures count against
// the forwarder's health like any other transport's, because they reach
// exchangeContext as errors.
func (pool *forwarderPool) exchangeHTTPS(
	ctx context.Context,
	request *dns.Msg,
	upstream forwarding.Upstream,
	timeout time.Duration,
) (*dns.Msg, error) {
	endpoint, err := pool.dohEndpoint(upstream, timeout)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	inflight := endpoint.inflight.Add(1)
	defer endpoint.inflight.Add(-1)
	connection := endpoint.connection(pool, inflight)
	if !connection.warm.Load() {
		// This query waits for the connection's first exchange, and so for
		// its handshake.
		markConnectionOpened(ctx)
		select {
		case connection.first <- struct{}{}:
			defer func() { <-connection.first }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if !info.Reused {
			markConnectionOpened(ctx)
		}
	}})
	response, err := dnsclient.ExchangeDoH(ctx, connection.client, upstream.URL(), request)
	if err == nil || errors.Is(err, dnsclient.ErrDoHAnswer) {
		connection.warm.Store(true)
	}
	return response, err
}

// connection picks a connection round-robin among as many as the queries in
// flight call for, opening it on first use.
func (endpoint *dohEndpoint) connection(pool *forwarderPool, inflight int64) *dohConnection {
	width := min(maxDoHConnections, 1+int((inflight-1)/dohStreamsPerConnection))
	index := 0
	if width > 1 {
		index = int(endpoint.next.Add(1) % uint64(width))
	}
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	if connection := endpoint.connections[index]; connection != nil {
		return connection
	}
	connection := &dohConnection{
		client: &http.Client{Transport: pool.dohTransport(endpoint.upstream, endpoint.timeout)},
		first:  make(chan struct{}, 1),
	}
	endpoint.connections[index] = connection
	return connection
}

// close drops the endpoint's idle connections.
func (endpoint *dohEndpoint) close() {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	for _, connection := range endpoint.connections {
		if connection != nil {
			connection.client.CloseIdleConnections()
		}
	}
}

// dohEndpoint returns the forwarder's endpoint, creating it on first use.
func (pool *forwarderPool) dohEndpoint(upstream forwarding.Upstream, timeout time.Duration) (*dohEndpoint, error) {
	key := upstream.String()
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.closed {
		return nil, errForwarderPoolClosed
	}
	if endpoint := pool.dohClients[key]; endpoint != nil {
		return endpoint, nil
	}
	endpoint := &dohEndpoint{upstream: upstream, timeout: timeout}
	pool.dohClients[key] = endpoint
	return endpoint, nil
}

// dohTransport dials the forwarder's bootstrap address, or its host when it
// has none, and authenticates the server as the URL's host (RFC 8484 §10,
// RFC 2818 §3.1). The transport never uses an HTTP proxy from the
// environment: a resolver's upstream traffic goes straight to the upstream.
func (pool *forwarderPool) dohTransport(upstream forwarding.Upstream, timeout time.Duration) *http.Transport {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	configuration := pool.dohTLSConfig(upstream.Host())
	if configuration == nil {
		configuration = new(tls.Config)
	} else {
		configuration = configuration.Clone()
	}
	configuration.ServerName = upstream.Host()
	configuration.NextProtos = []string{"h2", "http/1.1"}
	if configuration.MinVersion < tls.VersionTLS12 {
		// RFC 8484 §5.2 relies on HTTP/2, which needs TLS 1.2 or later
		// (RFC 9113 §9.2).
		configuration.MinVersion = tls.VersionTLS12
	}
	if configuration.ClientSessionCache == nil {
		configuration.ClientSessionCache = pool.sessions
	}
	dialAddress := upstream.DialAddress()
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: pool.idleTimeout}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialAddress)
		},
		TLSClientConfig:        configuration,
		TLSHandshakeTimeout:    timeout,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           pool.maxIdlePerHost,
		MaxIdleConnsPerHost:    pool.maxIdlePerHost,
		IdleConnTimeout:        pool.idleTimeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 64 << 10,
		HTTP2: &http.HTTP2Config{
			// A connection the upstream dropped without a GOAWAY is found
			// by a ping rather than by the next query timing out on it.
			SendPingTimeout: pool.idleTimeout / 2,
			PingTimeout:     timeout,
		},
	}
}
