// Package outbound dials the internet services Sable itself talks to, such as
// GitHub for updates, without depending only on the host's resolver.
//
// Sable is a DNS server, so it already knows how to resolve names through the
// forwarders or iterative resolution its operator configured. The host's
// resolver is often a home router, and some of them (Starlink's, for one)
// drop queries. A Dialer resolves through Sable first and falls back to the
// host's resolver only when Sable has no answer.
package outbound

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"
)

const (
	dialTimeout = 30 * time.Second
	// minimumAttemptTimeout keeps one address from spending the whole dial
	// budget while it still gives a slow link time to connect.
	minimumAttemptTimeout = 2 * time.Second
)

// Resolver resolves a host name to its addresses.
type Resolver interface {
	LookupAddresses(ctx context.Context, host string) ([]netip.Addr, error)
}

// Dialer opens TCP connections, resolving host names through Resolver first
// and through the host's resolver when Resolver fails or has no addresses.
type Dialer struct {
	Resolver Resolver
	dialer   net.Dialer
}

// NewDialer returns a Dialer that resolves through resolver. A nil resolver
// leaves resolution to the host.
func NewDialer(resolver Resolver) *Dialer {
	return &Dialer{Resolver: resolver, dialer: net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}}
}

// DialContext connects to address on network, as net.Dialer.DialContext does.
func (dialer *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || dialer.Resolver == nil {
		return dialer.dialer.DialContext(ctx, network, address)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return dialer.dialer.DialContext(ctx, network, address)
	}
	addresses, err := dialer.Resolver.LookupAddresses(ctx, host)
	addresses = usable(addresses, network)
	if err != nil || len(addresses) == 0 {
		return dialer.dialer.DialContext(ctx, network, address)
	}
	return dialer.dialAddresses(ctx, network, port, addresses)
}

// dialAddresses tries each address in turn, giving each an equal share of the
// time left, as the standard library does, so one unreachable address family
// cannot use up the whole budget.
func (dialer *Dialer) dialAddresses(ctx context.Context, network, port string, addresses []netip.Addr) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialer.dialer.Timeout)
	defer cancel()
	var failures []error
	for index, address := range addresses {
		deadline, _ := ctx.Deadline()
		share := time.Until(deadline) / time.Duration(len(addresses)-index)
		attempt, cancelAttempt := context.WithTimeout(ctx, max(share, minimumAttemptTimeout))
		connection, err := dialer.dialer.DialContext(attempt, network, net.JoinHostPort(address.String(), port))
		cancelAttempt()
		if err == nil {
			return connection, nil
		}
		failures = append(failures, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(failures...)
}

// usable keeps the addresses network can reach and alternates the address
// families, starting with the family of the first address, so a broken IPv6
// or IPv4 path costs one attempt before the other family gets a turn.
func usable(addresses []netip.Addr, network string) []netip.Addr {
	var first, second []netip.Addr
	for _, address := range addresses {
		address = address.Unmap()
		if network == "tcp4" && !address.Is4() || network == "tcp6" && !address.Is6() {
			continue
		}
		if len(first) == 0 || address.Is6() == first[0].Is6() {
			first = append(first, address)
		} else {
			second = append(second, address)
		}
	}
	ordered := make([]netip.Addr, 0, len(first)+len(second))
	for index := range max(len(first), len(second)) {
		if index < len(first) {
			ordered = append(ordered, first[index])
		}
		if index < len(second) {
			ordered = append(ordered, second[index])
		}
	}
	return ordered
}

// HTTPClient returns a client like http.DefaultClient whose connections resolve
// through resolver, with timeout bounding each request. A nil resolver returns
// a plain client that resolves through the host.
func HTTPClient(resolver Resolver, timeout time.Duration) *http.Client {
	if resolver == nil {
		return &http.Client{Timeout: timeout}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = NewDialer(resolver).DialContext
	return &http.Client{Transport: transport, Timeout: timeout}
}
