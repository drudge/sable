//go:build faultinject

package faultinject

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"
	"syscall"
)

// HTTPClient returns a copy of client whose connections fail while the
// address they dial is unreachable: new dials are refused, and a connection
// already open is reset on its next read or write. A client whose transport
// isn't an *http.Transport is returned unchanged.
func HTTPClient(client *http.Client) *http.Client {
	var transport *http.Transport
	switch configured := client.Transport.(type) {
	case nil:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		transport = configured.Clone()
	default:
		return client
	}
	dial := transport.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if unreachable(address) {
			return nil, fmt.Errorf("faultinject: dial %s: %w", address, syscall.ECONNREFUSED)
		}
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &faultNetConn{Conn: conn, address: address}, nil
	}
	copied := *client
	copied.Transport = transport
	return &copied
}

func unreachable(address string) bool { return slices.Contains(Current().Unreachable, address) }

// faultNetConn resets itself once its address becomes unreachable, so a
// partition also cuts keep-alive connections opened before it.
type faultNetConn struct {
	net.Conn
	address string
}

func (conn *faultNetConn) Read(buffer []byte) (int, error) {
	read, err := conn.Conn.Read(buffer)
	if cut := conn.cut(); cut != nil {
		return 0, cut
	}
	return read, err
}

func (conn *faultNetConn) Write(buffer []byte) (int, error) {
	if cut := conn.cut(); cut != nil {
		return 0, cut
	}
	return conn.Conn.Write(buffer)
}

func (conn *faultNetConn) cut() error {
	if !unreachable(conn.address) {
		return nil
	}
	_ = conn.Conn.Close()
	return fmt.Errorf("faultinject: connection to %s: %w", conn.address, syscall.ECONNRESET)
}
