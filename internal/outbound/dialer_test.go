package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"
)

type fakeResolver struct {
	addresses []netip.Addr
	err       error
	hosts     []string
}

func (resolver *fakeResolver) LookupAddresses(_ context.Context, host string) ([]netip.Addr, error) {
	resolver.hosts = append(resolver.hosts, host)
	return resolver.addresses, resolver.err
}

func serverPort(t *testing.T, server *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func get(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// A name only Sable can resolve still connects, so the host's resolver is
// never asked. The .invalid name would fail any real resolver.
func TestHTTPClientResolvesThroughSable(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	}))
	defer server.Close()
	resolver := &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	client := HTTPClient(resolver, 5*time.Second)

	if body := get(t, client, "http://releases.sable.invalid:"+serverPort(t, server)+"/"); body != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
	if !slices.Equal(resolver.hosts, []string{"releases.sable.invalid"}) {
		t.Fatalf("resolved hosts = %v", resolver.hosts)
	}
}

// When Sable cannot answer, the host's resolver still gets its turn.
func TestDialerFallsBackToTheHostResolver(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	}))
	defer server.Close()
	client := HTTPClient(&fakeResolver{err: errors.New("DNS runtime is unavailable")}, 5*time.Second)

	if body := get(t, client, "http://localhost:"+serverPort(t, server)+"/"); body != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
}

// An address that refuses the connection costs one attempt, and the next
// address is tried.
func TestDialerTriesTheNextAddress(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	// 127.0.0.2 has nothing listening on this port on Linux, and is not
	// routable at all on macOS; either way the dial fails fast.
	resolver := &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}}
	dialer := NewDialer(resolver)
	dialer.dialer.Timeout = 5 * time.Second

	connection, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort("example.invalid", port))
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer connection.Close()
	if got := connection.RemoteAddr().String(); got != listener.Addr().String() {
		t.Fatalf("connected to %s, want %s", got, listener.Addr())
	}
}

func TestUsableAlternatesFamiliesAndHonorsTheNetwork(t *testing.T) {
	t.Parallel()

	addresses := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
	}
	tests := map[string][]string{
		"tcp":  {"192.0.2.1", "2001:db8::1", "192.0.2.2", "2001:db8::2"},
		"tcp4": {"192.0.2.1", "192.0.2.2"},
		"tcp6": {"2001:db8::1", "2001:db8::2"},
	}
	for network, want := range tests {
		var got []string
		for _, address := range usable(addresses, network) {
			got = append(got, address.String())
		}
		if !slices.Equal(got, want) {
			t.Errorf("usable(%s) = %v, want %v", network, got, want)
		}
	}
}
