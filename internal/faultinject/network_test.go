//go:build faultinject

package faultinject

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
)

func TestHTTPClientRefusesUnreachableAddressesUntilTheyHeal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	}))
	defer server.Close()
	address := server.Listener.Addr().String()
	write := UseFaults(t, Faults{})
	client := HTTPClient(&http.Client{})

	mustGet(t, client, server.URL)
	write(Faults{Unreachable: []string{address}})
	_, err := client.Get(server.URL)
	if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("GET while unreachable: err = %v, want a refused or reset connection", err)
	}
	write(Faults{Unreachable: []string{"127.0.0.1:1"}})
	mustGet(t, client, server.URL)
}

func TestHTTPClientResetsAnOpenConnectionWhenItsAddressGoesUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	write := UseFaults(t, Faults{})
	transport := HTTPClient(&http.Client{}).Transport.(*http.Transport)
	conn, err := transport.DialContext(t.Context(), "tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	write(Faults{Unreachable: []string{server.Listener.Addr().String()}})
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("write on a cut connection: err = %v, want ECONNRESET", err)
	}
}

func mustGet(t *testing.T, client *http.Client, url string) {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	response.Body.Close()
}
