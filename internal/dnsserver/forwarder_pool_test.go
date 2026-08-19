package dnsserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// countingListener records how many TCP connections the upstream accepted, so a
// test can prove the pool reused one connection across several queries.
type countingListener struct {
	net.Listener
	accepted atomic.Int64
}

func (listener *countingListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err == nil {
		listener.accepted.Add(1)
	}
	return connection, err
}

func startTestDoTServer(t *testing.T) (endpoint string, accepted *atomic.Int64, roots *x509.CertPool) {
	t.Helper()
	certificate, pool := selfSignedDoTCertificate(t)
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	counting := &countingListener{Listener: base}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{testRR(t, "example.test. 60 IN A 192.0.2.10")}
		_ = writer.WriteMsg(response)
	})
	server := &dns.Server{Listener: tls.NewListener(counting, serverTLS), Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return "tls://" + base.Addr().String(), &counting.accepted, pool
}

func trustingPool(roots *x509.CertPool) *forwarderPool {
	pool := newForwarderPool()
	pool.tlsConfig = func(host string) *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: roots, ClientSessionCache: pool.sessions}
	}
	return pool
}

func TestForwarderPoolReusesDoTConnections(t *testing.T) {
	t.Parallel()
	endpoint, accepted, roots := startTestDoTServer(t)
	pool := trustingPool(roots)

	for attempt := range 5 {
		request := new(dns.Msg)
		request.SetQuestion("example.test.", dns.TypeA)
		response, err := pool.exchange(context.Background(), request, endpoint, 2*time.Second)
		if err != nil {
			t.Fatalf("exchange %d: %v", attempt, err)
		}
		if len(response.Answer) != 1 {
			t.Fatalf("exchange %d answer = %v, want one record", attempt, response.Answer)
		}
	}
	if got := accepted.Load(); got != 1 {
		t.Fatalf("upstream accepted %d connections for 5 queries, want 1 (connection reuse)", got)
	}
}

func TestForwarderPoolRedialsAfterConnectionDrops(t *testing.T) {
	t.Parallel()
	endpoint, accepted, roots := startTestDoTServer(t)
	pool := trustingPool(roots)

	request := new(dns.Msg)
	request.SetQuestion("example.test.", dns.TypeA)
	if _, err := pool.exchange(context.Background(), request, endpoint, 2*time.Second); err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	// Simulate an upstream that closed the connection while it sat idle in the
	// pool. The next exchange must notice the dead connection and re-dial rather
	// than fail.
	pool.mu.Lock()
	for _, connections := range pool.idle {
		for _, candidate := range connections {
			_ = candidate.connection.Close()
		}
	}
	pool.mu.Unlock()

	if _, err := pool.exchange(context.Background(), request, endpoint, 2*time.Second); err != nil {
		t.Fatalf("exchange after a dropped connection: %v", err)
	}
	if got := accepted.Load(); got != 2 {
		t.Fatalf("upstream accepted %d connections, want 2 (one re-dial after the drop)", got)
	}
}

func selfSignedDoTCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots
}
