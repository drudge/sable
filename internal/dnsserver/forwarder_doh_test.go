package dnsserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testDoHServer is an RFC 8484 upstream over HTTP/2 that records what it was
// sent. Its certificate names example.com and 127.0.0.1, so a forwarder can
// reach it as "https://example.com:port/dns-query (127.0.0.1)".
type testDoHServer struct {
	server      *httptest.Server
	connections atomic.Int64
	queries     atomic.Int64
	mu          sync.Mutex
	wireIDs     []uint16
	protocols   []string
}

func startTestDoHServer(t testing.TB) *testDoHServer {
	t.Helper()
	upstream := &testDoHServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", upstream.answer)
	mux.HandleFunc("/wrong-type", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/dns-json")
		_, _ = writer.Write([]byte(`{"Status":0}`))
	})
	mux.HandleFunc("/unavailable", func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "overloaded", http.StatusServiceUnavailable)
	})
	mux.HandleFunc("/oversize", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(make([]byte, dns.MaxMsgSize+1))
	})
	upstream.server = httptest.NewUnstartedServer(mux)
	upstream.server.EnableHTTP2 = true
	upstream.server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			upstream.connections.Add(1)
		}
	}
	upstream.server.StartTLS()
	t.Cleanup(upstream.server.Close)
	return upstream
}

func (upstream *testDoHServer) answer(writer http.ResponseWriter, request *http.Request) {
	upstream.queries.Add(1)
	wire, err := io.ReadAll(request.Body)
	query := new(dns.Msg)
	if err != nil || request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/dns-message" ||
		query.Unpack(wire) != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	upstream.mu.Lock()
	upstream.wireIDs = append(upstream.wireIDs, query.Id)
	upstream.protocols = append(upstream.protocols, request.Proto)
	upstream.mu.Unlock()
	response := new(dns.Msg)
	response.SetReply(query)
	switch query.Question[0].Name {
	case "large.example.test.":
		// Far past any UDP payload size: DoH carries it whole (RFC 8484 §6).
		for index := range 40 {
			record, _ := dns.NewRR(query.Question[0].Name + " 60 IN TXT \"" + strings.Repeat("x", 200) + string(rune('a'+index%26)) + "\"")
			response.Answer = append(response.Answer, record)
		}
	default:
		record, _ := dns.NewRR(query.Question[0].Name + " 60 IN A 192.0.2.10")
		response.Answer = []dns.RR{record}
	}
	packed, _ := response.Pack()
	writer.Header().Set("Content-Type", "application/dns-message")
	_, _ = io.Copy(writer, bytes.NewReader(packed))
}

func (upstream *testDoHServer) roots() *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(upstream.server.Certificate())
	return roots
}

// forwarder names the server by host with a bootstrap address, so the test
// covers dialing one address while authenticating another name.
func (upstream *testDoHServer) forwarder(path string) string {
	_, port, _ := net.SplitHostPort(upstream.server.Listener.Addr().String())
	return "https://example.com:" + port + path + " (127.0.0.1)"
}

func trustDoH(pool *forwarderPool, roots *x509.CertPool) {
	pool.dohTLSConfig = func(host string) *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: roots, ClientSessionCache: pool.sessions}
	}
}

func TestForwarderPoolDoHUsesHTTP2AndMessageIDZero(t *testing.T) {
	t.Parallel()
	upstream := startTestDoHServer(t)
	pool := newForwarderPool()
	trustDoH(pool, upstream.roots())
	t.Cleanup(pool.Close)

	const queries = 24
	var group sync.WaitGroup
	errs := make(chan error, queries)
	for index := range queries {
		group.Add(1)
		go func() {
			defer group.Done()
			request := testForwarderRequest()
			request.Id = uint16(1000 + index)
			response, err := pool.exchange(context.Background(), request, upstream.forwarder("/dns-query"), 2*time.Second)
			switch {
			case err != nil:
				errs <- err
			case response.Id != request.Id:
				errs <- errFromString("response ID was not restored")
			case len(response.Answer) != 1:
				errs <- errFromString("missing answer")
			}
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	for index, id := range upstream.wireIDs {
		if id != 0 {
			t.Fatalf("query %d went out with ID %d; RFC 8484 §4.1 asks for 0", index, id)
		}
		if upstream.protocols[index] != "HTTP/2.0" {
			t.Fatalf("query %d used %s, want HTTP/2", index, upstream.protocols[index])
		}
	}
	if got := upstream.connections.Load(); got < 1 || got > queries/dohStreamsPerConnection {
		t.Fatalf("upstream accepted %d connections for %d concurrent queries, want 1 to %d",
			got, queries, queries/dohStreamsPerConnection)
	}
}

// TestForwarderPoolDoHReusesOneConnectionWhenQuiet checks a forwarder with
// few queries in flight keeps to one HTTP/2 connection.
func TestForwarderPoolDoHReusesOneConnectionWhenQuiet(t *testing.T) {
	t.Parallel()
	upstream := startTestDoHServer(t)
	pool := newForwarderPool()
	trustDoH(pool, upstream.roots())
	t.Cleanup(pool.Close)
	for attempt := range 10 {
		if _, err := pool.exchange(context.Background(), testForwarderRequest(), upstream.forwarder("/dns-query"), 2*time.Second); err != nil {
			t.Fatalf("exchange %d: %v", attempt, err)
		}
	}
	if got := upstream.connections.Load(); got != 1 {
		t.Fatalf("upstream accepted %d connections for 10 queries in a row, want 1", got)
	}
}

func TestForwarderPoolDoHRefusesBadAnswers(t *testing.T) {
	t.Parallel()
	upstream := startTestDoHServer(t)
	pool := newForwarderPool()
	trustDoH(pool, upstream.roots())
	t.Cleanup(pool.Close)

	for path, want := range map[string]string{
		"/wrong-type":  "content type",
		"/unavailable": "HTTP 503",
		"/oversize":    "oversized",
		"/missing":     "HTTP 404",
	} {
		_, err := pool.exchange(context.Background(), testForwarderRequest(), upstream.forwarder(path), 2*time.Second)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error = %v, want %q", path, err, want)
		}
	}
	// A server that answers, even badly, has a connection to share, so later
	// queries to it stop taking turns.
	unavailable, _ := pool.upstream(upstream.forwarder("/unavailable"))
	pool.mu.Lock()
	warm := pool.dohClients[unavailable.String()].connections[0].warm.Load()
	pool.mu.Unlock()
	if !warm {
		t.Error("an endpoint that answered HTTP 503 still serializes its queries")
	}
	_, port, _ := net.SplitHostPort(upstream.server.Listener.Addr().String())
	_, err := pool.exchange(context.Background(), testForwarderRequest(),
		"https://wrong.example:"+port+"/dns-query (127.0.0.1)", 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a certificate for another name was accepted: %v", err)
	}
	if strings.Contains(err.Error(), "wrong.example:"+port+"/dns-query") {
		t.Fatalf("the error repeats the request URL: %v", err)
	}
}

func TestForwarderPoolDoHCarriesLargeAnswersWhole(t *testing.T) {
	t.Parallel()
	upstream := startTestDoHServer(t)
	pool := newForwarderPool()
	trustDoH(pool, upstream.roots())
	t.Cleanup(pool.Close)

	request := new(dns.Msg)
	request.SetQuestion("large.example.test.", dns.TypeTXT)
	request.SetEdns0(1232, false)
	response, err := pool.exchange(context.Background(), request, upstream.forwarder("/dns-query"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if response.Truncated || len(response.Answer) != 40 || response.Len() <= 1232 {
		t.Fatalf("large answer truncated=%v records=%d size=%d", response.Truncated, len(response.Answer), response.Len())
	}
}

func TestForwarderPoolCloseRetiresDoHConnections(t *testing.T) {
	t.Parallel()
	upstream := startTestDoHServer(t)
	pool := newForwarderPool()
	trustDoH(pool, upstream.roots())
	if _, err := pool.exchange(context.Background(), testForwarderRequest(), upstream.forwarder("/dns-query"), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	pool.Close()
	pool.mu.Lock()
	remaining := len(pool.dohClients)
	pool.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("%d DoH clients survived Close", remaining)
	}
	if _, err := pool.exchange(context.Background(), testForwarderRequest(), upstream.forwarder("/dns-query"), time.Second); err == nil {
		t.Fatal("a closed pool still sent a DoH query")
	}
}

// TestHandlerResolvesThroughDoHForwarder runs a client query through the whole
// handler to a DoH forwarder, and checks a failing DoH forwarder is marked
// unhealthy and the next one answers.
func TestHandlerResolvesThroughDoHForwarder(t *testing.T) {
	t.Parallel()
	upstream := startTestDoHServer(t)
	configuration := testRuntimeConfig()
	configuration.Mode = "forward"
	broken := upstream.forwarder("/unavailable")
	configuration.Forwarders = []string{broken, upstream.forwarder("/dns-query")}
	configuration.Retries = 1
	configuration.RetryTimeout = time.Second
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	t.Cleanup(handler.Close)
	trustDoH(handler.forwarderConnections, upstream.roots())

	for _, name := range []string{"one.example.test.", "two.example.test."} {
		query := new(dns.Msg)
		query.SetQuestion(name, dns.TypeA)
		query.Id = 4242
		client := &responseCapture{remoteIP: "127.0.0.1"}
		handler.ServeDNS(client, query)
		if client.message == nil || client.message.Rcode != dns.RcodeSuccess || len(client.message.Answer) != 1 ||
			client.message.Id != 4242 {
			t.Fatalf("%s: response = %v", name, client.message)
		}
	}
	if handler.upstreamHealth.retryAfter[broken].IsZero() {
		t.Fatal("the failing DoH forwarder was not marked unhealthy")
	}
}

// TestForwarderPoolDialsBootstrapAddressForDoTAndDoQ checks the bootstrap
// address on tls:// and quic://: Sable connects to the address and
// authenticates the server as the host name (RFC 7858 §4.2, RFC 9250 §4.1).
func TestForwarderPoolDialsBootstrapAddressForDoTAndDoQ(t *testing.T) {
	t.Parallel()
	dot, _, dotRoots := startTestDoTServer(t)
	doq, _, doqRoots := startTestDoQForwarder(t)
	for _, test := range []struct {
		endpoint string
		roots    *x509.CertPool
	}{{dot, dotRoots}, {doq, doqRoots}} {
		scheme, address, _ := strings.Cut(test.endpoint, "://")
		_, port, _ := net.SplitHostPort(address)
		pool := trustingPool(test.roots)
		t.Cleanup(pool.Close)
		named := scheme + "://dns.example.test:" + port + " (127.0.0.1)"
		if _, err := pool.exchange(context.Background(), testForwarderRequest(), named, 2*time.Second); err != nil {
			t.Fatalf("%s: %v", named, err)
		}
		wrong := scheme + "://other.example.test:" + port + " (127.0.0.1)"
		if _, err := pool.exchange(context.Background(), testForwarderRequest(), wrong, 2*time.Second); err == nil {
			t.Fatalf("%s: a certificate for another name was accepted", wrong)
		}
	}
}

type errFromString string

func (err errFromString) Error() string { return string(err) }

// BenchmarkForwarderPoolEncrypted compares forwarding over DNS over TLS and
// DNS over HTTPS to local upstreams on loopback: serial runs measure the
// per-query cost on a warm connection, parallel runs the throughput of the
// pool (several pooled DoT connections against one multiplexed HTTP/2
// connection).
func BenchmarkForwarderPoolEncrypted(b *testing.B) {
	dot, _, dotRoots := startTestDoTServer(b)
	doh := startTestDoHServer(b)
	pool := trustingPool(dotRoots)
	trustDoH(pool, doh.roots())
	b.Cleanup(pool.Close)
	endpoints := map[string]string{"tls": dot, "https": doh.forwarder("/dns-query")}
	for _, protocol := range []string{"tls", "https"} {
		endpoint := endpoints[protocol]
		if _, err := pool.exchange(context.Background(), testForwarderRequest(), endpoint, 2*time.Second); err != nil {
			b.Fatal(err)
		}
		b.Run(protocol+"/serial", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := pool.exchange(context.Background(), testForwarderRequest(), endpoint, 2*time.Second); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(protocol+"/parallel", func(b *testing.B) {
			b.ReportAllocs()
			b.SetParallelism(8)
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := pool.exchange(context.Background(), testForwarderRequest(), endpoint, 2*time.Second); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}
