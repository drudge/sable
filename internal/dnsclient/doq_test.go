package dnsclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// startEchoDoQServer runs a minimal RFC 9250 server that answers every query
// with a single A record so the client framing can be exercised end to end.
func startEchoDoQServer(t *testing.T) (string, *x509.CertPool) {
	t.Helper()

	certificate, pool := generateTestCertificate(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{doqALPN},
	}, &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("ListenAddr() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			connection, acceptErr := listener.Accept(context.Background())
			if acceptErr != nil {
				return
			}
			go serveEchoDoQConnection(connection)
		}
	}()
	return listener.Addr().String(), pool
}

func serveEchoDoQConnection(connection *quic.Conn) {
	for {
		stream, err := connection.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			defer stream.Close()
			var header [2]byte
			if _, err := io.ReadFull(stream, header[:]); err != nil {
				return
			}
			wire := make([]byte, binary.BigEndian.Uint16(header[:]))
			if _, err := io.ReadFull(stream, wire); err != nil {
				return
			}
			request := new(dns.Msg)
			if err := request.Unpack(wire); err != nil {
				return
			}
			response := new(dns.Msg)
			response.SetReply(request)
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   net.ParseIP("192.0.2.20"),
			})
			responseWire, err := response.Pack()
			if err != nil {
				return
			}
			framed := make([]byte, 2+len(responseWire))
			binary.BigEndian.PutUint16(framed[:2], uint16(len(responseWire)))
			copy(framed[2:], responseWire)
			_, _ = stream.Write(framed)
		}()
	}
}

func generateTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dns.example"},
		DNSNames:     []string{"dns.example"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: parsed}, pool
}

func TestExchangeDoQStreamFramesQueryAndResponse(t *testing.T) {
	t.Parallel()

	address, pool := startEchoDoQServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := quic.DialAddr(ctx, address, &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: "dns.example",
		RootCAs:    pool,
		NextProtos: []string{doqALPN},
	}, &quic.Config{HandshakeIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("DialAddr() error = %v", err)
	}
	defer func() { _ = connection.CloseWithError(0, "") }()

	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	request.Id = 0
	wire, err := request.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	response, err := exchangeDoQStream(ctx, connection, wire)
	if err != nil {
		t.Fatalf("exchangeDoQStream() error = %v", err)
	}
	if response.Id != 0 {
		t.Errorf("response ID = %d, want 0", response.Id)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1", len(response.Answer))
	}
}

func TestQueryOverQUICZeroesTheMessageID(t *testing.T) {
	t.Parallel()

	var observedID uint16 = 1
	result, err := query(context.Background(), Request{
		Server: "127.0.0.1:853", Name: "example.com", Type: "A", Transport: "quic",
	}, nil, nil, func(_ context.Context, message *dns.Msg, server, serverName string, _ time.Duration) (*dns.Msg, time.Duration, error) {
		observedID = message.Id
		if server != "127.0.0.1:853" {
			t.Errorf("server = %q, want 127.0.0.1:853", server)
		}
		if serverName != "" {
			t.Errorf("server name = %q, want empty", serverName)
		}
		response := new(dns.Msg)
		response.SetReply(message)
		return response, 2 * time.Millisecond, nil
	})
	if err != nil {
		t.Fatalf("query() error = %v", err)
	}
	if observedID != 0 {
		t.Errorf("DoQ query ID = %d, want 0 per RFC 9250", observedID)
	}
	if result.Server != "127.0.0.1:853" {
		t.Errorf("Server = %q", result.Server)
	}
}

func TestExchangeQUICRequiresHostPort(t *testing.T) {
	t.Parallel()

	_, _, err := ExchangeQUIC(context.Background(), new(dns.Msg), "dns.example", "", time.Second)
	if err == nil || !strings.Contains(err.Error(), "parse QUIC server") {
		t.Fatalf("ExchangeQUIC() error = %v, want a host:port failure", err)
	}
}
