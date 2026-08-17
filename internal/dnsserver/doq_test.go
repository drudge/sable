package dnsserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func startTestDoQListener(t *testing.T, handler dns.Handler) (string, *x509.CertPool) {
	t.Helper()

	certificatePath, privateKeyPath := writeTestCertificate(t)
	certificate, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair() error = %v", err)
	}
	group := NewListenerGroup(handler, slog.New(slog.NewTextHandler(io.Discard, nil)))
	group.certificates.activate(&certificate)
	listener, err := group.openDoQ(listenerTarget{kind: listenerDoQ, address: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("openDoQ() error = %v", err)
	}
	go func() { _ = listener.quicServer.serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = listener.quicServer.shutdown(ctx)
	})

	pem, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("test certificate was not accepted into the trust pool")
	}
	return listener.quicServer.packets.LocalAddr().String(), pool
}

func dialTestDoQ(t *testing.T, address string, pool *x509.CertPool) *quic.Conn {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
	t.Cleanup(func() { _ = connection.CloseWithError(doqNoError, "") })
	return connection
}

func writeTestDoQMessage(t *testing.T, stream *quic.Stream, wire []byte) {
	t.Helper()

	framed := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(wire)))
	copy(framed[2:], wire)
	if _, err := stream.Write(framed); err != nil {
		t.Fatalf("write DoQ query error = %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close DoQ send side error = %v", err)
	}
}

func TestDoQServerAnswersQueryOnItsOwnStream(t *testing.T) {
	t.Parallel()

	address, pool := startTestDoQListener(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		if protocol, ok := writer.(interface{ QueryProtocol() string }); !ok || protocol.QueryProtocol() != "QUIC" {
			t.Errorf("QueryProtocol() = %v, want QUIC", protocol)
		}
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.10"),
		})
		_ = writer.WriteMsg(response)
	}))
	connection := dialTestDoQ(t, address, pool)

	// RFC 9250 section 4.2 gives every query its own bidirectional stream, so
	// two queries on one connection must both be answered.
	for _, name := range []string{"one.example.", "two.example."} {
		request := new(dns.Msg)
		request.SetQuestion(name, dns.TypeA)
		request.Id = 0

		stream, err := connection.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatalf("OpenStreamSync() error = %v", err)
		}
		wire, err := request.Pack()
		if err != nil {
			t.Fatalf("Pack() error = %v", err)
		}
		writeTestDoQMessage(t, stream, wire)

		_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
		responseWire, err := readDoQMessage(stream)
		if err != nil {
			t.Fatalf("read DoQ response for %s error = %v", name, err)
		}
		response := new(dns.Msg)
		if err := response.Unpack(responseWire); err != nil {
			t.Fatalf("Unpack() error = %v", err)
		}
		if response.Id != 0 {
			t.Errorf("response ID = %d, want 0", response.Id)
		}
		if len(response.Answer) != 1 || response.Question[0].Name != name {
			t.Fatalf("response for %s = %v", name, response)
		}
	}
}

func TestDoQServerAbortsConnectionOnEDNSTCPKeepalive(t *testing.T) {
	t.Parallel()

	address, pool := startTestDoQListener(t, dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {
		t.Error("handler was reached for a query carrying edns-tcp-keepalive")
	}))
	connection := dialTestDoQ(t, address, pool)

	request := new(dns.Msg)
	request.SetQuestion("keepalive.example.", dns.TypeA)
	request.Id = 0
	request.SetEdns0(dns.DefaultMsgSize, false)
	request.IsEdns0().Option = append(request.IsEdns0().Option, &dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE})
	wire, err := request.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	stream, err := connection.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("OpenStreamSync() error = %v", err)
	}
	writeTestDoQMessage(t, stream, wire)

	// RFC 9250 section 5.5.2 makes the option fatal for the whole connection.
	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, readErr := readDoQMessage(stream); readErr == nil {
		t.Fatal("read DoQ response error = nil, want connection abort")
	}
	select {
	case <-connection.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("connection was not closed after edns-tcp-keepalive")
	}
}

func TestReadDoQMessageRejectsZeroLengthPrefix(t *testing.T) {
	t.Parallel()

	address, pool := startTestDoQListener(t, dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {
		t.Error("handler was reached for a zero-length DoQ message")
	}))
	connection := dialTestDoQ(t, address, pool)

	stream, err := connection.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("OpenStreamSync() error = %v", err)
	}
	writeTestDoQMessage(t, stream, nil)

	select {
	case <-connection.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("connection was not closed after a zero-length message")
	}
}

func TestListenerKeysIncludeDoQTargets(t *testing.T) {
	t.Parallel()

	targets := listenerKeys(ListenerConfig{DoQ: []string{"127.0.0.1:8853"}, MinimumTLS: tls.VersionTLS12})
	if _, ok := targets["doq:127.0.0.1:8853"]; !ok {
		t.Fatalf("DoQ listener target is missing from %v", targets)
	}
}

func TestLoadCertificateIsRequiredForDoQ(t *testing.T) {
	t.Parallel()

	if _, err := loadCertificate(ListenerConfig{DoQ: []string{"127.0.0.1:853"}}); err == nil {
		t.Fatal("loadCertificate() error = nil for a DoQ listener without a key pair")
	}
}

func TestDoQShutdownClosesEstablishedConnections(t *testing.T) {
	t.Parallel()

	certificatePath, privateKeyPath := writeTestCertificate(t)
	certificate, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair() error = %v", err)
	}
	group := NewListenerGroup(dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	group.certificates.activate(&certificate)
	listener, err := group.openDoQ(listenerTarget{kind: listenerDoQ, address: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("openDoQ() error = %v", err)
	}
	go func() { _ = listener.quicServer.serve() }()

	pem, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("test certificate was not accepted into the trust pool")
	}
	connection := dialTestDoQ(t, listener.quicServer.packets.LocalAddr().String(), pool)

	// The server only sees the connection once it accepts a stream, so open one
	// before shutting down.
	stream, err := connection.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("OpenStreamSync() error = %v", err)
	}
	request := new(dns.Msg)
	request.SetQuestion("shutdown.example.", dns.TypeA)
	request.Id = 0
	wire, err := request.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	writeTestDoQMessage(t, stream, wire)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := listener.quicServer.shutdown(ctx); err != nil {
		t.Fatalf("shutdown() error = %v", err)
	}
	select {
	case <-connection.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("established connection outlived the shutdown")
	}
}
