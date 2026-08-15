package dnsserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type trackingCloser struct{ closed bool }

func (closer *trackingCloser) Close() error {
	closer.closed = true
	return nil
}

func TestListenerKeysIncludeEveryProtocolAndTLSVersion(t *testing.T) {
	t.Parallel()

	targets := listenerKeys(ListenerConfig{
		PlainDNS:   []string{"127.0.0.1:8053"},
		DoT:        []string{"127.0.0.1:8853"},
		DoH:        []string{"127.0.0.1:8443"},
		MinimumTLS: 0x0304,
	})
	for _, key := range []string{
		"dns-udp:127.0.0.1:8053",
		"dns-tcp:127.0.0.1:8053",
		"dot:127.0.0.1:8853:tls772",
		"doh:127.0.0.1:8443:tls772",
	} {
		if _, ok := targets[key]; !ok {
			t.Errorf("listener target %q is missing from %v", key, targets)
		}
	}
}

func TestDynamicUpdateAcceptFuncAdmitsUpdateMessages(t *testing.T) {
	header := dns.Header{Bits: uint16(dns.OpcodeUpdate << 11), Qdcount: 1, Ancount: 8, Nscount: 16, Arcount: 1}
	if got := dynamicUpdateAcceptFunc(header); got != dns.MsgAccept {
		t.Fatalf("dynamicUpdateAcceptFunc() = %v, want MsgAccept", got)
	}
	header.Qdcount = 2
	if got := dynamicUpdateAcceptFunc(header); got != dns.MsgReject {
		t.Fatalf("dynamicUpdateAcceptFunc() = %v, want MsgReject", got)
	}
}

func TestLoadCertificateRequiresValidPairForEncryptedDNS(t *testing.T) {
	t.Parallel()

	configuration := ListenerConfig{DoT: []string{"127.0.0.1:853"}}
	if _, err := loadCertificate(configuration); err == nil {
		t.Fatal("loadCertificate() error = nil for missing pair")
	}

	certificatePath, privateKeyPath := writeTestCertificate(t)
	configuration.Certificate = certificatePath
	configuration.PrivateKey = privateKeyPath
	certificate, err := loadCertificate(configuration)
	if err != nil {
		t.Fatalf("loadCertificate() error = %v", err)
	}
	if len(certificate.Certificate) == 0 {
		t.Fatal("loaded certificate chain is empty")
	}
}

func TestListenerReplacementRollsBackEveryOpenedSocket(t *testing.T) {
	t.Parallel()

	group := NewListenerGroup(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	existing := &activeListener{}
	group.listeners["existing"] = existing
	opened := new(trackingCloser)
	openCalls := 0
	group.openListener = func(target listenerTarget) (*activeListener, error) {
		openCalls++
		if openCalls == 2 {
			return nil, errors.New("address unavailable")
		}
		return &activeListener{target: target, socket: opened}, nil
	}
	err := group.Replace(context.Background(), ListenerConfig{PlainDNS: []string{"127.0.0.1:8053"}})
	if err == nil {
		t.Fatal("Replace() error = nil, want listener failure")
	}
	if !opened.closed {
		t.Fatal("newly opened socket was not closed")
	}
	if len(group.listeners) != 1 || group.listeners["existing"] != existing {
		t.Fatalf("active listener set changed after rejected replacement: %v", group.listeners)
	}
}

func writeTestCertificate(t *testing.T) (string, string) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dns.example"},
		DNSNames:     []string{"dns.example"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}

	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "certificate.pem")
	privateKeyPath := filepath.Join(directory, "private-key.pem")
	writePEMFile(t, certificatePath, "CERTIFICATE", der)
	writePEMFile(t, privateKeyPath, "PRIVATE KEY", privateKeyDER)
	return certificatePath, privateKeyPath
}

func writePEMFile(t *testing.T, path, blockType string, contents []byte) {
	t.Helper()
	encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: contents})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}
