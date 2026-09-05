package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

type memoryVault struct{ values map[string][]byte }

func (vault *memoryVault) Put(_ context.Context, name string, value []byte) error {
	if vault.values == nil {
		vault.values = make(map[string][]byte)
	}
	vault.values[name] = append([]byte(nil), value...)
	return nil
}

func (vault *memoryVault) Get(_ context.Context, name string) ([]byte, error) {
	value, ok := vault.values[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), value...), nil
}

func TestCredentialsAreEncryptedVaultMaterialNotConfiguration(t *testing.T) {
	vault := &memoryVault{}
	manager := New(vault, slog.New(slog.NewTextHandler(io.Discard, nil)), t.TempDir())
	credentials := Credentials{APIToken: "secret-token", ZoneID: "zone-id"}
	if err := manager.PutCredentials(context.Background(), "cloudflare", credentials); err != nil {
		t.Fatal(err)
	}
	status := manager.Status(context.Background(), config.EncryptedDNS{
		CertificateMode: "acme", ACME: config.ACME{DNSProvider: "cloudflare"},
	})
	if !status.CredentialsConfigured {
		t.Fatal("stored credentials were not reported as configured")
	}
	if _, ok := vault.values["external-dns/providers/cloudflare"]; !ok {
		t.Fatal("credentials were not stored under the provider secret")
	}
}

func TestCredentialUpdatesKeepExistingSecrets(t *testing.T) {
	vault := &memoryVault{}
	manager := New(vault, slog.New(slog.NewTextHandler(io.Discard, nil)), t.TempDir())
	ctx := context.Background()
	if err := manager.PutCredentials(ctx, "route53", Credentials{AccessKeyID: "access", SecretAccessKey: "secret", ZoneID: "zone-1"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.PutCredentials(ctx, "route53", Credentials{ZoneID: "zone-2"}); err != nil {
		t.Fatal(err)
	}
	credentials, ok := manager.credentials(ctx, "route53")
	if !ok {
		t.Fatal("updated credentials were not readable")
	}
	if credentials.SecretAccessKey != "secret" || credentials.AccessKeyID != "access" || credentials.ZoneID != "zone-2" {
		t.Fatalf("merged credentials = %#v", credentials)
	}
}

func TestChallengeZoneSupportsRegistrableAndExplicitZones(t *testing.T) {
	if zone, err := challengeZone("", "dns.example.co.uk"); err != nil || zone != "example.co.uk" {
		t.Fatalf("detected zone = %q, %v", zone, err)
	}
	if zone, err := challengeZone("delegated.example.com", "dns.delegated.example.com"); err != nil || zone != "delegated.example.com" {
		t.Fatalf("explicit zone = %q, %v", zone, err)
	}
}

func TestEnsureUsesCurrentManagedCertificateWithoutProviderCredentials(t *testing.T) {
	directory := t.TempDir()
	configuration := config.EncryptedDNS{
		CertificateMode: "acme",
		ACME: config.ACME{
			Domains: []string{"dns.example.test"}, StorageDirectory: "tls",
			RenewBefore: config.Duration{Duration: 24 * time.Hour}, DNSProvider: "cloudflare",
		},
	}
	certificate, privateKey := testCertificate(t, "dns.example.test", time.Now().Add(30*24*time.Hour))
	certificatePath, privateKeyPath := certificatePaths(directory, configuration.ACME.StorageDirectory)
	if err := commitKeyPair(certificatePath, privateKeyPath, certificate, privateKey); err != nil {
		t.Fatal(err)
	}
	manager := New(&memoryVault{}, slog.New(slog.NewTextHandler(io.Discard, nil)), directory)
	changed, err := manager.Ensure(context.Background(), configuration, false)
	if err != nil || changed {
		t.Fatalf("Ensure() = %v, %v", changed, err)
	}
	if status := manager.Status(context.Background(), configuration); status.NotAfter.IsZero() {
		t.Fatal("current certificate was not reflected in status")
	}
	if info, err := os.Stat(filepath.Join(directory, "tls", "private-key.pem")); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %v", info.Mode().Perm())
	}
}

func testCertificate(t *testing.T, domain string, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(1), Subject: pkix.Name{CommonName: domain},
		DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestStatusReportsInstalledCertificateIdentity(t *testing.T) {
	directory := t.TempDir()
	configuration := config.EncryptedDNS{
		CertificateMode: "acme",
		ACME: config.ACME{
			Domains: []string{"dns.example.test"}, StorageDirectory: "tls",
			RenewBefore: config.Duration{Duration: 24 * time.Hour}, DNSProvider: "cloudflare",
		},
	}
	certificate, privateKey := testMultiNameCertificate(t, time.Now().Add(30*24*time.Hour))
	certificatePath, privateKeyPath := certificatePaths(directory, configuration.ACME.StorageDirectory)
	if err := commitKeyPair(certificatePath, privateKeyPath, certificate, privateKey); err != nil {
		t.Fatal(err)
	}
	manager := New(&memoryVault{}, slog.New(slog.NewTextHandler(io.Discard, nil)), directory)
	if _, err := manager.Ensure(context.Background(), configuration, false); err != nil {
		t.Fatal(err)
	}

	status := manager.Status(context.Background(), configuration)
	wantNames := []string{"192.0.2.10", "dns.example.test"}
	if !slices.Equal(status.CoveredNames, wantNames) {
		t.Fatalf("CoveredNames = %v, want %v", status.CoveredNames, wantNames)
	}
	if status.Subject != "dns.example.test" {
		t.Fatalf("Subject = %q, want dns.example.test", status.Subject)
	}
	if status.SerialNumber != "01:e2:40" {
		t.Fatalf("SerialNumber = %q, want 01:e2:40", status.SerialNumber)
	}
	if len(status.Fingerprint) != 95 || strings.Count(status.Fingerprint, ":") != 31 {
		t.Fatalf("Fingerprint = %q, want 32 colon-separated octets", status.Fingerprint)
	}
	// The IP address is a subject alternative name like any other. Reporting it
	// is what lets the console show every identity a client may dial.
	if !slices.Contains(status.CoveredNames, "192.0.2.10") {
		t.Fatal("CoveredNames omitted the certificate's IP address")
	}
}

func TestFormatSerialNumberRendersOctets(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		serial *big.Int
		want   string
	}{
		{name: "nil", serial: nil, want: ""},
		{name: "zero", serial: big.NewInt(0), want: "00"},
		{name: "single octet", serial: big.NewInt(15), want: "0f"},
		{name: "multiple octets", serial: big.NewInt(123456), want: "01:e2:40"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := formatSerialNumber(testCase.serial); got != testCase.want {
				t.Fatalf("formatSerialNumber() = %q, want %q", got, testCase.want)
			}
		})
	}
}

func testMultiNameCertificate(t *testing.T, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(123456), Subject: pkix.Name{CommonName: "dns.example.test"},
		DNSNames: []string{"dns.example.test"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.10")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
