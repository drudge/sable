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
	"os"
	"path/filepath"
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
	if _, ok := vault.values[credentialSecretPrefix+"cloudflare"]; !ok {
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
