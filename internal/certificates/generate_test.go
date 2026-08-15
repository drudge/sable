package certificates

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateSelfSignedCreatesProtectedUsableKeyPair(t *testing.T) {
	directory := t.TempDir()
	manager := New(&memoryVault{}, slog.New(slog.NewTextHandler(io.Discard, nil)), directory)
	manager.now = func() time.Time { return time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC) }
	result, err := manager.GenerateSelfSigned(context.Background(), ManualCertificateOptions{
		Names: []string{"dns.example.test", "192.0.2.10"}, StorageDirectory: "data/tls/manual", ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CertificateFile != filepath.Join("data", "tls", "manual", "certificate.pem") || result.PrivateKeyFile != filepath.Join("data", "tls", "manual", "private-key.pem") {
		t.Fatalf("generated paths = %#v", result)
	}
	certificatePath := filepath.Join(directory, result.CertificateFile)
	privateKeyPath := filepath.Join(directory, result.PrivateKeyFile)
	pair, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("dns.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(privateKeyPath); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %v", info.Mode().Perm())
	}
}

func TestImportKeyPairValidatesAndStoresProtectedFiles(t *testing.T) {
	directory := t.TempDir()
	manager := New(&memoryVault{}, slog.New(slog.NewTextHandler(io.Discard, nil)), directory)
	generated, err := manager.GenerateSelfSigned(context.Background(), ManualCertificateOptions{Names: []string{"dns.example.test"}, StorageDirectory: "source"})
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, _ := os.ReadFile(filepath.Join(directory, generated.CertificateFile))
	privateKeyPEM, _ := os.ReadFile(filepath.Join(directory, generated.PrivateKeyFile))
	imported, err := manager.ImportKeyPair(context.Background(), ImportCertificateOptions{
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM, StorageDirectory: "imported",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(directory, imported.CertificateFile), filepath.Join(directory, imported.PrivateKeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ImportKeyPair(context.Background(), ImportCertificateOptions{
		CertificatePEM: certificatePEM, PrivateKeyPEM: []byte("not a key"), StorageDirectory: "invalid",
	}); err == nil {
		t.Fatal("mismatched key pair was accepted")
	}
}

func TestGenerateClusterPKICreatesMutualTLSIdentity(t *testing.T) {
	directory := t.TempDir()
	manager := New(&memoryVault{}, slog.New(slog.NewTextHandler(io.Discard, nil)), directory)
	result, err := manager.GenerateClusterPKI(context.Background(), ClusterPKIOptions{
		NodeName: "dns-1", Names: []string{"dns-1.example.test", "192.0.2.10"}, StorageDirectory: "data/cluster/pki", ValidFor: 825 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(directory, result.CAFile))
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA {
		t.Fatal("generated cluster trust anchor is not a CA")
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(directory, result.CertificateFile), filepath.Join(directory, result.PrivateKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	node, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := node.Verify(x509.VerifyOptions{Roots: roots, DNSName: "dns-1.example.test", KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			t.Fatalf("verify usage %v: %v", usage, err)
		}
	}
	if !node.IPAddresses[0].Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("node IP SANs = %v", node.IPAddresses)
	}
	if info, err := os.Stat(filepath.Join(directory, result.CAPrivateKeyFile)); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("CA private key mode = %v", info.Mode().Perm())
	}
}

func TestGeneratedCertificateDirectoryCannotEscapeConfigurationDirectory(t *testing.T) {
	manager := New(&memoryVault{}, slog.New(slog.NewTextHandler(io.Discard, nil)), t.TempDir())
	for _, directory := range []string{"../outside", "/tmp/outside"} {
		if _, err := manager.GenerateSelfSigned(context.Background(), ManualCertificateOptions{Names: []string{"dns.example.test"}, StorageDirectory: directory}); err == nil {
			t.Fatalf("unsafe directory %q was accepted", directory)
		}
	}
}
