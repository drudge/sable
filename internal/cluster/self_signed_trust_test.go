package cluster

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/drudge/sable/internal/certificates"
)

func TestSelfSignedTrustStillVerifiesNamesAndExpiry(t *testing.T) {
	directory := t.TempDir()
	generated, err := certificates.New(nil, slog.Default(), directory).GenerateSelfSigned(context.Background(), certificates.ManualCertificateOptions{
		Names: []string{"127.0.0.1"}, ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := readSelfSignedTrustAnchor(filepath.Join(directory, generated.CertificateFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateClusterTrustAnchor(anchor); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(anchor)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	for _, test := range []struct {
		name  string
		time  time.Time
		valid bool
	}{
		{"127.0.0.1", time.Now(), true},
		{"192.0.2.1", time.Now(), false},
		{"127.0.0.1", certificate.NotAfter.Add(time.Second), false},
	} {
		_, err := certificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: test.name, CurrentTime: test.time})
		if (err == nil) != test.valid {
			t.Fatalf("verify %s at %s: %v", test.name, test.time, err)
		}
	}
}

func TestIssuedLeafIsNotAutomaticallyTrusted(t *testing.T) {
	directory := t.TempDir()
	generated, err := certificates.New(nil, slog.Default(), directory).GenerateClusterPKI(context.Background(), certificates.ClusterPKIOptions{
		NodeName: "primary", Names: []string{"127.0.0.1"}, ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, generated.CertificateFile)
	anchor, err := readSelfSignedTrustAnchor(file)
	if err != nil || len(anchor) != 0 {
		t.Fatalf("issued leaf auto trust: %q, %v", anchor, err)
	}
	contents, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateClusterTrustAnchor(contents); err == nil {
		t.Fatal("accepted an issued leaf as a trust anchor")
	}
}

func TestLocalConfigurationDetectsTrustReplacementAtSamePath(t *testing.T) {
	makeCertificate := func() []byte {
		t.Helper()
		directory := t.TempDir()
		generated, err := certificates.New(nil, slog.Default(), directory).GenerateSelfSigned(context.Background(), certificates.ManualCertificateOptions{Names: []string{"127.0.0.1"}, ValidFor: 24 * time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(filepath.Join(directory, generated.CertificateFile))
		if err != nil {
			t.Fatal(err)
		}
		return contents
	}
	original, replacement := makeCertificate(), makeCertificate()
	for _, explicitAnchor := range []bool{false, true} {
		directory := t.TempDir()
		path := filepath.Join(directory, "trust.pem")
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
		options := Options{DataDirectory: directory, NodeName: "primary", HTTPSCertificateFile: path}
		if explicitAnchor {
			options.TrustAnchorFile = path
		}
		service, err := Open(options)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = service.Close(context.Background()) })
		if service.LocalConfiguration().TrustRestartRequired {
			t.Fatal("unchanged certificate needs restart")
		}
		if err := os.WriteFile(path, replacement, 0600); err != nil {
			t.Fatal(err)
		}
		if !service.LocalConfiguration().TrustRestartRequired {
			t.Fatal("same-path replacement was not detected")
		}
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
		if service.LocalConfiguration().TrustRestartRequired {
			t.Fatal("restored certificate still needs restart")
		}
	}
}
