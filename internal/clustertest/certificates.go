package clustertest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/drudge/sable/internal/certificates"
)

// GeneratePrimaryCertificate generates cluster PKI for a node named primary.
func GeneratePrimaryCertificate(t *testing.T, directory string) certificates.GeneratedCertificate {
	return GenerateClusterCertificate(t, directory, "primary")
}

// GenerateClusterCertificate generates cluster PKI for the named node.
func GenerateClusterCertificate(t *testing.T, directory, nodeName string) certificates.GeneratedCertificate {
	t.Helper()
	generated, err := certificates.New(nil, Logger(io.Discard), directory).GenerateClusterPKI(
		context.Background(),
		certificates.ClusterPKIOptions{
			NodeName: nodeName, Names: []string{"127.0.0.1"},
			StorageDirectory: "data/cluster/pki", ValidFor: certificateLife,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return generated
}

// GenerateReplicaCertificate generates a self-signed certificate for 127.0.0.1 and ::1.
func GenerateReplicaCertificate(t *testing.T, directory string) certificates.GeneratedCertificate {
	t.Helper()
	generated, err := certificates.New(nil, Logger(io.Discard), directory).GenerateSelfSigned(
		context.Background(),
		certificates.ManualCertificateOptions{
			Names: []string{"127.0.0.1", "::1"}, StorageDirectory: "data/tls/self-signed", ValidFor: certificateLife,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return generated
}

// TrustedHTTPClient returns an HTTPS client that trusts only the PEM certificate at certificatePath.
func TrustedHTTPClient(t *testing.T, certificatePath string) *http.Client {
	t.Helper()
	certificate, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatalf("load trusted certificate %s", certificatePath)
	}
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots,
		}},
	}
}
