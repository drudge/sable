package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	persistedTrustAnchorFileName = "cluster-trust-anchor.pem"
	enrollmentBundlePrefix       = "sable-enroll-v1."
	maximumTrustAnchorBytes      = 256 << 10
)

type enrollmentBundle struct {
	Token       string `json:"token"`
	TrustAnchor string `json:"trust_anchor"`
}

func encodeEnrollmentBundle(token string, trustAnchor []byte) (string, error) {
	if len(trustAnchor) == 0 {
		return token, nil
	}
	if err := validateClusterTrustAnchor(trustAnchor); err != nil {
		return "", err
	}
	contents, err := json.Marshal(enrollmentBundle{Token: token, TrustAnchor: string(trustAnchor)})
	if err != nil {
		return "", fmt.Errorf("encode enrollment bundle: %w", err)
	}
	return enrollmentBundlePrefix + base64.RawURLEncoding.EncodeToString(contents), nil
}

func decodeEnrollmentBundle(value string) (string, []byte, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, enrollmentBundlePrefix) {
		return value, nil, nil
	}
	contents, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, enrollmentBundlePrefix))
	if err != nil {
		return "", nil, errors.New("enrollment token bundle is malformed")
	}
	var bundle enrollmentBundle
	if err := json.Unmarshal(contents, &bundle); err != nil || strings.TrimSpace(bundle.Token) == "" {
		return "", nil, errors.New("enrollment token bundle is malformed")
	}
	trustAnchor := []byte(bundle.TrustAnchor)
	if err := validateClusterTrustAnchor(trustAnchor); err != nil {
		return "", nil, fmt.Errorf("enrollment token bundle: %w", err)
	}
	return strings.TrimSpace(bundle.Token), trustAnchor, nil
}

func loadClusterTrustAnchor(directory, configuredFile string) (string, []byte, error) {
	configuredFile = strings.TrimSpace(configuredFile)
	file := configuredFile
	if file == "" {
		persisted := filepath.Join(directory, persistedTrustAnchorFileName)
		if _, err := os.Stat(persisted); err == nil {
			file = persisted
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", nil, fmt.Errorf("inspect cluster trust anchor: %w", err)
		}
	}
	if file == "" {
		return "", nil, nil
	}
	contents, err := os.ReadFile(file)
	if err != nil {
		return "", nil, fmt.Errorf("read cluster trust anchor: %w", err)
	}
	if err := validateClusterTrustAnchor(contents); err != nil {
		return "", nil, err
	}
	return file, contents, nil
}

func loadPersistedClusterTrustAnchor(directory string) (string, []byte, error) {
	file := filepath.Join(directory, persistedTrustAnchorFileName)
	contents, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("read persisted cluster trust anchor: %w", err)
	}
	if err := validateClusterTrustAnchor(contents); err != nil {
		return "", nil, err
	}
	return file, contents, nil
}

func readConfiguredTrustAnchor(file string) ([]byte, error) {
	file = strings.TrimSpace(file)
	if file == "" {
		return nil, nil
	}
	contents, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read local cluster trust anchor: %w", err)
	}
	if err := validateClusterTrustAnchor(contents); err != nil {
		return nil, err
	}
	return contents, nil
}

func validateClusterTrustAnchor(contents []byte) error {
	rest := contents
	found := false
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			if len(strings.TrimSpace(string(rest))) != 0 {
				return errors.New("cluster trust anchor contains invalid PEM data")
			}
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse cluster trust anchor: %w", err)
		}
		if !certificate.IsCA {
			return errors.New("cluster trust anchor must contain only CA certificates")
		}
		found = true
	}
	if !found {
		return errors.New("cluster trust anchor does not contain a CA certificate")
	}
	return nil
}

func httpClientWithClusterTrust(base *http.Client, trustAnchor []byte) (*http.Client, error) {
	if base == nil {
		base = &http.Client{Timeout: 15 * time.Second}
	}
	if len(trustAnchor) == 0 {
		return base, nil
	}
	if err := validateClusterTrustAnchor(trustAnchor); err != nil {
		return nil, err
	}
	// Enrollment bundles pin the primary's private cluster CA. Keeping this
	// separate from the platform pool avoids platform-verifier differences and
	// prevents an unrelated publicly trusted certificate from replacing the
	// enrolled cluster identity.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trustAnchor) {
		return nil, errors.New("add cluster trust anchor to certificate pool")
	}

	client := *base
	var transport *http.Transport
	switch configured := base.Transport.(type) {
	case nil:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		transport = configured.Clone()
	default:
		return nil, errors.New("cluster trust requires an HTTP transport with TLS configuration support")
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.RootCAs = pool
	client.Transport = transport
	return &client, nil
}

func (service *Service) httpClientForMember(node member) (*http.Client, error) {
	anchor := []byte(node.TrustAnchor)
	if len(anchor) == 0 {
		// Clusters enrolled before per-member trust was added still have the
		// primary CA pinned in the replica's protected cluster directory.
		// It is also the trust source used during initial enrollment.
		if len(service.trustAnchorPEM) > 0 {
			return service.httpClient, nil
		}
		return service.baseHTTPClient, nil
	}
	key := node.ID + ":" + node.TrustAnchor
	service.clientsMu.Lock()
	defer service.clientsMu.Unlock()
	if client := service.memberClients[key]; client != nil {
		return client, nil
	}
	client, err := httpClientWithClusterTrust(service.baseHTTPClient, anchor)
	if err != nil {
		return nil, fmt.Errorf("prepare trust for cluster node %q: %w", node.Name, err)
	}
	service.memberClients[key] = client
	return client, nil
}

// TLSConfigForNode returns the TLS trust used for an enrolled node's
// advertised HTTPS endpoint. Callers can reuse the cluster's pinned member CA
// for another protocol served by that same endpoint, such as DNS-over-HTTPS.
func (service *Service) TLSConfigForNode(nodeID string) (*tls.Config, error) {
	service.mu.RLock()
	if service.manifest == nil {
		service.mu.RUnlock()
		return nil, ErrNotInitialized
	}
	index := slices.IndexFunc(service.manifest.Nodes, func(node member) bool { return node.ID == nodeID })
	if index < 0 {
		service.mu.RUnlock()
		return nil, errors.New("cluster node is no longer a member")
	}
	node := service.manifest.Nodes[index]
	service.mu.RUnlock()

	client, err := service.httpClientForMember(node)
	if err != nil {
		return nil, err
	}
	switch transport := client.Transport.(type) {
	case nil:
		return nil, nil
	case *http.Transport:
		if transport.TLSClientConfig == nil {
			return nil, nil
		}
		return transport.TLSClientConfig.Clone(), nil
	default:
		return nil, errors.New("cluster HTTP client does not expose a TLS configuration")
	}
}

func writeClusterTrustAnchor(directory string, contents []byte) (string, error) {
	if err := validateClusterTrustAnchor(contents); err != nil {
		return "", err
	}
	path := filepath.Join(directory, persistedTrustAnchorFileName)
	temporary, err := os.CreateTemp(directory, ".cluster-trust-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create cluster trust anchor: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return "", fmt.Errorf("protect cluster trust anchor: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return "", fmt.Errorf("write cluster trust anchor: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", fmt.Errorf("sync cluster trust anchor: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close cluster trust anchor: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return "", fmt.Errorf("commit cluster trust anchor: %w", err)
	}
	return path, nil
}
