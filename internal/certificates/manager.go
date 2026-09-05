package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/acme"
	"golang.org/x/net/publicsuffix"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsprovider"
)

type Vault = dnsprovider.Vault

type Credentials = dnsprovider.Credentials

type Status struct {
	Mode                  string
	Provider              string
	CredentialsConfigured bool
	Domains               []string
	Issuer                string
	NotBefore             time.Time
	NotAfter              time.Time
	LastAttempt           time.Time
	LastSuccess           time.Time
	LastError             string
	Renewing              bool
	ProviderEndpoint      string
	TSIGAlgorithm         string

	// The fields below describe the certificate that is actually installed,
	// which is not always the certificate the settings ask for: a name added to
	// the configuration is only covered once a renewal succeeds. Reading them
	// from the leaf rather than from the configuration is what lets the console
	// show that difference instead of hiding it.
	Subject      string
	SerialNumber string
	Fingerprint  string
	CoveredNames []string
}

type Manager struct {
	logger              *slog.Logger
	now                 func() time.Time
	baseDirectory       string
	providerCredentials *dnsprovider.Store

	mu     sync.RWMutex
	status Status
}

func New(vault Vault, logger *slog.Logger, baseDirectory string) *Manager {
	return &Manager{
		logger: logger, now: time.Now, baseDirectory: baseDirectory,
		providerCredentials: dnsprovider.NewStore(vault),
	}
}

func (manager *Manager) Status(ctx context.Context, encrypted config.EncryptedDNS) Status {
	manager.mu.RLock()
	status := manager.status
	manager.mu.RUnlock()
	status.Mode = encrypted.CertificateMode
	status.Provider = encrypted.ACME.DNSProvider
	status.Domains = append([]string(nil), encrypted.ACME.Domains...)
	if encrypted.CertificateMode == "acme" {
		credentials, configured := manager.credentials(ctx, encrypted.ACME.DNSProvider)
		status.CredentialsConfigured = configured
		if configured {
			status.ProviderEndpoint = credentials.Endpoint
			status.TSIGAlgorithm = credentials.TSIGAlgorithm
		}
	}
	return status
}

func (manager *Manager) PutCredentials(ctx context.Context, provider string, credentials Credentials) error {
	return manager.providerCredentials.Put(ctx, provider, credentials)
}

// Ensure obtains or renews the configured certificate. It returns true when
// new certificate files were committed and listeners should be refreshed.
func (manager *Manager) Ensure(ctx context.Context, encrypted config.EncryptedDNS, force bool) (bool, error) {
	if encrypted.CertificateMode != "acme" {
		return false, nil
	}
	manager.mu.Lock()
	if manager.status.Renewing {
		manager.mu.Unlock()
		return false, errors.New("certificate issuance is already in progress")
	}
	manager.status.Renewing = true
	manager.status.LastAttempt = manager.now()
	manager.mu.Unlock()
	defer func() {
		manager.mu.Lock()
		manager.status.Renewing = false
		manager.mu.Unlock()
	}()

	certificatePath, privateKeyPath := certificatePaths(manager.baseDirectory, encrypted.ACME.StorageDirectory)
	if !force {
		current, err := readCertificate(certificatePath)
		if err == nil && certificateMatches(current, encrypted.ACME.Domains) && current.NotAfter.Sub(manager.now()) > encrypted.ACME.RenewBefore.Duration {
			manager.recordCertificate(current, "")
			return false, nil
		}
	}
	credentials, ok := manager.credentials(ctx, encrypted.ACME.DNSProvider)
	if !ok {
		err := fmt.Errorf("%s DNS credentials are not configured", encrypted.ACME.DNSProvider)
		manager.recordError(err)
		return false, err
	}
	provider, err := newDNSProvider(encrypted.ACME.DNSProvider, credentials)
	if err != nil {
		manager.recordError(err)
		return false, err
	}
	certificate, privateKey, leaf, err := manager.issue(ctx, encrypted.ACME, provider, manager.baseDirectory)
	if err != nil {
		manager.recordError(err)
		return false, err
	}
	if err := commitKeyPair(certificatePath, privateKeyPath, certificate, privateKey); err != nil {
		manager.recordError(err)
		return false, err
	}
	manager.recordCertificate(leaf, "")
	manager.logger.Info("public TLS certificate issued", "domains", encrypted.ACME.Domains, "issuer", leaf.Issuer.CommonName, "expires", leaf.NotAfter)
	return true, nil
}

func (manager *Manager) issue(ctx context.Context, configuration config.ACME, provider dnsProvider, baseDirectory string) ([]byte, []byte, *x509.Certificate, error) {
	directory := resolvePath(baseDirectory, configuration.StorageDirectory)
	accountKey, err := loadOrCreateAccountKey(filepath.Join(directory, "account.key"))
	if err != nil {
		return nil, nil, nil, err
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: configuration.DirectoryURL}
	if _, err := client.GetReg(ctx, ""); err != nil {
		if _, registerErr := client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + configuration.Email}}, acme.AcceptTOS); registerErr != nil {
			return nil, nil, nil, fmt.Errorf("register ACME account: %w", registerErr)
		}
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(configuration.Domains...))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create ACME order: %w", err)
	}
	cleanups := make([]func(context.Context) error, 0, len(order.AuthzURLs))
	defer func() {
		for _, cleanup := range cleanups {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if cleanupErr := cleanup(cleanupContext); cleanupErr != nil {
				manager.logger.Warn("remove ACME DNS challenge", "error", cleanupErr)
			}
			cancel()
		}
	}()
	for _, authorizationURL := range order.AuthzURLs {
		authorization, err := client.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("get ACME authorization: %w", err)
		}
		if authorization.Status == acme.StatusValid {
			continue
		}
		challenge := dns01Challenge(authorization)
		if challenge == nil {
			return nil, nil, nil, fmt.Errorf("ACME server did not offer DNS-01 for %s", authorization.Identifier.Value)
		}
		value, err := client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("create DNS-01 value: %w", err)
		}
		zone, err := challengeZone(configuration.DNSZone, authorization.Identifier.Value)
		if err != nil {
			return nil, nil, nil, err
		}
		name := "_acme-challenge." + strings.TrimSuffix(authorization.Identifier.Value, ".")
		cleanup, err := provider.Present(ctx, zone, name, value)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("publish DNS-01 challenge for %s: %w", authorization.Identifier.Value, err)
		}
		cleanups = append(cleanups, cleanup)
		if err := waitForTXT(ctx, name, value); err != nil {
			return nil, nil, nil, err
		}
		if _, err := client.Accept(ctx, challenge); err != nil {
			return nil, nil, nil, fmt.Errorf("accept DNS-01 challenge: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, authorizationURL); err != nil {
			return nil, nil, nil, fmt.Errorf("validate DNS-01 challenge: %w", err)
		}
	}
	ready, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("wait for ACME order: %w", err)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate certificate key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: configuration.Domains[0]}, DNSNames: configuration.Domains}, privateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create certificate request: %w", err)
	}
	chain, _, err := client.CreateOrderCert(ctx, ready.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("finalize ACME order: %w", err)
	}
	certificatePEM := make([]byte, 0, len(chain)*1024)
	for _, der := range chain {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode certificate key: %w", err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse issued certificate: %w", err)
	}
	return certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), leaf, nil
}

func (manager *Manager) credentials(ctx context.Context, provider string) (Credentials, bool) {
	return manager.providerCredentials.Get(ctx, provider)
}

func (manager *Manager) recordCertificate(certificate *x509.Certificate, lastError string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.status.Issuer = certificate.Issuer.CommonName
	manager.status.NotBefore = certificate.NotBefore
	manager.status.NotAfter = certificate.NotAfter
	manager.status.LastError = lastError
	manager.status.LastSuccess = manager.now()
	manager.status.Subject = certificate.Subject.CommonName
	manager.status.SerialNumber = formatSerialNumber(certificate.SerialNumber)
	manager.status.Fingerprint = formatFingerprint(sha256.Sum256(certificate.Raw))
	manager.status.CoveredNames = coveredNames(certificate)
}

// coveredNames lists every identity the leaf actually authenticates. A client
// trusts the connection only when the name it dialed appears here, so this is
// the list worth showing rather than the configured domains.
func coveredNames(certificate *x509.Certificate) []string {
	names := make([]string, 0, len(certificate.DNSNames)+len(certificate.IPAddresses))
	names = append(names, certificate.DNSNames...)
	for _, address := range certificate.IPAddresses {
		names = append(names, address.String())
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// formatSerialNumber renders the serial the way certificate viewers do, as
// colon-separated octets, so it can be compared against openssl output by eye.
func formatSerialNumber(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	octets := serial.Bytes()
	if len(octets) == 0 {
		return "00"
	}
	encoded := make([]string, 0, len(octets))
	for _, octet := range octets {
		encoded = append(encoded, fmt.Sprintf("%02x", octet))
	}
	return strings.Join(encoded, ":")
}

func formatFingerprint(sum [sha256.Size]byte) string {
	encoded := make([]string, 0, len(sum))
	for _, octet := range sum {
		encoded = append(encoded, fmt.Sprintf("%02x", octet))
	}
	return strings.Join(encoded, ":")
}

func (manager *Manager) recordError(err error) {
	manager.mu.Lock()
	manager.status.LastError = err.Error()
	manager.mu.Unlock()
	manager.logger.Error("public TLS certificate operation failed", "error", err)
}

func dns01Challenge(authorization *acme.Authorization) *acme.Challenge {
	for _, challenge := range authorization.Challenges {
		if challenge.Type == "dns-01" {
			return challenge
		}
	}
	return nil
}

func challengeZone(configured, domain string) (string, error) {
	if configured != "" {
		return strings.TrimSuffix(strings.ToLower(configured), "."), nil
	}
	zone, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(domain), "."), "*."))
	if err != nil {
		return "", fmt.Errorf("determine DNS zone for %s: configure the DNS zone explicitly: %w", domain, err)
	}
	return zone, nil
}

func waitForTXT(ctx context.Context, name, expected string) error {
	deadline := time.NewTimer(2 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		for _, resolver := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
			message := new(dns.Msg)
			message.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
			response, _, err := new(dns.Client).ExchangeContext(ctx, message, resolver)
			if err != nil {
				continue
			}
			for _, answer := range response.Answer {
				if record, ok := answer.(*dns.TXT); ok && strings.Join(record.Txt, "") == expected {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("DNS-01 record %s did not propagate within 2 minutes", name)
		case <-ticker.C:
		}
	}
}

func certificatePaths(baseDirectory, storageDirectory string) (string, string) {
	directory := resolvePath(baseDirectory, storageDirectory)
	return filepath.Join(directory, "certificate.pem"), filepath.Join(directory, "private-key.pem")
}

func resolvePath(baseDirectory, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(baseDirectory, path))
}

func readCertificate(path string) (*x509.Certificate, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate file does not contain a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func certificateMatches(certificate *x509.Certificate, domains []string) bool {
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			if !slices.Contains(certificate.DNSNames, domain) {
				return false
			}
			continue
		}
		if certificate.VerifyHostname(domain) != nil {
			return false
		}
	}
	return true
}

func loadOrCreateAccountKey(path string) (*ecdsa.PrivateKey, error) {
	contents, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(contents)
		if block == nil {
			return nil, errors.New("ACME account key is not PEM encoded")
		}
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse ACME account key: %w", parseErr)
		}
		privateKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("ACME account key is not an ECDSA key")
		}
		return privateKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read ACME account key: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ACME account key: %w", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode ACME account key: %w", err)
	}
	if err := writeAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func commitKeyPair(certificatePath, privateKeyPath string, certificate, privateKey []byte) error {
	if err := writeAtomic(privateKeyPath, privateKey, 0o600); err != nil {
		return fmt.Errorf("write certificate private key: %w", err)
	}
	if err := writeAtomic(certificatePath, certificate, 0o600); err != nil {
		return fmt.Errorf("write certificate chain: %w", err)
	}
	return nil
}

func writeAtomic(path string, contents []byte, permissions os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create certificate directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".sable-certificate-*")
	if err != nil {
		return fmt.Errorf("create temporary certificate file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(permissions); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("commit certificate file: %w", err)
	}
	return nil
}
