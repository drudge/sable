package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/drudge/sable/internal/dnsname"
)

const (
	defaultManualCertificateDirectory = "data/tls/manual"
	defaultClusterPKIDirectory        = "data/cluster/pki"
	maximumGeneratedCertificateLife   = 10 * 365 * 24 * time.Hour
)

type ManualCertificateOptions struct {
	Names            []string
	StorageDirectory string
	ValidFor         time.Duration
}

type ImportCertificateOptions struct {
	CertificatePEM   []byte
	PrivateKeyPEM    []byte
	StorageDirectory string
}

type ClusterPKIOptions struct {
	NodeName         string
	Names            []string
	StorageDirectory string
	ValidFor         time.Duration
}

type GeneratedCertificate struct {
	CertificateFile  string
	PrivateKeyFile   string
	CAFile           string
	CAPrivateKeyFile string
	NotAfter         time.Time
}

func (manager *Manager) GenerateSelfSigned(_ context.Context, options ManualCertificateOptions) (GeneratedCertificate, error) {
	validFor, err := generatedValidity(options.ValidFor)
	if err != nil {
		return GeneratedCertificate{}, err
	}
	dnsNames, ipAddresses, err := certificateSANs(options.Names)
	if err != nil {
		return GeneratedCertificate{}, err
	}
	if len(dnsNames)+len(ipAddresses) == 0 {
		return GeneratedCertificate{}, errors.New("at least one DNS name or IP address is required")
	}
	certificateFile, privateKeyFile, err := manager.generatedKeyPairPaths(options.StorageDirectory, defaultManualCertificateDirectory, "certificate.pem", "private-key.pem")
	if err != nil {
		return GeneratedCertificate{}, err
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return GeneratedCertificate{}, fmt.Errorf("generate certificate private key: %w", err)
	}
	now := manager.now().UTC()
	serial, err := randomSerial()
	if err != nil {
		return GeneratedCertificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: firstCertificateName(dnsNames, ipAddresses), Organization: []string{"Sable DNS"}},
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: now.Add(validFor),
		DNSNames: dnsNames, IPAddresses: ipAddresses,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return GeneratedCertificate{}, fmt.Errorf("create self-signed certificate: %w", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKeyPEM, err := encodePrivateKey(privateKey)
	if err != nil {
		return GeneratedCertificate{}, err
	}
	if err := commitKeyPair(certificateFile.absolute, privateKeyFile.absolute, certificatePEM, privateKeyPEM); err != nil {
		return GeneratedCertificate{}, err
	}
	manager.logger.Info("self-signed public TLS certificate generated", "names", options.Names, "expires", template.NotAfter)
	return GeneratedCertificate{CertificateFile: certificateFile.configured, PrivateKeyFile: privateKeyFile.configured, NotAfter: template.NotAfter}, nil
}

func (manager *Manager) ImportKeyPair(_ context.Context, options ImportCertificateOptions) (GeneratedCertificate, error) {
	if len(options.CertificatePEM) == 0 || len(options.PrivateKeyPEM) == 0 {
		return GeneratedCertificate{}, errors.New("certificate chain and private key are required")
	}
	pair, err := tls.X509KeyPair(options.CertificatePEM, options.PrivateKeyPEM)
	if err != nil {
		return GeneratedCertificate{}, fmt.Errorf("validate imported key pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return GeneratedCertificate{}, errors.New("imported certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return GeneratedCertificate{}, fmt.Errorf("parse imported certificate: %w", err)
	}
	now := manager.now()
	if now.Before(leaf.NotBefore) {
		return GeneratedCertificate{}, errors.New("imported certificate is not valid yet")
	}
	if !now.Before(leaf.NotAfter) {
		return GeneratedCertificate{}, errors.New("imported certificate has expired")
	}
	certificateFile, privateKeyFile, err := manager.generatedKeyPairPaths(options.StorageDirectory, defaultManualCertificateDirectory, "certificate.pem", "private-key.pem")
	if err != nil {
		return GeneratedCertificate{}, err
	}
	if err := commitKeyPair(certificateFile.absolute, privateKeyFile.absolute, options.CertificatePEM, options.PrivateKeyPEM); err != nil {
		return GeneratedCertificate{}, err
	}
	manager.logger.Info("public TLS certificate imported", "subject", leaf.Subject.String(), "expires", leaf.NotAfter)
	return GeneratedCertificate{CertificateFile: certificateFile.configured, PrivateKeyFile: privateKeyFile.configured, NotAfter: leaf.NotAfter}, nil
}

func (manager *Manager) GenerateClusterPKI(_ context.Context, options ClusterPKIOptions) (GeneratedCertificate, error) {
	validFor, err := generatedValidity(options.ValidFor)
	if err != nil {
		return GeneratedCertificate{}, err
	}
	if strings.TrimSpace(options.NodeName) == "" {
		return GeneratedCertificate{}, errors.New("cluster node name is required")
	}
	dnsNames, ipAddresses, err := certificateSANs(options.Names)
	if err != nil {
		return GeneratedCertificate{}, err
	}
	if len(dnsNames)+len(ipAddresses) == 0 {
		return GeneratedCertificate{}, errors.New("the node certificate requires at least one advertised DNS name or IP address")
	}
	directory, configuredDirectory, err := manager.generatedDirectory(options.StorageDirectory, defaultClusterPKIDirectory)
	if err != nil {
		return GeneratedCertificate{}, err
	}
	caCertificateFile := filepath.Join(directory, "cluster-ca.pem")
	caPrivateKeyFile := filepath.Join(directory, "cluster-ca-private-key.pem")
	nodeCertificateFile := filepath.Join(directory, "node-certificate.pem")
	nodePrivateKeyFile := filepath.Join(directory, "node-private-key.pem")

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return GeneratedCertificate{}, fmt.Errorf("generate cluster CA key: %w", err)
	}
	now := manager.now().UTC()
	caSerial, err := randomSerial()
	if err != nil {
		return GeneratedCertificate{}, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial, Subject: pkix.Name{CommonName: "Sable Cluster CA", Organization: []string{"Sable DNS"}},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(maximumGeneratedCertificateLife),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return GeneratedCertificate{}, fmt.Errorf("create cluster CA: %w", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		return GeneratedCertificate{}, fmt.Errorf("parse generated cluster CA: %w", err)
	}
	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return GeneratedCertificate{}, fmt.Errorf("generate cluster node key: %w", err)
	}
	nodeSerial, err := randomSerial()
	if err != nil {
		return GeneratedCertificate{}, err
	}
	nodeTemplate := &x509.Certificate{
		SerialNumber: nodeSerial, Subject: pkix.Name{CommonName: strings.TrimSpace(options.NodeName), Organization: []string{"Sable DNS Cluster Node"}},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(validFor),
		DNSNames: dnsNames, IPAddresses: ipAddresses,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	nodeDER, err := x509.CreateCertificate(rand.Reader, nodeTemplate, caCertificate, &nodeKey.PublicKey, caKey)
	if err != nil {
		return GeneratedCertificate{}, fmt.Errorf("create cluster node certificate: %w", err)
	}
	caKeyPEM, err := encodePrivateKey(caKey)
	if err != nil {
		return GeneratedCertificate{}, err
	}
	nodeKeyPEM, err := encodePrivateKey(nodeKey)
	if err != nil {
		return GeneratedCertificate{}, err
	}
	if err := writeAtomic(caPrivateKeyFile, caKeyPEM, 0o600); err != nil {
		return GeneratedCertificate{}, fmt.Errorf("write cluster CA private key: %w", err)
	}
	if err := writeAtomic(caCertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		return GeneratedCertificate{}, fmt.Errorf("write cluster CA certificate: %w", err)
	}
	if err := commitKeyPair(nodeCertificateFile, nodePrivateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nodeDER}), nodeKeyPEM); err != nil {
		return GeneratedCertificate{}, err
	}
	manager.logger.Info("private cluster PKI generated", "node", options.NodeName, "names", options.Names, "node_expires", nodeTemplate.NotAfter)
	return GeneratedCertificate{
		CAFile:           filepath.Join(configuredDirectory, "cluster-ca.pem"),
		CAPrivateKeyFile: filepath.Join(configuredDirectory, "cluster-ca-private-key.pem"),
		CertificateFile:  filepath.Join(configuredDirectory, "node-certificate.pem"),
		PrivateKeyFile:   filepath.Join(configuredDirectory, "node-private-key.pem"),
		NotAfter:         nodeTemplate.NotAfter,
	}, nil
}

type generatedPath struct {
	absolute   string
	configured string
}

func (manager *Manager) generatedKeyPairPaths(value, fallback, certificateName, keyName string) (generatedPath, generatedPath, error) {
	directory, configured, err := manager.generatedDirectory(value, fallback)
	if err != nil {
		return generatedPath{}, generatedPath{}, err
	}
	return generatedPath{absolute: filepath.Join(directory, certificateName), configured: filepath.Join(configured, certificateName)},
		generatedPath{absolute: filepath.Join(directory, keyName), configured: filepath.Join(configured, keyName)}, nil
}

func (manager *Manager) generatedDirectory(value, fallback string) (string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	if filepath.IsAbs(value) {
		return "", "", errors.New("generated certificate storage must be relative to sable.toml")
	}
	cleaned := filepath.Clean(value)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", "", errors.New("generated certificate storage must stay inside the Sable configuration directory")
	}
	return filepath.Join(manager.baseDirectory, cleaned), cleaned, nil
}

func generatedValidity(value time.Duration) (time.Duration, error) {
	if value == 0 {
		value = 365 * 24 * time.Hour
	}
	if value < 24*time.Hour || value > maximumGeneratedCertificateLife {
		return 0, errors.New("certificate validity must be between 1 and 3650 days")
	}
	return value, nil
}

func certificateSANs(values []string) ([]string, []net.IP, error) {
	dnsNames := make([]string, 0, len(values))
	ipAddresses := make([]net.IP, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if address := net.ParseIP(strings.Trim(value, "[]")); address != nil {
			key := "ip:" + address.String()
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				ipAddresses = append(ipAddresses, address)
			}
			continue
		}
		wildcard := strings.HasPrefix(value, "*.")
		name, err := dnsname.Normalize(strings.TrimPrefix(value, "*."))
		if err != nil {
			return nil, nil, fmt.Errorf("invalid certificate name %q: %w", value, err)
		}
		if wildcard {
			name = "*." + name
		}
		key := "dns:" + name
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			dnsNames = append(dnsNames, name)
		}
	}
	return dnsNames, ipAddresses, nil
}

func firstCertificateName(dnsNames []string, ipAddresses []net.IP) string {
	if len(dnsNames) > 0 {
		return dnsNames[0]
	}
	return ipAddresses[0].String()
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial number: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func encodePrivateKey(key any) ([]byte, error) {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}
