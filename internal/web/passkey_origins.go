package web

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/drudge/sable/internal/auth"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Derive a stable scope before the first enrollment, even on a standalone node.
// A later cluster join, promotion, or membership change must not change the
// RP ID already stored inside the authenticator. The PSL includes private
// suffixes, so independent tenants of services like github.io stay separate.
func defaultPasskeyRPID(hostname string) (string, error) {
	hostname, err := idna.Lookup.ToASCII(strings.ToLower(hostname))
	if err != nil || hostname == "" {
		return "", errors.New("invalid Sable hostname")
	}
	if net.ParseIP(hostname) != nil {
		return "", errors.New("use a DNS hostname for passkeys")
	}
	if hostname == "localhost" {
		return hostname, nil
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		return "", errors.New("passkeys require a hostname beneath a registrable domain")
	}
	return domain, nil
}

// Use existing HTTPS identities, rather than a second passkey-specific list.
// Wildcard certificate names establish TLS coverage, not authorization for
// every sibling website, so only explicit DNS names become trusted origins.
func (server *Server) passkeyTrustedOrigins(ctx context.Context) []string {
	origins := map[string]struct{}{}
	addHost := func(hostname, port string) {
		hostname = strings.TrimSuffix(strings.TrimSpace(hostname), ".")
		if strings.Contains(hostname, "*") {
			return
		}
		hostname, err := idna.Lookup.ToASCII(strings.ToLower(hostname))
		if err != nil {
			return
		}
		if _, err := defaultPasskeyRPID(hostname); err != nil {
			return
		}
		if port != "" && port != "443" {
			number, err := strconv.Atoi(port)
			if err != nil || number < 1 || number > 65535 {
				return
			}
			origins["https://"+net.JoinHostPort(hostname, port)] = struct{}{}
		} else {
			origins["https://"+hostname] = struct{}{}
		}
	}
	addURL := func(raw string) {
		address, err := url.Parse(raw)
		if err != nil || address.Scheme != "https" || address.Hostname() == "" || address.User != nil || (address.Path != "" && address.Path != "/") || address.RawQuery != "" || address.Fragment != "" {
			return
		}
		addHost(address.Hostname(), address.Port())
		addHost(address.Hostname(), "443")
	}
	if server.cluster != nil {
		state := server.cluster.Snapshot()
		if state.Initialized {
			for _, node := range state.Nodes {
				addURL(node.AdvertiseURL)
			}
		}
	}
	if server.config != nil {
		configuration := server.config.Current().Config
		addURL(configuration.Cluster.AdvertiseURL)
		if configuration.Server.HTTPSListen != "" {
			host, port, err := net.SplitHostPort(configuration.Server.HTTPSListen)
			if err == nil {
				addHost(host, port)
				names := configuration.EncryptedDNS.ACME.Domains
				if configuration.EncryptedDNS.CertificateMode != "acme" {
					names = nil
					if server.certificates != nil {
						names = server.certificates.Status(ctx, configuration.EncryptedDNS).CoveredNames
					}
				}
				for _, name := range names {
					addHost(name, port)
					addHost(name, "443")
				}
			}
		}
	}
	result := make([]string, 0, len(origins))
	for origin := range origins {
		result = append(result, origin)
	}
	slices.Sort(result)
	return result
}

// Plain HTTP deployments behind a proxy may have no configured HTTPS names.
// In that case retain the exact, verified enrollment origin as the fallback.
// Once HTTPS identities exist, the current configuration is authoritative.
func (server *Server) passkeyCredentialOriginAllowed(ctx context.Context, key auth.Passkey, origin string) bool {
	if origins := server.passkeyTrustedOrigins(ctx); len(origins) > 0 {
		address, err := url.Parse(origin)
		if err != nil {
			return false
		}
		domain, err := defaultPasskeyRPID(address.Hostname())
		return err == nil && domain == key.RPID && slices.Contains(origins, origin)
	}
	var registration struct {
		Origin string `json:"origin"`
	}
	if err := json.Unmarshal(key.Credential.Attestation.ClientDataJSON, &registration); err != nil {
		return false
	}
	return registration.Origin == origin
}
