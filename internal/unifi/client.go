package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	requestTimeout      = 30 * time.Second
	maximumResponseSize = 32 << 20
	userAgent           = "Sable DNS UniFi synchronizer"
)

// ErrUnauthorized reports credentials the controller rejected. The console
// turns this into setup guidance rather than a generic failure.
var ErrUnauthorized = errors.New("unifi controller rejected the supplied credentials")

// Credentials authenticate against a controller. An API key is preferred; the
// local account is a fallback for controllers too old to issue keys.
type Credentials struct {
	APIKey   string `json:"api_key,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// Configured reports whether at least one usable credential is present.
func (credentials Credentials) Configured() bool {
	if strings.TrimSpace(credentials.APIKey) != "" {
		return true
	}
	return strings.TrimSpace(credentials.Username) != "" && strings.TrimSpace(credentials.Password) != ""
}

// Options describe one controller.
type Options struct {
	ControllerURL string
	Site          string
	Credentials   Credentials
	// CAFile pins the controller's certificate authority. UniFi consoles ship
	// a self-signed certificate, so operators either pin it here or accept the
	// risk with InsecureSkipVerify.
	CAFile             string
	InsecureSkipVerify bool
}

// Client reads inventory from a UniFi controller.
type Client struct {
	baseURL     *url.URL
	site        string
	credentials Credentials
	http        *http.Client

	mu           sync.Mutex
	loggedIn     bool
	csrfToken    string
	loginAttempt bool
}

// New builds a client. It fails fast on an unusable controller URL or CA file
// so the setup wizard can report the problem before any network call.
func New(options Options) (*Client, error) {
	raw := strings.TrimSpace(options.ControllerURL)
	if raw == "" {
		return nil, errors.New("controller URL is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("controller URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("controller URL scheme %q must be http or https", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, errors.New("controller URL must include a host")
	}
	parsed = &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}
	if !options.Credentials.Configured() {
		return nil, errors.New("an API key or a local account username and password are required")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.InsecureSkipVerify}
	if path := strings.TrimSpace(options.CAFile); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read controller CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("controller CA file %s contains no certificates", path)
		}
		tlsConfig.RootCAs = pool
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("prepare controller cookie jar: %w", err)
	}
	site := strings.TrimSpace(options.Site)
	if site == "" {
		site = "default"
	}
	return &Client{
		baseURL:     parsed,
		site:        site,
		credentials: options.Credentials,
		http: &http.Client{
			Timeout: requestTimeout,
			Jar:     jar,
			Transport: &http.Transport{
				TLSClientConfig:     tlsConfig,
				MaxIdleConnsPerHost: 4,
			},
		},
	}, nil
}

// Inventory reads the networks, reservations, and active clients in one pass.
func (client *Client) Inventory(ctx context.Context) (Inventory, error) {
	networks, err := client.networks(ctx)
	if err != nil {
		return Inventory{}, err
	}
	reserved, err := client.reservedHosts(ctx)
	if err != nil {
		return Inventory{}, err
	}
	active, err := client.activeHosts(ctx)
	if err != nil {
		return Inventory{}, err
	}
	hosts := placeHosts(networks, mergeHosts(reserved, active))
	return Inventory{Networks: networks, Hosts: hosts}, nil
}

type networkPayload struct {
	ID      string `json:"_id"`
	AltID   string `json:"id"`
	Name    string `json:"name"`
	Purpose string `json:"purpose"`
	Enabled *bool  `json:"enabled"`
	Subnet  string `json:"ip_subnet"`
	Subnet6 string `json:"ipv6_subnet"`
}

func (client *Client) networks(ctx context.Context) ([]Network, error) {
	var payload struct {
		Data []networkPayload `json:"data"`
	}
	if err := client.get(ctx, "rest/networkconf", &payload); err != nil {
		return nil, fmt.Errorf("read UniFi networks: %w", err)
	}
	networks := make([]Network, 0, len(payload.Data))
	for _, entry := range payload.Data {
		id := entry.ID
		if id == "" {
			id = entry.AltID
		}
		if id == "" || entry.Name == "" {
			continue
		}
		if entry.Enabled != nil && !*entry.Enabled {
			continue
		}
		network := Network{ID: id, Name: entry.Name, Slug: SanitizeLabel(entry.Name), Purpose: entry.Purpose}
		for _, candidate := range []string{entry.Subnet, entry.Subnet6} {
			for _, field := range strings.Fields(candidate) {
				prefix, err := netip.ParsePrefix(field)
				if err != nil {
					continue
				}
				network.Subnets = append(network.Subnets, prefix.Masked())
			}
		}
		if !network.Addressable() {
			continue
		}
		networks = append(networks, network)
	}
	return networks, nil
}

type clientPayload struct {
	MAC        string `json:"mac"`
	Name       string `json:"name"`
	Hostname   string `json:"hostname"`
	IP         string `json:"ip"`
	FixedIP    string `json:"fixed_ip"`
	UseFixedIP bool   `json:"use_fixedip"`
	NetworkID  string `json:"network_id"`
	// OverrideNetworkID pins a client to one network wherever it connects, and
	// LastNetworkID is where the controller last saw it. Reservations usually
	// carry one of these instead of network_id, so they stand in when the
	// preferred field is absent.
	OverrideNetworkID      string `json:"virtual_network_override_id"`
	OverrideNetworkEnabled bool   `json:"virtual_network_override_enabled"`
	LastNetworkID          string `json:"last_connection_network_id"`
}

// networkID resolves the network an entry belongs to. The controller fills
// network_id on active clients but usually leaves it empty on reservations,
// which would otherwise strand a device the operator explicitly configured.
func (payload clientPayload) networkID() string {
	if payload.OverrideNetworkEnabled {
		if id := strings.TrimSpace(payload.OverrideNetworkID); id != "" {
			return id
		}
	}
	if id := strings.TrimSpace(payload.NetworkID); id != "" {
		return id
	}
	return strings.TrimSpace(payload.LastNetworkID)
}

func (client *Client) reservedHosts(ctx context.Context) ([]Host, error) {
	var payload struct {
		Data []clientPayload `json:"data"`
	}
	if err := client.get(ctx, "rest/user", &payload); err != nil {
		return nil, fmt.Errorf("read UniFi reservations: %w", err)
	}
	hosts := make([]Host, 0, len(payload.Data))
	for _, entry := range payload.Data {
		if !entry.UseFixedIP {
			continue
		}
		if host, ok := entry.host(entry.FixedIP, true); ok {
			hosts = append(hosts, host)
		}
	}
	return hosts, nil
}

func (client *Client) activeHosts(ctx context.Context) ([]Host, error) {
	var payload struct {
		Data []clientPayload `json:"data"`
	}
	if err := client.get(ctx, "stat/sta", &payload); err != nil {
		return nil, fmt.Errorf("read UniFi clients: %w", err)
	}
	hosts := make([]Host, 0, len(payload.Data))
	for _, entry := range payload.Data {
		address := entry.IP
		if entry.UseFixedIP && entry.FixedIP != "" {
			address = entry.FixedIP
		}
		if host, ok := entry.host(address, entry.UseFixedIP); ok {
			hosts = append(hosts, host)
		}
	}
	return hosts, nil
}

func (payload clientPayload) host(rawAddress string, reserved bool) (Host, bool) {
	address, err := netip.ParseAddr(strings.TrimSpace(rawAddress))
	if err != nil || !address.IsValid() || address.IsUnspecified() {
		return Host{}, false
	}
	name := strings.TrimSpace(payload.Name)
	if name == "" {
		name = strings.TrimSpace(payload.Hostname)
	}
	if SanitizeLabel(name) == "" {
		return Host{}, false
	}
	return Host{
		MAC:       strings.ToLower(strings.TrimSpace(payload.MAC)),
		Hostname:  name,
		Address:   address.Unmap(),
		NetworkID: payload.networkID(),
		Reserved:  reserved,
	}, true
}

// get calls a Network application endpoint, authenticating with the API key
// when one is configured and falling back to a local-account session when the
// controller rejects it.
func (client *Client) get(ctx context.Context, endpoint string, target any) error {
	response, err := client.do(ctx, endpoint)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		drain(response.Body)
		if err := client.login(ctx); err != nil {
			return err
		}
		response, err = client.do(ctx, endpoint)
		if err != nil {
			return err
		}
		defer response.Body.Close()
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return ErrUnauthorized
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("controller returned %s for %s", response.Status, endpoint)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseSize+1))
	if err != nil {
		return fmt.Errorf("read controller response: %w", err)
	}
	if len(body) > maximumResponseSize {
		return fmt.Errorf("controller response for %s exceeds %d MiB", endpoint, maximumResponseSize>>20)
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode controller response for %s: %w", endpoint, err)
	}
	return nil
}

func (client *Client) do(ctx context.Context, endpoint string) (*http.Response, error) {
	target := client.baseURL.JoinPath("proxy", "network", "api", "s", client.site, endpoint)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build controller request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)
	client.mu.Lock()
	if key := strings.TrimSpace(client.credentials.APIKey); key != "" && !client.loggedIn {
		request.Header.Set("X-API-KEY", key)
	}
	if client.csrfToken != "" {
		request.Header.Set("X-CSRF-Token", client.csrfToken)
	}
	client.mu.Unlock()
	response, err := client.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("contact controller: %w", err)
	}
	return response, nil
}

// login establishes a local-account session. It runs at most once per client
// so a genuinely bad password fails instead of looping.
func (client *Client) login(ctx context.Context) error {
	client.mu.Lock()
	if client.loginAttempt {
		client.mu.Unlock()
		return ErrUnauthorized
	}
	client.loginAttempt = true
	username := strings.TrimSpace(client.credentials.Username)
	password := client.credentials.Password
	client.mu.Unlock()

	if username == "" || password == "" {
		return ErrUnauthorized
	}
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		return fmt.Errorf("encode controller login: %w", err)
	}
	target := client.baseURL.JoinPath("api", "auth", "login")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build controller login: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)
	response, err := client.http.Do(request)
	if err != nil {
		return fmt.Errorf("contact controller: %w", err)
	}
	defer response.Body.Close()
	drain(response.Body)
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return ErrUnauthorized
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("controller login returned %s", response.Status)
	}
	client.mu.Lock()
	client.loggedIn = true
	if token := response.Header.Get("X-CSRF-Token"); token != "" {
		client.csrfToken = token
	}
	client.mu.Unlock()
	return nil
}

func drain(body io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 1<<20))
}
