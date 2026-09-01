package config

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/pelletier/go-toml/v2"

	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/durationfmt"
	"github.com/drudge/sable/internal/unifi"
)

const (
	defaultHTTPListen          = "127.0.0.1:5380"
	defaultDNSListen           = "127.0.0.1:8053"
	defaultDatabaseDriver      = "sqlite"
	defaultDatabaseDSN         = "data/sable.db"
	defaultResolverTimeout     = 2 * time.Second
	defaultResolverRetries     = 2
	defaultResolverRetryWait   = 1500 * time.Millisecond
	defaultShutdownTimeout     = 15 * time.Second
	defaultReloadDebounce      = 250 * time.Millisecond
	defaultCacheSize           = 65_536
	defaultCacheMinimumTTL     = 10
	defaultCacheMaximumTTL     = 7 * 24 * 60 * 60
	defaultCacheNegativeTTL    = 300
	defaultCacheFailureTTL     = 10
	defaultCacheStaleTTL       = 3 * 24 * 60 * 60
	defaultCacheStaleAnswerTTL = 30
	defaultCacheStaleResetTTL  = 30
	defaultCacheStaleMaxWait   = 1800 * time.Millisecond
	defaultCachePrefetchMinTTL = 2
	defaultCachePrefetchAtTTL  = 9
	defaultCachePrefetchSample = 5 * time.Minute
	defaultCachePrefetchHits   = 30
	defaultQueryLogBuffer      = 8_192
	defaultQueryLogBatch       = 256
	defaultQueryLogFlush       = 250 * time.Millisecond
	defaultQueryLogKeep        = 30 * 24 * time.Hour
	defaultServerLogBuffer     = 4_096
	defaultServerLogBatch      = 128
	defaultServerLogFlush      = time.Second
	defaultServerLogKeep       = 60 * 24 * time.Hour
	defaultServerLogLevel      = "info"
	defaultStatisticsKeep      = durationfmt.Year
	defaultBackupDirectory     = "data/backups"
	defaultBackupInterval      = 24 * time.Hour
	defaultBackupRunAt         = "02:00"
	defaultBackupRetention     = 7
	defaultTLSVersion          = "1.3"
	defaultCertificateMode     = "manual"
	defaultACMEDirectoryURL    = "https://acme-v02.api.letsencrypt.org/directory"
	defaultACMEStorageDir      = "data/tls/acme"
	defaultACMERenewBefore     = 30 * 24 * time.Hour
	defaultHostTTL             = 300
	defaultUniFiSite           = "default"
	defaultUniFiInterval       = 2 * time.Minute
	minimumUniFiInterval       = 30 * time.Second
	defaultUniFiRecordTTL      = 300
	defaultBlockListUpdate     = 24 * time.Hour
	defaultBlockingTTL         = 30
	defaultSessionTTL          = 12 * time.Hour
	defaultAPITokenTTL         = 90 * 24 * time.Hour
	defaultSecretKeyFile       = "data/sable.key"
	defaultClusterDataDir      = "data/cluster"
	defaultZSKLifetime         = 30 * 24 * time.Hour
	defaultKSKLifetime         = 365 * 24 * time.Hour
	defaultKeyPrepublish       = 24 * time.Hour
	defaultKeyRetireAfter      = 7 * 24 * time.Hour
)

type Duration struct {
	time.Duration
}

func (duration *Duration) UnmarshalText(value []byte) error {
	parsed, err := durationfmt.Parse(string(value))
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", value, err)
	}
	duration.Duration = parsed
	return nil
}

func (duration Duration) MarshalText() ([]byte, error) {
	return []byte(duration.String()), nil
}

func (duration Duration) String() string {
	return durationfmt.Format(duration.Duration)
}

type Config struct {
	Server       Server       `toml:"server"`
	Database     Database     `toml:"database"`
	Resolver     Resolver     `toml:"resolver"`
	TSIGKeys     []TSIGKey    `toml:"tsig_keys"`
	Blocking     Blocking     `toml:"blocking"`
	QueryLog     QueryLog     `toml:"query_log"`
	ServerLog    ServerLog    `toml:"server_log"`
	Statistics   Statistics   `toml:"statistics"`
	Backup       Backup       `toml:"backup"`
	EncryptedDNS EncryptedDNS `toml:"encrypted_dns"`
	UniFi        UniFi        `toml:"unifi"`
	OIDC         OIDC         `toml:"oidc"`
	Security     Security     `toml:"security"`
	Cluster      Cluster      `toml:"cluster"`
	Updates      Updates      `toml:"updates"`
	Reload       Reload       `toml:"config"`
}

// Updates holds how the console looks for new Sable releases.
type Updates struct {
	// PreRelease includes release candidates when resolving the newest
	// release. The console writes the operator's choice here so it survives a
	// restart, which matters because a server tracking release candidates
	// finds nothing at all on a stable-only check.
	PreRelease bool `toml:"pre_release"`
}

// TSIGKey names a shared secret used to authenticate NOTIFY, AXFR, IXFR, and
// dynamic updates. Only the name and algorithm belong in TOML: the secret
// itself lives in the encrypted vault alongside DNSSEC and ACME material, so
// the configuration file, its backups, and cluster replicas never hold it in
// the clear. Secret stays readable from TOML so an older configuration still
// loads, and the first boot after an upgrade moves it into the vault.
type TSIGKey struct {
	Name      string `toml:"name" json:"name"`
	Algorithm string `toml:"algorithm" json:"algorithm"`
	Secret    string `toml:"secret,omitempty" json:"-"`
}

type Server struct {
	HTTPListen      string   `toml:"http_listen"`
	HTTPSListen     string   `toml:"https_listen"`
	DNSListen       []string `toml:"dns_listen"`
	ShutdownTimeout Duration `toml:"shutdown_timeout"`
}

type Database struct {
	Driver string `toml:"driver"`
	DSN    string `toml:"dsn"`
}

type Resolver struct {
	Mode                       string         `toml:"mode"`
	Forwarders                 []string       `toml:"forwarders"`
	RootHints                  []string       `toml:"root_hints"`
	Routes                     []ForwardRoute `toml:"routes"`
	Hosts                      []HostOverride `toml:"hosts"`
	Timeout                    Duration       `toml:"timeout"`
	Retries                    int            `toml:"retries"`
	RetryTimeout               Duration       `toml:"retry_timeout"`
	CacheSize                  int            `toml:"cache_size"`
	CacheMinimumTTL            uint32         `toml:"cache_minimum_ttl"`
	CacheMaximumTTL            uint32         `toml:"cache_maximum_ttl"`
	CacheNegativeTTL           uint32         `toml:"cache_negative_ttl"`
	CacheFailureTTL            uint32         `toml:"cache_failure_ttl"`
	SaveCache                  bool           `toml:"save_cache"`
	ServeStale                 bool           `toml:"serve_stale"`
	CacheStaleTTL              uint32         `toml:"cache_stale_ttl"`
	CacheStaleAnswerTTL        uint32         `toml:"cache_stale_answer_ttl"`
	CacheStaleResetTTL         uint32         `toml:"cache_stale_reset_ttl"`
	CacheStaleMaxWait          Duration       `toml:"cache_stale_max_wait"`
	CachePrefetchMinimumTTL    uint32         `toml:"cache_prefetch_minimum_ttl"`
	CachePrefetchTriggerTTL    uint32         `toml:"cache_prefetch_trigger_ttl"`
	CachePrefetchSample        Duration       `toml:"cache_prefetch_sample_interval"`
	CachePrefetchHitsPerHour   uint32         `toml:"cache_prefetch_hits_per_hour"`
	DNSSECValidation           bool           `toml:"dnssec_validation"`
	DNSSECTrustAnchorUpdates   bool           `toml:"dnssec_trust_anchor_updates"`
	DNSSECTrustAnchors         []string       `toml:"dnssec_trust_anchors"`
	DNSSECNegativeTrustAnchors []string       `toml:"dnssec_negative_trust_anchors"`
}

type ForwardRoute struct {
	Domain     string   `toml:"domain"`
	Forwarders []string `toml:"forwarders"`
}

type HostOverride struct {
	Name      string   `toml:"name"`
	Addresses []string `toml:"addresses"`
	TTL       uint32   `toml:"ttl"`
}

type Blocking struct {
	Enabled         bool        `toml:"enabled"`
	Domains         []string    `toml:"domains"`
	AllowedDomains  []string    `toml:"allowed_domains"`
	Lists           []BlockList `toml:"lists"`
	UpdateInterval  Duration    `toml:"update_interval"`
	ResponseType    string      `toml:"response_type"`
	ResponseTTL     uint32      `toml:"response_ttl"`
	CustomAddresses []string    `toml:"custom_addresses"`
	BypassClients   []string    `toml:"bypass_clients"`
	AllowTXTReport  bool        `toml:"allow_txt_report"`
}

type BlockList struct {
	Name   string `toml:"name"`
	Path   string `toml:"path"`
	URL    string `toml:"url"`
	Format string `toml:"format"`
}

type QueryLog struct {
	Enabled       bool     `toml:"enabled"`
	BufferSize    int      `toml:"buffer_size"`
	BatchSize     int      `toml:"batch_size"`
	FlushInterval Duration `toml:"flush_interval"`
	Retention     Duration `toml:"retention"`
}

// ServerLog controls whether the runtime log survives a restart. Without it the
// console only shows what this process logged since it started, so an upgrade
// or a crash loop erases the record of what led to it. Volume is far below the
// query log, which is why the retention default is much longer.
type ServerLog struct {
	Enabled       bool     `toml:"enabled"`
	Level         string   `toml:"level"`
	BufferSize    int      `toml:"buffer_size"`
	BatchSize     int      `toml:"batch_size"`
	FlushInterval Duration `toml:"flush_interval"`
	Retention     Duration `toml:"retention"`
}

// Statistics controls how long the minute buckets behind dashboard history
// remain available. Lifetime counters are stored separately and never fall
// when old chart buckets are pruned.
type Statistics struct {
	Retention Duration `toml:"retention"`
}

// Backup controls encrypted archives created on the node itself. The
// passphrase deliberately does not live here; it is held in the encrypted
// secret vault so sable.toml is never enough to open an archive.
type Backup struct {
	Enabled        bool     `toml:"enabled"`
	Directory      string   `toml:"directory"`
	Interval       Duration `toml:"interval"`
	RunAt          string   `toml:"run_at"`
	RetentionCount int      `toml:"retention_count"`
}

type EncryptedDNS struct {
	DoTListen       []string `toml:"dot_listen"`
	DoHListen       []string `toml:"doh_listen"`
	DoQListen       []string `toml:"doq_listen"`
	CertificateMode string   `toml:"certificate_mode"`
	CertificateFile string   `toml:"certificate_file"`
	PrivateKeyFile  string   `toml:"private_key_file"`
	MinimumVersion  string   `toml:"minimum_tls_version"`
	ACME            ACME     `toml:"acme"`
}

// ACME contains public certificate policy. Provider credentials are encrypted
// in the secret vault and are deliberately never serialized to TOML.
type ACME struct {
	Email            string   `toml:"email"`
	Domains          []string `toml:"domains"`
	DirectoryURL     string   `toml:"directory_url"`
	DNSProvider      string   `toml:"dns_provider"`
	DNSZone          string   `toml:"dns_zone"`
	StorageDirectory string   `toml:"storage_dir"`
	RenewBefore      Duration `toml:"renew_before"`
}

// UniFi configures the host synchronizer that publishes UniFi networks,
// reservations, and connected clients as authoritative records. Controller
// credentials are encrypted in the secret vault and are deliberately never
// serialized to TOML.
type UniFi struct {
	Enabled       bool           `toml:"enabled"`
	ControllerURL string         `toml:"controller_url"`
	Site          string         `toml:"site"`
	Interval      Duration       `toml:"interval"`
	Sources       []string       `toml:"sources"`
	CAFile        string         `toml:"tls_ca_file"`
	Insecure      bool           `toml:"tls_insecure"`
	Networks      []UniFiNetwork `toml:"networks"`
}

// UniFiNetwork maps one UniFi network onto a Sable zone. The identifier is the
// controller's own network id, which survives renames; the name is cached for
// display and for the {{network}} placeholder.
type UniFiNetwork struct {
	ID               string `toml:"id"`
	Name             string `toml:"name"`
	Zone             string `toml:"zone"`
	HostnameTemplate string `toml:"hostname_template"`
	TTL              uint32 `toml:"ttl"`
	Reverse          bool   `toml:"reverse"`
	Enabled          bool   `toml:"enabled"`
}

// DisplayName names the mapping in logs and console messages, falling back to
// the controller identifier when the cached name is missing.
func (network UniFiNetwork) DisplayName() string {
	if network.Name != "" {
		return network.Name
	}
	return network.ID
}

// SyncsReservations reports whether configured fixed-IP reservations are
// published.
func (unifi UniFi) SyncsReservations() bool { return slices.Contains(unifi.Sources, "reservations") }

// SyncsActiveClients reports whether currently connected clients are published.
func (unifi UniFi) SyncsActiveClients() bool { return slices.Contains(unifi.Sources, "active") }

// ActiveNetworks returns the mappings that are switched on.
func (unifi UniFi) ActiveNetworks() []UniFiNetwork {
	networks := make([]UniFiNetwork, 0, len(unifi.Networks))
	for _, network := range unifi.Networks {
		if network.Enabled {
			networks = append(networks, network)
		}
	}
	return networks
}

// Runnable reports whether the synchronizer has enough configuration to do
// anything at all.
func (unifi UniFi) Runnable() bool {
	return unifi.Enabled && unifi.ControllerURL != "" && len(unifi.ActiveNetworks()) > 0
}

type Security struct {
	Enabled       bool     `toml:"enabled"`
	SecureCookies bool     `toml:"secure_cookies"`
	SessionTTL    Duration `toml:"session_ttl"`
	APITokenTTL   Duration `toml:"api_token_ttl"`
	SecretKeyFile string   `toml:"secret_key_file"`
}

// Cluster contains node-local identity settings. Membership and synchronized
// state are stored in the cluster data directory, not in TOML.
type Cluster struct {
	DataDirectory   string `toml:"data_dir"`
	NodeName        string `toml:"node_name"`
	AdvertiseURL    string `toml:"advertise_url"`
	TrustAnchorFile string `toml:"trust_anchor_file"`
}

type Reload struct {
	Watch    bool     `toml:"watch"`
	Debounce Duration `toml:"debounce"`
}

func Defaults() Config {
	return Config{
		Server: Server{
			HTTPListen:      defaultHTTPListen,
			DNSListen:       []string{defaultDNSListen},
			ShutdownTimeout: Duration{Duration: defaultShutdownTimeout},
		},
		Database: Database{
			Driver: defaultDatabaseDriver,
			DSN:    defaultDatabaseDSN,
		},
		Resolver: Resolver{
			Mode:                     "forward",
			Forwarders:               []string{"1.1.1.1:53", "9.9.9.9:53"},
			Timeout:                  Duration{Duration: defaultResolverTimeout},
			Retries:                  defaultResolverRetries,
			RetryTimeout:             Duration{Duration: defaultResolverRetryWait},
			CacheSize:                defaultCacheSize,
			CacheMinimumTTL:          defaultCacheMinimumTTL,
			CacheMaximumTTL:          defaultCacheMaximumTTL,
			CacheNegativeTTL:         defaultCacheNegativeTTL,
			CacheFailureTTL:          defaultCacheFailureTTL,
			CacheStaleTTL:            defaultCacheStaleTTL,
			CacheStaleAnswerTTL:      defaultCacheStaleAnswerTTL,
			CacheStaleResetTTL:       defaultCacheStaleResetTTL,
			CacheStaleMaxWait:        Duration{Duration: defaultCacheStaleMaxWait},
			CachePrefetchMinimumTTL:  defaultCachePrefetchMinTTL,
			CachePrefetchTriggerTTL:  defaultCachePrefetchAtTTL,
			CachePrefetchSample:      Duration{Duration: defaultCachePrefetchSample},
			CachePrefetchHitsPerHour: defaultCachePrefetchHits,
			DNSSECValidation:         true,
			DNSSECTrustAnchorUpdates: true,
		},
		Blocking: Blocking{
			Enabled: true, UpdateInterval: Duration{Duration: defaultBlockListUpdate},
			ResponseType: "nxdomain", ResponseTTL: defaultBlockingTTL, AllowTXTReport: true,
		},
		QueryLog: QueryLog{
			Enabled:       true,
			BufferSize:    defaultQueryLogBuffer,
			BatchSize:     defaultQueryLogBatch,
			FlushInterval: Duration{Duration: defaultQueryLogFlush},
			Retention:     Duration{Duration: defaultQueryLogKeep},
		},
		ServerLog: ServerLog{
			Enabled:       true,
			Level:         defaultServerLogLevel,
			BufferSize:    defaultServerLogBuffer,
			BatchSize:     defaultServerLogBatch,
			FlushInterval: Duration{Duration: defaultServerLogFlush},
			Retention:     Duration{Duration: defaultServerLogKeep},
		},
		Statistics: Statistics{Retention: Duration{Duration: defaultStatisticsKeep}},
		Backup: Backup{
			Directory:      defaultBackupDirectory,
			Interval:       Duration{Duration: defaultBackupInterval},
			RunAt:          defaultBackupRunAt,
			RetentionCount: defaultBackupRetention,
		},
		EncryptedDNS: EncryptedDNS{
			MinimumVersion:  defaultTLSVersion,
			CertificateMode: defaultCertificateMode,
			ACME: ACME{
				DirectoryURL: defaultACMEDirectoryURL, StorageDirectory: defaultACMEStorageDir,
				RenewBefore: Duration{Duration: defaultACMERenewBefore},
			},
		},
		UniFi: UniFi{
			Site:     defaultUniFiSite,
			Interval: Duration{Duration: defaultUniFiInterval},
			Sources:  []string{"reservations", "active"},
		},
		OIDC: DefaultOIDC(),
		Security: Security{
			Enabled:       true,
			SessionTTL:    Duration{Duration: defaultSessionTTL},
			APITokenTTL:   Duration{Duration: defaultAPITokenTTL},
			SecretKeyFile: defaultSecretKeyFile,
		},
		Cluster: Cluster{DataDirectory: defaultClusterDataDir},
		Reload: Reload{
			Watch:    true,
			Debounce: Duration{Duration: defaultReloadDebounce},
		},
	}
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()

	loaded, err := Decode(file)
	if err != nil {
		return Config{}, fmt.Errorf("load %s: %w", path, err)
	}
	return loaded, nil
}

func Decode(reader io.Reader) (Config, error) {
	loaded := Defaults()
	decoder := toml.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&loaded); err != nil {
		return Config{}, fmt.Errorf("decode TOML: %w", err)
	}
	loaded.normalize()
	if err := loaded.Validate(); err != nil {
		return Config{}, err
	}
	return loaded, nil
}

func (configuration Config) Validate() error {
	var validationErrors []error
	validationErrors = append(validationErrors, validateAddress("server.http_listen", configuration.Server.HTTPListen))
	if configuration.Server.HTTPSListen != "" {
		validationErrors = append(validationErrors, validateAddress("server.https_listen", configuration.Server.HTTPSListen))
	}
	for index, address := range configuration.Server.DNSListen {
		validationErrors = append(validationErrors, validateAddress(fmt.Sprintf("server.dns_listen[%d]", index), address))
	}
	for index, address := range configuration.Resolver.Forwarders {
		validationErrors = append(validationErrors, validateAddress(fmt.Sprintf("resolver.forwarders[%d]", index), address))
	}
	for index, address := range configuration.Resolver.RootHints {
		validationErrors = append(validationErrors, validateRootHint(fmt.Sprintf("resolver.root_hints[%d]", index), address))
	}
	for index, anchor := range configuration.Resolver.DNSSECTrustAnchors {
		if _, err := parseDNSSECTrustAnchor(anchor); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("resolver.dnssec_trust_anchors[%d]: %w", index, err))
		}
	}
	for index, anchor := range configuration.Resolver.DNSSECNegativeTrustAnchors {
		if anchor == "." {
			continue
		}
		if _, err := dnsname.Normalize(anchor); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("resolver.dnssec_negative_trust_anchors[%d]: %w", index, err))
		}
	}
	tsigKeys := make(map[string]struct{}, len(configuration.TSIGKeys))
	for index, key := range configuration.TSIGKeys {
		field := fmt.Sprintf("tsig_keys[%d]", index)
		if key.Name == "" || key.Name == "." {
			validationErrors = append(validationErrors, fmt.Errorf("%s.name is required", field))
		}
		if _, duplicate := tsigKeys[key.Name]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("duplicate TSIG key %q", key.Name))
		}
		tsigKeys[key.Name] = struct{}{}
		if key.Algorithm != dns.HmacSHA256 && key.Algorithm != dns.HmacSHA384 && key.Algorithm != dns.HmacSHA512 {
			validationErrors = append(validationErrors, fmt.Errorf("%s.algorithm must be hmac-sha256, hmac-sha384, or hmac-sha512", field))
		}
		// A blank secret is not an error here: the key has been migrated to
		// the vault, and the runtime fails loudly if the vault cannot produce
		// it. Only a secret still written in TOML is checked.
		if key.Secret != "" {
			if err := ValidateTSIGSecret(key.Secret); err != nil {
				validationErrors = append(validationErrors, fmt.Errorf("%s.secret: %w", field, err))
			}
		}
	}
	seenRouteDomains := make(map[string]struct{}, len(configuration.Resolver.Routes))
	for index, route := range configuration.Resolver.Routes {
		field := fmt.Sprintf("resolver.routes[%d]", index)
		if route.Domain == "" {
			validationErrors = append(validationErrors, fmt.Errorf("%s.domain is required", field))
		}
		if _, err := dnsname.Normalize(route.Domain); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("%s.domain: %w", field, err))
		}
		if len(route.Forwarders) == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("%s.forwarders must contain at least one address", field))
		}
		if _, duplicate := seenRouteDomains[route.Domain]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("duplicate conditional forwarding domain %q", route.Domain))
		}
		seenRouteDomains[route.Domain] = struct{}{}
		for forwarderIndex, address := range route.Forwarders {
			validationErrors = append(validationErrors, validateAddress(
				fmt.Sprintf("%s.forwarders[%d]", field, forwarderIndex),
				address,
			))
		}
	}
	seenHostNames := make(map[string]struct{}, len(configuration.Resolver.Hosts))
	for index, host := range configuration.Resolver.Hosts {
		field := fmt.Sprintf("resolver.hosts[%d]", index)
		if host.Name == "" {
			validationErrors = append(validationErrors, fmt.Errorf("%s.name is required", field))
		}
		if _, err := dnsname.Normalize(host.Name); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("%s.name: %w", field, err))
		}
		if _, duplicate := seenHostNames[host.Name]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("duplicate local host override %q", host.Name))
		}
		seenHostNames[host.Name] = struct{}{}
		if len(host.Addresses) == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("%s.addresses must contain at least one IP address", field))
		}
		for addressIndex, address := range host.Addresses {
			parsed, err := netip.ParseAddr(address)
			if err != nil {
				validationErrors = append(validationErrors, fmt.Errorf("%s.addresses[%d] must be an IP address: %w", field, addressIndex, err))
			} else if parsed.Zone() != "" {
				validationErrors = append(validationErrors, fmt.Errorf("%s.addresses[%d] must not contain an IPv6 zone", field, addressIndex))
			}
		}
		if host.TTL == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("%s.ttl must be positive", field))
		}
	}
	if len(configuration.Server.DNSListen) == 0 {
		validationErrors = append(validationErrors, errors.New("server.dns_listen must contain at least one address"))
	}
	if configuration.Resolver.Mode != "forward" && configuration.Resolver.Mode != "recursive" {
		validationErrors = append(validationErrors, errors.New("resolver.mode must be forward or recursive"))
	}
	if configuration.Resolver.Mode == "forward" && len(configuration.Resolver.Forwarders) == 0 {
		validationErrors = append(validationErrors, errors.New("resolver.forwarders must contain at least one address in forward mode"))
	}
	if configuration.Resolver.Timeout.Duration <= 0 {
		validationErrors = append(validationErrors, errors.New("resolver.timeout must be positive"))
	}
	if configuration.Resolver.Retries < 1 || configuration.Resolver.Retries > 10 {
		validationErrors = append(validationErrors, errors.New("resolver.retries must be between 1 and 10"))
	}
	if configuration.Resolver.RetryTimeout.Duration <= 0 {
		validationErrors = append(validationErrors, errors.New("resolver.retry_timeout must be positive"))
	}
	if configuration.Resolver.CacheSize <= 0 {
		validationErrors = append(validationErrors, errors.New("resolver.cache_size must be positive"))
	}
	if configuration.Resolver.CacheMaximumTTL == 0 {
		validationErrors = append(validationErrors, errors.New("resolver.cache_maximum_ttl must be positive"))
	}
	if configuration.Resolver.CacheMinimumTTL > configuration.Resolver.CacheMaximumTTL {
		validationErrors = append(validationErrors, errors.New("resolver.cache_minimum_ttl must not exceed cache_maximum_ttl"))
	}
	if configuration.Resolver.ServeStale && configuration.Resolver.CacheStaleTTL == 0 {
		validationErrors = append(validationErrors, errors.New("resolver.cache_stale_ttl must be positive when serve_stale is enabled"))
	}
	if configuration.Resolver.ServeStale && configuration.Resolver.CacheStaleAnswerTTL == 0 {
		validationErrors = append(validationErrors, errors.New("resolver.cache_stale_answer_ttl must be positive when serve_stale is enabled"))
	}
	if configuration.Resolver.ServeStale && configuration.Resolver.CacheStaleResetTTL == 0 {
		validationErrors = append(validationErrors, errors.New("resolver.cache_stale_reset_ttl must be positive when serve_stale is enabled"))
	}
	if configuration.Resolver.ServeStale && configuration.Resolver.CacheStaleMaxWait.Duration <= 0 {
		validationErrors = append(validationErrors, errors.New("resolver.cache_stale_max_wait must be positive when serve_stale is enabled"))
	}
	if configuration.Resolver.CachePrefetchSample.Duration <= 0 || configuration.Resolver.CachePrefetchSample.Duration > 24*time.Hour {
		validationErrors = append(validationErrors, errors.New("resolver.cache_prefetch_sample_interval must be between 1ns and 24h"))
	}
	if configuration.Resolver.CachePrefetchTriggerTTL > 0 && configuration.Resolver.CachePrefetchHitsPerHour == 0 {
		validationErrors = append(validationErrors, errors.New("resolver.cache_prefetch_hits_per_hour must be positive when prefetching is enabled"))
	}
	if configuration.Server.ShutdownTimeout.Duration <= 0 {
		validationErrors = append(validationErrors, errors.New("server.shutdown_timeout must be positive"))
	}
	if configuration.Reload.Debounce.Duration <= 0 {
		validationErrors = append(validationErrors, errors.New("config.debounce must be positive"))
	}
	if configuration.Database.Driver != "sqlite" && configuration.Database.Driver != "postgres" {
		validationErrors = append(validationErrors, fmt.Errorf("database.driver must be sqlite or postgres, got %q", configuration.Database.Driver))
	}
	if configuration.Database.DSN == "" {
		validationErrors = append(validationErrors, errors.New("database.dsn is required"))
	}
	if configuration.QueryLog.BufferSize <= 0 {
		validationErrors = append(validationErrors, errors.New("query_log.buffer_size must be positive"))
	}
	if configuration.QueryLog.BatchSize <= 0 || configuration.QueryLog.BatchSize > configuration.QueryLog.BufferSize {
		validationErrors = append(validationErrors, errors.New("query_log.batch_size must be positive and no larger than buffer_size"))
	}
	if configuration.QueryLog.FlushInterval.Duration <= 0 {
		validationErrors = append(validationErrors, errors.New("query_log.flush_interval must be positive"))
	}
	if configuration.QueryLog.Retention.Duration <= 0 {
		validationErrors = append(validationErrors, errors.New("query_log.retention must be positive"))
	}
	if configuration.ServerLog.BufferSize <= 0 {
		validationErrors = append(validationErrors, errors.New("server_log.buffer_size must be positive"))
	}
	if configuration.ServerLog.BatchSize <= 0 || configuration.ServerLog.BatchSize > configuration.ServerLog.BufferSize {
		validationErrors = append(validationErrors, errors.New("server_log.batch_size must be positive and no larger than buffer_size"))
	}
	if configuration.ServerLog.FlushInterval.Duration <= 0 {
		validationErrors = append(validationErrors, errors.New("server_log.flush_interval must be positive"))
	}
	if configuration.ServerLog.Retention.Duration <= 0 {
		validationErrors = append(validationErrors, errors.New("server_log.retention must be positive"))
	}
	if !validServerLogLevel(configuration.ServerLog.Level) {
		validationErrors = append(validationErrors, fmt.Errorf("server_log.level must be debug, info, warn, or error, got %q", configuration.ServerLog.Level))
	}
	if configuration.Statistics.Retention.Duration <= 0 {
		validationErrors = append(validationErrors, errors.New("statistics.retention must be positive"))
	}
	if configuration.Backup.Directory == "" {
		validationErrors = append(validationErrors, errors.New("backup.directory is required"))
	}
	if configuration.Backup.Interval.Duration < time.Hour {
		validationErrors = append(validationErrors, errors.New("backup.interval must be at least 1h"))
	}
	if _, err := time.Parse("15:04", configuration.Backup.RunAt); err != nil {
		validationErrors = append(validationErrors, errors.New("backup.run_at must use HH:MM local time"))
	}
	if configuration.Backup.RetentionCount < 1 || configuration.Backup.RetentionCount > 1000 {
		validationErrors = append(validationErrors, errors.New("backup.retention_count must be between 1 and 1000"))
	}
	for index, address := range configuration.EncryptedDNS.DoTListen {
		validationErrors = append(validationErrors, validateAddress(fmt.Sprintf("encrypted_dns.dot_listen[%d]", index), address))
	}
	for index, address := range configuration.EncryptedDNS.DoHListen {
		validationErrors = append(validationErrors, validateAddress(fmt.Sprintf("encrypted_dns.doh_listen[%d]", index), address))
	}
	for index, address := range configuration.EncryptedDNS.DoQListen {
		validationErrors = append(validationErrors, validateAddress(fmt.Sprintf("encrypted_dns.doq_listen[%d]", index), address))
	}
	validationErrors = append(validationErrors, validateTCPListenerConflicts(configuration))
	validationErrors = append(validationErrors, validateUDPListenerConflicts(configuration))
	if configuration.EncryptedDNS.CertificateMode != "manual" && configuration.EncryptedDNS.CertificateMode != "acme" {
		validationErrors = append(validationErrors, errors.New("encrypted_dns.certificate_mode must be manual or acme"))
	}
	if (configuration.EncryptedDNS.encryptedListenerCount() > 0 || configuration.Server.HTTPSListen != "") && configuration.EncryptedDNS.CertificateMode == "manual" {
		if configuration.EncryptedDNS.CertificateFile == "" {
			validationErrors = append(validationErrors, errors.New("encrypted_dns.certificate_file is required for encrypted listeners"))
		}
		if configuration.EncryptedDNS.PrivateKeyFile == "" {
			validationErrors = append(validationErrors, errors.New("encrypted_dns.private_key_file is required for encrypted listeners"))
		}
	}
	if configuration.EncryptedDNS.CertificateMode == "acme" {
		acmeConfiguration := configuration.EncryptedDNS.ACME
		if len(acmeConfiguration.Domains) == 0 {
			validationErrors = append(validationErrors, errors.New("encrypted_dns.acme.domains requires at least one domain"))
		}
		for index, domain := range acmeConfiguration.Domains {
			name := strings.TrimPrefix(domain, "*.")
			if name == "" || name == "." {
				validationErrors = append(validationErrors, fmt.Errorf("encrypted_dns.acme.domains[%d] is invalid", index))
			} else if _, err := dnsname.Normalize(name); err != nil {
				validationErrors = append(validationErrors, fmt.Errorf("encrypted_dns.acme.domains[%d]: %w", index, err))
			}
		}
		if acmeConfiguration.Email == "" || !strings.Contains(acmeConfiguration.Email, "@") {
			validationErrors = append(validationErrors, errors.New("encrypted_dns.acme.email must be a valid contact email"))
		}
		if directory, err := url.Parse(acmeConfiguration.DirectoryURL); err != nil || directory.Scheme != "https" || directory.Host == "" {
			validationErrors = append(validationErrors, errors.New("encrypted_dns.acme.directory_url must be an HTTPS URL"))
		}
		if !slices.Contains([]string{"cloudflare", "porkbun", "namecheap", "godaddy", "digitalocean", "hetzner", "rfc2136", "route53", "ovh"}, acmeConfiguration.DNSProvider) {
			validationErrors = append(validationErrors, errors.New("encrypted_dns.acme.dns_provider is not supported"))
		}
		if acmeConfiguration.StorageDirectory == "" {
			validationErrors = append(validationErrors, errors.New("encrypted_dns.acme.storage_dir is required"))
		}
		if acmeConfiguration.RenewBefore.Duration < 24*time.Hour || acmeConfiguration.RenewBefore.Duration > 60*24*time.Hour {
			validationErrors = append(validationErrors, errors.New("encrypted_dns.acme.renew_before must be between 1d and 60d"))
		}
	}
	if configuration.EncryptedDNS.MinimumVersion != "1.2" && configuration.EncryptedDNS.MinimumVersion != "1.3" {
		validationErrors = append(validationErrors, errors.New("encrypted_dns.minimum_tls_version must be 1.2 or 1.3"))
	}
	if configuration.Security.SessionTTL.Duration <= 0 {
		validationErrors = append(validationErrors, errors.New("security.session_ttl must be positive"))
	}
	if configuration.Security.APITokenTTL.Duration <= 0 {
		validationErrors = append(validationErrors, errors.New("security.api_token_ttl must be positive"))
	}
	if configuration.Security.SecretKeyFile == "" {
		validationErrors = append(validationErrors, errors.New("security.secret_key_file is required"))
	}
	if configuration.Cluster.DataDirectory == "" {
		validationErrors = append(validationErrors, errors.New("cluster.data_dir is required"))
	}
	if err := ValidateClusterAdvertiseURL(configuration.Cluster.AdvertiseURL); err != nil {
		validationErrors = append(validationErrors, err)
	}
	if configuration.Security.Enabled && !configuration.Security.SecureCookies && !isLoopbackListener(configuration.Server.HTTPListen) {
		validationErrors = append(validationErrors, errors.New("security.secure_cookies must be true when server.http_listen is not loopback"))
	}
	seenBlockLists := make(map[string]struct{}, len(configuration.Blocking.Lists))
	for index, domain := range configuration.Blocking.Domains {
		if _, err := dnsname.Normalize(strings.TrimPrefix(domain, "*.")); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("blocking.domains[%d]: %w", index, err))
		}
	}
	for index, list := range configuration.Blocking.Lists {
		field := fmt.Sprintf("blocking.lists[%d]", index)
		if list.Name == "" {
			validationErrors = append(validationErrors, fmt.Errorf("%s.name is required", field))
		}
		if list.Path == "" {
			validationErrors = append(validationErrors, fmt.Errorf("%s.path is required", field))
		}
		if list.URL != "" {
			if err := blockcompiler.ValidateURL(list.URL); err != nil {
				validationErrors = append(validationErrors, fmt.Errorf("%s.url: %w", field, err))
			}
		}
		if err := blockcompiler.ValidateFormat(list.Format); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("%s.format: %w", field, err))
		}
		if _, duplicate := seenBlockLists[list.Name]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("duplicate block list name %q", list.Name))
		}
		seenBlockLists[list.Name] = struct{}{}
	}
	for index, domain := range configuration.Blocking.AllowedDomains {
		if _, err := dnsname.Normalize(strings.TrimPrefix(domain, "*.")); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("blocking.allowed_domains[%d]: %w", index, err))
		}
	}
	if configuration.Blocking.UpdateInterval.Duration <= 0 {
		validationErrors = append(validationErrors, errors.New("blocking.update_interval must be positive"))
	}
	if configuration.Blocking.ResponseType != "nxdomain" && configuration.Blocking.ResponseType != "zero" && configuration.Blocking.ResponseType != "custom" {
		validationErrors = append(validationErrors, errors.New("blocking.response_type must be nxdomain, zero, or custom"))
	}
	if configuration.Blocking.ResponseType == "custom" && len(configuration.Blocking.CustomAddresses) == 0 {
		validationErrors = append(validationErrors, errors.New("blocking.custom_addresses must not be empty for a custom response"))
	}
	for index, address := range configuration.Blocking.CustomAddresses {
		if parsed, err := netip.ParseAddr(address); err != nil || parsed.Zone() != "" {
			validationErrors = append(validationErrors, fmt.Errorf("blocking.custom_addresses[%d] must be an IP address", index))
		}
	}
	for index, client := range configuration.Blocking.BypassClients {
		if _, err := netip.ParsePrefix(client); err != nil {
			if address, addressErr := netip.ParseAddr(client); addressErr != nil || address.Zone() != "" {
				validationErrors = append(validationErrors, fmt.Errorf("blocking.bypass_clients[%d] must be an IP address or CIDR network", index))
			}
		}
	}
	validationErrors = append(validationErrors, configuration.UniFi.validate()...)
	validationErrors = append(validationErrors, configuration.OIDC.validate()...)
	if configuration.OIDC.Enabled && strings.TrimSpace(configuration.OIDC.RedirectURL) == "" {
		if err := validateProviderURL("oidc.redirect_url", configuration.OIDCRedirectURL(), true); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf(
				"%w (derived from the advertised address; set oidc.redirect_url or cluster.advertise_url)", err))
		}
	}
	return errors.Join(validationErrors...)
}

func validServerLogLevel(level string) bool {
	switch level {
	case "debug", "info", "warn", "error":
		return true
	default:
		return false
	}
}

// Validate reports every problem with the UniFi settings. The setup wizard
// calls it before persisting so the operator sees the same rules the loader
// enforces.
func (settings UniFi) Validate() error {
	return errors.Join(settings.validate()...)
}

func (settings UniFi) validate() []error {
	var validationErrors []error
	if settings.Interval.Duration < minimumUniFiInterval {
		validationErrors = append(validationErrors, fmt.Errorf("unifi.interval must be at least %s", minimumUniFiInterval))
	}
	for _, source := range settings.Sources {
		if source != "reservations" && source != "active" {
			validationErrors = append(validationErrors, fmt.Errorf("unifi.sources contains unsupported source %q", source))
		}
	}
	if settings.Enabled {
		if settings.ControllerURL == "" {
			validationErrors = append(validationErrors, errors.New("unifi.controller_url is required when unifi.enabled is true"))
		} else if parsed, err := url.Parse(settings.ControllerURL); err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			validationErrors = append(validationErrors, errors.New("unifi.controller_url must be an absolute http or https URL"))
		}
		if len(settings.Sources) == 0 {
			validationErrors = append(validationErrors, errors.New("unifi.sources must contain reservations, active, or both"))
		}
	}
	// A zone reached by more than one network needs the network in its names,
	// or two devices with the same hostname on different VLANs overwrite one
	// another every sync.
	networksPerZone := make(map[string]int, len(settings.Networks))
	for _, network := range settings.ActiveNetworks() {
		networksPerZone[network.Zone]++
	}
	seenIDs := make(map[string]struct{}, len(settings.Networks))
	for index, network := range settings.Networks {
		field := fmt.Sprintf("unifi.networks[%d]", index)
		if network.ID == "" {
			validationErrors = append(validationErrors, fmt.Errorf("%s.id is required", field))
		} else if _, duplicate := seenIDs[network.ID]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("duplicate unifi network mapping %q", network.ID))
		}
		seenIDs[network.ID] = struct{}{}
		if network.Zone == "" {
			validationErrors = append(validationErrors, fmt.Errorf("%s.zone is required", field))
		} else if _, err := dnsname.Normalize(network.Zone); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("%s.zone: %w", field, err))
		}
		template, err := unifi.ParseTemplate(network.HostnameTemplate)
		if err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("%s.hostname_template: %w", field, err))
			continue
		}
		if !network.Enabled {
			continue
		}
		if networksPerZone[network.Zone] > 1 && !template.UsesNetwork() {
			validationErrors = append(validationErrors, fmt.Errorf(
				"%s.hostname_template must contain {{network}} because more than one network publishes into %s",
				field, network.Zone))
		}
	}
	return validationErrors
}

// ValidateClusterAdvertiseURL validates the trusted endpoint used for cluster
// enrollment and synchronization. An empty URL leaves clustering disabled.
func ValidateClusterAdvertiseURL(value string) error {
	if value == "" {
		return nil
	}
	advertiseURL, err := url.Parse(value)
	if err != nil || !strings.EqualFold(advertiseURL.Scheme, "https") || advertiseURL.Host == "" ||
		advertiseURL.User != nil || advertiseURL.RawQuery != "" || advertiseURL.Fragment != "" {
		return errors.New("cluster.advertise_url must be an absolute https URL without credentials, query, or fragment")
	}
	return nil
}

func validateTCPListenerConflicts(configuration Config) error {
	targets := make(map[string]string)
	var conflicts []error
	listeners := []struct {
		field     string
		addresses []string
	}{
		{field: "server.http_listen", addresses: []string{configuration.Server.HTTPListen}},
		{field: "server.https_listen", addresses: []string{configuration.Server.HTTPSListen}},
		{field: "server.dns_listen", addresses: configuration.Server.DNSListen},
		{field: "encrypted_dns.dot_listen", addresses: configuration.EncryptedDNS.DoTListen},
		{field: "encrypted_dns.doh_listen", addresses: configuration.EncryptedDNS.DoHListen},
	}
	for _, listener := range listeners {
		for _, address := range listener.addresses {
			if address == "" {
				continue
			}
			if existing, duplicate := targets[address]; duplicate {
				if listener.field == "encrypted_dns.doh_listen" && existing == "server.https_listen" {
					// The public console/API and DoH intentionally share one TLS
					// listener. The web server dispatches /dns-query directly to
					// the DNS handler while keeping every other route protected.
					continue
				}
				conflicts = append(conflicts, fmt.Errorf("TCP listener %s conflicts with %s at %s", listener.field, existing, address))
				continue
			}
			targets[address] = listener.field
		}
	}
	return errors.Join(conflicts...)
}

// validateUDPListenerConflicts rejects a DNS-over-QUIC endpoint that would
// contend for a UDP port already claimed by the plain DNS listener.
func validateUDPListenerConflicts(configuration Config) error {
	claimed := make(map[string]string, len(configuration.Server.DNSListen))
	for _, address := range configuration.Server.DNSListen {
		if address != "" {
			claimed[address] = "server.dns_listen"
		}
	}
	var conflicts []error
	for _, address := range configuration.EncryptedDNS.DoQListen {
		if address == "" {
			continue
		}
		if existing, duplicate := claimed[address]; duplicate {
			conflicts = append(conflicts, fmt.Errorf("UDP listener encrypted_dns.doq_listen conflicts with %s at %s", existing, address))
			continue
		}
		claimed[address] = "encrypted_dns.doq_listen"
	}
	return errors.Join(conflicts...)
}

// encryptedListenerCount reports how many encrypted DNS endpoints need the
// shared TLS certificate.
func (encrypted EncryptedDNS) encryptedListenerCount() int {
	return len(encrypted.DoTListen) + len(encrypted.DoHListen) + len(encrypted.DoQListen)
}

// SharesHTTPSWithDoH reports whether the public HTTPS console listener also
// serves the standard DNS-over-HTTPS endpoint at /dns-query.
func (configuration Config) SharesHTTPSWithDoH() bool {
	if configuration.Server.HTTPSListen == "" {
		return false
	}
	return slices.Contains(configuration.EncryptedDNS.DoHListen, configuration.Server.HTTPSListen)
}

// DedicatedDoHListeners returns DoH endpoints that need their own listener.
// An endpoint shared with the HTTPS console is opened by the web server.
func (configuration Config) DedicatedDoHListeners() []string {
	listeners := make([]string, 0, len(configuration.EncryptedDNS.DoHListen))
	for _, address := range configuration.EncryptedDNS.DoHListen {
		if address != configuration.Server.HTTPSListen {
			listeners = append(listeners, address)
		}
	}
	return listeners
}

func (configuration *Config) normalize() {
	configuration.Database.Driver = strings.ToLower(strings.TrimSpace(configuration.Database.Driver))
	configuration.ServerLog.Level = strings.ToLower(strings.TrimSpace(configuration.ServerLog.Level))
	configuration.Backup.Directory = strings.TrimSpace(configuration.Backup.Directory)
	configuration.Backup.RunAt = strings.TrimSpace(configuration.Backup.RunAt)
	configuration.Server.HTTPSListen = strings.TrimSpace(configuration.Server.HTTPSListen)
	configuration.Server.DNSListen = uniqueTrimmed(configuration.Server.DNSListen)
	configuration.Resolver.Forwarders = uniqueTrimmed(configuration.Resolver.Forwarders)
	configuration.Resolver.Mode = strings.ToLower(strings.TrimSpace(configuration.Resolver.Mode))
	if configuration.Resolver.Mode == "" {
		configuration.Resolver.Mode = "forward"
	}
	configuration.Resolver.RootHints = uniqueTrimmed(configuration.Resolver.RootHints)
	configuration.EncryptedDNS.DoTListen = uniqueTrimmed(configuration.EncryptedDNS.DoTListen)
	configuration.EncryptedDNS.DoHListen = uniqueTrimmed(configuration.EncryptedDNS.DoHListen)
	configuration.EncryptedDNS.DoQListen = uniqueTrimmed(configuration.EncryptedDNS.DoQListen)
	configuration.EncryptedDNS.CertificateMode = strings.ToLower(strings.TrimSpace(configuration.EncryptedDNS.CertificateMode))
	if configuration.EncryptedDNS.CertificateMode == "" {
		configuration.EncryptedDNS.CertificateMode = defaultCertificateMode
	}
	configuration.EncryptedDNS.CertificateFile = strings.TrimSpace(configuration.EncryptedDNS.CertificateFile)
	configuration.EncryptedDNS.PrivateKeyFile = strings.TrimSpace(configuration.EncryptedDNS.PrivateKeyFile)
	configuration.EncryptedDNS.MinimumVersion = strings.TrimSpace(configuration.EncryptedDNS.MinimumVersion)
	configuration.EncryptedDNS.ACME.Email = strings.TrimSpace(configuration.EncryptedDNS.ACME.Email)
	configuration.EncryptedDNS.ACME.Domains = uniqueTrimmed(configuration.EncryptedDNS.ACME.Domains)
	configuration.EncryptedDNS.ACME.DirectoryURL = strings.TrimSpace(configuration.EncryptedDNS.ACME.DirectoryURL)
	configuration.EncryptedDNS.ACME.DNSProvider = strings.ToLower(strings.TrimSpace(configuration.EncryptedDNS.ACME.DNSProvider))
	configuration.EncryptedDNS.ACME.DNSZone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(configuration.EncryptedDNS.ACME.DNSZone)), ".")
	configuration.EncryptedDNS.ACME.StorageDirectory = strings.TrimSpace(configuration.EncryptedDNS.ACME.StorageDirectory)
	if configuration.EncryptedDNS.ACME.DirectoryURL == "" {
		configuration.EncryptedDNS.ACME.DirectoryURL = defaultACMEDirectoryURL
	}
	if configuration.EncryptedDNS.ACME.StorageDirectory == "" {
		configuration.EncryptedDNS.ACME.StorageDirectory = defaultACMEStorageDir
	}
	if configuration.EncryptedDNS.ACME.RenewBefore.Duration == 0 {
		configuration.EncryptedDNS.ACME.RenewBefore.Duration = defaultACMERenewBefore
	}
	configuration.normalizeUniFi()
	configuration.Security.SecretKeyFile = strings.TrimSpace(configuration.Security.SecretKeyFile)
	configuration.Cluster.DataDirectory = strings.TrimSpace(configuration.Cluster.DataDirectory)
	configuration.Cluster.NodeName = strings.TrimSpace(configuration.Cluster.NodeName)
	configuration.Cluster.AdvertiseURL = strings.TrimRight(strings.TrimSpace(configuration.Cluster.AdvertiseURL), "/")
	configuration.Cluster.TrustAnchorFile = strings.TrimSpace(configuration.Cluster.TrustAnchorFile)
	for index := range configuration.TSIGKeys {
		key := &configuration.TSIGKeys[index]
		key.Name = strings.ToLower(dns.Fqdn(strings.TrimSpace(key.Name)))
		key.Algorithm = canonicalTSIGAlgorithm(key.Algorithm)
		key.Secret = strings.TrimSpace(key.Secret)
	}
	slices.SortFunc(configuration.TSIGKeys, func(left, right TSIGKey) int {
		return strings.Compare(left.Name, right.Name)
	})
	for index := range configuration.Resolver.Routes {
		route := &configuration.Resolver.Routes[index]
		route.Domain = normalizeDomain(route.Domain)
		route.Forwarders = uniqueTrimmed(route.Forwarders)
	}
	configuration.Resolver.DNSSECTrustAnchors = uniqueTrimmed(configuration.Resolver.DNSSECTrustAnchors)
	configuration.Resolver.DNSSECNegativeTrustAnchors = uniqueDomainsAllowRoot(configuration.Resolver.DNSSECNegativeTrustAnchors)
	slices.SortFunc(configuration.Resolver.Routes, func(left, right ForwardRoute) int {
		return strings.Compare(left.Domain, right.Domain)
	})
	for index := range configuration.Resolver.Hosts {
		host := &configuration.Resolver.Hosts[index]
		host.Name = normalizeDomain(host.Name)
		host.Addresses = uniqueAddresses(host.Addresses)
		if host.TTL == 0 {
			host.TTL = defaultHostTTL
		}
	}
	slices.SortFunc(configuration.Resolver.Hosts, func(left, right HostOverride) int {
		return strings.Compare(left.Name, right.Name)
	})

	normalizedDomains := make([]string, 0, len(configuration.Blocking.Domains))
	for _, domain := range configuration.Blocking.Domains {
		normalized := normalizePolicyDomain(domain)
		if normalized != "" {
			normalizedDomains = append(normalizedDomains, normalized)
		}
	}
	slices.Sort(normalizedDomains)
	configuration.Blocking.Domains = slices.Compact(normalizedDomains)
	normalizedAllowed := make([]string, 0, len(configuration.Blocking.AllowedDomains))
	for _, domain := range configuration.Blocking.AllowedDomains {
		normalized := normalizePolicyDomain(domain)
		if normalized != "" {
			normalizedAllowed = append(normalizedAllowed, normalized)
		}
	}
	slices.Sort(normalizedAllowed)
	configuration.Blocking.AllowedDomains = slices.Compact(normalizedAllowed)
	configuration.Blocking.ResponseType = strings.ToLower(strings.TrimSpace(configuration.Blocking.ResponseType))
	if configuration.Blocking.ResponseType == "" {
		configuration.Blocking.ResponseType = "nxdomain"
	}
	if configuration.Blocking.UpdateInterval.Duration == 0 {
		configuration.Blocking.UpdateInterval.Duration = defaultBlockListUpdate
	}
	configuration.Blocking.CustomAddresses = uniqueAddresses(configuration.Blocking.CustomAddresses)
	configuration.Blocking.BypassClients = uniqueTrimmed(configuration.Blocking.BypassClients)
	for index := range configuration.Blocking.Lists {
		list := &configuration.Blocking.Lists[index]
		list.Name = strings.TrimSpace(list.Name)
		list.Path = strings.TrimSpace(list.Path)
		list.URL = strings.TrimSpace(list.URL)
		if list.Path == "" && list.URL != "" {
			list.Path = blockcompiler.CachePath(list.URL)
		}
		list.Format = strings.ToLower(strings.TrimSpace(list.Format))
		if list.Format == "" {
			list.Format = string(blockcompiler.FormatAuto)
		}
	}
	slices.SortFunc(configuration.Blocking.Lists, func(left, right BlockList) int {
		return strings.Compare(left.Name, right.Name)
	})
}

// ValidateTSIGSecret reports whether a shared secret is usable. The console and
// the configuration loader both apply it so a key rejected on one path cannot
// slip in through the other.
func ValidateTSIGSecret(secret string) error {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(secret))
	if err != nil || len(decoded) < 16 {
		return errors.New("must be base64 encoding at least 128 bits")
	}
	return nil
}

func canonicalTSIGAlgorithm(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return dns.HmacSHA256
	}
	return dns.Fqdn(value)
}

func (configuration Config) BlockListPaths(baseDirectory string) []string {
	paths := make([]string, 0, len(configuration.Blocking.Lists))
	for _, list := range configuration.Blocking.Lists {
		path := list.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDirectory, path)
		}
		paths = append(paths, filepath.Clean(path))
	}
	return paths
}

func (configuration Config) ReloadDependencyPaths(baseDirectory string) []string {
	paths := configuration.BlockListPaths(baseDirectory)
	if configuration.EncryptedDNS.CertificateMode == "acme" {
		certificate, privateKey := configuration.EncryptedDNSCertificatePaths(baseDirectory)
		paths = append(paths, certificate, privateKey)
	}
	for _, path := range []string{
		configuration.EncryptedDNS.CertificateFile,
		configuration.EncryptedDNS.PrivateKeyFile,
		configuration.Cluster.TrustAnchorFile,
	} {
		if path == "" {
			continue
		}
		paths = append(paths, resolvePath(baseDirectory, path))
	}
	return paths
}

func (configuration Config) EncryptedDNSCertificatePaths(baseDirectory string) (string, string) {
	if configuration.EncryptedDNS.CertificateMode == "acme" {
		directory := resolvePath(baseDirectory, configuration.EncryptedDNS.ACME.StorageDirectory)
		return filepath.Join(directory, "certificate.pem"), filepath.Join(directory, "private-key.pem")
	}
	return resolveOptionalPath(baseDirectory, configuration.EncryptedDNS.CertificateFile),
		resolveOptionalPath(baseDirectory, configuration.EncryptedDNS.PrivateKeyFile)
}

func (configuration Config) SecuritySecretKeyPath(baseDirectory string) string {
	return resolveOptionalPath(baseDirectory, configuration.Security.SecretKeyFile)
}

// BackupDirectoryPath resolves the local archive directory through the same
// configuration-relative rules as Sable's other filesystem settings.
func (configuration Config) BackupDirectoryPath(baseDirectory string) string {
	return resolvePath(baseDirectory, configuration.Backup.Directory)
}

// AdvertisedBaseURL is the address other nodes and browsers are told to reach
// this one at, preferring what the operator configured over what can be guessed
// from the listeners.
func (configuration Config) AdvertisedBaseURL() string {
	if configuration.Cluster.AdvertiseURL != "" {
		return configuration.Cluster.AdvertiseURL
	}
	if configuration.Server.HTTPSListen != "" {
		return "https://" + configuration.Server.HTTPSListen
	}
	return "http://" + configuration.Server.HTTPListen
}

// OIDCRedirectURL is the callback this node hands the provider. Every node uses
// the same path, so the only thing that differs between them is the host, which
// each one already knows. That is what lets the rest of the [oidc] section be
// identical cluster-wide while the callback stays node-local.
func (configuration Config) OIDCRedirectURL() string {
	if override := strings.TrimSpace(configuration.OIDC.RedirectURL); override != "" {
		return override
	}
	return strings.TrimRight(configuration.AdvertisedBaseURL(), "/") + OIDCCallbackPath
}

func (configuration Config) ClusterDataPath(baseDirectory string) string {
	return resolvePath(baseDirectory, configuration.Cluster.DataDirectory)
}

func (configuration Config) ClusterTrustAnchorPath(baseDirectory string) string {
	return resolveOptionalPath(baseDirectory, configuration.Cluster.TrustAnchorFile)
}

func (encrypted EncryptedDNS) MinimumTLSVersion() uint16 {
	if encrypted.MinimumVersion == "1.2" {
		return tls.VersionTLS12
	}
	return tls.VersionTLS13
}

func resolveOptionalPath(baseDirectory, path string) string {
	if path == "" {
		return ""
	}
	return resolvePath(baseDirectory, path)
}

func resolvePath(baseDirectory, path string) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDirectory, path)
	}
	return filepath.Clean(path)
}

func (configuration *Config) normalizeUniFi() {
	settings := &configuration.UniFi
	settings.ControllerURL = strings.TrimRight(strings.TrimSpace(settings.ControllerURL), "/")
	settings.Site = strings.TrimSpace(settings.Site)
	if settings.Site == "" {
		settings.Site = defaultUniFiSite
	}
	if settings.Interval.Duration <= 0 {
		settings.Interval.Duration = defaultUniFiInterval
	}
	settings.CAFile = strings.TrimSpace(settings.CAFile)
	sources := make([]string, 0, len(settings.Sources))
	for _, source := range settings.Sources {
		source = strings.ToLower(strings.TrimSpace(source))
		if source != "" && !slices.Contains(sources, source) {
			sources = append(sources, source)
		}
	}
	slices.Sort(sources)
	settings.Sources = sources
	for index := range settings.Networks {
		network := &settings.Networks[index]
		network.ID = strings.TrimSpace(network.ID)
		network.Name = strings.TrimSpace(network.Name)
		network.Zone = normalizeDomain(network.Zone)
		network.HostnameTemplate = strings.TrimSpace(network.HostnameTemplate)
		if network.HostnameTemplate == "" {
			network.HostnameTemplate = unifi.DefaultHostnameTemplate
		}
		if network.TTL == 0 {
			network.TTL = defaultUniFiRecordTTL
		}
	}
	slices.SortFunc(settings.Networks, func(left, right UniFiNetwork) int {
		if compared := strings.Compare(left.Zone, right.Zone); compared != 0 {
			return compared
		}
		return strings.Compare(left.ID, right.ID)
	})
}

func normalizeDomain(domain string) string {
	domain = strings.TrimPrefix(strings.TrimSpace(domain), "*.")
	normalized, err := dnsname.Normalize(domain)
	if err != nil {
		return strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	}
	return normalized
}

func normalizePolicyDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	wildcard := strings.HasPrefix(domain, "*.")
	domain = strings.TrimPrefix(domain, "*.")
	normalized, err := dnsname.Normalize(domain)
	if err != nil {
		normalized = strings.Trim(strings.ToLower(domain), ".")
	}
	if wildcard && normalized != "" {
		return "*." + normalized
	}
	return normalized
}

func parseDNSSECTrustAnchor(value string) (dns.RR, error) {
	fields := strings.Fields(value)
	if len(fields) < 5 {
		return nil, errors.New("must be an owner name followed by a DS or DNSKEY record")
	}
	owner := strings.ToLower(strings.TrimSpace(fields[0]))
	if owner != "." {
		normalized, err := dnsname.Normalize(owner)
		if err != nil {
			return nil, fmt.Errorf("owner: %w", err)
		}
		owner = normalized
	}
	recordType := strings.ToUpper(fields[1])
	if recordType != "DS" && recordType != "DNSKEY" {
		return nil, errors.New("record type must be DS or DNSKEY")
	}
	record, err := dns.NewRR(fmt.Sprintf("%s 0 IN %s", dns.Fqdn(owner), strings.Join(fields[1:], " ")))
	if err != nil {
		return nil, fmt.Errorf("parse record: %w", err)
	}
	return record, nil
}

func validateAddress(field, address string) error {
	if strings.TrimSpace(address) == "" {
		return fmt.Errorf("%s is required", field)
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return fmt.Errorf("%s must be host:port: %w", field, err)
	}
	return nil
}

func validateRootHint(field, address string) error {
	if err := validateAddress(field, address); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(address)
	parsed, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil || parsed.Zone() != "" {
		return fmt.Errorf("%s must use an IPv4 or IPv6 address", field)
	}
	return nil
}

func isLoopbackListener(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	parsed := net.ParseIP(host)
	return parsed != nil && parsed.IsLoopback()
}

func uniqueTrimmed(values []string) []string {
	unique := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := unique[trimmed]; exists {
			continue
		}
		unique[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func uniqueDomainsAllowRoot(values []string) []string {
	unique := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := "."
		if strings.TrimSpace(value) != "." {
			normalized = normalizeDomain(value)
		}
		if normalized == "" {
			continue
		}
		if _, exists := unique[normalized]; exists {
			continue
		}
		unique[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

func uniqueAddresses(values []string) []string {
	unique := make(map[netip.Addr]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			trimmed := strings.TrimSpace(value)
			if trimmed != "" {
				result = append(result, trimmed)
			}
			continue
		}
		address = address.Unmap()
		if _, exists := unique[address]; exists {
			continue
		}
		unique[address] = struct{}{}
		result = append(result, address.String())
	}
	return result
}

// Marshal encodes a configuration back to TOML. Restoring a backup onto a node
// that has to point at a different database rewrites the file this way, so the
// configuration the node boots with names the database it can actually reach.
func Marshal(configuration Config) ([]byte, error) {
	encoded, err := toml.Marshal(configuration)
	if err != nil {
		return nil, fmt.Errorf("encode TOML: %w", err)
	}
	return encoded, nil
}

func AbsolutePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve configuration path: %w", err)
	}
	return absolute, nil
}
