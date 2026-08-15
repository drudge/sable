package dnsserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/forwarding"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/trustanchor"
)

const fallbackErrorCode = dns.RcodeServerFailure

type Runtime struct {
	mode                string
	forwarders          []string
	rootHints           []string
	delegations         *delegationCache
	baseRoutes          []ForwardingRoute
	routes              map[string][]string
	upstreams           string
	timeout             time.Duration
	staleMaxWait        time.Duration
	blocked             map[string]struct{}
	allowedExact        map[string]struct{}
	allowedWildcard     map[string]struct{}
	blocking            bool
	blockType           string
	blockTTL            uint32
	blockAddrs          []netip.Addr
	bypass              []netip.Prefix
	blockTXT            bool
	cache               *ResponseCache
	blockLists          []BlockListStats
	hosts               map[string]localHostRecords
	zones               map[string]*authoritativeZone
	managedZones        map[string]managedZone
	tsigKeys            map[string]tsigKey
	zoneCount           int
	dnssec              *dnssecValidator
	zoneInsecure        []string
	managedTrustAnchors bool
}

type managedZone struct {
	kind      string
	primaries []string
	tsigKey   string
}

type tsigKey struct {
	algorithm string
	secret    string
}

type RuntimeConfig struct {
	Mode                       string
	Forwarders                 []string
	RootHints                  []string
	Routes                     []ForwardingRoute
	Timeout                    time.Duration
	CacheSize                  int
	CacheMinimumTTL            uint32
	CacheMaximumTTL            uint32
	CacheNegativeTTL           uint32
	CacheFailureTTL            uint32
	ServeStale                 bool
	CacheStaleTTL              uint32
	CacheStaleAnswerTTL        uint32
	CacheStaleResetTTL         uint32
	CacheStaleMaxWait          time.Duration
	CachePrefetchMinimumTTL    uint32
	CachePrefetchTriggerTTL    uint32
	CachePrefetchSample        time.Duration
	CachePrefetchHitsPerHour   uint32
	Blocking                   bool
	BlockedDomains             []string
	AllowedDomains             []string
	BlockLists                 []BlockListStats
	BlockingType               string
	BlockingTTL                uint32
	BlockingAddrs              []string
	BypassClients              []string
	AllowTXTReport             bool
	Hosts                      []HostOverride
	Zones                      []AuthoritativeZone
	TSIGKeys                   []TSIGKey
	DNSSECValidation           bool
	DNSSECTrustAnchorUpdates   bool
	DNSSECTrustAnchors         []string
	DNSSECNegativeTrustAnchors []string
}

type TSIGKey struct {
	Name      string
	Algorithm string
	Secret    string
}

type ForwardingRoute struct {
	Domain     string
	Forwarders []string
}

type HostOverride struct {
	Name      string
	Addresses []string
	TTL       uint32
}

type AuthoritativeZone struct {
	Name            string
	Type            string
	Disabled        bool
	ZoneTransfer    string
	TransferACL     []string
	PrimaryServers  []string
	PrimaryProtocol string
	TSIGKey         string
	DynamicUpdates  bool
	// DNSSECValidationDisabled marks the zone subtree insecure for the
	// validator. Forwarder and stub zones frequently point at private servers
	// that serve an unsigned copy of a signed delegation.
	DNSSECValidationDisabled bool
	Records                  []ZoneRecord
}

type ZoneRecord struct {
	Name      string
	Type      string
	Value     string
	TTL       uint32
	Disabled  bool
	ExpiresAt time.Time
}

type authoritativeZone struct {
	name         string
	records      map[string]map[uint16][]authoritativeRecord
	anames       map[string][]authoritativeANAME
	forwarders   map[string][]authoritativeForwarder
	owners       map[string]struct{}
	soa          []authoritativeRecord
	nsecs        []authoritativeRecord
	nsec3s       []authoritativeRecord
	signed       bool
	transferMode string
	transferACL  []netip.Prefix
	tsigKey      string
	kind         string
	dynamic      bool
}

type authoritativeForwarder struct {
	priority uint16
	endpoint string
}

type authoritativeRecord struct {
	record    dns.RR
	expiresAt time.Time
}

type authoritativeANAME struct {
	target    string
	ttl       uint32
	expiresAt time.Time
}

type localHostRecords struct {
	ipv4 []dns.RR
	ipv6 []dns.RR
}

type BlockListStats struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Lines    int    `json:"lines"`
	Accepted int    `json:"accepted"`
	Invalid  int    `json:"invalid"`
}

type Stats struct {
	Queries                  uint64             `json:"queries"`
	NoError                  uint64             `json:"no_error"`
	ServerFailures           uint64             `json:"server_failures"`
	NXDomain                 uint64             `json:"nx_domain"`
	Refused                  uint64             `json:"refused"`
	Blocked                  uint64             `json:"blocked"`
	Failures                 uint64             `json:"failures"`
	UpstreamErrors           uint64             `json:"upstream_errors"`
	CacheHits                uint64             `json:"cache_hits"`
	CacheMisses              uint64             `json:"cache_misses"`
	CacheEntries             int                `json:"cache_entries"`
	RoutedQueries            uint64             `json:"routed_queries"`
	LocalAnswers             uint64             `json:"local_answers"`
	AuthoritativeAnswers     uint64             `json:"authoritative_answers"`
	LocalHosts               int                `json:"local_hosts"`
	Zones                    int                `json:"zones"`
	BlockedDomains           int                `json:"blocked_domains"`
	BlockLists               int                `json:"block_lists"`
	BlockSources             []BlockListStats   `json:"block_sources"`
	StartedAt                time.Time          `json:"started_at"`
	DNSSECSecure             uint64             `json:"dnssec_secure"`
	DNSSECInsecure           uint64             `json:"dnssec_insecure"`
	DNSSECBogus              uint64             `json:"dnssec_bogus"`
	DNSSECTrustAnchorUpdates bool               `json:"dnssec_trust_anchor_updates"`
	DNSSECTrustAnchors       trustanchor.Status `json:"dnssec_trust_anchors"`
}

type Handler struct {
	runtime              atomic.Pointer[Runtime]
	queries              atomic.Uint64
	noError              atomic.Uint64
	serverFailures       atomic.Uint64
	nxDomain             atomic.Uint64
	refused              atomic.Uint64
	blocked              atomic.Uint64
	failures             atomic.Uint64
	upstreamErrors       atomic.Uint64
	cacheHits            atomic.Uint64
	cacheMisses          atomic.Uint64
	routedQueries        atomic.Uint64
	localAnswers         atomic.Uint64
	authoritativeAnswers atomic.Uint64
	dnssecSecure         atomic.Uint64
	dnssecInsecure       atomic.Uint64
	dnssecBogus          atomic.Uint64
	trustAnchorManager   *trustanchor.Manager
	upstreamIndex        atomic.Uint64
	pausedUntil          atomic.Int64
	startedAt            time.Time
	observer             atomic.Pointer[observerHolder]
	upstreamExchange     upstreamExchangeFunc
	zoneTransfer         zoneTransferFunc
	zoneRefresh          zoneRefreshFunc
	journalMu            sync.RWMutex
	zoneJournals         map[string][]zoneDelta
	expiredMu            sync.Mutex
	expiredZones         atomic.Pointer[map[string]struct{}]
	notifications        chan ZoneNotification
	zoneUpdater          atomic.Pointer[zoneUpdaterHolder]
	zoneUpdateAuditor    atomic.Pointer[zoneUpdateAuditorHolder]
}

type ZoneNotification struct {
	Zone       string
	Source     string
	ReceivedAt time.Time
}

type upstreamExchangeFunc func(context.Context, *dns.Msg, string, time.Duration) (*dns.Msg, error)
type zoneTransferFunc func(context.Context, string, string, string, transferAuth, time.Duration) ([]dns.RR, error)
type zoneRefreshFunc func(context.Context, string, string, string, *dns.SOA, transferAuth, time.Duration) ([]dns.RR, error)

type observerHolder struct {
	observer querylog.Observer
}

type resolution struct {
	response         *dns.Msg
	source           querylog.Source
	transientFailure bool
}

func Compile(configuration RuntimeConfig) (*Runtime, error) {
	mode := strings.ToLower(strings.TrimSpace(configuration.Mode))
	if mode == "" {
		mode = "forward"
	}
	if mode != "forward" && mode != "recursive" {
		return nil, errors.New("resolver mode must be forward or recursive")
	}
	if mode == "forward" && len(configuration.Forwarders) == 0 {
		return nil, errors.New("at least one forwarder is required in forward mode")
	}
	rootHints, err := normalizeRootHints(configuration.RootHints)
	if err != nil {
		return nil, err
	}
	if configuration.Timeout <= 0 {
		return nil, errors.New("resolver timeout must be positive")
	}
	if configuration.CacheSize <= 0 {
		return nil, errors.New("cache size must be positive")
	}
	var validator *dnssecValidator
	if configuration.DNSSECValidation {
		var err error
		validator, err = newDNSSECValidator(configuration.DNSSECTrustAnchors, configuration.DNSSECNegativeTrustAnchors)
		if err != nil {
			return nil, fmt.Errorf("compile DNSSEC validator: %w", err)
		}
	}
	blocked := make(map[string]struct{}, len(configuration.BlockedDomains))
	for _, domain := range configuration.BlockedDomains {
		normalized, err := dnsname.Normalize(strings.TrimPrefix(strings.TrimSpace(domain), "*."))
		if err != nil {
			return nil, fmt.Errorf("invalid blocked domain %q: %w", domain, err)
		}
		blocked[normalized] = struct{}{}
	}
	allowedExact := make(map[string]struct{}, len(configuration.AllowedDomains))
	allowedWildcard := make(map[string]struct{}, len(configuration.AllowedDomains))
	for _, domain := range configuration.AllowedDomains {
		domain = strings.TrimSpace(domain)
		wildcard := strings.HasPrefix(domain, "*.")
		normalized, err := dnsname.Normalize(strings.TrimPrefix(domain, "*."))
		if err != nil {
			return nil, fmt.Errorf("invalid allowed domain %q: %w", domain, err)
		}
		if wildcard {
			allowedWildcard[normalized] = struct{}{}
		} else {
			allowedExact[normalized] = struct{}{}
		}
	}
	blockingType := configuration.BlockingType
	if blockingType == "" {
		blockingType = "nxdomain"
	}
	if blockingType != "nxdomain" && blockingType != "zero" && blockingType != "custom" {
		return nil, fmt.Errorf("invalid blocking response type %q", configuration.BlockingType)
	}
	blockAddresses := make([]netip.Addr, 0, len(configuration.BlockingAddrs)+2)
	if blockingType == "zero" {
		blockAddresses = append(blockAddresses, netip.IPv4Unspecified(), netip.IPv6Unspecified())
	} else if blockingType == "custom" {
		for _, value := range configuration.BlockingAddrs {
			address, err := netip.ParseAddr(value)
			if err != nil || address.Zone() != "" {
				return nil, fmt.Errorf("invalid custom blocking address %q", value)
			}
			blockAddresses = append(blockAddresses, address.Unmap())
		}
	}
	bypass := make([]netip.Prefix, 0, len(configuration.BypassClients))
	for _, value := range configuration.BypassClients {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil || address.Zone() != "" {
				return nil, fmt.Errorf("invalid blocking bypass client %q", value)
			}
			prefix = netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen())
		}
		bypass = append(bypass, prefix.Masked())
	}
	routes := make(map[string][]string, len(configuration.Routes))
	for _, route := range configuration.Routes {
		domain, err := dnsname.Normalize(route.Domain)
		if err != nil || len(route.Forwarders) == 0 {
			return nil, fmt.Errorf("conditional forwarding route %q is invalid", route.Domain)
		}
		if _, duplicate := routes[domain]; duplicate {
			return nil, fmt.Errorf("duplicate conditional forwarding route %q", route.Domain)
		}
		routes[domain] = append([]string(nil), route.Forwarders...)
	}
	hosts := make(map[string]localHostRecords, len(configuration.Hosts))
	for _, host := range configuration.Hosts {
		name, err := dnsname.Normalize(host.Name)
		if err != nil || host.TTL == 0 || len(host.Addresses) == 0 {
			return nil, fmt.Errorf("local host override %q is invalid", host.Name)
		}
		if _, duplicate := hosts[name]; duplicate {
			return nil, fmt.Errorf("duplicate local host override %q", host.Name)
		}
		records := localHostRecords{}
		for _, rawAddress := range host.Addresses {
			address, err := netip.ParseAddr(rawAddress)
			if err != nil || address.Zone() != "" {
				return nil, fmt.Errorf("local host override %q has invalid address %q", host.Name, rawAddress)
			}
			address = address.Unmap()
			header := dns.RR_Header{Name: dns.Fqdn(name), Class: dns.ClassINET, Ttl: host.TTL}
			if address.Is4() {
				header.Rrtype = dns.TypeA
				records.ipv4 = append(records.ipv4, &dns.A{Hdr: header, A: net.IP(address.AsSlice())})
			} else {
				header.Rrtype = dns.TypeAAAA
				records.ipv6 = append(records.ipv6, &dns.AAAA{Hdr: header, AAAA: net.IP(address.AsSlice())})
			}
		}
		hosts[name] = records
	}
	zones := make(map[string]*authoritativeZone, len(configuration.Zones))
	managedZones := make(map[string]managedZone)
	tsigKeys := make(map[string]tsigKey, len(configuration.TSIGKeys))
	for _, key := range configuration.TSIGKeys {
		name := strings.ToLower(dns.Fqdn(strings.TrimSpace(key.Name)))
		if _, duplicate := tsigKeys[name]; duplicate {
			return nil, fmt.Errorf("duplicate TSIG key %q", name)
		}
		algorithm := strings.ToLower(dns.Fqdn(strings.TrimSpace(key.Algorithm)))
		if algorithm == "." {
			algorithm = dns.HmacSHA256
		}
		tsigKeys[name] = tsigKey{algorithm: algorithm, secret: key.Secret}
	}
	zoneCount := 0
	zoneInsecure := make([]string, 0)
	for _, configuredZone := range configuration.Zones {
		if configuredZone.Disabled {
			continue
		}
		zoneCount++
		zoneName, err := dnsname.Normalize(configuredZone.Name)
		if err != nil || len(configuredZone.Records) == 0 {
			return nil, fmt.Errorf("authoritative zone %q is invalid", configuredZone.Name)
		}
		if _, duplicate := zones[zoneName]; duplicate {
			return nil, fmt.Errorf("duplicate authoritative zone %q", configuredZone.Name)
		}
		zoneType := strings.ToLower(strings.TrimSpace(configuredZone.Type))
		if zoneType == "" {
			zoneType = "primary"
		}
		if configuredZone.DNSSECValidationDisabled {
			if zoneType != "forwarder" && zoneType != "stub" {
				return nil, fmt.Errorf("authoritative zone %q may not disable DNSSEC validation for a %s zone", zoneName, zoneType)
			}
			zoneInsecure = append(zoneInsecure, zoneName)
		}
		zoneTSIGKey := ""
		if strings.TrimSpace(configuredZone.TSIGKey) != "" {
			zoneTSIGKey = strings.ToLower(dns.Fqdn(strings.TrimSpace(configuredZone.TSIGKey)))
			if _, found := tsigKeys[zoneTSIGKey]; !found {
				return nil, fmt.Errorf("authoritative zone %q references unknown TSIG key %q", zoneName, zoneTSIGKey)
			}
		}
		if zoneType == "stub" {
			managedZones[zoneName] = managedZone{kind: zoneType, primaries: append([]string(nil), configuredZone.PrimaryServers...), tsigKey: zoneTSIGKey}
			if _, duplicate := routes[zoneName]; duplicate {
				return nil, fmt.Errorf("stub zone %q duplicates a forwarding route", zoneName)
			}
			protocol := configuredZone.PrimaryProtocol
			if protocol == "" {
				protocol = "udp"
			}
			for _, primary := range configuredZone.PrimaryServers {
				routes[zoneName] = append(routes[zoneName], protocol+"://"+primary)
			}
			if len(routes[zoneName]) == 0 {
				return nil, fmt.Errorf("stub zone %q requires at least one primary server", zoneName)
			}
			continue
		}
		if zoneType == "secondary" {
			managedZones[zoneName] = managedZone{kind: zoneType, primaries: append([]string(nil), configuredZone.PrimaryServers...), tsigKey: zoneTSIGKey}
		}
		zone := &authoritativeZone{
			name: zoneName, records: make(map[string]map[uint16][]authoritativeRecord),
			anames: make(map[string][]authoritativeANAME), forwarders: make(map[string][]authoritativeForwarder),
			owners:       make(map[string]struct{}),
			transferMode: configuredZone.ZoneTransfer,
			tsigKey:      zoneTSIGKey,
			kind:         zoneType,
			dynamic:      configuredZone.DynamicUpdates,
		}
		if zone.transferMode == "" {
			zone.transferMode = "deny"
		}
		for _, rawPrefix := range configuredZone.TransferACL {
			prefix, parseErr := netip.ParsePrefix(rawPrefix)
			if parseErr != nil {
				address, addressErr := netip.ParseAddr(rawPrefix)
				if addressErr != nil || address.Zone() != "" {
					return nil, fmt.Errorf("authoritative zone %q transfer ACL %q is invalid", zoneName, rawPrefix)
				}
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
			zone.transferACL = append(zone.transferACL, prefix)
		}
		hasDNSKEY, hasRRSIG := false, false
		for _, record := range configuredZone.Records {
			if record.Disabled || (!record.ExpiresAt.IsZero() && !record.ExpiresAt.After(time.Now())) {
				continue
			}
			owner, err := authoritativeOwner(zoneName, record.Name)
			if err != nil {
				return nil, fmt.Errorf("authoritative zone %q record owner %q: %w", zoneName, record.Name, err)
			}
			recordType := strings.ToUpper(strings.TrimSpace(record.Type))
			if recordType == "ANAME" {
				target, normalizeErr := dnsname.Normalize(record.Value)
				if normalizeErr != nil {
					return nil, fmt.Errorf("compile authoritative zone %q ANAME record: %w", zoneName, normalizeErr)
				}
				zone.anames[owner] = append(zone.anames[owner], authoritativeANAME{
					target: target, ttl: record.TTL, expiresAt: record.ExpiresAt,
				})
				zone.owners[owner] = struct{}{}
				continue
			}
			if recordType == "FWD" {
				forwarder, parseErr := forwarding.ParseRecord(record.Value)
				if parseErr != nil {
					return nil, fmt.Errorf("compile authoritative zone %q FWD record: %w", zoneName, parseErr)
				}
				zone.forwarders[owner] = append(zone.forwarders[owner], authoritativeForwarder{
					priority: forwarder.Priority, endpoint: forwarder.Endpoint(),
				})
				zone.owners[owner] = struct{}{}
				continue
			}
			if _, found := dns.StringToType[recordType]; !found {
				return nil, fmt.Errorf("authoritative zone %q has unsupported record type %q", zoneName, record.Type)
			}
			rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", dns.Fqdn(owner), record.TTL, recordType, record.Value))
			if err != nil {
				return nil, fmt.Errorf("compile authoritative zone %q record: %w", zoneName, err)
			}
			if owner != zoneName && !strings.HasSuffix(owner, "."+zoneName) {
				return nil, fmt.Errorf("authoritative record owner %q is outside zone %q", owner, zoneName)
			}
			byType := zone.records[owner]
			if byType == nil {
				byType = make(map[uint16][]authoritativeRecord)
				zone.records[owner] = byType
			}
			compiledRecord := authoritativeRecord{record: rr, expiresAt: record.ExpiresAt}
			byType[rr.Header().Rrtype] = append(byType[rr.Header().Rrtype], compiledRecord)
			zone.owners[owner] = struct{}{}
			for ancestor := owner; ancestor != zoneName; {
				separator := strings.IndexByte(ancestor, '.')
				if separator < 0 {
					break
				}
				ancestor = ancestor[separator+1:]
				zone.owners[ancestor] = struct{}{}
			}
			if owner == zoneName && rr.Header().Rrtype == dns.TypeSOA {
				zone.soa = append(zone.soa, compiledRecord)
			}
			if rr.Header().Rrtype == dns.TypeNSEC {
				zone.nsecs = append(zone.nsecs, compiledRecord)
			}
			if rr.Header().Rrtype == dns.TypeNSEC3 {
				zone.nsec3s = append(zone.nsec3s, compiledRecord)
			}
			if rr.Header().Rrtype == dns.TypeDNSKEY {
				hasDNSKEY = true
			}
			if rr.Header().Rrtype == dns.TypeRRSIG {
				hasRRSIG = true
			}
		}
		zone.signed = hasDNSKEY && hasRRSIG
		if len(zone.soa) != 1 || (zoneType != "forwarder" && len(zone.records[zoneName][dns.TypeNS]) == 0) {
			return nil, fmt.Errorf("authoritative zone %q has invalid authority records", zoneName)
		}
		if zoneType == "forwarder" && len(zone.forwarders[zoneName]) == 0 {
			return nil, fmt.Errorf("forwarder zone %q requires an active apex FWD record", zoneName)
		}
		for owner, ordered := range zone.forwarders {
			slices.SortFunc(ordered, func(left, right authoritativeForwarder) int {
				return int(left.priority) - int(right.priority)
			})
			if _, duplicate := routes[owner]; duplicate {
				return nil, fmt.Errorf("authoritative zone %q FWD owner duplicates forwarding route %q", zoneName, owner)
			}
			endpoints := make([]string, 0, len(ordered))
			for _, forwarder := range ordered {
				endpoints = append(endpoints, forwarder.endpoint)
			}
			routes[owner] = endpoints
			zone.forwarders[owner] = ordered
		}
		zones[zoneName] = zone
	}
	slices.Sort(zoneInsecure)
	if validator != nil {
		validator.setZoneInsecure(zoneInsecure)
	}
	return &Runtime{
		mode:            mode,
		forwarders:      append([]string(nil), configuration.Forwarders...),
		rootHints:       rootHints,
		delegations:     newDelegationCache(4096),
		baseRoutes:      cloneForwardingRoutes(configuration.Routes),
		routes:          routes,
		upstreams:       upstreamSignature(configuration.Forwarders, routes) + "|mode=" + mode + "|roots=" + strings.Join(rootHints, ",") + dnssecRuntimeSignature(configuration),
		timeout:         configuration.Timeout,
		staleMaxWait:    configuration.CacheStaleMaxWait,
		blocked:         blocked,
		allowedExact:    allowedExact,
		allowedWildcard: allowedWildcard,
		blocking:        configuration.Blocking,
		blockType:       blockingType,
		blockTTL:        configuration.BlockingTTL,
		blockAddrs:      blockAddresses,
		bypass:          bypass,
		blockTXT:        configuration.AllowTXTReport,
		cache: NewResponseCacheWithOptions(configuration.CacheSize, CacheOptions{
			MinimumTTL: configuration.CacheMinimumTTL, MaximumTTL: configuration.CacheMaximumTTL,
			NegativeTTL: configuration.CacheNegativeTTL, FailureTTL: configuration.CacheFailureTTL,
			ServeStale: configuration.ServeStale, StaleTTL: configuration.CacheStaleTTL,
			StaleAnswerTTL: configuration.CacheStaleAnswerTTL, StaleResetTTL: configuration.CacheStaleResetTTL,
			PrefetchMinTTL: configuration.CachePrefetchMinimumTTL, PrefetchAtTTL: configuration.CachePrefetchTriggerTTL,
			PrefetchSample: configuration.CachePrefetchSample, PrefetchHits: configuration.CachePrefetchHitsPerHour,
		}),
		blockLists:          append([]BlockListStats(nil), configuration.BlockLists...),
		hosts:               hosts,
		zones:               zones,
		managedZones:        managedZones,
		tsigKeys:            tsigKeys,
		zoneCount:           zoneCount,
		dnssec:              validator,
		zoneInsecure:        zoneInsecure,
		managedTrustAnchors: configuration.DNSSECValidation && configuration.DNSSECTrustAnchorUpdates && len(configuration.DNSSECTrustAnchors) == 0,
	}, nil
}

func NewHandler(runtime *Runtime) *Handler {
	handler := &Handler{
		startedAt: time.Now(), upstreamExchange: exchangeForwarder,
		zoneTransfer: exchangeZoneTransfer, zoneRefresh: exchangeIncrementalZoneTransfer,
		zoneJournals: make(map[string][]zoneDelta), notifications: make(chan ZoneNotification, 256),
	}
	emptyExpired := make(map[string]struct{})
	handler.expiredZones.Store(&emptyExpired)
	handler.runtime.Store(runtime)
	return handler
}

func (handler *Handler) ExportCache() ([]PersistedResponse, error) {
	return handler.runtime.Load().cache.Export()
}

func (handler *Handler) RestoreCache(entries []PersistedResponse) (int, error) {
	return handler.runtime.Load().cache.Restore(entries)
}

func (handler *Handler) Activate(runtime *Runtime) {
	active := handler.runtime.Load()
	if active.upstreams == runtime.upstreams && active.cache.Compatible(runtime.cache) {
		runtime.cache = active.cache
		runtime.delegations = active.delegations
	}
	if runtime.managedTrustAnchors && runtime.dnssec != nil && handler.trustAnchorManager != nil {
		if anchors, initialized := handler.trustAnchorManager.ActiveAnchors(); initialized {
			runtime.dnssec.replaceManagedTrustPoint(".", anchors, len(anchors) == 0)
		}
	}
	handler.recordRuntimeChanges(active, runtime, time.Now())
	handler.runtime.Store(runtime)
}

// ActivateZones compiles only authoritative data and atomically swaps it into
// the active runtime. Blocking tables, hosts, DNSSEC validation state, and the
// response cache are reused, so a zone mutation does not rebuild large policy
// lists or put SQL on the DNS request path.
func (handler *Handler) ActivateZones(zones []AuthoritativeZone, keys []TSIGKey) error {
	active := handler.runtime.Load()
	compiled, err := Compile(RuntimeConfig{
		Mode:       active.mode,
		Forwarders: append([]string(nil), active.forwarders...),
		RootHints:  append([]string(nil), active.rootHints...),
		Routes:     cloneForwardingRoutes(active.baseRoutes),
		Timeout:    active.timeout,
		CacheSize:  active.cache.Capacity(),
		Zones:      zones,
		TSIGKeys:   keys,
	})
	if err != nil {
		return err
	}
	candidate := *active
	candidate.routes = compiled.routes
	candidate.zones = compiled.zones
	candidate.managedZones = compiled.managedZones
	candidate.tsigKeys = compiled.tsigKeys
	candidate.zoneCount = compiled.zoneCount
	candidate.zoneInsecure = compiled.zoneInsecure
	if candidate.dnssec != nil {
		candidate.dnssec.setZoneInsecure(compiled.zoneInsecure)
	}
	if !forwardingRouteMapsEqual(active.routes, candidate.routes) || !slices.Equal(active.zoneInsecure, candidate.zoneInsecure) {
		candidate.upstreams = active.upstreams + "|zone-routes=" + upstreamSignature(nil, candidate.routes) +
			"|zone-insecure=" + strings.Join(candidate.zoneInsecure, ",")
	}
	handler.Activate(&candidate)
	return nil
}

func forwardingRouteMapsEqual(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for domain, leftForwarders := range left {
		if !slices.Equal(leftForwarders, right[domain]) {
			return false
		}
	}
	return true
}

func cloneForwardingRoutes(routes []ForwardingRoute) []ForwardingRoute {
	cloned := make([]ForwardingRoute, len(routes))
	for index, route := range routes {
		cloned[index] = route
		cloned[index].Forwarders = append([]string(nil), route.Forwarders...)
	}
	return cloned
}

func (handler *Handler) SetTrustAnchorManager(manager *trustanchor.Manager) {
	handler.trustAnchorManager = manager
	if manager == nil {
		return
	}
	if anchors, initialized := manager.ActiveAnchors(); initialized {
		handler.ApplyManagedTrustAnchors(anchors, len(anchors) == 0)
	}
}

func (handler *Handler) DNSSECTrustAnchorUpdatesEnabled() bool {
	runtime := handler.runtime.Load()
	return runtime != nil && runtime.managedTrustAnchors
}

func (handler *Handler) ApplyManagedTrustAnchors(anchors []string, deleted bool) {
	for {
		active := handler.runtime.Load()
		if active == nil || !active.managedTrustAnchors || active.dnssec == nil {
			return
		}
		if active.dnssec.managedTrustPointEqual(".", anchors, deleted) {
			return
		}
		validator, err := newDNSSECValidator(anchors, active.dnssec.negativeAnchors)
		if err != nil {
			return
		}
		validator.setZoneInsecure(active.dnssec.zoneInsecureDomains())
		if deleted {
			validator.replaceManagedTrustPoint(".", nil, true)
		}
		candidate := *active
		candidate.dnssec = validator
		candidate.cache = NewResponseCache(active.cache.Capacity())
		if handler.runtime.CompareAndSwap(active, &candidate) {
			return
		}
	}
}

func (handler *Handler) DNSSECTrustAnchorQuery(ctx context.Context, name string, recordType uint16) (*dns.Msg, error) {
	runtime := handler.runtime.Load()
	if runtime == nil {
		return nil, errors.New("DNS runtime is unavailable")
	}
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), recordType)
	message.RecursionDesired = true
	message.CheckingDisabled = true
	message.SetEdns0(1232, true)
	forwarders, _ := runtime.forwardersFor(name)
	return handler.resolveNetworkContext(ctx, message, runtime, forwarders)
}

func (handler *Handler) SetQueryObserver(observer querylog.Observer) {
	if observer == nil {
		handler.observer.Store(nil)
		return
	}
	handler.observer.Store(&observerHolder{observer: observer})
}

func (handler *Handler) ServeDNS(writer dns.ResponseWriter, request *dns.Msg) {
	observer := handler.activeQueryObserver()
	var startedAt time.Time
	if observer != nil {
		startedAt = time.Now()
	}
	handler.queries.Add(1)
	runtime := handler.runtime.Load()
	if handler.serveDynamicUpdate(writer, request, runtime, observer, startedAt) {
		return
	}
	if handler.serveNotify(writer, request, runtime) {
		return
	}
	if handler.serveZoneTransfer(writer, request, runtime) {
		return
	}
	if len(request.Question) == 1 && handler.zoneExpired(request.Question[0].Name) {
		result := resolution{response: errorResponse(request, dns.RcodeServerFailure), source: querylog.SourceError}
		handler.recordResponseCode(result.response.Rcode)
		handler.writeResponse(writer, request, result.response)
		if observer != nil {
			handler.recordQuery(observer, writer, request, result, startedAt)
		}
		return
	}
	result := handler.resolveForClient(request, runtime, responseWriterClientIP(writer))
	handler.recordResponseCode(result.response.Rcode)
	handler.writeResponse(writer, request, result.response)
	if observer != nil {
		handler.recordQuery(observer, writer, request, result, startedAt)
	}
}

func (handler *Handler) serveZoneTransfer(writer dns.ResponseWriter, request *dns.Msg, runtime *Runtime) bool {
	if request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 {
		return false
	}
	question := request.Question[0]
	if question.Qtype != dns.TypeAXFR && question.Qtype != dns.TypeIXFR {
		return false
	}
	zone := runtime.zones[normalizeName(question.Name)]
	if zone == nil || !zone.transferAllowed(responseWriterClientIP(writer)) ||
		writer.LocalAddr() == nil || !strings.HasPrefix(writer.LocalAddr().Network(), "tcp") ||
		handler.zoneExpired(question.Name) {
		_ = writer.WriteMsg(errorResponse(request, dns.RcodeRefused))
		handler.refused.Add(1)
		return true
	}
	if !tsigRequestAuthenticated(writer, request, zone.tsigKey) {
		_ = writer.WriteMsg(errorResponse(request, dns.RcodeRefused))
		handler.refused.Add(1)
		return true
	}
	records := zone.transferRecords(time.Now())
	if question.Qtype == dns.TypeIXFR {
		records = handler.incrementalTransferRecords(request, zone.name, records)
	}
	if len(records) == 0 || (question.Qtype == dns.TypeAXFR && len(records) < 2) {
		_ = writer.WriteMsg(errorResponse(request, dns.RcodeServerFailure))
		handler.serverFailures.Add(1)
		return true
	}
	envelopes := make(chan *dns.Envelope, (len(records)+127)/128)
	for len(records) > 0 {
		count := min(128, len(records))
		envelopes <- &dns.Envelope{RR: records[:count]}
		records = records[count:]
	}
	close(envelopes)
	if err := new(dns.Transfer).Out(writer, request, envelopes); err != nil {
		handler.failures.Add(1)
		return true
	}
	handler.authoritativeAnswers.Add(1)
	handler.noError.Add(1)
	return true
}

func (zone *authoritativeZone) transferAllowed(client string) bool {
	address, err := netip.ParseAddr(client)
	if err != nil {
		return false
	}
	address = address.Unmap()
	switch zone.transferMode {
	case "allow":
		return true
	case "private":
		return address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast()
	case "acl":
		for _, prefix := range zone.transferACL {
			if prefix.Contains(address) {
				return true
			}
		}
	}
	return false
}

func (zone *authoritativeZone) transferRecords(now time.Time) []dns.RR {
	soa := cloneRecords(zone.soa, "", now)
	if len(soa) != 1 {
		return nil
	}
	body := make([]dns.RR, 0, len(zone.owners))
	for _, typed := range zone.records {
		for recordType, records := range typed {
			if recordType == dns.TypeSOA {
				continue
			}
			body = append(body, cloneRecords(records, "", now)...)
		}
	}
	slices.SortFunc(body, func(left, right dns.RR) int { return strings.Compare(left.String(), right.String()) })
	result := make([]dns.RR, 0, len(body)+2)
	result = append(result, soa[0])
	result = append(result, body...)
	result = append(result, dns.Copy(soa[0]))
	return result
}

func (handler *Handler) NotifyZone(ctx context.Context, zoneName string, targets []string) []error {
	auth := handler.transferAuth(zoneName, "")
	errorsByTarget := make([]error, 0)
	for _, target := range targets {
		message := new(dns.Msg)
		message.SetNotify(dns.Fqdn(zoneName))
		var response *dns.Msg
		var err error
		if auth.keyName == "" {
			response, err = handler.upstreamExchange(ctx, message, "udp://"+target, 2*time.Second)
		} else {
			message.SetTsig(auth.keyName, auth.algorithm, 300, time.Now().Unix())
			client := &dns.Client{
				Net: "udp", Timeout: 2 * time.Second,
				TsigSecret: map[string]string{auth.keyName: auth.secret},
			}
			response, _, err = client.ExchangeContext(ctx, message, target)
		}
		if err != nil {
			errorsByTarget = append(errorsByTarget, fmt.Errorf("%s: %w", target, err))
			continue
		}
		if response.Rcode != dns.RcodeSuccess {
			errorsByTarget = append(errorsByTarget, fmt.Errorf("%s returned %s", target, dns.RcodeToString[response.Rcode]))
		}
	}
	return errorsByTarget
}

func (handler *Handler) FetchZone(
	ctx context.Context,
	zoneName, zoneType string,
	primaries []string,
	protocol, tsigKeyName string,
) ([]ZoneRecord, error) {
	zoneName, err := dnsname.Normalize(zoneName)
	if err != nil {
		return nil, err
	}
	zoneType = strings.ToLower(strings.TrimSpace(zoneType))
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		if zoneType == "stub" {
			protocol = "udp"
		} else {
			protocol = "tcp"
		}
	}
	if len(primaries) == 0 {
		return nil, errors.New("at least one primary server is required")
	}
	timeout := handler.runtime.Load().timeout
	var failures []error
	auth := handler.transferAuth(zoneName, tsigKeyName)
	for _, primary := range primaries {
		var records []dns.RR
		if zoneType == "secondary" {
			records, err = handler.zoneTransfer(ctx, zoneName, primary, protocol, auth, timeout)
		} else if zoneType == "stub" {
			records, err = handler.fetchStubZone(ctx, zoneName, primary, protocol, timeout)
		} else {
			return nil, fmt.Errorf("zone type %q cannot be synchronized", zoneType)
		}
		if err == nil {
			return zoneRecordsFromRR(zoneName, records)
		}
		failures = append(failures, fmt.Errorf("%s: %w", primary, err))
	}
	return nil, fmt.Errorf("synchronize %s zone %q: %w", zoneType, zoneName, errors.Join(failures...))
}

func exchangeZoneTransfer(
	ctx context.Context,
	zoneName, primary, protocol string,
	auth transferAuth,
	timeout time.Duration,
) ([]dns.RR, error) {
	if protocol != "tcp" && protocol != "tls" {
		return nil, fmt.Errorf("AXFR protocol must be tcp or tls")
	}
	transfer := &dns.Transfer{DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout}
	if protocol == "tls" {
		host, _, err := net.SplitHostPort(primary)
		if err != nil {
			return nil, fmt.Errorf("TLS primary address: %w", err)
		}
		transfer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ServerName: strings.Trim(host, "[]")}
	}
	request := new(dns.Msg)
	request.SetAxfr(dns.Fqdn(zoneName))
	applyTransferTSIG(request, transfer, auth)
	envelopes, err := transfer.In(request, primary)
	if err != nil {
		return nil, err
	}
	defer transfer.Close()
	var records []dns.RR
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case envelope, open := <-envelopes:
			if !open {
				if len(records) < 2 || records[0].Header().Rrtype != dns.TypeSOA || records[len(records)-1].Header().Rrtype != dns.TypeSOA {
					return nil, errors.New("AXFR did not contain opening and closing SOA records")
				}
				return records[:len(records)-1], nil
			}
			if envelope.Error != nil {
				return nil, envelope.Error
			}
			records = append(records, envelope.RR...)
		}
	}
}

func (handler *Handler) fetchStubZone(
	ctx context.Context,
	zoneName, primary, protocol string,
	timeout time.Duration,
) ([]dns.RR, error) {
	endpoint := protocol + "://" + primary
	var records []dns.RR
	for _, recordType := range []uint16{dns.TypeSOA, dns.TypeNS} {
		request := new(dns.Msg)
		request.SetQuestion(dns.Fqdn(zoneName), recordType)
		response, err := handler.upstreamExchange(ctx, request, endpoint, timeout)
		if err != nil {
			return nil, err
		}
		if response.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("%s query returned %s", dns.TypeToString[recordType], dns.RcodeToString[response.Rcode])
		}
		for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
			for _, record := range section {
				if record.Header().Rrtype == recordType || record.Header().Rrtype == dns.TypeA || record.Header().Rrtype == dns.TypeAAAA {
					records = append(records, record)
				}
			}
		}
	}
	return uniqueZoneRR(records), nil
}

func uniqueZoneRR(records []dns.RR) []dns.RR {
	seen := make(map[string]struct{}, len(records))
	result := make([]dns.RR, 0, len(records))
	for _, record := range records {
		key := strings.ToLower(record.String())
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, record)
	}
	return result
}

func zoneRecordsFromRR(zoneName string, records []dns.RR) ([]ZoneRecord, error) {
	result := make([]ZoneRecord, 0, len(records))
	for _, record := range uniqueZoneRR(records) {
		owner := normalizeName(record.Header().Name)
		if owner != zoneName && !strings.HasSuffix(owner, "."+zoneName) {
			continue
		}
		name := "@"
		if owner != zoneName {
			name = strings.TrimSuffix(owner, "."+zoneName)
		}
		fields := strings.Fields(record.String())
		if len(fields) < 5 {
			return nil, fmt.Errorf("invalid transferred record %q", record.String())
		}
		result = append(result, ZoneRecord{
			Name: name, Type: dns.TypeToString[record.Header().Rrtype],
			Value: strings.Join(fields[4:], " "), TTL: record.Header().Ttl,
		})
	}
	return result, nil
}

func (handler *Handler) recordResponseCode(code int) {
	switch code {
	case dns.RcodeSuccess:
		handler.noError.Add(1)
	case dns.RcodeServerFailure:
		handler.serverFailures.Add(1)
	case dns.RcodeNameError:
		handler.nxDomain.Add(1)
	case dns.RcodeRefused:
		handler.refused.Add(1)
	}
}

func (handler *Handler) resolve(request *dns.Msg, runtime *Runtime) resolution {
	return handler.resolveForClient(request, runtime, "")
}

func (handler *Handler) resolveForClient(request *dns.Msg, runtime *Runtime, clientIP string) resolution {
	if len(request.Question) == 0 {
		return resolution{response: errorResponse(request, dns.RcodeFormatError), source: querylog.SourceError}
	}
	if response, found := handler.resolveANAME(request, runtime); found {
		handler.authoritativeAnswers.Add(1)
		return resolution{response: response, source: querylog.SourceAuthoritative}
	}
	if response, found := runtime.authoritativeResponse(request); found {
		handler.authoritativeAnswers.Add(1)
		return resolution{response: response, source: querylog.SourceAuthoritative}
	}
	if response, found := runtime.localResponse(request); found {
		handler.localAnswers.Add(1)
		return resolution{response: response, source: querylog.SourceLocal}
	}

	if runtime.blocking && !handler.BlockingPaused() && !runtime.clientBypasses(clientIP) &&
		!runtime.matchesAllowed(request.Question[0].Name) && runtime.matchesBlocked(request.Question[0].Name) {
		handler.blocked.Add(1)
		return resolution{response: runtime.blockedResponse(request), source: querylog.SourceBlocked}
	}
	if response, found, prefetch := runtime.cache.GetWithPrefetch(request); found {
		handler.cacheHits.Add(1)
		if prefetch {
			handler.prefetch(request, runtime)
		}
		return resolution{response: response, source: querylog.SourceCache}
	}
	handler.cacheMisses.Add(1)

	forwarders, routed := runtime.forwardersFor(request.Question[0].Name)
	if routed {
		handler.routedQueries.Add(1)
	}
	if runtime.staleMaxWait > 0 && runtime.cache.HasStale(request) {
		return handler.resolveWithStaleWait(request, runtime, forwarders)
	}
	return handler.resolveLiveUpstream(request, runtime, forwarders, true)
}

func (handler *Handler) resolveWithStaleWait(request *dns.Msg, runtime *Runtime, forwarders []string) resolution {
	result := make(chan resolution, 1)
	go func() {
		result <- handler.resolveLiveUpstream(request.Copy(), runtime, forwarders, false)
	}()
	timer := time.NewTimer(runtime.staleMaxWait)
	defer timer.Stop()
	select {
	case resolved := <-result:
		if resolved.transientFailure {
			return handler.resolveUpstreamFailure(request, runtime)
		}
		return resolved
	case <-timer.C:
		if response, found := runtime.cache.GetStale(request); found {
			handler.cacheHits.Add(1)
			prepareResponseForClient(response, request)
			return resolution{response: response, source: querylog.SourceCache}
		}
		return <-result
	}
}

func (handler *Handler) resolveLiveUpstream(request *dns.Msg, runtime *Runtime, forwarders []string, staleFallback bool) resolution {
	response, validation, validationErr := handler.resolveUpstream(request, runtime, forwarders)
	if validation == validationBogus {
		handler.dnssecBogus.Add(1)
		if !request.CheckingDisabled {
			return resolution{response: dnssecBogusResponse(request, validationErr), source: querylog.SourceError}
		}
	} else if validation == validationSecure {
		handler.dnssecSecure.Add(1)
	} else if validation == validationInsecure {
		handler.dnssecInsecure.Add(1)
	}
	if validationErr != nil && validation != validationBogus {
		handler.upstreamErrors.Add(1)
		if !staleFallback {
			return resolution{response: errorResponse(request, fallbackErrorCode), source: querylog.SourceError, transientFailure: true}
		}
		return handler.resolveUpstreamFailure(request, runtime)
	}
	if response == nil {
		handler.upstreamErrors.Add(1)
		if !staleFallback {
			return resolution{response: errorResponse(request, fallbackErrorCode), source: querylog.SourceError, transientFailure: true}
		}
		return handler.resolveUpstreamFailure(request, runtime)
	}
	response.Id = request.Id
	response.Question = append(response.Question[:0], request.Question...)
	response.CheckingDisabled = request.CheckingDisabled
	response.AuthenticatedData = validation == validationSecure
	// CD is a diagnostic escape hatch, not permission to poison the shared
	// cache with data that failed validation for every other client.
	if validation != validationBogus {
		runtime.cache.Set(request, response)
	}
	prepareResponseForClient(response, request)
	return resolution{response: response, source: querylog.SourceUpstream}
}

func (handler *Handler) prefetch(request *dns.Msg, runtime *Runtime) {
	request = request.Copy()
	go func() {
		forwarders, _ := runtime.forwardersFor(request.Question[0].Name)
		response, validation, err := handler.resolveUpstream(request, runtime, forwarders)
		if err != nil || response == nil || validation == validationBogus {
			runtime.cache.CancelPrefetch(request)
			return
		}
		response.Id = request.Id
		response.Question = append(response.Question[:0], request.Question...)
		response.CheckingDisabled = request.CheckingDisabled
		response.AuthenticatedData = validation == validationSecure
		if !runtime.cache.Set(request, response) {
			runtime.cache.CancelPrefetch(request)
		}
	}()
}

func (handler *Handler) resolveUpstreamFailure(request *dns.Msg, runtime *Runtime) resolution {
	if response, found := runtime.cache.GetStale(request); found {
		handler.cacheHits.Add(1)
		prepareResponseForClient(response, request)
		return resolution{response: response, source: querylog.SourceCache}
	}
	response := errorResponse(request, fallbackErrorCode)
	runtime.cache.Set(request, response)
	return resolution{response: response, source: querylog.SourceError}
}

func (handler *Handler) resolveANAME(request *dns.Msg, runtime *Runtime) (*dns.Msg, bool) {
	alias, found := runtime.authoritativeANAMEFor(request)
	if !found {
		return nil, false
	}
	if response, cached := runtime.cache.Get(request); cached {
		handler.cacheHits.Add(1)
		response.Authoritative = true
		return response, true
	}
	handler.cacheMisses.Add(1)
	targetRequest := request.Copy()
	targetRequest.Question[0].Name = dns.Fqdn(alias.target)
	targetResponse, local := runtime.authoritativeResponse(targetRequest)
	if !local {
		forwarders, routed := runtime.forwardersFor(alias.target)
		if routed {
			handler.routedQueries.Add(1)
		}
		var err error
		var validation validationState
		targetResponse, validation, err = handler.resolveUpstream(targetRequest, runtime, forwarders)
		if err != nil {
			handler.upstreamErrors.Add(1)
			return errorResponse(request, fallbackErrorCode), true
		}
		if validation == validationBogus {
			handler.dnssecBogus.Add(1)
			return dnssecBogusResponse(request, errors.New("ANAME target failed DNSSEC validation")), true
		}
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	response.RecursionAvailable = true
	if targetResponse.Rcode != dns.RcodeSuccess {
		response.Rcode = dns.RcodeServerFailure
		return response, true
	}
	for _, answer := range targetResponse.Answer {
		typeCode := answer.Header().Rrtype
		if typeCode != request.Question[0].Qtype || (typeCode != dns.TypeA && typeCode != dns.TypeAAAA) {
			continue
		}
		clone := dns.Copy(answer)
		clone.Header().Name = request.Question[0].Name
		clone.Header().Ttl = min(clone.Header().Ttl, alias.ttl)
		response.Answer = append(response.Answer, clone)
	}
	if len(response.Answer) == 0 {
		if zone := runtime.authoritativeZoneFor(normalizeName(request.Question[0].Name)); zone != nil {
			response.Ns = cloneRecords(zone.soa, "", time.Now())
		}
	}
	runtime.cache.Set(request, response)
	return response, true
}

func (handler *Handler) PauseBlocking(duration time.Duration) time.Time {
	until := time.Now().Add(duration)
	handler.pausedUntil.Store(until.UnixNano())
	return until
}

func (handler *Handler) ResumeBlocking() { handler.pausedUntil.Store(0) }

func (handler *Handler) BlockingPausedUntil() time.Time {
	value := handler.pausedUntil.Load()
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value)
}

func (handler *Handler) BlockingPaused() bool {
	until := handler.BlockingPausedUntil()
	if until.IsZero() || !time.Now().Before(until) {
		if !until.IsZero() {
			handler.pausedUntil.CompareAndSwap(until.UnixNano(), 0)
		}
		return false
	}
	return true
}

func (handler *Handler) Stats() Stats {
	runtime := handler.runtime.Load()
	anchorStatus := trustanchor.Status{}
	if runtime.managedTrustAnchors && handler.trustAnchorManager != nil {
		anchorStatus = handler.trustAnchorManager.Status()
	}
	return Stats{
		Queries:                  handler.queries.Load(),
		NoError:                  handler.noError.Load(),
		ServerFailures:           handler.serverFailures.Load(),
		NXDomain:                 handler.nxDomain.Load(),
		Refused:                  handler.refused.Load(),
		Blocked:                  handler.blocked.Load(),
		Failures:                 handler.failures.Load(),
		UpstreamErrors:           handler.upstreamErrors.Load(),
		CacheHits:                handler.cacheHits.Load(),
		CacheMisses:              handler.cacheMisses.Load(),
		CacheEntries:             runtime.cache.Len(),
		RoutedQueries:            handler.routedQueries.Load(),
		LocalAnswers:             handler.localAnswers.Load(),
		AuthoritativeAnswers:     handler.authoritativeAnswers.Load(),
		LocalHosts:               len(runtime.hosts),
		Zones:                    runtime.zoneCount,
		BlockedDomains:           len(runtime.blocked),
		BlockLists:               len(runtime.blockLists),
		BlockSources:             append([]BlockListStats(nil), runtime.blockLists...),
		StartedAt:                handler.startedAt,
		DNSSECSecure:             handler.dnssecSecure.Load(),
		DNSSECInsecure:           handler.dnssecInsecure.Load(),
		DNSSECBogus:              handler.dnssecBogus.Load(),
		DNSSECTrustAnchorUpdates: runtime.managedTrustAnchors,
		DNSSECTrustAnchors:       anchorStatus,
	}
}

func authoritativeOwner(zoneName, recordName string) (string, error) {
	recordName = strings.TrimSpace(strings.ToLower(recordName))
	if recordName == "" || recordName == "@" {
		return zoneName, nil
	}
	absolute := strings.HasSuffix(recordName, ".")
	recordName = strings.TrimSuffix(recordName, ".")
	normalized, err := dnsname.NormalizeOwner(recordName)
	if err != nil {
		return "", err
	}
	if absolute {
		return normalized, nil
	}
	if normalized == zoneName || strings.HasSuffix(normalized, "."+zoneName) {
		return normalized, nil
	}
	return normalized + "." + zoneName, nil
}

func (runtime *Runtime) authoritativeResponse(request *dns.Msg) (*dns.Msg, bool) {
	if request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 {
		return nil, false
	}
	question := request.Question[0]
	if question.Qclass != dns.ClassINET && question.Qclass != dns.ClassANY {
		return nil, false
	}
	queryName := normalizeName(question.Name)
	zone := runtime.authoritativeZoneFor(queryName)
	if zone == nil {
		return nil, false
	}
	if zone.forwards(queryName) {
		return nil, false
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	response.RecursionAvailable = true
	now := time.Now()
	records := zone.records[queryName]
	wildcardOwner := ""
	if !hasActiveRecords(records, now) {
		if _, ownerExists := zone.owners[queryName]; ownerExists {
			records = map[uint16][]authoritativeRecord{}
		} else {
			records, wildcardOwner = zone.wildcardRecords(queryName, now)
		}
	}
	if records == nil {
		response.Rcode = dns.RcodeNameError
		response.Ns = cloneRecords(zone.soa, "", now)
		if requestWantsDNSSEC(request) && zone.signed {
			response.Ns = append(response.Ns, zone.signaturesFor(zone.name, dns.TypeSOA, "", now)...)
			response.Ns = append(response.Ns, zone.negativeProof(queryName, false, now)...)
		}
		return response, true
	}
	if question.Qtype == dns.TypeANY {
		for _, typed := range records {
			response.Answer = append(response.Answer, cloneRecords(typed, queryName, now)...)
		}
	} else {
		response.Answer = append(response.Answer, cloneRecords(records[question.Qtype], queryName, now)...)
		if question.Qtype != dns.TypeCNAME && len(response.Answer) == 0 {
			response.Answer = append(response.Answer, cloneRecords(records[dns.TypeCNAME], queryName, now)...)
		}
	}
	if len(response.Answer) == 0 {
		response.Ns = cloneRecords(zone.soa, "", now)
		if requestWantsDNSSEC(request) && zone.signed {
			response.Ns = append(response.Ns, zone.signaturesFor(zone.name, dns.TypeSOA, "", now)...)
			if wildcardOwner != "" {
				response.Ns = append(response.Ns, zone.wildcardNoDataProof(queryName, wildcardOwner, now)...)
			} else {
				response.Ns = append(response.Ns, zone.negativeProof(queryName, true, now)...)
			}
		}
	} else if requestWantsDNSSEC(request) && zone.signed && question.Qtype != dns.TypeRRSIG && question.Qtype != dns.TypeANY {
		covered := make(map[string]struct{})
		for _, answer := range response.Answer {
			key := signingRecordKey(answer.Header().Name, answer.Header().Rrtype)
			if _, exists := covered[key]; exists || answer.Header().Rrtype == dns.TypeRRSIG {
				continue
			}
			covered[key] = struct{}{}
			response.Answer = append(response.Answer, zone.signaturesFor(normalizeName(answer.Header().Name), answer.Header().Rrtype, queryName, now)...)
		}
		if wildcardOwner != "" {
			response.Ns = append(response.Ns, zone.wildcardAnswerProof(queryName, now)...)
		}
	}
	return response, true
}

func requestWantsDNSSEC(request *dns.Msg) bool {
	option := request.IsEdns0()
	return option != nil && option.Do()
}

func signingRecordKey(owner string, recordType uint16) string {
	return strings.ToLower(dns.Fqdn(owner)) + "/" + fmt.Sprint(recordType)
}

func (zone *authoritativeZone) signaturesFor(owner string, coveredType uint16, responseOwner string, now time.Time) []dns.RR {
	owner = normalizeName(owner)
	records := zone.records[owner][dns.TypeRRSIG]
	if len(records) == 0 && responseOwner != "" {
		for current := owner; current != zone.name; {
			separator := strings.IndexByte(current, '.')
			if separator < 0 {
				break
			}
			current = current[separator+1:]
			if wildcard := zone.records["*."+current][dns.TypeRRSIG]; len(wildcard) > 0 {
				records = wildcard
				break
			}
		}
	}
	result := make([]dns.RR, 0, 1)
	for _, record := range records {
		if !record.expiresAt.IsZero() && !record.expiresAt.After(now) {
			continue
		}
		signature, ok := record.record.(*dns.RRSIG)
		if !ok || signature.TypeCovered != coveredType {
			continue
		}
		clone := dns.Copy(signature)
		if responseOwner != "" && strings.HasPrefix(clone.Header().Name, "*.") {
			clone.Header().Name = dns.Fqdn(responseOwner)
		}
		result = append(result, clone)
	}
	return result
}

func (zone *authoritativeZone) negativeProof(name string, nameExists bool, now time.Time) []dns.RR {
	if len(zone.nsec3s) > 0 {
		return zone.negativeNSEC3Proof(name, nameExists, now)
	}
	proofs := make([]dns.RR, 0, 4)
	seen := make(map[string]struct{})
	addProof := func(record dns.RR) {
		if record == nil {
			return
		}
		owner := normalizeName(record.Header().Name)
		if _, duplicate := seen[owner]; duplicate {
			return
		}
		seen[owner] = struct{}{}
		proofs = append(proofs, dns.Copy(record))
		proofs = append(proofs, zone.signaturesFor(owner, dns.TypeNSEC, "", now)...)
	}
	if nameExists {
		addProof(zone.nsecAt(name, now))
		return proofs
	}
	addProof(zone.nsecCovering(name, now))
	closest := zone.name
	for current := name; current != zone.name; {
		separator := strings.IndexByte(current, '.')
		if separator < 0 {
			break
		}
		current = current[separator+1:]
		if _, exists := zone.owners[current]; exists {
			closest = current
			break
		}
	}
	addProof(zone.nsecCovering("*."+closest, now))
	return proofs
}

func (zone *authoritativeZone) negativeNSEC3Proof(name string, nameExists bool, now time.Time) []dns.RR {
	proofs := make([]dns.RR, 0, 6)
	seen := make(map[string]struct{})
	addProof := func(record dns.RR) {
		if record == nil {
			return
		}
		owner := normalizeName(record.Header().Name)
		if _, duplicate := seen[owner]; duplicate {
			return
		}
		seen[owner] = struct{}{}
		proofs = append(proofs, dns.Copy(record))
		proofs = append(proofs, zone.signaturesFor(owner, dns.TypeNSEC3, "", now)...)
	}
	if nameExists {
		addProof(zone.nsec3At(name, now))
		return proofs
	}
	closest := zone.closestEncloser(name)
	addProof(zone.nsec3At(closest, now))
	addProof(zone.nsec3Covering(nextCloserName(name, closest), now))
	addProof(zone.nsec3Covering("*."+closest, now))
	return proofs
}

func (zone *authoritativeZone) wildcardNoDataProof(name, wildcardOwner string, now time.Time) []dns.RR {
	if len(zone.nsec3s) > 0 {
		return zone.wildcardNSEC3NoDataProof(name, wildcardOwner, now)
	}
	proofs := make([]dns.RR, 0, 4)
	for _, record := range []dns.RR{zone.nsecCovering(name, now), zone.nsecAt(wildcardOwner, now)} {
		if record == nil {
			continue
		}
		owner := normalizeName(record.Header().Name)
		if slices.ContainsFunc(proofs, func(existing dns.RR) bool { return normalizeName(existing.Header().Name) == owner }) {
			continue
		}
		proofs = append(proofs, dns.Copy(record))
		proofs = append(proofs, zone.signaturesFor(owner, dns.TypeNSEC, "", now)...)
	}
	return proofs
}

func (zone *authoritativeZone) wildcardAnswerProof(name string, now time.Time) []dns.RR {
	proofs := make([]dns.RR, 0, 4)
	addProof := func(record dns.RR, recordType uint16) {
		if record == nil {
			return
		}
		owner := normalizeName(record.Header().Name)
		if slices.ContainsFunc(proofs, func(existing dns.RR) bool { return normalizeName(existing.Header().Name) == owner }) {
			return
		}
		proofs = append(proofs, dns.Copy(record))
		proofs = append(proofs, zone.signaturesFor(owner, recordType, "", now)...)
	}
	if len(zone.nsec3s) == 0 {
		addProof(zone.nsecCovering(name, now), dns.TypeNSEC)
		return proofs
	}
	closest := zone.closestEncloser(name)
	addProof(zone.nsec3At(closest, now), dns.TypeNSEC3)
	addProof(zone.nsec3Covering(nextCloserName(name, closest), now), dns.TypeNSEC3)
	return proofs
}

func (zone *authoritativeZone) wildcardNSEC3NoDataProof(name, wildcardOwner string, now time.Time) []dns.RR {
	proofs := make([]dns.RR, 0, 4)
	seen := make(map[string]struct{})
	for _, record := range []dns.RR{zone.nsec3Covering(name, now), zone.nsec3At(wildcardOwner, now)} {
		if record == nil {
			continue
		}
		owner := normalizeName(record.Header().Name)
		if _, duplicate := seen[owner]; duplicate {
			continue
		}
		seen[owner] = struct{}{}
		proofs = append(proofs, dns.Copy(record))
		proofs = append(proofs, zone.signaturesFor(owner, dns.TypeNSEC3, "", now)...)
	}
	return proofs
}

func (zone *authoritativeZone) closestEncloser(name string) string {
	for current := normalizeName(name); ; {
		if _, exists := zone.owners[current]; exists {
			return current
		}
		if current == zone.name {
			return zone.name
		}
		separator := strings.IndexByte(current, '.')
		if separator < 0 {
			return zone.name
		}
		current = current[separator+1:]
	}
}

func nextCloserName(name, closest string) string {
	current := normalizeName(name)
	for current != closest {
		separator := strings.IndexByte(current, '.')
		if separator < 0 || current[separator+1:] == closest {
			return current
		}
		current = current[separator+1:]
	}
	return current
}

func (zone *authoritativeZone) nsec3At(name string, now time.Time) dns.RR {
	name = dns.Fqdn(normalizeName(name))
	for _, record := range zone.nsec3s {
		if !record.expiresAt.IsZero() && !record.expiresAt.After(now) {
			continue
		}
		if nsec3, ok := record.record.(*dns.NSEC3); ok && nsec3.Match(name) {
			return nsec3
		}
	}
	return nil
}

func (zone *authoritativeZone) nsec3Covering(name string, now time.Time) dns.RR {
	name = dns.Fqdn(normalizeName(name))
	for _, record := range zone.nsec3s {
		if !record.expiresAt.IsZero() && !record.expiresAt.After(now) {
			continue
		}
		if nsec3, ok := record.record.(*dns.NSEC3); ok && nsec3.Cover(name) {
			return nsec3
		}
	}
	return nil
}

func (zone *authoritativeZone) nsecAt(name string, now time.Time) dns.RR {
	for _, record := range zone.records[normalizeName(name)][dns.TypeNSEC] {
		if record.expiresAt.IsZero() || record.expiresAt.After(now) {
			return record.record
		}
	}
	return nil
}

func (zone *authoritativeZone) nsecCovering(name string, now time.Time) dns.RR {
	name = dns.Fqdn(normalizeName(name))
	for _, record := range zone.nsecs {
		if !record.expiresAt.IsZero() && !record.expiresAt.After(now) {
			continue
		}
		nsec, ok := record.record.(*dns.NSEC)
		if !ok {
			continue
		}
		ownerCompared := compareCanonicalWireName(nsec.Hdr.Name, name)
		nextCompared := compareCanonicalWireName(name, nsec.NextDomain)
		ownerToNext := compareCanonicalWireName(nsec.Hdr.Name, nsec.NextDomain)
		if (ownerToNext < 0 && ownerCompared < 0 && nextCompared < 0) ||
			(ownerToNext >= 0 && (ownerCompared < 0 || nextCompared < 0)) {
			return nsec
		}
	}
	return nil
}

func compareCanonicalWireName(left, right string) int {
	leftLabels := dns.SplitDomainName(strings.ToLower(left))
	rightLabels := dns.SplitDomainName(strings.ToLower(right))
	for leftIndex, rightIndex := len(leftLabels)-1, len(rightLabels)-1; leftIndex >= 0 && rightIndex >= 0; leftIndex, rightIndex = leftIndex-1, rightIndex-1 {
		if compared := strings.Compare(leftLabels[leftIndex], rightLabels[rightIndex]); compared != 0 {
			return compared
		}
	}
	return len(leftLabels) - len(rightLabels)
}

func (zone *authoritativeZone) forwards(name string) bool {
	for current := name; current != ""; {
		if len(zone.forwarders[current]) != 0 {
			return true
		}
		if current == zone.name {
			return false
		}
		separator := strings.IndexByte(current, '.')
		if separator < 0 {
			return false
		}
		current = current[separator+1:]
	}
	return false
}

func (runtime *Runtime) authoritativeANAMEFor(request *dns.Msg) (authoritativeANAME, bool) {
	if request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 {
		return authoritativeANAME{}, false
	}
	question := request.Question[0]
	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return authoritativeANAME{}, false
	}
	queryName := normalizeName(question.Name)
	zone := runtime.authoritativeZoneFor(queryName)
	if zone == nil {
		return authoritativeANAME{}, false
	}
	now := time.Now()
	for _, alias := range zone.anames[queryName] {
		if alias.expiresAt.IsZero() || alias.expiresAt.After(now) {
			return alias, true
		}
	}
	return authoritativeANAME{}, false
}

func (runtime *Runtime) authoritativeZoneFor(name string) *authoritativeZone {
	for current := name; current != ""; {
		if zone := runtime.zones[current]; zone != nil {
			return zone
		}
		separator := strings.IndexByte(current, '.')
		if separator < 0 {
			return nil
		}
		current = current[separator+1:]
	}
	return nil
}

func (zone *authoritativeZone) wildcardRecords(name string, now time.Time) (map[uint16][]authoritativeRecord, string) {
	for current := name; current != zone.name; {
		separator := strings.IndexByte(current, '.')
		if separator < 0 {
			return nil, ""
		}
		current = current[separator+1:]
		if records := zone.records["*."+current]; hasActiveRecords(records, now) {
			return records, "*." + current
		}
	}
	return nil, ""
}

func hasActiveRecords(records map[uint16][]authoritativeRecord, now time.Time) bool {
	for _, typed := range records {
		for _, record := range typed {
			if record.expiresAt.IsZero() || record.expiresAt.After(now) {
				return true
			}
		}
	}
	return false
}

func cloneRecords(records []authoritativeRecord, owner string, now time.Time) []dns.RR {
	clones := make([]dns.RR, 0, len(records))
	for _, record := range records {
		if !record.expiresAt.IsZero() && !record.expiresAt.After(now) {
			continue
		}
		clone := dns.Copy(record.record)
		if owner != "" && strings.HasPrefix(clone.Header().Name, "*.") {
			clone.Header().Name = dns.Fqdn(owner)
		}
		clones = append(clones, clone)
	}
	return clones
}

func (runtime *Runtime) localResponse(request *dns.Msg) (*dns.Msg, bool) {
	if request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 {
		return nil, false
	}
	question := request.Question[0]
	if question.Qclass != dns.ClassINET {
		return nil, false
	}
	records, found := runtime.localHostFor(question.Name)
	if !found {
		return nil, false
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.RecursionAvailable = true
	switch question.Qtype {
	case dns.TypeA:
		response.Answer = append(response.Answer, records.ipv4...)
	case dns.TypeAAAA:
		response.Answer = append(response.Answer, records.ipv6...)
	case dns.TypeANY:
		response.Answer = append(response.Answer, records.ipv4...)
		response.Answer = append(response.Answer, records.ipv6...)
	}
	return response, true
}

func (runtime *Runtime) localHostFor(name string) (localHostRecords, bool) {
	records, found := runtime.hosts[normalizeName(name)]
	return records, found
}

func (handler *Handler) PurgeCache() int {
	return handler.runtime.Load().cache.Clear()
}

func (handler *Handler) CachedResponses() []CachedResponse {
	return handler.runtime.Load().cache.Snapshot()
}

func (handler *Handler) writeResponse(writer dns.ResponseWriter, request, response *dns.Msg) {
	localAddress := writer.LocalAddr()
	if localAddress != nil && strings.HasPrefix(localAddress.Network(), "udp") {
		maximumSize := minimumDNSUDPSize
		if option := request.IsEdns0(); option != nil {
			maximumSize = int(option.UDPSize())
		}
		response.Truncate(maximumSize)
	}
	if err := writer.WriteMsg(response); err != nil {
		handler.failures.Add(1)
	}
}

func (handler *Handler) recordQuery(
	observer querylog.Observer,
	writer dns.ResponseWriter,
	request *dns.Msg,
	result resolution,
	startedAt time.Time,
) {
	if len(request.Question) == 0 {
		return
	}
	question := request.Question[0]
	observer.Record(querylog.Event{
		OccurredAt:   startedAt,
		ClientIP:     responseWriterClientIP(writer),
		Name:         normalizeName(question.Name),
		RecordType:   question.Qtype,
		Class:        question.Qclass,
		ResponseCode: result.response.Rcode,
		Source:       result.source,
		Protocol:     queryProtocol(writer),
		Answer:       queryAnswer(result.response),
		Duration:     time.Since(startedAt),
	})
}

func queryProtocol(writer dns.ResponseWriter) string {
	if marked, ok := writer.(interface{ QueryProtocol() string }); ok {
		return marked.QueryProtocol()
	}
	if _, ok := writer.(*dohResponseWriter); ok {
		return "HTTPS"
	}
	if address := writer.LocalAddr(); address != nil {
		network := strings.ToLower(address.Network())
		if strings.HasPrefix(network, "udp") {
			return "UDP"
		}
		if strings.HasPrefix(network, "tcp") {
			return "TCP"
		}
	}
	return ""
}

func queryAnswer(response *dns.Msg) string {
	if response == nil || len(response.Answer) == 0 {
		return ""
	}
	const maximumAnswerBytes = 16 << 10
	var result strings.Builder
	for index, record := range response.Answer {
		if index == 64 {
			break
		}
		fields := strings.Fields(record.String())
		if len(fields) < 4 {
			continue
		}
		value := strings.Join(fields[3:], " ")
		if result.Len()+len(value)+1 > maximumAnswerBytes {
			break
		}
		if result.Len() > 0 {
			result.WriteByte('\n')
		}
		result.WriteString(value)
	}
	return result.String()
}

func (handler *Handler) activeQueryObserver() querylog.Observer {
	holder := handler.observer.Load()
	if holder == nil || !holder.observer.Enabled() {
		return nil
	}
	return holder.observer
}

func (handler *Handler) exchange(request *dns.Msg, runtime *Runtime, forwarders []string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runtime.timeout)
	defer cancel()
	return handler.exchangeContext(ctx, request, runtime, forwarders)
}

func (handler *Handler) exchangeContext(ctx context.Context, request *dns.Msg, runtime *Runtime, forwarders []string) (*dns.Msg, error) {
	if len(forwarders) == 0 {
		return nil, errors.New("no forwarding endpoints are available")
	}
	start := handler.upstreamIndex.Add(1) - 1
	attemptTimeout := max(runtime.timeout/time.Duration(len(forwarders)), time.Nanosecond)
	var exchangeErrors []error
	for offset := range len(forwarders) {
		forwarder := forwarders[(start+uint64(offset))%uint64(len(forwarders))]
		attemptContext, stopAttempt := context.WithTimeout(ctx, attemptTimeout)
		response, err := handler.upstreamExchange(attemptContext, request, forwarder, attemptTimeout)
		stopAttempt()
		if err == nil {
			return response, nil
		}
		exchangeErrors = append(exchangeErrors, fmt.Errorf("%s: %w", forwarder, err))
	}
	return nil, fmt.Errorf("all forwarders failed: %w", errors.Join(exchangeErrors...))
}

func (handler *Handler) resolveUpstream(request *dns.Msg, runtime *Runtime, forwarders []string) (*dns.Msg, validationState, error) {
	if runtime.dnssec == nil {
		response, err := handler.resolveNetwork(request, runtime, forwarders)
		if response != nil {
			response.AuthenticatedData = false
		}
		return response, validationIndeterminate, err
	}
	upstreamRequest := dnssecUpstreamRequest(request)
	response, err := handler.resolveNetwork(upstreamRequest, runtime, forwarders)
	if err != nil {
		return nil, validationIndeterminate, err
	}
	validationContext, cancel := context.WithTimeout(context.Background(), max(4*runtime.timeout, 2*time.Second))
	defer cancel()
	query := func(ctx context.Context, name string, recordType uint16) (*dns.Msg, error) {
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(name), recordType)
		message.RecursionDesired = true
		message.CheckingDisabled = true
		message.SetEdns0(1232, true)
		queryForwarders, _ := runtime.forwardersFor(name)
		return handler.resolveNetworkContext(ctx, message, runtime, queryForwarders)
	}
	state, validationErr := runtime.dnssec.validate(validationContext, response, request.Question[0], query)
	return response, state, validationErr
}

func dnssecUpstreamRequest(request *dns.Msg) *dns.Msg {
	message := request.Copy()
	message.AuthenticatedData = false
	message.CheckingDisabled = true
	option := message.IsEdns0()
	if option == nil {
		message.SetEdns0(1232, true)
	} else {
		option.SetDo()
		if option.UDPSize() < 1232 {
			option.SetUDPSize(1232)
		}
	}
	return message
}

func prepareResponseForClient(response, request *dns.Msg) {
	response.AuthenticatedData = response.AuthenticatedData && (request.AuthenticatedData || requestWantsDNSSEC(request))
	response.CheckingDisabled = request.CheckingDisabled
	requestOption := request.IsEdns0()
	if requestOption == nil {
		response.Extra = slices.DeleteFunc(response.Extra, func(record dns.RR) bool {
			return record.Header().Rrtype == dns.TypeOPT
		})
	} else if responseOption := response.IsEdns0(); responseOption != nil {
		responseOption.SetDo(requestOption.Do())
	}
	if requestWantsDNSSEC(request) {
		return
	}
	explicitType := uint16(0)
	if len(request.Question) > 0 {
		explicitType = request.Question[0].Qtype
	}
	strip := func(records []dns.RR) []dns.RR {
		return slices.DeleteFunc(records, func(record dns.RR) bool {
			return isDNSSECAuthenticationType(record.Header().Rrtype) && record.Header().Rrtype != explicitType
		})
	}
	response.Answer = strip(response.Answer)
	response.Ns = strip(response.Ns)
	response.Extra = strip(response.Extra)
}

func isDNSSECAuthenticationType(recordType uint16) bool {
	switch recordType {
	case dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeCDS, dns.TypeCDNSKEY:
		return true
	default:
		return false
	}
}

func dnssecBogusResponse(request *dns.Msg, validationErr error) *dns.Msg {
	response := errorResponse(request, dns.RcodeServerFailure)
	response.RecursionAvailable = true
	option := request.IsEdns0()
	if option == nil {
		return response
	}
	response.SetEdns0(option.UDPSize(), requestWantsDNSSEC(request))
	extra := "DNSSEC validation failed"
	if validationErr != nil {
		extra = validationErr.Error()
	}
	if len(extra) > 180 {
		extra = extra[:180]
	}
	response.IsEdns0().Option = append(response.IsEdns0().Option, &dns.EDNS0_EDE{
		InfoCode: dns.ExtendedErrorCodeDNSBogus, ExtraText: extra,
	})
	return response
}

func dnssecRuntimeSignature(configuration RuntimeConfig) string {
	return fmt.Sprintf("|dnssec=%t|rfc5011=%t|anchors=%s|negative=%s", configuration.DNSSECValidation, configuration.DNSSECTrustAnchorUpdates,
		strings.Join(configuration.DNSSECTrustAnchors, "\x00"), strings.Join(configuration.DNSSECNegativeTrustAnchors, "\x00"))
}

func exchangeForwarder(ctx context.Context, request *dns.Msg, forwarder string, timeout time.Duration) (*dns.Msg, error) {
	protocol, address, err := forwarding.ParseEndpoint(forwarder)
	if err != nil {
		return nil, err
	}
	network := protocol
	if protocol == "tls" {
		network = "tcp-tls"
	}
	client := &dns.Client{Net: network, Timeout: timeout}
	if protocol == "tls" {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, splitErr
		}
		client.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	}
	response, _, err := client.ExchangeContext(ctx, request, address)
	if err != nil {
		return nil, err
	}
	if protocol != "udp" || !response.Truncated {
		return response, nil
	}
	client.Net = "tcp"
	response, _, err = client.ExchangeContext(ctx, request, address)
	if err != nil {
		return nil, fmt.Errorf("retry truncated response over TCP: %w", err)
	}
	return response, nil
}

func (runtime *Runtime) forwardersFor(name string) ([]string, bool) {
	name = normalizeName(name)
	for name != "" {
		if forwarders, found := runtime.routes[name]; found {
			return forwarders, true
		}
		separator := strings.IndexByte(name, '.')
		if separator < 0 {
			break
		}
		name = name[separator+1:]
	}
	if runtime.mode == "recursive" {
		return nil, false
	}
	return runtime.forwarders, false
}

func upstreamSignature(forwarders []string, routes map[string][]string) string {
	var signature strings.Builder
	for _, forwarder := range forwarders {
		signature.WriteString(forwarder)
		signature.WriteByte(0)
	}
	domains := make([]string, 0, len(routes))
	for domain := range routes {
		domains = append(domains, domain)
	}
	slices.Sort(domains)
	for _, domain := range domains {
		signature.WriteString(domain)
		signature.WriteByte(1)
		for _, forwarder := range routes[domain] {
			signature.WriteString(forwarder)
			signature.WriteByte(0)
		}
	}
	return signature.String()
}

func errorResponse(request *dns.Msg, code int) *dns.Msg {
	response := new(dns.Msg)
	response.SetRcode(request, code)
	return response
}

func responseWriterClientIP(writer dns.ResponseWriter) string {
	address := writer.RemoteAddr()
	if address == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return address.String()
	}
	return host
}

func (runtime *Runtime) matchesBlocked(name string) bool {
	return matchesDomainSet(runtime.blocked, name)
}

func (runtime *Runtime) matchesAllowed(name string) bool {
	name = normalizeName(name)
	if _, found := runtime.allowedExact[name]; found {
		return true
	}
	for {
		separator := strings.IndexByte(name, '.')
		if separator < 0 {
			return false
		}
		name = name[separator+1:]
		if _, found := runtime.allowedWildcard[name]; found {
			return true
		}
	}
}

func matchesDomainSet(domains map[string]struct{}, name string) bool {
	name = normalizeName(name)
	for name != "" {
		if _, found := domains[name]; found {
			return true
		}
		separator := strings.IndexByte(name, '.')
		if separator < 0 {
			return false
		}
		name = name[separator+1:]
	}
	return false
}

func (runtime *Runtime) clientBypasses(value string) bool {
	if value == "" || len(runtime.bypass) == 0 {
		return false
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	address = address.Unmap()
	for _, prefix := range runtime.bypass {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (runtime *Runtime) blockedResponse(request *dns.Msg) *dns.Msg {
	question := request.Question[0]
	if question.Qtype == dns.TypeTXT && runtime.blockTXT {
		response := new(dns.Msg)
		response.SetReply(request)
		response.RecursionAvailable = true
		response.Answer = append(response.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: runtime.blockTTL},
			Txt: []string{"blocked by Sable"},
		})
		return response
	}
	if runtime.blockType == "nxdomain" {
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeNameError)
		response.RecursionAvailable = true
		return response
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.RecursionAvailable = true
	for _, address := range runtime.blockAddrs {
		header := dns.RR_Header{Name: question.Name, Class: dns.ClassINET, Ttl: runtime.blockTTL}
		if address.Is4() && (question.Qtype == dns.TypeA || question.Qtype == dns.TypeANY) {
			header.Rrtype = dns.TypeA
			response.Answer = append(response.Answer, &dns.A{Hdr: header, A: net.IP(address.AsSlice())})
		} else if address.Is6() && (question.Qtype == dns.TypeAAAA || question.Qtype == dns.TypeANY) {
			header.Rrtype = dns.TypeAAAA
			response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: net.IP(address.AsSlice())})
		}
	}
	return response
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}
