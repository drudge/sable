package dnsserver

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/clientaccess"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/trustanchor"
)

const fallbackErrorCode = dns.RcodeServerFailure

type Runtime struct {
	maxConcurrent          int
	maxConcurrentPerClient int
	recursion              clientaccess.Policy
	mode                   string
	forwarders             []string
	rootHints              []string
	qnameMinimization      bool
	delegations            *delegationCache
	zoneCuts               *zoneCutCache
	nameServers            *addressCache
	baseRoutes             []ForwardingRoute
	routes                 map[string][]string
	upstreams              string
	timeout                time.Duration
	retries                int
	retryTimeout           time.Duration
	staleMaxWait           time.Duration
	// blocked maps each blocked domain to the set of sources that list it,
	// an index into blockedOwners. The set rides along with the lookup the
	// policy check already makes, so attribution costs no extra work per query.
	blocked       map[string]uint32
	blockedOwners [][]string
	// exceptions maps each host a block list's @@ rule unblocks, with its
	// subdomains, to the lists that carry the rule. firmBlocked holds the
	// blocks an exception doesn't lift: $important rules and the operator's
	// own blocked domains. Both are consulted only once a block matches.
	exceptions  map[string]uint32
	firmBlocked map[string]struct{}
	allowed     allowList
	blocking    bool
	blockType   string
	blockTTL    uint32
	blockAddrs  []netip.Addr
	// ruleSets are the policies for particular clients, picked through
	// ruleSetClients. defaultSet narrows the block lists for everyone else;
	// nil uses them all. holds block everything for particular clients, until
	// a time in Unix nanoseconds, or forever when it is zero.
	ruleSets            []ruleSet
	ruleSetClients      clientTable[int]
	defaultSet          *ruleSet
	holds               clientTable[int64]
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
	// zoneSource and keySource are the inputs the authoritative data above
	// was compiled from, kept so a later activation can recompile it against
	// different forwarding routes or TSIG keys.
	zoneSource []AuthoritativeZone
	keySource  []TSIGKey
	// zoneGeneration counts ActivateZones calls behind this runtime. Zero
	// means its zones came from Compile and no zone change has landed since.
	zoneGeneration uint64
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
	MaxConcurrent          int
	MaxConcurrentPerClient int
	Recursion              string
	RecursionClients       []string
	Mode                   string
	Forwarders             []string
	RootHints              []string
	// DisableQNAMEMinimization has iterative resolution ask every server for
	// the full name. Minimization is on unless this is set.
	DisableQNAMEMinimization bool
	Routes                   []ForwardingRoute
	Timeout                  time.Duration
	Retries                  int
	RetryTimeout             time.Duration
	CacheSize                int
	CacheMinimumTTL          uint32
	CacheMaximumTTL          uint32
	CacheNegativeTTL         uint32
	CacheFailureTTL          uint32
	ServeStale               bool
	CacheStaleTTL            uint32
	CacheStaleAnswerTTL      uint32
	CacheStaleResetTTL       uint32
	CacheStaleMaxWait        time.Duration
	CachePrefetchMinimumTTL  uint32
	CachePrefetchTriggerTTL  uint32
	CachePrefetchSample      time.Duration
	CachePrefetchHitsPerHour uint32
	Blocking                 bool
	BlockedDomains           []string
	// BlockedDomainOwners runs parallel to BlockedDomains and indexes
	// BlockedDomainOwnerSets, the block lists that contributed each domain.
	// Both are optional; without them blocked queries carry no attribution.
	BlockedDomainOwners    []uint32
	BlockedDomainOwnerSets [][]string
	// ExceptionDomains are the hosts block lists unblock with @@ rules, and
	// ExceptionDomainOwners runs parallel, indexing BlockedDomainOwnerSets.
	// ImportantBlockedDomains are the blocks an exception doesn't lift:
	// $important rules and the operator's own blocked domains.
	ExceptionDomains        []string
	ExceptionDomainOwners   []uint32
	ImportantBlockedDomains []string
	AllowedDomains          []string
	BlockLists              []BlockListStats
	BlockingType            string
	BlockingTTL             uint32
	BlockingAddrs           []string
	RuleSets                []RuleSetPolicy
	// DefaultLists names the block-list sources for clients without a rule
	// set. Nil applies every source.
	DefaultLists []string
	// Holds block everything for particular clients.
	Holds                      []HoldPolicy
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
	Name     string
	Type     string
	Disabled bool
	// AwaitingTransfer marks a zone that a catalog provisioned but that has not
	// received its first transfer yet. It holds no records, so it is not
	// compiled into the runtime and answers nothing until its content arrives.
	AwaitingTransfer bool
	ZoneTransfer     string
	TransferACL      []string
	PrimaryServers   []string
	PrimaryProtocol  string
	TSIGKey          string
	DynamicUpdates   bool
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
	// Exceptions and Unsupported count a list's @@ rules and the adblock
	// rules DNS can't apply.
	Exceptions  int `json:"exceptions,omitempty"`
	Unsupported int `json:"unsupported,omitempty"`
}

type Stats struct {
	ResolutionInflight       int                   `json:"resolution_inflight"`
	ResolutionClients        int                   `json:"resolution_clients"`
	ResolutionRejectedGlobal uint64                `json:"resolution_rejected_global"`
	ResolutionRejectedClient uint64                `json:"resolution_rejected_client"`
	Queries                  uint64                `json:"queries"`
	NoError                  uint64                `json:"no_error"`
	ServerFailures           uint64                `json:"server_failures"`
	NXDomain                 uint64                `json:"nx_domain"`
	Refused                  uint64                `json:"refused"`
	Blocked                  uint64                `json:"blocked"`
	Failures                 uint64                `json:"failures"`
	UpstreamErrors           uint64                `json:"upstream_errors"`
	CacheHits                uint64                `json:"cache_hits"`
	CacheMisses              uint64                `json:"cache_misses"`
	Panics                   uint64                `json:"panics"`
	CacheEntries             int                   `json:"cache_entries"`
	RoutedQueries            uint64                `json:"routed_queries"`
	LocalAnswers             uint64                `json:"local_answers"`
	AuthoritativeAnswers     uint64                `json:"authoritative_answers"`
	LocalHosts               int                   `json:"local_hosts"`
	Zones                    int                   `json:"zones"`
	BlockedDomains           int                   `json:"blocked_domains"`
	BlockLists               int                   `json:"block_lists"`
	BlockSources             []BlockListStats      `json:"block_sources"`
	StartedAt                time.Time             `json:"started_at"`
	DNSSECSecure             uint64                `json:"dnssec_secure"`
	DNSSECInsecure           uint64                `json:"dnssec_insecure"`
	DNSSECBogus              uint64                `json:"dnssec_bogus"`
	DNSSECTrustAnchorUpdates bool                  `json:"dnssec_trust_anchor_updates"`
	DNSSECTrustAnchors       trustanchor.Status    `json:"dnssec_trust_anchors"`
	Latency                  []DNSLatencyHistogram `json:"latency"`
}

type Handler struct {
	admission resolutionAdmission
	runtime   atomic.Pointer[Runtime]
	// attached holds the IPv6 networks this node is attached to, which
	// private recursion admits. A background watcher replaces the list; a
	// lookup only loads it.
	attached atomic.Pointer[[]netip.Prefix]
	// deviceAddresses ties addresses to the hardware address of the device
	// using them. A background worker replaces it; a lookup only loads it.
	deviceAddresses      atomic.Pointer[DeviceAddresses]
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
	panics               atomic.Uint64
	maintenanceStop      chan struct{}
	maintenanceDone      chan struct{}
	maintenanceStarted   atomic.Bool
	maintenanceOnce      sync.Once
	backgroundContext    context.Context
	backgroundCancel     context.CancelFunc
	backgroundMu         sync.Mutex
	backgroundClosed     bool
	backgroundWG         sync.WaitGroup
	backgroundWaitOnce   sync.Once
	backgroundDone       chan struct{}
	routedQueries        atomic.Uint64
	localAnswers         atomic.Uint64
	authoritativeAnswers atomic.Uint64
	dnssecSecure         atomic.Uint64
	dnssecInsecure       atomic.Uint64
	dnssecBogus          atomic.Uint64
	trustAnchorManager   atomic.Pointer[trustanchor.Manager]
	// activationMu serializes every writer of runtime. Each one rebuilds from
	// the runtime it finds under the lock, so no writer can store a runtime
	// built from one that another writer has already replaced.
	activationMu         sync.Mutex
	upstreamIndex        atomic.Uint64
	pausedUntil          atomic.Int64
	startedAt            time.Time
	observer             atomic.Pointer[observerHolder]
	upstreamExchange     upstreamExchangeFunc
	forwarderConnections *forwarderPool
	upstreamHealth       *upstreamHealthTracker
	// authorityHealth is upstreamHealth for the authoritative servers
	// iterative resolution asks.
	authorityHealth *upstreamHealthTracker
	inflight        *inflightGroup
	// detached holds recursive lookups still running after the client that
	// started them stopped waiting, so a retry joins one instead of starting
	// over.
	detachedMu        sync.Mutex
	detached          map[inflightKey]*detachedLookup
	zoneTransfer      zoneTransferFunc
	zoneRefresh       zoneRefreshFunc
	journalMu         sync.RWMutex
	zoneJournals      map[string][]zoneDelta
	expiredMu         sync.Mutex
	expiredZones      atomic.Pointer[map[string]struct{}]
	notifications     chan ZoneNotification
	zoneUpdater       atomic.Pointer[zoneUpdaterHolder]
	zoneUpdateAuditor atomic.Pointer[zoneUpdateAuditorHolder]
	logger            atomic.Pointer[slog.Logger]
	failureLog        *failureLogLimiter
	latency           dnsLatencyHistograms
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
	decision         querylog.Decision
	transientFailure bool
	// stillRunning marks a failure only because the client's wait ran out
	// while its recursive lookup went on.
	stillRunning bool
}

func NewHandler(runtime *Runtime) *Handler {
	forwarders := newForwarderPool()
	backgroundContext, backgroundCancel := context.WithCancel(context.Background())
	handler := &Handler{
		startedAt: time.Now(), upstreamExchange: forwarders.exchange, forwarderConnections: forwarders,
		upstreamHealth: newUpstreamHealthTracker(), authorityHealth: newAuthorityHealthTracker(), inflight: newInflightGroup(),
		zoneTransfer: exchangeZoneTransfer, zoneRefresh: exchangeIncrementalZoneTransfer,
		zoneJournals: make(map[string][]zoneDelta), notifications: make(chan ZoneNotification, 256),
		failureLog:      newFailureLogLimiter(),
		maintenanceStop: make(chan struct{}), maintenanceDone: make(chan struct{}),
		backgroundContext: backgroundContext, backgroundCancel: backgroundCancel, backgroundDone: make(chan struct{}),
	}
	emptyExpired := make(map[string]struct{})
	handler.expiredZones.Store(&emptyExpired)
	handler.runtime.Store(runtime)
	return handler
}

func (handler *Handler) Stats() Stats {
	active, clients, rejectedGlobal, rejectedClient := handler.admission.snapshot()
	runtime := handler.runtime.Load()
	anchorStatus := trustanchor.Status{}
	if manager := handler.trustAnchorManager.Load(); runtime.managedTrustAnchors && manager != nil {
		anchorStatus = manager.Status()
	}
	return Stats{
		ResolutionInflight: active, ResolutionClients: clients, ResolutionRejectedGlobal: rejectedGlobal, ResolutionRejectedClient: rejectedClient,
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
		Panics:                   handler.panics.Load(),
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
		Latency:                  handler.latency.snapshot(),
	}
}

func (handler *Handler) CachedResponses() []CachedResponse {
	return handler.runtime.Load().cache.Snapshot()
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
	switch address := address.(type) {
	case *net.UDPAddr:
		if client := address.AddrPort().Addr(); client.IsValid() {
			return client.Unmap().String()
		}
	case *net.TCPAddr:
		if client := address.AddrPort().Addr(); client.IsValid() {
			return client.Unmap().String()
		}
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return address.String()
	}
	return host
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// questionName is the normalized name of a request's first question, or ""
// when it has none.
func questionName(request *dns.Msg) string {
	if len(request.Question) == 0 {
		return ""
	}
	return normalizeName(request.Question[0].Name)
}

// isCanonicalDomain reports whether name is already the lowercase, ASCII,
// dot-trimmed form that dnsname.Normalize produces, so a block-list entry can be
// keyed without repeating the expensive IDNA pass. It still confirms the name is
// structurally valid so a malformed input falls back to full normalization.
func isCanonicalDomain(name string) bool {
	if name == "" || len(name) > 255 || name[0] == '.' || name[len(name)-1] == '.' {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character >= 0x80 || (character >= 'A' && character <= 'Z') || character == ' ' {
			return false
		}
	}
	_, valid := dns.IsDomainName(name)
	return valid
}
