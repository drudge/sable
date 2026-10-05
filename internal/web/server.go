package web

import (
	"context"
	"crypto/tls"
	json "encoding/json/v2"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/auth"
	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	blockinginsights "github.com/drudge/sable/internal/insights/blocking"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/serverlog"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/version"
	"github.com/drudge/sable/internal/web/pages"
	"github.com/drudge/sable/internal/zone"
)

const (
	maximumFormBytes        = 64 << 10
	maximumZoneImportBytes  = 16 << 20
	defaultRecentQueryLimit = 50
	webReadHeaderTimeout    = 5 * time.Second
	webRequestBodyTimeout   = 30 * time.Second
	webReadTimeout          = 5 * time.Minute
	webWriteTimeout         = 5 * time.Minute
	webIdleTimeout          = 60 * time.Second
	webMaximumHeaderBytes   = 64 << 10
)

type Server struct {
	mcpUseMu      sync.Mutex
	mcpStreams    mcpStreams
	httpServer    *http.Server
	listener      net.Listener
	httpsListener net.Listener
	certificate   atomic.Pointer[tls.Certificate]
	logger        *slog.Logger
	stats         interface {
		Stats() dnsserver.Stats
		PurgeCache() int
		CachedResponses() []dnsserver.CachedResponse
	}
	config   interface{ Current() config.Snapshot }
	zones    interface{ Current() zone.Snapshot }
	database string
	queryLog interface{ Stats() querylog.Stats }
	queries  interface {
		RecentQueryEvents(context.Context, int) ([]querylog.Entry, error)
	}
	runtimeLogs interface {
		Entries(serverlog.Filter) []serverlog.Entry
	}
	// reverseNames names the clients in the dashboard rankings from PTR
	// records the resolver can reach, which covers the reverse zones this
	// server does not answer for itself. Nil when the DNS handler cannot
	// resolve, in which case the rankings fall back to local zones alone.
	reverseNames *reverseNameCache
	// attachedNetworks is the IPv6 networks private recursion admits besides
	// the fixed private ranges. Nil in tests that don't set it.
	attachedNetworks  attachedNetworkSource
	reload            func(context.Context) error
	auth              Authenticator
	sso               ssoController
	ssoAdmin          ssoAdministration
	ssoStateStore     *ssoStateStore
	preAuthTokens     *preAuthTokenStore
	passkeyCeremonies passkeyCeremonyStore
	crossOrigin       *http.CrossOriginProtection
	securityEnabled   bool
	secureCookies     bool
	sessionCookie     string
	setupRequired     atomic.Bool
	history           *statsHistory
	insightCache      dashboardInsightCache
	// pushKeys signs alerts pushed to browsers. alerts sends alerts, and
	// alertSecrets keeps their destinations' URLs and keys in the vault.
	pushKeys     pushKeySource
	alerts       *alerts.Dispatcher
	alertSecrets *alerts.SecretStore
	// watchLastAlert reports when each domain watch last alerted.
	watchLastAlert func() map[string]time.Time
	// blockingActivityCache, the app caches, and blockListAnalysis back the
	// Insights page, which answers from a recent count while it refreshes.
	blockingActivityCache windowCache[querylog.BlockingActivity]
	deviceActivityCache   windowCache[querylog.ClientActivityReport]
	deviceSignalCache     windowCache[map[string][]string]
	repeatedLookupCache   windowCache[[]querylog.LookupTimes]
	appActivityCache      windowCache[querylog.AppActivity]
	appSightingCache      windowCache[querylog.AppSightings]
	blockListAnalysis     blockinginsights.ContributionCache
	baseDirectory         string
	historyPrune          chan struct{}
	runtimeContext        context.Context
	runtimeCancel         context.CancelFunc
	runtimeLifecycleMu    sync.Mutex
	runtimeStarted        bool
	runtimeClosed         bool
	runtimeWG             sync.WaitGroup
	runtimeWaitOnce       sync.Once
	runtimeDone           chan struct{}
	blockLists            *blockcompiler.Updater
	dnssec                dnssecController
	cluster               clusterController
	dynamicDNS            dynamicDNSController
	unifi                 unifiController
	certificates          certificateController
	tsigKeys              tsigController
	updates               updateController
	backups               backupController
	backupStaging         backupStaging
	administrator         administrator
	restart               func()
	restartRequested      atomic.Bool
	instanceID            string
	demoLogin             devDemoAutoLoginState

	// mcpUse is the MCP call count, saved by flushMCPUse under mcpUseMu.
	mcpUse       store.MCPUse
	mcpUseLoaded bool
	mcpUseDirty  bool
	// commandZones and dashboardClients keep reads every console page or
	// dashboard poll repeats.
	commandZones     commandZoneCache
	dashboardClients shortCache[struct{}, int]
}

type devDemoAutoLoginState struct {
	username  string
	password  string
	available atomic.Bool
}

type certificateController interface {
	Status(context.Context, config.EncryptedDNS) certificates.Status
	PutCredentials(context.Context, string, certificates.Credentials) error
	Ensure(context.Context, config.EncryptedDNS, bool) (bool, error)
}

func (server *Server) SetCertificateController(controller certificateController) {
	server.certificates = controller
}

func (server *Server) SetDNSSECController(controller dnssecController) {
	server.dnssec = controller
}

func (server *Server) SetRuntimeLogs(logs interface {
	Entries(serverlog.Filter) []serverlog.Entry
}) {
	server.runtimeLogs = logs
}

func (server *Server) SetRestartController(restart func()) {
	server.restart = restart
}

// SetStatsStore persists query statistics so the dashboard ranges keep their
// history across restarts. Without it the console only charts this process.
func (server *Server) SetStatsStore(ctx context.Context, statistics statsStore) error {
	return server.history.attach(ctx, statistics)
}

// SetStatsRetention updates dashboard-history retention and schedules an
// immediate sweep so a shorter window takes effect without waiting an hour.
func (server *Server) SetStatsRetention(retention time.Duration) {
	if !server.history.setRetention(retention) {
		return
	}
	select {
	case server.historyPrune <- struct{}{}:
	default:
	}
}

// Authenticator is the authentication capability used by the web console.
// Callers should pass a nil interface when security is disabled.
type Authenticator interface {
	SetupRequired(context.Context) (bool, error)
	Setup(context.Context, string, string, string, string) (auth.Credentials, error)
	Login(context.Context, string, string, string, string) (auth.Credentials, error)
	AuthenticateSession(context.Context, string) (auth.Principal, error)
	AuthenticateToken(context.Context, string) (auth.Principal, error)
	ValidateCSRF(auth.Principal, string) bool
	Logout(context.Context, auth.Principal, string, string) error
	CreateAPIToken(context.Context, auth.Principal, int64, string, []string, auth.APITokenExpiration, string, string) (string, time.Time, error)
	Profile(context.Context, auth.Principal) (auth.ProfileSnapshot, error)
	Avatar(context.Context, auth.Principal) (auth.Avatar, error)
	UpdateOwnProfile(context.Context, auth.Principal, string, string, string, string) error
	ChangeOwnPassword(context.Context, auth.Principal, string, string, string, string) error
	RevokeOwnAPIToken(context.Context, auth.Principal, int64, string, string) error
}

func New(
	logger *slog.Logger,
	stats interface {
		Stats() dnsserver.Stats
		PurgeCache() int
		CachedResponses() []dnsserver.CachedResponse
	},
	configuration interface{ Current() config.Snapshot },
	zones interface{ Current() zone.Snapshot },
	database string,
	queryLog interface{ Stats() querylog.Stats },
	queries interface {
		RecentQueryEvents(context.Context, int) ([]querylog.Entry, error)
	},
	reload func(context.Context) error,
	authentication Authenticator,
	securityEnabled bool,
	setupRequired bool,
	secureCookies bool,
) (*Server, error) {
	runtimeContext, runtimeCancel := context.WithCancel(context.Background())
	logger = quietAbandoned(logger)
	server := &Server{
		logger: logger, stats: stats, config: configuration, zones: zones, database: database,
		queryLog: queryLog, queries: queries, reload: reload,
		auth: authentication, preAuthTokens: newPreAuthTokenStore(), ssoStateStore: newSSOStateStore(),
		crossOrigin:     http.NewCrossOriginProtection(),
		history:         newStatsHistory(logger, configuration.Current().Config.Statistics.Retention.Duration),
		historyPrune:    make(chan struct{}, 1),
		securityEnabled: securityEnabled, secureCookies: secureCookies,
		instanceID:     strconv.FormatInt(time.Now().UnixNano(), 36),
		runtimeContext: runtimeContext, runtimeCancel: runtimeCancel, runtimeDone: make(chan struct{}),
	}
	server.blockingActivityCache.serveStale()
	server.deviceActivityCache.serveStale()
	server.deviceSignalCache.serveStale()
	server.repeatedLookupCache.serveStale()
	server.appActivityCache.serveStale()
	server.appSightingCache.serveStale()
	// Each cache counts in the background, detached from the request that asked,
	// for as long as the server runs.
	server.insightCache.background = server.goBackground
	server.appActivityCache.background = server.goBackground
	server.appSightingCache.background = server.goBackground
	server.blockingActivityCache.background = server.goBackground
	server.deviceActivityCache.background = server.goBackground
	server.deviceSignalCache.background = server.goBackground
	server.repeatedLookupCache.background = server.goBackground
	if administration, ok := authentication.(administrator); ok {
		server.administrator = administration
	}
	if resolver, ok := stats.(reverseResolver); ok {
		server.reverseNames = newReverseNameCache(resolver, logger)
	}
	baseDirectory := "."
	if located, ok := configuration.(interface{ BaseDirectory() string }); ok {
		baseDirectory = located.BaseDirectory()
	}
	server.baseDirectory = baseDirectory
	server.sessionCookie = scopedSessionCookieName(configuration.Current().Config.SecuritySecretKeyPath(baseDirectory))
	server.configureDevDemoAutoLogin()
	server.blockLists = blockcompiler.NewUpdater(baseDirectory)
	if securityEnabled && authentication == nil {
		return nil, errors.New("authentication service is required when security is enabled")
	}
	server.setupRequired.Store(setupRequired)
	protectedApplication := secureHeaders(server.newRouter(), secureCookies)
	rootHandler := protectedApplication
	if resolver, ok := stats.(dns.Handler); ok {
		rootMux := http.NewServeMux()
		rootMux.Handle("/dns-query", secureHeaders(server.sharedDoHHandler(dnsserver.NewDoHHandler(resolver)), true))
		rootMux.Handle("/", protectedApplication)
		rootHandler = rootMux
	}
	server.httpServer = &http.Server{
		Handler:           requestBodyDeadline(rootHandler),
		ReadHeaderTimeout: webReadHeaderTimeout,
		ReadTimeout:       webReadTimeout,
		WriteTimeout:      webWriteTimeout,
		IdleTimeout:       webIdleTimeout,
		MaxHeaderBytes:    webMaximumHeaderBytes,
	}
	return server, nil
}

func (server *Server) health(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	snapshot := server.config.Current()
	payload := struct {
		Status     string          `json:"status"`
		InstanceID string          `json:"instance_id"`
		Version    version.Info    `json:"version"`
		Revision   uint64          `json:"config_revision"`
		Stats      dnsserver.Stats `json:"stats"`
		QueryLog   querylog.Stats  `json:"query_log"`
	}{
		Status:     "ok",
		InstanceID: server.instanceID,
		Version:    version.Current(),
		Revision:   snapshot.Revision,
		Stats:      server.history.totals(time.Now(), server.stats.Stats()),
		QueryLog:   server.queryLog.Stats(),
	}
	writeJSON(writer, http.StatusOK, payload)
}

func (server *Server) policyAPI(writer http.ResponseWriter, _ *http.Request) {
	stats := server.stats.Stats()
	writeJSON(writer, http.StatusOK, struct {
		BlockedDomains       int                        `json:"blocked_domains"`
		LocalHosts           int                        `json:"local_hosts"`
		LocalAnswers         uint64                     `json:"local_answers"`
		AuthoritativeAnswers uint64                     `json:"authoritative_answers"`
		DNSSECSecure         uint64                     `json:"dnssec_secure"`
		DNSSECInsecure       uint64                     `json:"dnssec_insecure"`
		DNSSECBogus          uint64                     `json:"dnssec_bogus"`
		DNSSECTrustAnchors   any                        `json:"dnssec_trust_anchors"`
		Zones                int                        `json:"zones"`
		BlockLists           int                        `json:"block_lists"`
		RoutedQueries        uint64                     `json:"routed_queries"`
		CacheEntries         int                        `json:"cache_entries"`
		ConfigRevision       uint64                     `json:"config_revision"`
		Sources              []dnsserver.BlockListStats `json:"sources"`
	}{
		BlockedDomains:       stats.BlockedDomains,
		LocalHosts:           stats.LocalHosts,
		LocalAnswers:         stats.LocalAnswers,
		AuthoritativeAnswers: stats.AuthoritativeAnswers,
		DNSSECSecure:         stats.DNSSECSecure,
		DNSSECInsecure:       stats.DNSSECInsecure,
		DNSSECBogus:          stats.DNSSECBogus,
		DNSSECTrustAnchors:   stats.DNSSECTrustAnchors,
		Zones:                stats.Zones,
		BlockLists:           stats.BlockLists,
		RoutedQueries:        stats.RoutedQueries,
		CacheEntries:         stats.CacheEntries,
		ConfigRevision:       server.config.Current().Revision,
		Sources:              stats.BlockSources,
	})
}

func (server *Server) reloadBlockingUI(writer http.ResponseWriter, request *http.Request) {
	started := time.Now()
	if err := server.reload(request.Context()); err != nil {
		server.logBlockingOperation(request, err, "duration", time.Since(started))
		writer.WriteHeader(http.StatusUnprocessableEntity)
		_ = pages.ActionResult("Policy reload rejected: "+err.Error(), true).Render(request.Context(), writer)
		return
	}
	server.logBlockingOperation(request, nil, "duration", time.Since(started))
	server.recordControlPlaneAudit(request, blockingMutationAction(request.URL.Path), "blocking policy reloaded")
	_ = pages.ActionResult("Blocking policy reloaded", false).Render(request.Context(), writer)
}

func (server *Server) reloadConfiguration(writer http.ResponseWriter, request *http.Request) {
	if err := server.reload(request.Context()); err != nil {
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"status": "rejected", "error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "reloaded"})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		http.Error(writer, "encode response", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}
