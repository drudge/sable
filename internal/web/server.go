package web

import (
	"context"
	"crypto/tls"
	"embed"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsclient"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/serverlog"
	"github.com/drudge/sable/internal/version"
	"github.com/drudge/sable/internal/web/pages"
	"github.com/drudge/sable/internal/zone"
)

const (
	maximumFormBytes        = 64 << 10
	maximumZoneImportBytes  = 16 << 20
	defaultRecentQueryLimit = 50
)

//go:embed assets/*
var embeddedAssets embed.FS

type Server struct {
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
	reverseNames     *reverseNameCache
	reload           func(context.Context) error
	auth             authenticator
	sso              ssoController
	ssoAdmin         ssoAdministration
	ssoStateStore    *ssoStateStore
	preAuthTokens    *preAuthTokenStore
	crossOrigin      *http.CrossOriginProtection
	securityEnabled  bool
	secureCookies    bool
	sessionCookie    string
	setupRequired    atomic.Bool
	history          *statsHistory
	historyStop      chan struct{}
	historyStopOnce  sync.Once
	blockLists       *blockcompiler.Updater
	dnssec           dnssecController
	cluster          clusterController
	unifi            unifiController
	certificates     certificateController
	tsigKeys         tsigController
	updates          updateController
	backups          backupController
	backupStaging    backupStaging
	administrator    administrator
	restart          func()
	restartRequested atomic.Bool
	instanceID       string
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

type authenticator interface {
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
	authentication authenticator,
	securityEnabled bool,
	setupRequired bool,
	secureCookies bool,
) (*Server, error) {
	assets, err := fs.Sub(embeddedAssets, "assets")
	if err != nil {
		return nil, fmt.Errorf("prepare embedded assets: %w", err)
	}
	server := &Server{
		logger: logger, stats: stats, config: configuration, zones: zones, database: database,
		queryLog: queryLog, queries: queries, reload: reload,
		auth: authentication, preAuthTokens: newPreAuthTokenStore(), ssoStateStore: newSSOStateStore(),
		crossOrigin: http.NewCrossOriginProtection(),
		history:     newStatsHistory(logger), historyStop: make(chan struct{}),
		securityEnabled: securityEnabled, secureCookies: secureCookies,
		instanceID: strconv.FormatInt(time.Now().UnixNano(), 36),
	}
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
	server.sessionCookie = scopedSessionCookieName(configuration.Current().Config.SecuritySecretKeyPath(baseDirectory))
	server.blockLists = blockcompiler.NewUpdater(baseDirectory)
	if securityEnabled && authentication == nil {
		return nil, errors.New("authentication service is required when security is enabled")
	}
	server.setupRequired.Store(setupRequired)
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assets))))
	mux.HandleFunc("POST "+ssoStartPath, server.startSSO)
	mux.HandleFunc("GET "+ssoCallbackPath, server.completeSSO)
	mux.HandleFunc("GET /", server.dashboard)
	mux.HandleFunc("GET /about", server.aboutPage)
	mux.HandleFunc("GET /cluster", server.clusterPage)
	mux.HandleFunc("GET /zones", server.zonesPage)
	mux.HandleFunc("GET /zones/{zone}", server.zonesPage)
	mux.HandleFunc("GET /zones/{zone}/records/{record}/edit", server.zonesPage)
	mux.HandleFunc("GET /cache", server.cachePage)
	mux.HandleFunc("GET /blocked", server.blockingPage)
	mux.HandleFunc("GET /integrations", server.integrationsPage)
	mux.HandleFunc("POST /ui/integrations/unifi/wizard", server.runUniFiWizard)
	mux.HandleFunc("POST /ui/integrations/unifi/sync", server.syncUniFiNow)
	mux.HandleFunc("POST /ui/integrations/unifi/enabled", server.setUniFiEnabled)
	mux.HandleFunc("POST /ui/integrations/unifi/remove", server.removeUniFi)
	mux.HandleFunc("GET /ui/integrations/unifi/status", server.unifiStatusPanel)
	mux.HandleFunc("POST /ui/integrations/sso/check", server.checkSSO)
	mux.HandleFunc("POST /ui/integrations/sso/enabled", server.setSSOEnabled)
	mux.HandleFunc("POST /ui/integrations/sso/wizard", server.runSSOWizard)
	mux.HandleFunc("POST /ui/integrations/sso/remove", server.removeSSO)
	mux.HandleFunc("GET /dns-client", server.dnsClientPage)
	mux.HandleFunc("GET /logs", server.logsPage)
	mux.HandleFunc("GET /settings", server.settingsPage)
	mux.HandleFunc("POST /ui/settings", server.updateSettings)
	mux.HandleFunc("POST /ui/settings/tsig/save", server.saveTSIGKey)
	mux.HandleFunc("POST /ui/settings/tsig/delete", server.deleteTSIGKey)
	mux.HandleFunc("POST /ui/certificates/renew", server.renewCertificate)
	mux.HandleFunc("POST /ui/certificates/generate", server.generateManualCertificate)
	mux.HandleFunc("POST /ui/certificates/import", server.importManualCertificate)
	mux.HandleFunc("POST /ui/cluster/initialize", server.initializeCluster)
	mux.HandleFunc("POST /ui/cluster/onboarding", server.updateClusterOnboarding)
	mux.HandleFunc("POST /ui/cluster/settings", server.updateClusterSettings)
	mux.HandleFunc("POST /ui/cluster/join", server.joinCluster)
	mux.HandleFunc("POST /ui/cluster/enrollment-tokens", server.createClusterEnrollmentToken)
	mux.HandleFunc("POST /ui/cluster/nodes/{node}/promote", server.promoteClusterNode)
	mux.HandleFunc("POST /ui/cluster/nodes/{node}/remove", server.removeClusterNode)
	mux.HandleFunc("POST /ui/cluster/leave", server.leaveCluster)
	mux.HandleFunc("POST /ui/cluster/delete", server.deleteCluster)
	mux.HandleFunc("POST /ui/cluster/restart", server.restartServer)
	mux.HandleFunc("GET /ui/backup", server.backupPanel)
	mux.HandleFunc("GET /ui/backup/progress", server.backupProgress)
	mux.HandleFunc("POST /ui/backup/download", server.downloadBackup)
	mux.HandleFunc("GET /ui/backup/download/{token}", server.sendBackup)
	mux.HandleFunc("POST /ui/backup/restore", server.restoreBackup)
	mux.HandleFunc("POST /ui/backup/restart", server.restartServer)
	mux.HandleFunc("GET /ui/updates", server.updatePanel)
	mux.HandleFunc("POST /ui/updates/check", server.checkForUpdates)
	mux.HandleFunc("POST /ui/updates/install", server.installUpdate)
	mux.HandleFunc("POST /ui/updates/restart", server.restartServer)
	mux.HandleFunc("GET /ui/cluster/status", server.clusterLiveStatus)
	mux.HandleFunc("GET /administration", server.administrationPage)
	mux.HandleFunc("GET "+avatarPath, server.ownAvatar)
	mux.HandleFunc("GET /profile", server.profilePage)
	mux.HandleFunc("GET /ui/profile/tokens", server.profileTokens)
	mux.HandleFunc("POST /ui/profile", server.updateOwnProfile)
	mux.HandleFunc("POST /ui/profile/password", server.changeOwnPassword)
	mux.HandleFunc("POST /ui/profile/tokens/revoke", server.revokeOwnAPIToken)
	mux.HandleFunc("GET /ui/administration/tokens", server.administrationTokens)
	mux.HandleFunc("POST /ui/administration/users", server.createUser)
	mux.HandleFunc("POST /ui/administration/users/profile", server.updateUserProfile)
	mux.HandleFunc("POST /ui/administration/users/roles", server.updateUserRoles)
	mux.HandleFunc("POST /ui/administration/users/status", server.updateUserStatus)
	mux.HandleFunc("POST /ui/administration/users/password", server.updateUserPassword)
	mux.HandleFunc("POST /ui/administration/users/sign-in-method", server.updateUserPasswordLogin)
	mux.HandleFunc("POST /ui/administration/users/unlink", server.unlinkUserIdentity)
	mux.HandleFunc("POST /ui/administration/users/delete", server.deleteUser)
	mux.HandleFunc("POST /ui/administration/roles", server.createRole)
	mux.HandleFunc("POST /ui/administration/roles/update", server.updateRole)
	mux.HandleFunc("POST /ui/administration/roles/delete", server.deleteRole)
	mux.HandleFunc("POST /ui/administration/sessions/revoke", server.revokeSession)
	mux.HandleFunc("POST /ui/administration/tokens/revoke", server.revokeAPIToken)
	mux.HandleFunc("GET /ui/stats", server.runtimeStats)
	mux.HandleFunc("GET /ui/stats/chart", server.queryStatistics)
	mux.HandleFunc("GET /ui/query-log", server.recentQueryLog)
	mux.HandleFunc("GET /ui/logs/runtime", server.runtimeLogsPanel)
	mux.HandleFunc("GET /ui/logs/queries", server.queryLogsPanel)
	mux.HandleFunc("POST /ui/query", server.query)
	mux.HandleFunc("POST /ui/cache/purge", server.purgeCacheUI)
	mux.HandleFunc("GET /ui/cache/status", server.cacheStatus)
	mux.HandleFunc("POST /ui/cache/flush", server.flushCache)
	mux.HandleFunc("POST /ui/zones/add", server.addZone)
	mux.HandleFunc("POST /ui/zones/delete", server.deleteZone)
	mux.HandleFunc("POST /ui/zones/settings", server.updateZoneSettings)
	mux.HandleFunc("POST /ui/zones/dnssec", server.updateZoneDNSSEC)
	mux.HandleFunc("POST /ui/zones/dnssec/rollover", server.rolloverZoneDNSSECKey)
	mux.HandleFunc("POST /ui/zones/dnssec/confirm-ds", server.confirmZoneDNSSECDS)
	mux.HandleFunc("POST /ui/zones/clone", server.cloneZone)
	mux.HandleFunc("POST /ui/zones/toggle", server.toggleZone)
	mux.HandleFunc("POST /ui/zones/resync", server.resyncZone)
	mux.HandleFunc("POST /ui/zones/records/add", server.addZoneRecord)
	mux.HandleFunc("POST /ui/zones/records/update", server.updateZoneRecord)
	mux.HandleFunc("POST /ui/zones/records/delete", server.deleteZoneRecord)
	mux.HandleFunc("POST /ui/zones/import", server.importZone)
	mux.HandleFunc("POST /ui/zones/import-new", server.importNewZone)
	mux.HandleFunc("POST /ui/blocking/reload", server.reloadBlockingUI)
	mux.HandleFunc("POST /ui/blocking/domains/add", server.addBlockedDomain)
	mux.HandleFunc("POST /ui/blocking/domains/delete", server.deleteBlockedDomain)
	mux.HandleFunc("POST /ui/blocking/domains/flush", server.flushBlockedDomains)
	mux.HandleFunc("POST /ui/blocking/domains/import", server.importBlockedDomains)
	mux.HandleFunc("GET /ui/blocking/domains/export", server.exportBlockedDomains)
	mux.HandleFunc("POST /ui/blocking/lists/add", server.addBlockList)
	mux.HandleFunc("POST /ui/blocking/lists/delete", server.deleteBlockList)
	mux.HandleFunc("POST /ui/blocking/lists/update", server.updateBlockLists)
	mux.HandleFunc("POST /ui/blocking/toggle", server.toggleBlocking)
	mux.HandleFunc("POST /ui/blocking/pause", server.pauseBlocking)
	mux.HandleFunc("POST /ui/blocking/resume", server.resumeBlocking)
	mux.HandleFunc("POST /ui/blocking/allowed/add", server.addAllowedDomain)
	mux.HandleFunc("POST /ui/blocking/allowed/delete", server.deleteAllowedDomain)
	mux.HandleFunc("POST /ui/blocking/allowed/flush", server.flushAllowedDomains)
	mux.HandleFunc("POST /ui/blocking/allowed/import", server.importAllowedDomains)
	mux.HandleFunc("POST /ui/blocking/query-domain", server.addQueryPolicyDomain)
	mux.HandleFunc("GET /ui/blocking/allowed/export", server.exportAllowedDomains)
	mux.HandleFunc("POST /ui/api-tokens", server.createAPIToken)
	mux.HandleFunc("GET /setup", server.setupPage)
	mux.HandleFunc("POST /setup", server.setup)
	mux.HandleFunc("GET /login", server.loginPage)
	mux.HandleFunc("POST /login", server.login)
	mux.HandleFunc("POST /logout", server.logout)
	mux.HandleFunc("GET /api/v1/health", server.health)
	mux.HandleFunc("GET /api/v1/cluster", server.clusterAPI)
	mux.HandleFunc("GET /api/v1/cluster/nodes/{node}", server.clusterNodeAPI)
	mux.HandleFunc("POST /api/v1/cluster", server.initializeClusterAPI)
	mux.HandleFunc("POST /api/v1/cluster/enrollment-tokens", server.createClusterEnrollmentTokenAPI)
	mux.HandleFunc("POST /api/v1/cluster/enroll", server.enrollClusterNodeAPI)
	mux.HandleFunc("POST /api/v1/cluster/sync", server.clusterSyncAPI)
	mux.HandleFunc("POST /api/v1/cluster/nodes/{node}/promote", server.promoteClusterNodeAPI)
	mux.HandleFunc("DELETE /api/v1/cluster/nodes/{node}", server.removeClusterNodeAPI)
	mux.HandleFunc("DELETE /api/v1/cluster/membership", server.leaveClusterAPI)
	mux.HandleFunc("DELETE /api/v1/cluster", server.deleteClusterAPI)
	mux.HandleFunc("GET /metrics", server.metrics)
	mux.HandleFunc("GET /api/v1/query-log", server.queryLogAPI)
	mux.HandleFunc("GET /api/v1/logs/runtime", server.runtimeLogsAPI)
	mux.HandleFunc("GET /api/v1/logs/runtime/export", server.exportRuntimeLogs)
	mux.HandleFunc("GET /api/v1/logs/queries/export", server.exportQueryLogs)
	mux.HandleFunc("GET /api/v1/zones", server.zonesAPI)
	mux.HandleFunc("GET /api/v1/zones/export", server.exportZone)
	mux.HandleFunc("GET /api/v1/zones/ds", server.zoneDS)
	mux.HandleFunc("GET /api/v1/zones/dnssec", server.zoneDNSSECStatus)
	mux.HandleFunc("GET /api/v1/policy", server.policyAPI)
	mux.HandleFunc("POST /api/v1/cache/purge", server.purgeCache)
	mux.HandleFunc("POST /api/v1/blocking/reload", server.reloadConfiguration)
	mux.HandleFunc("POST /api/v1/config/reload", server.reloadConfiguration)
	protectedApplication := secureHeaders(server.accessControl(server.primaryWriteControl(mux)), secureCookies)
	rootHandler := protectedApplication
	if resolver, ok := stats.(dns.Handler); ok {
		rootMux := http.NewServeMux()
		rootMux.Handle("/dns-query", secureHeaders(server.sharedDoHHandler(dnsserver.NewDoHHandler(resolver)), true))
		rootMux.Handle("/", protectedApplication)
		rootHandler = rootMux
	}
	server.httpServer = &http.Server{
		Handler:           rootHandler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return server, nil
}

func (server *Server) sharedDoHHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// The HTTP listener is a loopback recovery/setup endpoint. DoH is
		// available only on the public TLS listener and only when that exact
		// address is configured as a DoH endpoint.
		if request.TLS == nil || !server.config.Current().Config.SharesHTTPSWithDoH() {
			http.NotFound(writer, request)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) Start(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for web console on %s: %w", address, err)
	}
	server.listener = listener
	server.history.record(time.Now(), server.stats.Stats())
	go server.collectStatsHistory()
	go server.runBlockListScheduler()
	go func() {
		if err := server.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			server.logger.Error("web console stopped", "error", err)
		}
	}()
	return nil
}

func (server *Server) StartTLS(address, certificateFile, privateKeyFile string, minimumVersion uint16) error {
	if strings.TrimSpace(address) == "" {
		return nil
	}
	if err := server.ReplaceCertificate(certificateFile, privateKeyFile); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for HTTPS web console on %s: %w", address, err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		MinVersion: minimumVersion,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			certificate := server.certificate.Load()
			if certificate == nil {
				return nil, errors.New("public TLS certificate is unavailable")
			}
			return certificate, nil
		},
	})
	server.httpsListener = tlsListener
	go func() {
		if err := server.httpServer.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
			server.logger.Error("HTTPS web console stopped", "error", err)
		}
	}()
	return nil
}

func (server *Server) ReplaceCertificate(certificateFile, privateKeyFile string) error {
	certificate, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return fmt.Errorf("load public TLS certificate: %w", err)
	}
	server.certificate.Store(&certificate)
	return nil
}

func (server *Server) Close(ctx context.Context) error {
	server.historyStopOnce.Do(func() { close(server.historyStop) })
	shutdownError := server.httpServer.Shutdown(ctx)
	// The collector also flushes on its way out, but Close can win the race, so
	// persist the trailing counters here too. A flush clears what it wrote, so
	// whichever call runs second only writes what the first one missed.
	server.history.record(time.Now(), server.stats.Stats())
	if err := server.history.flush(ctx); err != nil {
		server.logger.Warn("persist query statistics", "error", err)
	}
	return shutdownError
}

func (server *Server) dashboard(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	if err := pages.Dashboard(server.dashboardView(request)).Render(request.Context(), writer); err != nil {
		server.logger.Error("render dashboard", "error", err)
	}
}

func (server *Server) dashboardView(request *http.Request) pages.DashboardView {
	view := server.consoleView(request)
	if !view.CanLogs {
		return view
	}
	entries, err := server.queries.RecentQueryEvents(request.Context(), dashboardInsightEvents)
	if err != nil {
		server.logger.Warn("count dashboard clients", "error", err)
	} else {
		view.Stats.Clients = dashboardClientSample(entries)
	}
	view.Stats.Dropped = server.queryLog.Stats().Dropped
	// The rankings open on whatever range the chart opens on, so the panels and
	// the plot above them always answer for the same window.
	if window, valid := chartInsightWindow(view.Chart.ActiveRange, time.Now()); valid {
		view.Insights = server.dashboardInsightsView(request, window)
	}
	return view
}

// queryInsightReader is the optional query log capability the rankings need.
// A store that cannot aggregate simply leaves the panels empty rather than
// falling back to a sample whose totals nothing else on the page agrees with.
type queryInsightReader interface {
	QueryLogInsights(context.Context, time.Time, time.Time) (querylog.Insights, error)
}

func (server *Server) dashboardInsightsView(request *http.Request, window insightWindow) pages.DashboardInsightsView {
	reader, ok := server.queries.(queryInsightReader)
	if !ok {
		return pages.DashboardInsightsView{RangeLabel: window.Label, LogWindowQuery: window.logWindowQuery()}
	}
	insights, err := reader.QueryLogInsights(request.Context(), window.Start, window.End)
	if err != nil {
		server.logger.Warn("build dashboard insights", "error", err)
		return pages.DashboardInsightsView{RangeLabel: window.Label, LogWindowQuery: window.logWindowQuery()}
	}
	view := dashboardInsights(
		insights,
		window,
		server.config.Current().Config.Resolver.Hosts,
		server.zones.Current().Zones,
	)
	// Whatever the host overrides and the local zones could not name is asked
	// of the resolver, which is the only path that sees a reverse zone this
	// server merely forwards.
	server.nameRankedClients(view.TopClients)
	return view
}

func (server *Server) dnsClientPage(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	view := pages.DNSClientPageView{Console: console}
	if server.cluster != nil && console.CanCluster {
		state := server.cluster.Snapshot()
		if state.Initialized {
			nodes := append([]cluster.Node(nil), state.Nodes...)
			sort.SliceStable(nodes, func(left, right int) bool {
				if nodes[left].Role != nodes[right].Role {
					return nodes[left].Role == cluster.RolePrimary
				}
				return strings.ToLower(nodes[left].Name) < strings.ToLower(nodes[right].Name)
			})
			view.ClusterNodes = make([]pages.ResolverOption, 0, len(nodes))
			for _, node := range nodes {
				if node.ID == state.NodeID {
					continue
				}
				label := node.Name
				if strings.TrimSpace(label) == "" {
					label = node.ID
				}
				detail := clusterRoleLabel(node.Role)
				if len(node.Addresses) > 0 {
					detail += " · " + node.Addresses[0]
				}
				view.ClusterNodes = append(view.ClusterNodes, pages.ResolverOption{
					Value:  "cluster-node:" + node.ID,
					Label:  label,
					Detail: detail,
					Search: strings.Join(node.Addresses, " "),
				})
			}
		}
	}
	if err := pages.DNSClientPage(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render DNS client", "error", err)
	}
}

func (server *Server) aboutPage(writer http.ResponseWriter, request *http.Request) {
	current := version.Current()
	view := pages.AboutPageView{
		Console:      server.consoleView(request),
		Commit:       current.Commit,
		BuiltAt:      current.BuiltAt,
		GoVersion:    current.Go,
		ScrapeConfig: prometheusScrapeConfig(request),
		Update:       server.updateView(request, server.updateStatus()),
	}
	if err := pages.AboutPage(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render about page", "error", err)
	}
}

func prometheusScrapeConfig(request *http.Request) string {
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf(`scrape_configs:
  - job_name: "sable-dns"
    metrics_path: "/metrics"
    scheme: %q
    authorization:
      credentials: "YOUR_API_TOKEN"
    static_configs:
      - targets: [%q]`, scheme, request.Host)
}

func (server *Server) cachePage(writer http.ResponseWriter, request *http.Request) {
	view := server.consoleView(request)
	if err := pages.CachePage(server.cacheView(request.Context(), view, "")).Render(request.Context(), writer); err != nil {
		server.logger.Error("render DNS cache", "error", err)
	}
}

func (server *Server) cacheStatus(writer http.ResponseWriter, request *http.Request) {
	view := server.consoleView(request)
	if err := pages.CacheContent(server.cacheView(request.Context(), view, "")).Render(request.Context(), writer); err != nil {
		server.logger.Error("render DNS cache status", "error", err)
	}
}

func (server *Server) flushCache(writer http.ResponseWriter, request *http.Request) {
	removed := server.stats.PurgeCache()
	view := server.consoleView(request)
	message := fmt.Sprintf("Cleared %d cached DNS records", removed)
	if err := pages.CacheContent(server.cacheView(request.Context(), view, message)).Render(request.Context(), writer); err != nil {
		server.logger.Error("render cleared DNS cache", "error", err)
	}
}

func (server *Server) cacheView(ctx context.Context, console pages.DashboardView, message string) pages.CachePageView {
	stats := server.stats.Stats()
	domains := cachedDomainViews(server.stats.CachedResponses())
	return pages.CachePageView{
		Console:      console,
		Entries:      stats.CacheEntries,
		HitsLastHour: server.history.cacheHitsSince(ctx, time.Hour, time.Now(), stats),
		Domains:      domains,
		Message:      message,
	}
}

func cachedDomainViews(responses []dnsserver.CachedResponse) []pages.CacheDomainView {
	domains := make([]pages.CacheDomainView, 0, len(responses))
	for _, response := range responses {
		name := strings.TrimSuffix(response.Name, ".")
		if len(domains) == 0 || domains[len(domains)-1].Name != name {
			domains = append(domains, pages.CacheDomainView{Name: name})
		}
		domain := &domains[len(domains)-1]
		domain.Responses++
		domain.Records += len(response.Records)
		item := pages.CacheResponseView{
			RecordType: response.RecordType, RemainingTTL: response.RemainingTTL,
			Records: make([]pages.CacheRecordView, 0, len(response.Records)),
		}
		for _, record := range response.Records {
			item.Records = append(item.Records, pages.CacheRecordView{
				Section: record.Section, Value: record.Value, TTL: record.TTL,
			})
		}
		domain.Items = append(domain.Items, item)
		if domain.MinimumTTL == 0 || response.RemainingTTL < domain.MinimumTTL {
			domain.MinimumTTL = response.RemainingTTL
		}
	}
	return domains
}

func (server *Server) consoleView(request *http.Request) pages.DashboardView {
	snapshot := server.config.Current()
	dnsStats := server.stats.Stats()
	display := requestTimeDisplay(request)
	view := pages.DashboardView{
		Version:           version.Current().Release,
		TimeDisplay:       display,
		SecurityEnabled:   server.securityEnabled,
		CanSettings:       !server.securityEnabled,
		CanAdministration: !server.securityEnabled,
		CanZones:          !server.securityEnabled,
		CanBlocking:       !server.securityEnabled,
		CanLogs:           !server.securityEnabled,
		CanMetrics:        !server.securityEnabled,
		CanCluster:        !server.securityEnabled,
		Database:          server.database,
		DNSListeners:      strings.Join(snapshot.Config.Server.DNSListen, ", "),
		EncryptedDNS:      encryptedDNSStatus(snapshot.Config.EncryptedDNS),
		QueryServer:       snapshot.Config.Server.DNSListen[0],
		CacheSize:         snapshot.Config.Resolver.CacheSize,
		ForwardRoutes:     len(snapshot.Config.Resolver.Routes),
		LocalHosts:        len(snapshot.Config.Resolver.Hosts),
		QueryLogStatus:    queryLogStatus(snapshot.Config.QueryLog.Enabled, server.queryLog.Stats()),
		DNSSECStatus:      dnssecRuntimeStatus(snapshot.Config.Resolver, dnsStats),
		ConfigRevision:    snapshot.Revision,
		Stats:             statsView(server.history.totals(time.Now(), dnsStats)),
		Chart:             server.history.view(request.Context(), "hour", time.Now(), dnsStats, display),
	}
	if principal, ok := request.Context().Value(principalContextKey{}).(auth.Principal); ok {
		view.Username = principal.Username
		view.DisplayName = principal.DisplayName
		view.AvatarURL = avatarURL(principal.AvatarETag)
		view.CSRFToken = principal.CSRFToken
		view.CanSettings = auth.HasPermission(principal, auth.PermissionSettingsRead)
		view.CanAdministration = auth.HasPermission(principal, auth.PermissionUsersRead)
		view.CanZones = auth.HasPermission(principal, auth.PermissionZonesRead)
		view.CanBlocking = auth.HasPermission(principal, auth.PermissionBlockingRead)
		view.CanLogs = auth.HasPermission(principal, auth.PermissionLogsRead)
		view.CanMetrics = auth.HasPermission(principal, auth.PermissionMetricsRead)
		view.CanCluster = auth.HasPermission(principal, auth.PermissionClusterRead)
	}
	if server.cluster != nil {
		clusterState := server.cluster.Snapshot()
		view.ControlPlaneReadOnly = clusterState.Initialized && clusterState.LocalRole == cluster.RoleReplica
		view.PrimaryURL = clusterState.PrimaryURL
	}
	return view
}

func dnssecRuntimeStatus(resolver config.Resolver, stats dnsserver.Stats) string {
	if !resolver.DNSSECValidation {
		return "DNSSEC validation off"
	}
	if !resolver.DNSSECTrustAnchorUpdates || len(resolver.DNSSECTrustAnchors) > 0 {
		return "DNSSEC · static anchors"
	}
	status := stats.DNSSECTrustAnchors
	if !status.Initialized {
		return "DNSSEC · RFC 5011 initializing"
	}
	result := fmt.Sprintf("DNSSEC · RFC 5011 · %d anchors", status.Active)
	if status.Pending > 0 {
		result += fmt.Sprintf(" · %d pending", status.Pending)
	}
	return result
}

func encryptedDNSStatus(configuration config.EncryptedDNS) string {
	listeners := make([]string, 0, len(configuration.DoTListen)+len(configuration.DoHListen)+len(configuration.DoQListen))
	for _, address := range configuration.DoTListen {
		listeners = append(listeners, "DoT "+address)
	}
	for _, address := range configuration.DoHListen {
		listeners = append(listeners, "DoH "+address)
	}
	for _, address := range configuration.DoQListen {
		listeners = append(listeners, "DoQ "+address)
	}
	if len(listeners) == 0 {
		return "Disabled"
	}
	return strings.Join(listeners, ", ")
}

func (server *Server) recentQueryLog(writer http.ResponseWriter, request *http.Request) {
	entries, err := server.queries.RecentQueryEvents(request.Context(), defaultRecentQueryLimit)
	if err != nil {
		server.logger.Error("read recent query log", "error", err)
		http.Error(writer, "query log unavailable", http.StatusInternalServerError)
		return
	}
	if err := pages.RecentQueryLog(queryLogEntryViews(entries, requestTimeDisplay(request))).Render(request.Context(), writer); err != nil {
		server.logger.Error("render recent query log", "error", err)
	}
}

func (server *Server) runtimeStats(writer http.ResponseWriter, request *http.Request) {
	view := statsView(server.history.totals(time.Now(), server.stats.Stats()))
	// The client and dropped counts come from the query log rather than the
	// resolver counters, so the refreshed cards have to repeat the read the
	// dashboard performs or those two would drop to zero every poll.
	if server.canReadLogs(request) {
		view.Dropped = server.queryLog.Stats().Dropped
		entries, err := server.queries.RecentQueryEvents(request.Context(), dashboardInsightEvents)
		if err != nil {
			server.logger.Warn("count dashboard clients", "error", err)
		} else {
			view.Clients = dashboardClientSample(entries)
		}
	}
	if err := pages.Stats(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render runtime statistics", "error", err)
	}
}

func (server *Server) canReadLogs(request *http.Request) bool {
	principal, ok := request.Context().Value(principalContextKey{}).(auth.Principal)
	if !ok {
		return !server.securityEnabled
	}
	return auth.HasPermission(principal, auth.PermissionLogsRead)
}

func (server *Server) queryStatistics(writer http.ResponseWriter, request *http.Request) {
	rangeName := request.URL.Query().Get("range")
	display := requestTimeDisplay(request)
	location := display.Location
	if location == nil {
		location = time.Local
	}
	// The rankings are recounted only when a range control asked for the
	// chart, never on the ten-second refresh: aggregating a week of the query
	// log is worth doing on a click and wasteful on a poll.
	withInsights := request.URL.Query().Get("insights") == "1" && server.canReadLogs(request)
	if rangeName == "custom" {
		start, startErr := time.ParseInLocation("2006-01-02T15:04", request.URL.Query().Get("start"), location)
		end, endErr := time.ParseInLocation("2006-01-02T15:04", request.URL.Query().Get("end"), location)
		if startErr != nil || endErr != nil || !start.Before(end) {
			http.Error(writer, "custom range must contain valid start and end times", http.StatusBadRequest)
			return
		}
		view := server.history.customView(request.Context(), start, end, server.stats.Stats(), display)
		if err := pages.QueryChart(view).Render(request.Context(), writer); err != nil {
			server.logger.Error("render custom query statistics", "error", err)
			return
		}
		if withInsights {
			window := insightWindow{Start: start, End: end, Label: chartRangeLabel("custom")}
			server.renderInsights(writer, request, window)
		}
		return
	}
	if _, valid := chartDuration(rangeName); !valid {
		http.Error(writer, "range must be hour, day, week, month, or year", http.StatusBadRequest)
		return
	}
	now := time.Now()
	view := server.history.view(request.Context(), rangeName, now, server.stats.Stats(), display)
	if err := pages.QueryChart(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render query statistics", "error", err)
		return
	}
	if window, valid := chartInsightWindow(rangeName, now); valid && withInsights {
		server.renderInsights(writer, request, window)
	}
}

// renderInsights appends the rankings as an out-of-band swap so one range click
// updates the chart and the panels below it together.
func (server *Server) renderInsights(writer http.ResponseWriter, request *http.Request, window insightWindow) {
	insights := server.dashboardInsightsView(request, window)
	if err := pages.DashboardInsights(insights, true).Render(request.Context(), writer); err != nil {
		server.logger.Error("render dashboard insights", "error", err)
	}
}

func (server *Server) query(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		_ = pages.QueryResult(pages.QueryView{Error: err.Error()}).Render(request.Context(), writer)
		return
	}
	resolver := request.FormValue("resolver")
	var queryServer resolvedDNSServer
	var err error
	if strings.HasPrefix(strings.TrimSpace(resolver), clusterResolverPrefix) {
		if server.cluster == nil {
			err = fmt.Errorf("cluster DNS resolver is unavailable")
		} else {
			queryServer, err = resolveClusterDNSClientServer(
				resolver,
				server.cluster.Snapshot(),
				request.FormValue("local_server"),
				request.FormValue("transport"),
			)
		}
	} else {
		queryServer, err = resolveDNSClientServer(
			resolver,
			request.FormValue("server"),
			request.FormValue("custom_name"),
			request.FormValue("custom_ip"),
			request.FormValue("local_server"),
			request.FormValue("transport"),
		)
	}
	if err != nil {
		writer.WriteHeader(http.StatusUnprocessableEntity)
		_ = pages.QueryResult(pages.QueryView{Error: err.Error()}).Render(request.Context(), writer)
		return
	}
	queryRequest := dnsclient.Request{
		Name:       request.FormValue("name"),
		Type:       request.FormValue("type"),
		Server:     queryServer.address,
		TLSName:    queryServer.tlsName,
		DialIP:     queryServer.dialIP,
		Transport:  request.FormValue("transport"),
		EDNSSubnet: request.FormValue("edns_subnet"),
		DNSSEC:     request.FormValue("dnssec") == "true",
		Timeout:    5 * time.Second,
	}
	result, err := dnsclient.Query(request.Context(), queryRequest)
	if err != nil {
		writer.WriteHeader(http.StatusUnprocessableEntity)
		_ = pages.QueryResult(pages.QueryView{Error: err.Error()}).Render(request.Context(), writer)
		return
	}
	question := dns.Fqdn(queryRequest.Name)
	if len(result.Response.Question) > 0 {
		question = result.Response.Question[0].Name
	}
	flags := make([]string, 0, 4)
	if result.Response.Authoritative {
		flags = append(flags, "AA")
	}
	if result.Response.RecursionAvailable {
		flags = append(flags, "RA")
	}
	if result.Response.AuthenticatedData {
		flags = append(flags, "AD")
	}
	if result.Response.Truncated {
		flags = append(flags, "TC")
	}
	view := pages.QueryView{
		Success:    true,
		Question:   question,
		RecordType: strings.ToUpper(queryRequest.Type),
		Server:     result.Server,
		Protocol:   queryProtocolLabel(queryRequest.Transport),
		Elapsed:    result.Elapsed.Round(time.Microsecond).String(),
		Size:       fmt.Sprintf("%d bytes", result.Response.Len()),
		RCode:      dns.RcodeToString[result.Response.Rcode],
		Flags:      flags,
		Answers:    recordViews(result.Response.Answer),
		Authority:  recordViews(result.Response.Ns),
		Additional: recordViews(result.Response.Extra),
		Response:   result.Response.String(),
	}
	view.JSON = queryResultJSON(view)
	_ = pages.QueryResult(view).Render(request.Context(), writer)
}

func queryResultJSON(view pages.QueryView) string {
	export := struct {
		Question   string             `json:"question"`
		RecordType string             `json:"record_type"`
		Server     string             `json:"server"`
		Protocol   string             `json:"protocol"`
		Elapsed    string             `json:"elapsed"`
		Size       string             `json:"size"`
		RCode      string             `json:"rcode"`
		Flags      []string           `json:"flags"`
		Answers    []pages.RecordView `json:"answers"`
		Authority  []pages.RecordView `json:"authority"`
		Additional []pages.RecordView `json:"additional"`
	}{
		Question: view.Question, RecordType: view.RecordType, Server: view.Server,
		Protocol: view.Protocol, Elapsed: view.Elapsed, Size: view.Size, RCode: view.RCode,
		Flags: view.Flags, Answers: view.Answers, Authority: view.Authority, Additional: view.Additional,
	}
	encoded, err := json.Marshal(export)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func queryProtocolLabel(transport string) string {
	switch transport {
	case "tcp":
		return "TCP"
	case "tcp-tls":
		return "TLS"
	case "doh":
		return "HTTPS"
	case "quic":
		return "QUIC"
	default:
		return "UDP"
	}
}

func recordViews(records []dns.RR) []pages.RecordView {
	views := make([]pages.RecordView, 0, len(records))
	for _, record := range records {
		if opt, ok := record.(*dns.OPT); ok && len(opt.Option) == 0 {
			continue
		}
		fields := strings.Fields(record.String())
		data := ""
		if len(fields) > 4 {
			data = strings.Join(fields[4:], " ")
		}
		header := record.Header()
		views = append(views, pages.RecordView{
			Name: header.Name, Type: dns.TypeToString[header.Rrtype], Data: data, TTL: header.Ttl,
		})
	}
	return views
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

func (server *Server) queryLogAPI(writer http.ResponseWriter, request *http.Request) {
	limit := defaultRecentQueryLimit
	if rawLimit := request.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		limit = parsed
	}
	entries, err := server.queries.RecentQueryEvents(request.Context(), limit)
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "query log unavailable"})
		return
	}
	writeJSON(writer, http.StatusOK, queryLogAPIEntries(entries))
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

func (server *Server) purgeCache(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, struct {
		Removed int `json:"removed"`
	}{Removed: server.stats.PurgeCache()})
}

func (server *Server) purgeCacheUI(writer http.ResponseWriter, request *http.Request) {
	removed := server.stats.PurgeCache()
	_ = pages.ActionResult(fmt.Sprintf("Purged %d cache entries", removed), false).Render(request.Context(), writer)
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

func statsView(stats dnsserver.Stats) pages.StatsView {
	return pages.StatsView{
		Queries:              stats.Queries,
		NoError:              stats.NoError,
		ServerFailures:       stats.ServerFailures,
		NXDomain:             stats.NXDomain,
		Refused:              stats.Refused,
		Recursive:            stats.CacheHits + stats.CacheMisses,
		Blocked:              stats.Blocked,
		Failures:             stats.Failures,
		UpstreamErrors:       stats.UpstreamErrors,
		CacheHits:            stats.CacheHits,
		CacheMisses:          stats.CacheMisses,
		CacheEntries:         stats.CacheEntries,
		CacheHitRatio:        cacheHitRatio(stats.CacheHits, stats.CacheMisses),
		RoutedQueries:        stats.RoutedQueries,
		LocalAnswers:         stats.LocalAnswers,
		AuthoritativeAnswers: stats.AuthoritativeAnswers,
		DNSSECSecure:         stats.DNSSECSecure,
		DNSSECInsecure:       stats.DNSSECInsecure,
		DNSSECBogus:          stats.DNSSECBogus,
		LocalHosts:           stats.LocalHosts,
		BlockedDomains:       stats.BlockedDomains,
		BlockLists:           stats.BlockLists,
		Uptime:               time.Since(stats.StartedAt).Round(time.Second).String(),
	}
}

func cacheHitRatio(hits, misses uint64) string {
	total := hits + misses
	if total == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", float64(hits)*100/float64(total))
}

func queryLogStatus(enabled bool, stats querylog.Stats) string {
	if !enabled {
		return "Disabled"
	}
	if stats.Dropped == 0 {
		return fmt.Sprintf("Active · %d persisted", stats.Persisted)
	}
	return fmt.Sprintf("Active · %d dropped", stats.Dropped)
}

func queryLogEntryViews(entries []querylog.Entry, display pages.TimeDisplay) []pages.QueryLogEntryView {
	views := make([]pages.QueryLogEntryView, 0, len(entries))
	for _, entry := range entries {
		recordType := dns.TypeToString[entry.RecordType]
		if recordType == "" {
			recordType = strconv.Itoa(int(entry.RecordType))
		}
		status := dns.RcodeToString[entry.ResponseCode]
		if status == "" {
			status = strconv.Itoa(entry.ResponseCode)
		}
		views = append(views, pages.QueryLogEntryView{
			OccurredAt: pages.FormatClock(entry.OccurredAt, display, true),
			ClientIP:   entry.ClientIP,
			Name:       entry.Name,
			RecordType: recordType,
			Status:     status,
			Source:     string(entry.Source),
			Protocol:   entry.Protocol,
			Answers:    strings.Split(entry.Answer, "\n"),
			Duration:   entry.Duration.Round(time.Microsecond).String(),
		})
	}
	return views
}

type queryLogAPIEntry struct {
	ID           int64           `json:"id"`
	OccurredAt   time.Time       `json:"occurred_at"`
	ClientIP     string          `json:"client_ip"`
	Name         string          `json:"name"`
	RecordType   uint16          `json:"record_type"`
	Class        uint16          `json:"class"`
	ResponseCode int             `json:"response_code"`
	Source       querylog.Source `json:"source"`
	Protocol     string          `json:"protocol"`
	Answer       string          `json:"answer"`
	DurationUS   int64           `json:"duration_us"`
}

func queryLogAPIEntries(entries []querylog.Entry) []queryLogAPIEntry {
	result := make([]queryLogAPIEntry, 0, len(entries))
	for _, entry := range entries {
		result = append(result, queryLogAPIEntry{
			ID:           entry.ID,
			OccurredAt:   entry.OccurredAt,
			ClientIP:     entry.ClientIP,
			Name:         entry.Name,
			RecordType:   entry.RecordType,
			Class:        entry.Class,
			ResponseCode: entry.ResponseCode,
			Source:       entry.Source,
			Protocol:     entry.Protocol,
			Answer:       entry.Answer,
			DurationUS:   entry.Duration.Microseconds(),
		})
	}
	return result
}

// consoleFragmentHeader marks a response whose body is a rendered console
// fragment rather than a bare error. HTMX throws away 4xx and 5xx bodies by
// default, which silently hid every validation banner the server rendered, so
// the console opts those responses back into the swap when it sees this header.
// The status code itself stays honest for API clients and logs.
const consoleFragmentHeader = "X-Sable-Console-Fragment"

// writeFragmentStatus writes a status for a response carrying a console
// fragment, flagging anything other than 200 so the browser still swaps it in.
func writeFragmentStatus(writer http.ResponseWriter, status int) {
	if status != http.StatusOK {
		writer.Header().Set(consoleFragmentHeader, "true")
	}
	writer.WriteHeader(status)
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

// contentSecurityPolicy builds the console's policy.
//
// formActionOrigins names origins a form submission is allowed to end up at
// besides this server. It is empty everywhere except the sign-in page: that
// page posts to a handler which redirects to the identity provider, and
// browsers apply form-action across the redirect, so the provider has to be
// named or the redirect is dropped and single sign-on cannot start.
func contentSecurityPolicy(formActionOrigins []string) string {
	formAction := "form-action 'self'"
	for _, origin := range formActionOrigins {
		formAction += " " + origin
	}
	return strings.Join([]string{
		"default-src 'self'",
		"base-uri 'none'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		formAction,
		"style-src 'self'",
		"script-src 'self'",
		"connect-src 'self'",
		"img-src 'self' data:",
	}, "; ")
}

func secureHeaders(next http.Handler, forceHTTPS bool) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", contentSecurityPolicy(nil))
		writer.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		if forceHTTPS || request.TLS != nil {
			writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(writer, request)
	})
}
