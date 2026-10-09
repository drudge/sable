package web

import (
	"fmt"
	"net/http"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/cluster"
	webassets "github.com/drudge/sable/internal/web/assets"
	"github.com/drudge/sable/internal/web/pages"
)

// route declares everything Sable knows about one HTTP endpoint in one place:
// who may call it, how large and how slow its body may be, and whether a
// cluster replica may accept it. The middleware is built from these fields,
// so a new endpoint cannot forget a check that lives in some other table.
//
// Exactly one of public, signedIn, perm and anyPerm says who may call the
// route. A route that sets none is refused at startup, so a forgotten
// permission fails closed instead of opening the route to every account.
type route struct {
	pattern string
	handler func(*Server, http.ResponseWriter, *http.Request)

	// public routes need no account, such as sign-in and assets.
	public bool
	// signedIn routes need an account and nothing more. The handler either
	// serves only the caller's own data or authorizes the exact action
	// itself, as zone mutations and MCP tools do.
	signedIn bool
	// perm is the one permission the route needs.
	perm string
	// anyPerm lists permissions any one of which opens the route, for pages
	// that show each section only to an operator who may read it.
	anyPerm []string

	// insights routes answer only while Insights is on.
	insights bool
	// replicaLocal writes change only this node, so a replica accepts them.
	// Every other write must be made on the cluster primary.
	replicaLocal bool
	// bodyLimit caps the request body, maximumFormBytes when zero.
	bodyLimit int64
	// bodyTimeout extends the time the client has to send the body past
	// webRequestBodyTimeout, for uploads.
	bodyTimeout time.Duration

	// zone describes a zone mutation, which the handler authorizes against
	// the exact zone once it has parsed the form.
	zone zoneMutation
}

// zoneMutation is the audit action a zone change records and the
// permissions it needs. create needs zones.create on every zone; perms must
// all be held on the zone being changed.
type zoneMutation struct {
	action string
	create bool
	perms  []string
}

func (current *route) maximumBodyBytes() int64 {
	if current.bodyLimit > 0 {
		return current.bodyLimit
	}
	return maximumFormBytes
}

// policyError says what is wrong with a route's access policy, or nothing.
func (current *route) policyError() error {
	policies := 0
	for _, set := range []bool{current.public, current.signedIn, current.perm != "", len(current.anyPerm) > 0} {
		if set {
			policies++
		}
	}
	if policies != 1 {
		return fmt.Errorf("route %q must set exactly one of public, signedIn, perm and anyPerm", current.pattern)
	}
	if current.zone.action != "" && !current.signedIn {
		return fmt.Errorf("zone mutation %q authorizes itself and must be signedIn", current.pattern)
	}
	return nil
}

// routesByPattern finds a route by its mux pattern. It is filled once in
// init, which keeps the table out of package variable initialization: the
// handlers it names read it back.
var routesByPattern map[string]*route

func init() {
	routes := routeTable()
	routesByPattern = make(map[string]*route, len(routes))
	for index := range routes {
		current := &routes[index]
		if err := current.policyError(); err != nil {
			panic(err)
		}
		if _, duplicate := routesByPattern[current.pattern]; duplicate {
			panic(fmt.Sprintf("route %q is declared twice", current.pattern))
		}
		routesByPattern[current.pattern] = current
	}
}

// requestRoute finds the route serving a request. The mux records the
// pattern it matched; a handler called directly, as tests do, is found by
// its method and path.
func requestRoute(request *http.Request) *route {
	if current := routesByPattern[request.Pattern]; current != nil {
		return current
	}
	return routesByPattern[request.Method+" "+request.URL.Path]
}

// newRouter registers every route with the middleware its declaration asks
// for.
func (server *Server) newRouter() *http.ServeMux {
	mux := http.NewServeMux()
	for _, current := range routesByPattern {
		mux.Handle(current.pattern, server.routeHandler(current))
	}
	return mux
}

func (server *Server) routeHandler(current *route) http.Handler {
	var serve http.HandlerFunc = func(writer http.ResponseWriter, request *http.Request) {
		current.handler(server, writer, request)
	}
	if current.insights {
		serve = server.whileInsightsOn(serve)
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if current.bodyTimeout > 0 {
			// The server-wide deadline is the short one. Uploads extend it.
			_ = http.NewResponseController(writer).SetReadDeadline(time.Now().Add(current.bodyTimeout))
		}
		if !safeMethod(request.Method) {
			request.Body = http.MaxBytesReader(writer, request.Body, current.maximumBodyBytes())
		}
		request, allowed := server.authorizeRoute(writer, request, current)
		if !allowed || server.refuseReplicaWrite(writer, request, current) {
			return
		}
		serve(writer, request)
	})
}

// permits reports whether a signed-in principal may call the route.
func (current *route) permits(principal auth.Principal) bool {
	switch {
	case current.perm != "":
		return auth.HasPermission(principal, current.perm)
	case len(current.anyPerm) > 0:
		return hasAnyPermission(principal, current.anyPerm)
	default:
		return current.signedIn
	}
}

func staticHandler(handler http.Handler) func(*Server, http.ResponseWriter, *http.Request) {
	return func(_ *Server, writer http.ResponseWriter, request *http.Request) {
		handler.ServeHTTP(writer, request)
	}
}

func routeTable() []route {
	zoneRead := []string{auth.PermissionZonesRead}
	zoneSettings := []string{auth.PermissionZonesSettings}
	zoneDNSSEC := []string{auth.PermissionZonesDNSSEC}
	zoneRecords := []string{auth.PermissionZonesRecords}
	zoneConversion := []string{auth.PermissionZonesRecords, auth.PermissionZonesSettings}
	return []route{
		// Assets, sign-in, and setup, which work before anyone signs in.
		{pattern: "GET /assets/", handler: staticHandler(webassets.Handler()), public: true},
		{pattern: "GET " + serviceWorkerPath, handler: staticHandler(webassets.Root("sw.js")), public: true},
		{pattern: "GET " + webManifestPath, handler: staticHandler(http.HandlerFunc(serveWebManifest)), public: true},
		{pattern: "GET /setup", handler: (*Server).setupPage, public: true},
		{pattern: "POST /setup", handler: (*Server).setup, public: true, bodyLimit: authFormLimit},
		{pattern: "GET /login", handler: (*Server).loginPage, public: true},
		// Sessions are node-local by design, so signing in to a replica's own
		// console is a local write, not a control-plane change. Starting
		// single sign-on belongs with /login for exactly that reason: without
		// it a replica offers the button and then refuses the click.
		{pattern: "POST /login", handler: (*Server).login, public: true, replicaLocal: true, bodyLimit: authFormLimit},
		{pattern: "POST " + ssoStartPath, handler: (*Server).startSSO, public: true, replicaLocal: true, bodyLimit: authFormLimit},
		{pattern: "GET " + ssoCallbackPath, handler: (*Server).completeSSO, public: true},
		{pattern: "POST " + passkeyLoginBegin, handler: (*Server).beginPasskeyLogin, public: true, replicaLocal: true, bodyLimit: authFormLimit},
		{pattern: "POST " + passkeyLoginFinish, handler: (*Server).finishPasskeyLogin, public: true, replicaLocal: true, bodyLimit: authFormLimit},
		{pattern: "POST /logout", handler: (*Server).logout, signedIn: true, replicaLocal: true},

		// Pages every account sees.
		{pattern: "GET /", handler: (*Server).dashboard, signedIn: true},
		{pattern: "GET /about", handler: (*Server).aboutPage, signedIn: true},
		{pattern: "GET /ui/about/license", handler: (*Server).thirdPartyLicense, signedIn: true},
		{pattern: "GET /dns-client", handler: (*Server).dnsClientPage, signedIn: true},
		{pattern: "POST /ui/query", handler: (*Server).query, signedIn: true, replicaLocal: true},
		{pattern: "GET /ui/stats", handler: (*Server).runtimeStats, signedIn: true},
		{pattern: "GET /ui/stats/chart", handler: (*Server).queryStatistics, signedIn: true},
		{pattern: "GET /ui/stats/insights", handler: (*Server).dashboardInsightsPanel, signedIn: true},

		// The caller's own profile, passkeys, and tokens.
		{pattern: "GET " + avatarPath, handler: (*Server).ownAvatar, signedIn: true},
		{pattern: "GET /profile", handler: (*Server).profilePage, signedIn: true},
		{pattern: "GET /ui/profile/tokens", handler: (*Server).profileTokens, signedIn: true},
		{pattern: "POST /ui/profile", handler: (*Server).updateOwnProfile, signedIn: true, bodyLimit: authFormLimit},
		{pattern: "POST /ui/profile/password", handler: (*Server).changeOwnPassword, signedIn: true},
		{pattern: "POST /ui/profile/tokens/revoke", handler: (*Server).revokeOwnAPIToken, signedIn: true},
		{pattern: "POST /ui/profile/passkeys/begin", handler: (*Server).beginPasskeyRegistration, signedIn: true, bodyLimit: authFormLimit},
		{pattern: "POST /ui/profile/passkeys/finish", handler: (*Server).finishPasskeyRegistration, signedIn: true, bodyLimit: authFormLimit},
		{pattern: "POST /ui/profile/passkeys/remove", handler: (*Server).removeOwnPasskey, signedIn: true, bodyLimit: authFormLimit},
		{pattern: "POST /ui/profile/password/disable", handler: (*Server).disableOwnPassword, signedIn: true, bodyLimit: authFormLimit},
		{pattern: "POST /ui/profile/password/enable", handler: (*Server).enableOwnPassword, signedIn: true, bodyLimit: authFormLimit},
		// The handler checks that the caller may make a token for the owner
		// and with the groups it asks for.
		{pattern: "POST /ui/api-tokens", handler: (*Server).createAPIToken, signedIn: true, bodyLimit: authFormLimit},

		// Insights.
		{pattern: "GET /insights", handler: (*Server).insightsPage, anyPerm: insightsPermissions, insights: true},
		{pattern: "GET " + pages.InsightDeviceRoute + "{key}", handler: (*Server).insightsPage, anyPerm: insightsPermissions, insights: true},
		{pattern: "GET " + pages.InsightAppRoute + "{app}", handler: (*Server).insightsPage, anyPerm: insightsPermissions, insights: true},
		{pattern: "GET " + pages.InsightFindingRoute + "{finding}", handler: (*Server).insightsPage, anyPerm: insightsPermissions, insights: true},
		{pattern: "GET /ui/insights/overview", handler: (*Server).insightsOverviewPanel, anyPerm: insightsPermissions, insights: true},
		{pattern: "GET /ui/insights/device", handler: (*Server).insightsDevicePanel, anyPerm: insightsPermissions, insights: true},
		{pattern: "GET /ui/insights/app", handler: (*Server).insightsAppPanel, anyPerm: insightsPermissions, insights: true},
		{pattern: "POST /ui/insights/devices/name", handler: (*Server).nameInsightsDevice, anyPerm: insightsPermissions, insights: true},
		{pattern: "POST /ui/insights/devices/type", handler: (*Server).typeInsightsDevice, anyPerm: insightsPermissions, insights: true},
		{pattern: "POST /ui/insights/devices/rule-set", handler: (*Server).deviceRuleSet, perm: auth.PermissionBlockingWrite, insights: true},
		{pattern: "POST /ui/insights/devices/hold", handler: (*Server).deviceHold, perm: auth.PermissionBlockingWrite, insights: true},
		{pattern: "POST /ui/insights/feedback", handler: (*Server).hideInsightFinding, anyPerm: insightsPermissions, insights: true},
		{pattern: "POST /ui/insights/feedback/remove", handler: (*Server).showInsightFinding, anyPerm: insightsPermissions, insights: true},
		{pattern: "GET /ui/insights/settings", handler: (*Server).insightSettingsPanel, anyPerm: insightsPermissions, insights: true},
		{pattern: "POST /ui/insights/settings", handler: (*Server).saveInsightSettings, anyPerm: insightsPermissions, insights: true},
		{pattern: "POST /ui/insights/settings/reset", handler: (*Server).resetInsightSettings, anyPerm: insightsPermissions, insights: true},

		// Zones. Reads need zones.read, which may cover only some zones; the
		// pages show only those. Writes authorize the exact action on the
		// exact zone once the form is parsed, because a broad check here
		// would reject legitimate delete-only or DNSSEC-only groups.
		{pattern: "GET /zones", handler: (*Server).zonesPage, perm: auth.PermissionZonesRead},
		{pattern: "GET /zones/{zone}", handler: (*Server).zonesPage, perm: auth.PermissionZonesRead},
		{pattern: "GET /zones/{zone}/records/{record}/edit", handler: (*Server).zonesPage, perm: auth.PermissionZonesRead},
		{pattern: "GET /zones/import-catalog", handler: (*Server).importCatalog, perm: auth.PermissionZonesRead},
		{pattern: "GET /ui/zones/history", handler: (*Server).zoneHistoryList, perm: auth.PermissionZonesRead},
		{pattern: "GET /ui/zones/history/diff", handler: (*Server).zoneRevisionDiff, perm: auth.PermissionZonesRead},
		{pattern: "GET /api/v1/zones", handler: (*Server).zonesAPI, perm: auth.PermissionZonesRead},
		{pattern: "GET /api/v1/zones/dnssec", handler: (*Server).zoneDNSSECStatus, perm: auth.PermissionZonesRead},
		{pattern: "GET /api/v1/zones/convert-primary", handler: (*Server).reviewZoneConversion, perm: auth.PermissionZonesRead},
		{pattern: "GET /api/v1/zones/export", handler: (*Server).exportZone, perm: auth.PermissionZonesExport},
		{pattern: "GET /api/v1/zones/ds", handler: (*Server).zoneDS, perm: auth.PermissionZonesExport},
		{pattern: "POST /ui/zones/import-catalog", handler: (*Server).importCatalog, signedIn: true, zone: zoneMutation{action: "zone.catalog_import", create: true}},
		{pattern: "POST /ui/zones/add", handler: (*Server).addZone, signedIn: true, zone: zoneMutation{action: "zone.create", create: true}},
		{pattern: "POST /ui/zones/import-new", handler: (*Server).importNewZone, signedIn: true, bodyLimit: maximumZoneImportBytes + maximumFormBytes, bodyTimeout: webReadTimeout,
			zone: zoneMutation{action: "zone.import_new", create: true}},
		{pattern: "POST /ui/zones/clone", handler: (*Server).cloneZone, signedIn: true, zone: zoneMutation{action: "zone.clone", create: true, perms: zoneRead}},
		{pattern: "POST /ui/zones/delete", handler: (*Server).deleteZone, signedIn: true, zone: zoneMutation{action: "zone.delete", perms: []string{auth.PermissionZonesDelete}}},
		{pattern: "POST /ui/zones/settings", handler: (*Server).updateZoneSettings, signedIn: true, zone: zoneMutation{action: "zone.settings", perms: zoneSettings}},
		{pattern: "POST /ui/zones/toggle", handler: (*Server).toggleZone, signedIn: true, zone: zoneMutation{action: "zone.toggle", perms: zoneSettings}},
		{pattern: "POST /ui/zones/dnssec", handler: (*Server).updateZoneDNSSEC, signedIn: true, zone: zoneMutation{action: "zone.dnssec.settings", perms: zoneDNSSEC}},
		{pattern: "POST /ui/zones/dnssec/rollover", handler: (*Server).rolloverZoneDNSSECKey, signedIn: true, zone: zoneMutation{action: "zone.dnssec.rollover", perms: zoneDNSSEC}},
		{pattern: "POST /ui/zones/dnssec/confirm-ds", handler: (*Server).confirmZoneDNSSECDS, signedIn: true, zone: zoneMutation{action: "zone.dnssec.confirm_ds", perms: zoneDNSSEC}},
		{pattern: "POST /ui/zones/resync", handler: (*Server).resyncZone, signedIn: true, zone: zoneMutation{action: "zone.resync", perms: []string{auth.PermissionZonesTransfer}}},
		{pattern: "POST /ui/zones/import", handler: (*Server).importZone, signedIn: true, bodyLimit: maximumZoneImportBytes + maximumFormBytes, bodyTimeout: webReadTimeout,
			zone: zoneMutation{action: "zone.import", perms: []string{auth.PermissionZonesImport}}},
		{pattern: "POST /ui/zones/records/add", handler: (*Server).addZoneRecord, signedIn: true, zone: zoneMutation{action: "zone.record.create", perms: zoneRecords}},
		{pattern: "POST /ui/zones/records/update", handler: (*Server).updateZoneRecord, signedIn: true, zone: zoneMutation{action: "zone.record.update", perms: zoneRecords}},
		{pattern: "POST /ui/zones/records/delete", handler: (*Server).deleteZoneRecord, signedIn: true, zone: zoneMutation{action: "zone.record.delete", perms: zoneRecords}},
		{pattern: "POST /ui/zones/rollback", handler: (*Server).rollbackZone, signedIn: true, zone: zoneMutation{action: "zone.rollback", perms: zoneConversion}},
		// A final sync also needs zones.transfer.manage, which the handler
		// adds when the form asks for one.
		{pattern: "POST /ui/zones/convert-primary", handler: (*Server).convertZoneToPrimary, signedIn: true, zone: zoneMutation{action: "zone.convert_primary", perms: zoneConversion}},
		{pattern: "POST /api/v1/zones/convert-primary", handler: (*Server).convertZoneToPrimary, signedIn: true, zone: zoneMutation{action: "zone.convert_primary", perms: zoneConversion}},

		// Blocking.
		{pattern: "GET /blocked", handler: (*Server).blockingPage, perm: auth.PermissionBlockingRead},
		{pattern: "GET " + pages.BlockListRoute + "{name}", handler: (*Server).blockingPage, perm: auth.PermissionBlockingRead},
		{pattern: "GET " + pages.CheckDomainRoute + "{domain}", handler: (*Server).blockingPage, perm: auth.PermissionBlockingRead},
		{pattern: "GET /ui/blocking/list", handler: (*Server).blockListPanel, perm: auth.PermissionBlockingRead},
		{pattern: "GET /ui/blocking/check", handler: (*Server).checkDomainPanel, perm: auth.PermissionBlockingRead},
		{pattern: "GET /ui/blocking/rule-sets/form", handler: (*Server).ruleSetFormPanel, perm: auth.PermissionBlockingRead},
		{pattern: "GET " + pages.RuleSetRoute + "{name}", handler: (*Server).blockingPage, perm: auth.PermissionBlockingRead},
		{pattern: "GET /ui/blocking/rule-set", handler: (*Server).ruleSetPanel, perm: auth.PermissionBlockingRead},
		{pattern: "GET /ui/blocking/domains/export", handler: (*Server).exportBlockedDomains, perm: auth.PermissionBlockingRead},
		{pattern: "GET /ui/blocking/allowed/export", handler: (*Server).exportAllowedDomains, perm: auth.PermissionBlockingRead},
		{pattern: "GET /api/v1/policy", handler: (*Server).policyAPI, perm: auth.PermissionBlockingRead},
		{pattern: "POST /ui/blocking/reload", handler: (*Server).reloadBlockingUI, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/domains/add", handler: (*Server).addBlockedDomain, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/domains/delete", handler: (*Server).deleteBlockedDomain, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/domains/flush", handler: (*Server).flushBlockedDomains, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/domains/import", handler: (*Server).importBlockedDomains, perm: auth.PermissionBlockingWrite,
			bodyLimit: maximumDomainImportBytes, bodyTimeout: webReadTimeout},
		{pattern: "POST /ui/blocking/allowed/add", handler: (*Server).addAllowedDomain, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/allowed/delete", handler: (*Server).deleteAllowedDomain, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/allowed/flush", handler: (*Server).flushAllowedDomains, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/allowed/import", handler: (*Server).importAllowedDomains, perm: auth.PermissionBlockingWrite,
			bodyLimit: maximumDomainImportBytes, bodyTimeout: webReadTimeout},
		{pattern: "POST /ui/blocking/query-domain", handler: (*Server).addQueryPolicyDomain, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/lists/add", handler: (*Server).addBlockList, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/lists/delete", handler: (*Server).deleteBlockList, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/lists/update", handler: (*Server).updateBlockLists, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/lists/refresh", handler: (*Server).refreshBlockList, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/check/rule", handler: (*Server).checkDomainRule, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/rule-sets/save", handler: (*Server).saveRuleSet, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/rule-sets/delete", handler: (*Server).deleteRuleSet, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/rule-sets/domains/add", handler: (*Server).addRuleSetDomain, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/rule-sets/domains/delete", handler: (*Server).deleteRuleSetDomain, perm: auth.PermissionBlockingWrite},
		{pattern: "GET /ui/blocking/rule-sets/apps", handler: (*Server).ruleSetAppPicker, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/rule-sets/apps", handler: (*Server).saveRuleSetApps, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/rule-sets/apps/delete", handler: (*Server).deleteRuleSetApp, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/rule-sets/devices/add", handler: (*Server).addRuleSetDevice, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/rule-sets/devices/delete", handler: (*Server).deleteRuleSetDevice, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/rule-sets/default", handler: (*Server).saveDefaultLists, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/toggle", handler: (*Server).toggleBlocking, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/pause", handler: (*Server).pauseBlocking, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /ui/blocking/resume", handler: (*Server).resumeBlocking, perm: auth.PermissionBlockingWrite},
		{pattern: "POST /api/v1/blocking/reload", handler: (*Server).reloadConfiguration, perm: auth.PermissionBlockingWrite},

		// Logs and metrics.
		{pattern: "GET /logs", handler: (*Server).logsPage, perm: auth.PermissionLogsRead},
		{pattern: "GET " + pages.QueryRoute + "{id}", handler: (*Server).logsPage, perm: auth.PermissionLogsRead},
		{pattern: "GET /ui/query-log", handler: (*Server).recentQueryLog, perm: auth.PermissionLogsRead},
		{pattern: "GET /ui/logs/runtime", handler: (*Server).runtimeLogsPanel, perm: auth.PermissionLogsRead},
		{pattern: "GET /ui/logs/queries", handler: (*Server).queryLogsPanel, perm: auth.PermissionLogsRead},
		{pattern: "GET /ui/logs/query", handler: (*Server).queryDetailPanel, perm: auth.PermissionLogsRead},
		{pattern: "GET /api/v1/query-log", handler: (*Server).queryLogAPI, perm: auth.PermissionLogsRead},
		{pattern: "GET /api/v1/logs/runtime", handler: (*Server).runtimeLogsAPI, perm: auth.PermissionLogsRead},
		{pattern: "GET /api/v1/logs/runtime/export", handler: (*Server).exportRuntimeLogs, perm: auth.PermissionLogsRead},
		{pattern: "GET /api/v1/logs/queries/export", handler: (*Server).exportQueryLogs, perm: auth.PermissionLogsRead},
		{pattern: "GET /metrics", handler: (*Server).metrics, perm: auth.PermissionMetricsRead},
		{pattern: "GET " + technitiumStatsPath, handler: (*Server).technitiumStats, perm: auth.PermissionMetricsRead},

		// Settings, the cache, and certificates. The cache and the
		// certificate belong to this node alone.
		{pattern: "GET /settings", handler: (*Server).settingsPage, perm: auth.PermissionSettingsRead},
		{pattern: "POST /ui/settings", handler: (*Server).updateSettings, perm: auth.PermissionSettingsWrite},
		// Release channels belong to this process, not the cluster.
		{pattern: "POST /ui/settings/updates", handler: (*Server).updatePreferences, perm: auth.PermissionSettingsWrite, replicaLocal: true},
		{pattern: "POST /ui/settings/insights", handler: (*Server).saveInsightsSwitch, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/settings/insights/delete", handler: (*Server).deleteInsightData, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/settings/tsig/save", handler: (*Server).saveTSIGKey, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/settings/tsig/delete", handler: (*Server).deleteTSIGKey, perm: auth.PermissionSettingsWrite},
		{pattern: "GET /ui/settings/alerts/destinations/form", handler: (*Server).alertDestinationFormPanel, perm: auth.PermissionSettingsRead},
		{pattern: "POST /ui/settings/alerts/destinations/save", handler: (*Server).saveAlertDestination, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/settings/alerts/destinations/remove", handler: (*Server).removeAlertDestination, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/settings/alerts/destinations/test", handler: (*Server).testAlertDestination, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/settings/alerts/destinations/preview", handler: (*Server).previewAlertDestination, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/settings/alerts/paused", handler: (*Server).setAlertsPaused, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/settings/alerts/groups", handler: (*Server).saveAlertGroups, perm: auth.PermissionSettingsWrite},
		{pattern: "GET /ui/settings/alerts/watches/form", handler: (*Server).alertWatchFormPanel, perm: auth.PermissionSettingsRead},
		{pattern: "POST /ui/settings/alerts/watches/save", handler: (*Server).saveAlertWatch, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/settings/alerts/watches/remove", handler: (*Server).removeAlertWatch, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/settings/alerts/watches/enabled", handler: (*Server).setAlertWatchEnabled, perm: auth.PermissionSettingsWrite},
		{pattern: "GET /ui/settings/alerts/browsers/key", handler: (*Server).alertBrowserPushKey, perm: auth.PermissionSettingsRead},
		{pattern: "POST /ui/settings/alerts/browsers", handler: (*Server).addAlertBrowser, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/settings/alerts/browsers/remove", handler: (*Server).removeAlertBrowser, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/certificates/renew", handler: (*Server).renewCertificate, perm: auth.PermissionSettingsWrite, replicaLocal: true},
		{pattern: "POST /ui/certificates/generate", handler: (*Server).generateManualCertificate, perm: auth.PermissionSettingsWrite, replicaLocal: true},
		{pattern: "POST /ui/certificates/import", handler: (*Server).importManualCertificate, perm: auth.PermissionSettingsWrite, replicaLocal: true},
		{pattern: "GET /cache", handler: (*Server).cachePage, perm: auth.PermissionSettingsRead},
		{pattern: "GET /ui/cache/status", handler: (*Server).cacheStatus, perm: auth.PermissionSettingsRead},
		{pattern: "POST /ui/cache/purge", handler: (*Server).purgeCacheUI, perm: auth.PermissionSettingsWrite, replicaLocal: true},
		{pattern: "POST /ui/cache/flush", handler: (*Server).flushCache, perm: auth.PermissionSettingsWrite, replicaLocal: true},
		{pattern: "POST /api/v1/cache/purge", handler: (*Server).purgeCache, perm: auth.PermissionSettingsWrite, replicaLocal: true},
		{pattern: "POST /api/v1/config/reload", handler: (*Server).reloadConfiguration, perm: auth.PermissionSettingsWrite},

		// Integrations. Single sign-on can delegate every permission on the
		// node, so changing it needs users.write.
		{pattern: "GET /integrations", handler: (*Server).integrationsPage, perm: auth.PermissionSettingsRead},
		{pattern: "GET /ui/integrations/dynamic-dns/status", handler: (*Server).dynamicDNSStatusPanel, perm: auth.PermissionSettingsRead},
		{pattern: "POST /ui/integrations/dynamic-dns/save", handler: (*Server).saveDynamicDNS, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/integrations/dynamic-dns/sync", handler: (*Server).syncDynamicDNSNow, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/integrations/dynamic-dns/enabled", handler: (*Server).setDynamicDNSEnabled, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/integrations/dynamic-dns/remove", handler: (*Server).removeDynamicDNS, perm: auth.PermissionSettingsWrite},
		{pattern: "GET /ui/integrations/unifi/status", handler: (*Server).unifiStatusPanel, perm: auth.PermissionSettingsRead},
		{pattern: "POST /ui/integrations/unifi/wizard", handler: (*Server).runUniFiWizard, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/integrations/unifi/sync", handler: (*Server).syncUniFiNow, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/integrations/unifi/enabled", handler: (*Server).setUniFiEnabled, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/integrations/unifi/remove", handler: (*Server).removeUniFi, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/integrations/mcp/enabled", handler: (*Server).setMCPEnabled, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/integrations/mcp/remove", handler: (*Server).removeMCP, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/integrations/mcp/setup", handler: (*Server).saveMCPSetup, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/integrations/mcp/group", handler: (*Server).saveMCPGroup, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/integrations/mcp/token", handler: (*Server).createMCPToken, perm: auth.PermissionSettingsWrite},
		{pattern: "POST /ui/integrations/sso/check", handler: (*Server).checkSSO, perm: auth.PermissionUsersWrite},
		{pattern: "POST /ui/integrations/sso/enabled", handler: (*Server).setSSOEnabled, perm: auth.PermissionUsersWrite, bodyLimit: authFormLimit},
		{pattern: "POST /ui/integrations/sso/wizard", handler: (*Server).runSSOWizard, perm: auth.PermissionUsersWrite},
		{pattern: "POST /ui/integrations/sso/remove", handler: (*Server).removeSSO, perm: auth.PermissionUsersWrite},

		// The MCP server. Every message is a POST, reads included, so the
		// write tools refuse on a replica themselves and reads keep working.
		// Each tool checks its own grant before it runs.
		{pattern: "POST " + mcpPath, handler: (*Server).mcp, signedIn: true, replicaLocal: true, bodyLimit: mcpMaximumBodyBytes},
		{pattern: "GET " + mcpPath, handler: (*Server).mcpEvents, signedIn: true},
		{pattern: "DELETE " + mcpPath, handler: staticHandler(http.HandlerFunc(mcpMethodNotAllowed)), signedIn: true, replicaLocal: true},

		// Backups. Restoring replaces every user, role, and token on the
		// node, so it is held apart from the permission to take one.
		{pattern: "GET /ui/backup", handler: (*Server).backupPanel, perm: auth.PermissionBackupCreate},
		{pattern: "GET /ui/backup/progress", handler: (*Server).backupProgress, perm: auth.PermissionBackupCreate},
		{pattern: "POST /ui/backup/download", handler: (*Server).downloadBackup, perm: auth.PermissionBackupCreate},
		{pattern: "GET /ui/backup/download/{token}", handler: (*Server).sendBackup, perm: auth.PermissionBackupCreate},
		{pattern: "POST /ui/backup/run", handler: (*Server).downloadBackup, perm: auth.PermissionBackupCreate},
		{pattern: "GET /ui/backup/local", handler: (*Server).downloadLocalBackup, perm: auth.PermissionBackupCreate},
		{pattern: "POST /ui/backup/delete-local", handler: (*Server).deleteLocalBackup, perm: auth.PermissionBackupCreate},
		{pattern: "POST /ui/backup/schedule", handler: (*Server).updateBackupSchedule, perm: auth.PermissionBackupCreate},
		{pattern: "POST /ui/backup/restart", handler: (*Server).restartServer, perm: auth.PermissionBackupCreate},
		{pattern: "POST /ui/backup/restore", handler: (*Server).restoreBackup, perm: auth.PermissionBackupRestore,
			bodyLimit: maximumBackupUploadBytes, bodyTimeout: webReadTimeout},
		{pattern: "POST /ui/backup/restore-local", handler: (*Server).restoreLocalBackup, perm: auth.PermissionBackupRestore},

		// Updates. Checking reaches out to GitHub but changes nothing locally;
		// installing replaces the running executable. Both affect only this
		// process, so a replica accepts them.
		{pattern: "GET /ui/updates", handler: (*Server).updatePanel, perm: auth.PermissionUpdatesRead},
		{pattern: "POST /ui/updates/check", handler: (*Server).checkForUpdates, perm: auth.PermissionUpdatesRead, replicaLocal: true},
		{pattern: "POST /ui/updates/command-check", handler: (*Server).checkForUpdatesCommand, perm: auth.PermissionUpdatesRead, replicaLocal: true},
		{pattern: "POST /ui/updates/automatic-check", handler: (*Server).automaticUpdateCheck, perm: auth.PermissionUpdatesRead, replicaLocal: true},
		{pattern: "POST /ui/updates/install", handler: (*Server).installUpdate, perm: auth.PermissionUpdatesApply, replicaLocal: true},
		{pattern: "POST /ui/updates/restart", handler: (*Server).restartServer, perm: auth.PermissionUpdatesApply, replicaLocal: true},
		{pattern: "POST /ui/updates/cluster", handler: (*Server).startClusterUpdate, perm: auth.PermissionUpdatesApply},
		{pattern: "POST /ui/updates/cluster/stop", handler: (*Server).stopClusterUpdate, perm: auth.PermissionUpdatesApply},

		// Users, groups, sessions, and tokens. A session lives on the node
		// that issued it, so revoking one is a local write.
		{pattern: "GET /administration", handler: (*Server).administrationPage, perm: auth.PermissionUsersRead},
		{pattern: "GET /ui/administration/tokens", handler: (*Server).administrationTokens, perm: auth.PermissionUsersRead},
		{pattern: "POST /ui/administration/users", handler: (*Server).createUser, perm: auth.PermissionUsersWrite},
		{pattern: "POST /ui/administration/users/profile", handler: (*Server).updateUserProfile, perm: auth.PermissionUsersWrite},
		{pattern: "POST /ui/administration/users/roles", handler: (*Server).updateUserRoles, perm: auth.PermissionUsersWrite},
		{pattern: "POST /ui/administration/users/status", handler: (*Server).updateUserStatus, perm: auth.PermissionUsersWrite},
		{pattern: "POST /ui/administration/users/password", handler: (*Server).updateUserPassword, perm: auth.PermissionUsersWrite},
		{pattern: "POST /ui/administration/users/sign-in-method", handler: (*Server).updateUserPasswordLogin, perm: auth.PermissionUsersWrite},
		{pattern: "POST /ui/administration/users/unlink", handler: (*Server).unlinkUserIdentity, perm: auth.PermissionUsersWrite},
		{pattern: "POST /ui/administration/users/delete", handler: (*Server).deleteUser, perm: auth.PermissionUsersWrite},
		{pattern: "POST /ui/administration/roles", handler: (*Server).createRole, perm: auth.PermissionUsersWrite},
		{pattern: "POST /ui/administration/roles/update", handler: (*Server).updateRole, perm: auth.PermissionUsersWrite},
		{pattern: "POST /ui/administration/roles/delete", handler: (*Server).deleteRole, perm: auth.PermissionUsersWrite},
		{pattern: "POST /ui/administration/sessions/revoke", handler: (*Server).revokeSession, perm: auth.PermissionUsersWrite, replicaLocal: true},
		{pattern: "POST /ui/administration/tokens/revoke", handler: (*Server).revokeAPIToken, perm: auth.PermissionUsersWrite},

		// The cluster. A node changes its own settings, leaves, restarts,
		// and takes over as primary on its own say.
		{pattern: "GET /cluster", handler: (*Server).clusterPage, perm: auth.PermissionClusterRead},
		{pattern: "GET " + pages.ClusterNodeRoute + "{name}", handler: (*Server).clusterPage, perm: auth.PermissionClusterRead},
		{pattern: "GET /ui/cluster/status", handler: (*Server).clusterLiveStatus, perm: auth.PermissionClusterRead},
		{pattern: "GET /ui/cluster/node", handler: (*Server).clusterNodePanel, perm: auth.PermissionClusterRead},
		{pattern: "POST /ui/cluster/initialize", handler: (*Server).initializeCluster, perm: auth.PermissionClusterWrite},
		{pattern: "POST /ui/cluster/onboarding", handler: (*Server).updateClusterOnboarding, perm: auth.PermissionClusterWrite},
		{pattern: "POST /ui/cluster/settings", handler: (*Server).updateClusterSettings, perm: auth.PermissionClusterWrite, replicaLocal: true},
		{pattern: "POST /ui/cluster/join", handler: (*Server).joinCluster, perm: auth.PermissionClusterWrite},
		{pattern: "POST /ui/cluster/enrollment-tokens", handler: (*Server).createClusterEnrollmentToken, perm: auth.PermissionClusterWrite},
		{pattern: "POST /ui/cluster/nodes/{node}/promote", handler: (*Server).promoteClusterNode, perm: auth.PermissionClusterWrite, replicaLocal: true},
		{pattern: "POST /ui/cluster/nodes/{node}/remove", handler: (*Server).removeClusterNode, perm: auth.PermissionClusterWrite},
		{pattern: "POST /ui/cluster/leave", handler: (*Server).leaveCluster, perm: auth.PermissionClusterWrite, replicaLocal: true},
		{pattern: "POST /ui/cluster/delete", handler: (*Server).deleteCluster, perm: auth.PermissionClusterWrite},
		{pattern: "POST /ui/cluster/restart", handler: (*Server).restartServer, perm: auth.PermissionClusterWrite, replicaLocal: true},
		{pattern: "GET /api/v1/cluster", handler: (*Server).clusterAPI, perm: auth.PermissionClusterRead},
		{pattern: "GET /api/v1/cluster/nodes/{node}", handler: (*Server).clusterNodeAPI, perm: auth.PermissionClusterRead},
		{pattern: "POST /api/v1/cluster", handler: (*Server).initializeClusterAPI, perm: auth.PermissionClusterWrite},
		{pattern: "POST /api/v1/cluster/enrollment-tokens", handler: (*Server).createClusterEnrollmentTokenAPI, perm: auth.PermissionClusterWrite},
		{pattern: "POST /api/v1/cluster/nodes/{node}/promote", handler: (*Server).promoteClusterNodeAPI, perm: auth.PermissionClusterWrite, replicaLocal: true},
		{pattern: "DELETE /api/v1/cluster/nodes/{node}", handler: (*Server).removeClusterNodeAPI, perm: auth.PermissionClusterWrite},
		{pattern: "DELETE /api/v1/cluster/membership", handler: (*Server).leaveClusterAPI, perm: auth.PermissionClusterWrite, replicaLocal: true},
		{pattern: "DELETE /api/v1/cluster", handler: (*Server).deleteClusterAPI, perm: auth.PermissionClusterWrite},
		// Nodes reach each other with enrollment tokens and node keys the
		// handlers check, not with accounts.
		{pattern: "GET /api/v1/health", handler: (*Server).health, public: true},
		{pattern: "POST /api/v1/cluster/enroll", handler: (*Server).enrollClusterNodeAPI, public: true},
		{pattern: "POST /api/v1/cluster/sync", handler: (*Server).clusterSyncAPI, public: true, replicaLocal: true, bodyLimit: cluster.MaximumHeartbeatBytes},
	}
}
