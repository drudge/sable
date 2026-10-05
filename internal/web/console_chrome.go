package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/version"
	"github.com/drudge/sable/internal/web/pages"
)

func (server *Server) consoleView(request *http.Request) pages.DashboardView {
	snapshot := server.config.Current()
	dnsStats := server.stats.Stats()
	display := requestTimeDisplay(request)
	view := pages.DashboardView{
		Version:             version.Current().Release,
		TimeDisplay:         display,
		ShowFullRecordNames: requestShowFullRecordNames(request),
		SecurityEnabled:     server.securityEnabled,
		CanSettings:         !server.securityEnabled,
		CanWriteSettings:    !server.securityEnabled,
		BackupsAvailable:    server.backups != nil,
		CanCreateBackups:    !server.securityEnabled,
		CanRestoreBackups:   !server.securityEnabled,
		CanZones:            !server.securityEnabled,
		CanCreateZones:      !server.securityEnabled,
		CanBlocking:         !server.securityEnabled,
		CanWriteBlocking:    !server.securityEnabled,
		BlockingEnabled:     snapshot.Config.Blocking.Enabled,
		HasRemoteBlockLists: len(remoteBlockSources(snapshot.Config.Blocking)) > 0,
		CanLogs:             !server.securityEnabled,
		InsightsOff:         !snapshot.Config.Insights.Enabled,
		CanMetrics:          !server.securityEnabled,
		CanCheckUpdates:     server.updates != nil && !server.securityEnabled,
		CheckUpdatesOnLogin: snapshot.Config.Updates.CheckOnLogin && !version.Current().Development(),
		CanCluster:          !server.securityEnabled,
		CanWriteCluster:     !server.securityEnabled,
		Database:            server.database,
		DNSListeners:        strings.Join(snapshot.Config.Server.DNSListen, ", "),
		EncryptedDNS:        encryptedDNSStatus(snapshot.Config.EncryptedDNS),
		QueryServer:         snapshot.Config.Server.DNSListen[0],
		CacheSize:           snapshot.Config.Resolver.CacheSize,
		ForwardRoutes:       len(snapshot.Config.Resolver.Routes),
		LocalHosts:          len(snapshot.Config.Resolver.Hosts),
		QueryLogStatus:      queryLogStatus(snapshot.Config.QueryLog.Enabled, server.queryLog.Stats()),
		DNSSECStatus:        dnssecRuntimeStatus(snapshot.Config.Resolver, dnsStats),
		ConfigRevision:      snapshot.Revision,
		Stats:               statsView(server.history.totals(time.Now(), dnsStats)),
	}
	if principal, ok := request.Context().Value(principalContextKey{}).(auth.Principal); ok {
		view.Username = principal.Username
		view.DisplayName = principal.DisplayName
		view.AvatarURL = avatarURL(principal.AvatarETag)
		view.CSRFToken = principal.CSRFToken
		view.CanSettings = auth.HasPermission(principal, auth.PermissionSettingsRead)
		view.CanWriteSettings = auth.HasPermission(principal, auth.PermissionSettingsWrite)
		view.CanCreateBackups = auth.HasPermission(principal, auth.PermissionBackupCreate)
		view.CanRestoreBackups = auth.HasPermission(principal, auth.PermissionBackupRestore)
		view.CanAdministration = auth.HasPermission(principal, auth.PermissionUsersRead)
		view.CanWriteUsers = auth.HasPermission(principal, auth.PermissionUsersWrite)
		view.CanZones = auth.HasPermission(principal, auth.PermissionZonesRead)
		view.CanCreateZones = auth.HasPermission(principal, auth.PermissionZonesCreate)
		view.CanBlocking = auth.HasPermission(principal, auth.PermissionBlockingRead)
		view.CanWriteBlocking = auth.HasPermission(principal, auth.PermissionBlockingWrite)
		view.CanLogs = auth.HasPermission(principal, auth.PermissionLogsRead)
		view.CanMetrics = auth.HasPermission(principal, auth.PermissionMetricsRead)
		view.CanCheckUpdates = server.updates != nil && auth.HasPermission(principal, auth.PermissionUpdatesRead)
		view.CanCluster = auth.HasPermission(principal, auth.PermissionClusterRead)
		view.CanWriteCluster = auth.HasPermission(principal, auth.PermissionClusterWrite)
	}
	if server.cluster != nil {
		clusterState := server.cluster.Snapshot()
		view.ControlPlaneReadOnly = controlPlaneReadOnly(clusterState)
		view.PrimaryURL = clusterState.PrimaryURL
	}
	view.CommandEntities = server.commandPaletteEntities(request, snapshot, view)
	if controller, ok := server.backups.(localBackupController); ok {
		if schedule, err := controller.BackupSchedule(request.Context()); err == nil {
			view.BackupPassphraseStored = schedule.PassphraseStored
		}
	}
	return view
}

// commandPaletteEntities makes configured objects globally navigable without
// leaking the names of zones an operator is not authorized to read.
func (server *Server) commandPaletteEntities(request *http.Request, snapshot config.Snapshot, view pages.DashboardView) []pages.CommandEntityView {
	entities := make([]pages.CommandEntityView, 0)
	add := func(entity pages.CommandEntityView) {
		if entity.ID == "" {
			entity.ID = "command-entity-" + strconv.Itoa(len(entities))
		}
		entities = append(entities, entity)
	}

	if view.CanZones && server.zones != nil {
		principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
		for _, entry := range server.commandZoneEntries() {
			if server.securityEnabled && !auth.Authorize(principal, auth.PermissionZonesRead, auth.ResourceZone, entry.zoneID) {
				continue
			}
			for _, command := range entry.commands {
				add(command)
			}
		}
	}
	if view.CanCluster && view.CanWriteCluster && server.cluster != nil {
		server.addClusterCommands(request, add)
	}
	if view.CanSettings {
		server.addIntegrationCommands(request, snapshot.Config, view, add)
	}
	return entities
}

func (server *Server) addClusterCommands(request *http.Request, add func(pages.CommandEntityView)) {
	state := server.cluster.Snapshot()
	if !state.Initialized {
		add(pages.CommandEntityView{
			ID: "command-action-initialize-cluster", Label: "Initialize Cluster", Description: "Create a cluster with this server as primary", Icon: "server-crash", Kind: "Action",
			Keywords: "create setup primary replication", Route: "/cluster", Dialog: "initialize-cluster-dialog",
		})
		return
	}
	add(pages.CommandEntityView{
		ID: "command-action-configure-node", Label: "Configure Node", Description: "Edit this node's cluster identity and HTTPS endpoint", Icon: "server-cog", Kind: "Action",
		Keywords: "cluster local node settings identity endpoint", Route: "/cluster", Dialog: "cluster-settings-dialog",
	})
	if state.LocalRole == cluster.RolePrimary && state.NetworkReady {
		add(pages.CommandEntityView{
			ID: "command-action-add-replica", Label: "Add Replica", Description: "Create an enrollment token for a new replica", Icon: "server-plus", Kind: "Action",
			Keywords: "cluster node enroll token secondary", Route: "/cluster", Dialog: "enrollment-token-dialog",
		})
	}
	if command, ok := server.clusterUpdateCommand(request); ok {
		add(command)
	}
}

// addIntegrationCommands lists the Dynamic DNS, UniFi, and SSO integrations
// that are running or configured. Operators who can change them get the
// setup action; everyone else gets a link to the integration's card.
func (server *Server) addIntegrationCommands(request *http.Request, configuration config.Config, view pages.DashboardView, add func(pages.CommandEntityView)) {
	canSetUp := view.CanWriteSettings && !view.ControlPlaneReadOnly
	dynamicDNSPublishers := configuration.DynamicDNS.ConfiguredPublishers()
	if server.dynamicDNS != nil || len(dynamicDNSPublishers) > 0 {
		keywords := []string{"dynamic dns", "ddns", "integration", "public address", "a aaaa"}
		for _, publisher := range dynamicDNSPublishers {
			keywords = append(keywords, publisher.Provider)
			for _, record := range publisher.Records {
				keywords = append(keywords, record.Zone, record.Name)
			}
		}
		entity := pages.CommandEntityView{
			ID: "command-entity-integration-dynamic-dns", Label: "View Dynamic DNS", Description: "Open public address publication status", Icon: "cloud-sync", Kind: "Integration",
			Keywords: strings.Join(keywords, " "), Route: "/integrations", Focus: "#dynamic-dns-card",
		}
		if canSetUp {
			entity.Label = "Set Up Dynamic DNS"
			if len(dynamicDNSPublishers) > 0 {
				entity.Label = "Edit Dynamic DNS Setup"
			}
			entity.Description = "Configure providers, public names, and address discovery"
			entity.Href, entity.Route, entity.Focus = "/integrations?setup=dynamic-dns", "", ""
		}
		add(entity)
	}
	unifiSettings := configuration.UniFi
	unifiConfigured := unifiSettings.ControllerURL != "" || len(unifiSettings.Networks) > 0
	if server.unifi != nil || unifiConfigured {
		entity := pages.CommandEntityView{
			ID: "command-entity-integration-unifi", Label: "View UniFi Setup", Description: "Open the host synchronization integration", Icon: "wifi-sync", Kind: "Integration",
			Keywords: strings.Join([]string{"unifi", "integration", "host", "sync", unifiSettings.ControllerURL, unifiSettings.Site}, " "),
			Route:    "/integrations", Focus: "#unifi-card",
		}
		if canSetUp {
			entity.Label = "Set Up UniFi Sync"
			if unifiConfigured {
				entity.Label = "Edit UniFi Setup"
			}
			entity.Description = "Edit controller and network mappings"
			entity.Href, entity.Route, entity.Focus = "/integrations?setup=unifi", "", ""
		}
		add(entity)
	}
	oidcSettings := configuration.OIDC
	oidcConfigured := oidcSettings.Issuer != "" || oidcSettings.Enabled
	if server.ssoAdmin != nil || oidcConfigured {
		keywords := []string{"sso", "oidc", "integration", oidcSettings.Issuer, oidcSettings.ClientID}
		for _, mapping := range oidcSettings.RoleMappings {
			keywords = append(keywords, mapping.Group, mapping.Role)
		}
		entity := pages.CommandEntityView{
			ID: "command-entity-integration-sso", Label: "View SSO Setup", Description: "Open the single sign-on integration", Icon: "key-round", Kind: "Integration",
			Keywords: strings.Join(append(keywords, oidcSettings.Label()), " "), Route: "/integrations", Focus: "#sso-card",
		}
		if server.canManageSSO(request) && !view.ControlPlaneReadOnly {
			entity.Label = "Set Up Single Sign-On"
			if oidcConfigured {
				entity.Label = "Edit SSO Setup"
			}
			entity.Description = "Edit provider, claims, and role mappings"
			entity.Href, entity.Route, entity.Focus = "/integrations?setup=sso", "", ""
		}
		add(entity)
	}
}

func commandZoneDescription(zoneType string) string {
	switch zoneType {
	case "primary":
		return "Primary DNS zone"
	case "secondary":
		return "Secondary DNS zone"
	case "forwarder":
		return "Forwarding DNS zone"
	case "stub":
		return "Stub DNS zone"
	case "alias":
		return "Alias DNS zone"
	case "catalog":
		return "Catalog DNS zone"
	default:
		return "DNS zone"
	}
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

// consoleFragmentHeader marks a response whose body is a rendered console
// fragment rather than a bare error. htmx 4 swaps all error responses by
// default, so the console uses this marker to admit only complete UI fragments
// into a target. The status code itself stays honest for API clients and logs.
const consoleFragmentHeader = "X-Sable-Console-Fragment"

// writeFragmentStatus writes a status for a response carrying a console
// fragment, flagging anything other than 200 so the browser can distinguish it
// from an unrendered server error.
func writeFragmentStatus(writer http.ResponseWriter, status int) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	if status != http.StatusOK {
		writer.Header().Set(consoleFragmentHeader, "true")
	}
	writer.WriteHeader(status)
}
