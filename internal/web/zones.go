package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/durationfmt"
	"github.com/drudge/sable/internal/web/pages"
	zonemodel "github.com/drudge/sable/internal/zone"
)

const defaultZoneTTL = 300

type zoneEditor interface {
	UpdateZones(context.Context, func(*[]zonemodel.Zone) error) error
}

type zoneRevisionStore interface {
	ListZoneRevisions(context.Context, string, int) ([]zonemodel.Revision, error)
	ZoneRevision(context.Context, string, uint64) (zonemodel.Revision, error)
	PreviousZoneRevision(context.Context, string, uint64) (zonemodel.Revision, error)
}

type zoneNotifier interface {
	NotifyZone(context.Context, string, []string) []error
}

type zoneSynchronizer interface {
	FetchZone(context.Context, string, string, []string, string, string) ([]dnsserver.ZoneRecord, error)
	RefreshZone(context.Context, string, string, []string, string, string, []dnsserver.ZoneRecord) ([]dnsserver.ZoneRecord, bool, error)
}

func (server *Server) zonesPage(writer http.ResponseWriter, request *http.Request) {
	selected := request.PathValue("zone")
	if selected == "" {
		selected = request.URL.Query().Get("zone")
	}
	view := server.zonesView(request, "", "", selected)
	server.render(writer, request, pages.ZonesPage(view))
}

// catalogConsumerFormType is the value the create dialog submits for a catalog
// zone transferred from another server. It collapses to the "catalog" zone type
// once the form has been read, because the two roles differ only in whether the
// catalog has primary servers.
const catalogConsumerFormType = "secondary_catalog"

func (server *Server) zonesView(request *http.Request, message, errorMessage, selected string) pages.ZonesPageView {
	console := server.consoleView(request)
	// The page only reads the zones, so it skips the copy Current makes.
	zones := server.currentZonesRef().Zones
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	readable := func(zone zonemodel.Zone) bool {
		return !server.securityEnabled || auth.Authorize(principal, auth.PermissionZonesRead, auth.ResourceZone, zone.ID)
	}
	tsigKeys := server.tsigKeyNames(request.Context())
	aliasSources := make([]string, 0, len(zones))
	catalogTargets := make([]string, 0, len(zones))
	for _, zone := range zones {
		if !readable(zone) {
			continue
		}
		if zonemodel.IsProducerCatalog(zone) {
			catalogTargets = append(catalogTargets, zone.Name)
		}
		if zone.Type != "primary" && zone.Type != "secondary" {
			continue
		}
		aliasSources = append(aliasSources, zone.Name)
	}
	// A selected zone renders on its own, so a record change reads that one
	// zone's DNSSEC keys and history however many zones there are.
	if !slices.ContainsFunc(zones, func(zone zonemodel.Zone) bool { return zone.Name == selected && readable(zone) }) {
		selected = ""
	}
	_, historyAvailable := server.zones.(zoneRevisionStore)
	catalogs := newZoneCatalogIndex(zones)
	views := make([]pages.ZoneView, 0, len(zones))
	for _, zone := range zones {
		if !readable(zone) || (selected != "" && zone.Name != selected) {
			continue
		}
		zoneView := pages.ZoneView{
			ID:   zone.ID,
			Name: zone.Name, Type: zone.Type, DefaultTTL: zone.DefaultTTL, Disabled: zone.Disabled,
			ShowFullRecordNames: console.ShowFullRecordNames,
			ZoneTransfer:        zone.ZoneTransfer, TransferACL: append([]string(nil), zone.TransferACL...), Notify: append([]string(nil), zone.Notify...),
			PrimaryServers: append([]string(nil), zone.PrimaryServers...), PrimaryProtocol: zone.PrimaryProtocol,
			AliasZone: zone.AliasZone, AliasSources: aliasZoneChoices(aliasSources, zone),
			CatalogZone: zone.CatalogZone, CatalogGroup: zone.CatalogGroup, CatalogMemberID: zone.CatalogMemberID,
			CatalogTargets:        catalogZoneChoices(catalogTargets, zone),
			CatalogRole:           catalogRoleLabel(zone),
			CatalogManager:        catalogs.manager(zone),
			CatalogMembers:        catalogs.members(zone),
			AwaitingFirstTransfer: zonemodel.AwaitingFirstTransfer(zone),
			TSIGKey:               zone.TSIGKey, TSIGKeys: tsigKeys, DynamicUpdates: zone.DynamicUpdates,
			DNSSECValidationDisabled: zone.DNSSECValidationDisabled,
			DNSSEC:                   zone.DNSSEC, DNSSECAlgorithm: zone.DNSSECAlgorithm,
			DNSSECDenial: zone.DNSSECDenial, NSEC3Iterations: zone.NSEC3Iterations, NSEC3Salt: zone.NSEC3Salt,
			ZSKLifetime: durationOr(zone.ZSKLifetime.Duration, 30*24*time.Hour), KSKLifetime: durationOr(zone.KSKLifetime.Duration, 365*24*time.Hour),
			KeyPrepublish: durationOr(zone.KeyPrepublish.Duration, 24*time.Hour), KeyRetireAfter: durationOr(zone.KeyRetireAfter.Duration, 7*24*time.Hour),
			Records:              make([]pages.ZoneRecordView, 0, len(zone.Records)),
			CanSettings:          server.zoneAuthorized(principal, auth.PermissionZonesSettings, zone),
			CanRecords:           server.zoneAuthorized(principal, auth.PermissionZonesRecords, zone),
			CanTransfer:          server.zoneAuthorized(principal, auth.PermissionZonesTransfer, zone),
			CanDNSSEC:            server.zoneAuthorized(principal, auth.PermissionZonesDNSSEC, zone),
			CanImport:            server.zoneAuthorized(principal, auth.PermissionZonesImport, zone),
			CanExport:            server.zoneAuthorized(principal, auth.PermissionZonesExport, zone),
			CanDelete:            server.zoneAuthorized(principal, auth.PermissionZonesDelete, zone),
			CanCreate:            !server.securityEnabled || auth.Authorize(principal, auth.PermissionZonesCreate, "", ""),
			CanManagePermissions: console.CanAdministration,
		}
		zoneView.Revision = zone.Revision
		if zone.Type == "secondary" || zone.Type == zonemodel.TypeSecondaryForwarder {
			zoneView.ConversionFingerprint = zonemodel.ConversionFingerprint(zone)
			zoneView.ConversionSerial = conversionSerial(zone)
			if err := zonemodel.CheckPrimaryConversion(zone); err != nil {
				zoneView.ConversionError = err.Error()
			}
		}
		server.populateZoneDNSSECView(request.Context(), zone, &zoneView, console.TimeDisplay)
		for _, record := range zone.Records {
			expiryTTL := uint32(0)
			if record.ExpiresAt.After(time.Now()) {
				remaining := time.Until(record.ExpiresAt).Seconds()
				if remaining > 0 {
					expiryTTL = uint32(remaining + 0.999)
				}
			}
			zoneView.Records = append(zoneView.Records, pages.ZoneRecordView{
				ID: zonemodel.RecordID(record), Name: record.Name, Type: record.Type, Value: record.Value, TTL: record.TTL,
				Comments: record.Comments, Disabled: record.Disabled, ExpiryTTL: expiryTTL,
				// Managed hides a record's editor entirely; DNSSEC material is the
				// only thing that qualifies. Integration-owned records still open,
				// read-only, so their contents can be inspected.
				Managed:     strings.HasPrefix(record.Comments, "sable:dnssec"),
				SourceLabel: zoneRecordSourceLabel(record.Source),
			})
		}
		switch {
		case selected != "":
			server.loadZoneHistory(request, &zoneView, console.TimeDisplay)
		case historyAvailable && zone.Revision > 0:
			// The list fetches a zone's history when its dialog opens rather
			// than reading every zone's revisions to draw the rows.
			zoneView.HistoryLazy = true
		}
		views = append(views, zoneView)
	}
	return pages.ZonesPageView{
		Console: console, Zones: views, Selected: selected, Message: message, Error: errorMessage,
		CanCreate:    !server.securityEnabled || auth.Authorize(principal, auth.PermissionZonesCreate, "", ""),
		AliasSources: aliasSources,
		TSIGKeys:     tsigKeys,
	}
}

// loadZoneHistory fills a zone's recent revisions. A zone source without
// history leaves both fields empty, which hides the History action.
func (server *Server) loadZoneHistory(request *http.Request, view *pages.ZoneView, display pages.TimeDisplay) {
	history, ok := server.zones.(zoneRevisionStore)
	if !ok {
		return
	}
	revisions, err := history.ListZoneRevisions(request.Context(), view.Name, 20)
	if errors.Is(err, zonemodel.ErrRevisionHistoryUnavailable) {
		return
	}
	if err != nil {
		view.HistoryError = "Change history is temporarily unavailable."
		server.logger.Warn("load zone revision history", "zone", view.Name, "error", err)
		return
	}
	view.History = zoneRevisionViews(server.readableZoneRevisions(request, revisions), view.Revision, display)
}

// zoneCatalogIndex answers catalog membership for every zone on the page from
// one pass over the zones, instead of rescanning them for each row.
type zoneCatalogIndex struct {
	zones       map[string]zonemodel.Zone
	memberNames map[string][]string
}

func newZoneCatalogIndex(zones []zonemodel.Zone) zoneCatalogIndex {
	index := zoneCatalogIndex{zones: make(map[string]zonemodel.Zone, len(zones)), memberNames: make(map[string][]string)}
	for _, zone := range zones {
		if _, seen := index.zones[zone.Name]; !seen {
			index.zones[zone.Name] = zone
		}
		if zone.CatalogZone != "" {
			index.memberNames[zone.CatalogZone] = append(index.memberNames[zone.CatalogZone], zone.Name)
		}
	}
	for _, names := range index.memberNames {
		slices.Sort(names)
	}
	return index
}

// members lists the zones a catalog carries, so the console can show
// membership without making the operator read the raw PTR records.
func (index zoneCatalogIndex) members(current zonemodel.Zone) []string {
	if current.Type != "catalog" {
		return nil
	}
	return append(make([]string, 0, len(index.memberNames[current.Name])), index.memberNames[current.Name]...)
}

// manager names the consumer catalog that provisioned a zone, like
// catalogManagingZone.
func (index zoneCatalogIndex) manager(current zonemodel.Zone) string {
	if current.CatalogZone == "" {
		return ""
	}
	owner, found := index.zones[current.CatalogZone]
	if !found || !zonemodel.IsConsumerCatalog(owner) {
		return ""
	}
	return owner.Name
}

// catalogRoleLabel describes which side of RFC 9432 a catalog zone sits on.
func catalogRoleLabel(current zonemodel.Zone) string {
	switch {
	case zonemodel.IsConsumerCatalog(current):
		return "subscribed"
	case zonemodel.IsProducerCatalog(current):
		return "published"
	default:
		return ""
	}
}

// catalogZoneChoices returns the published catalogs a zone may join. The zone's
// current catalog is always present so a catalog the account cannot otherwise
// read is not silently dropped on save.
func catalogZoneChoices(targets []string, current zonemodel.Zone) []string {
	if current.Type == "catalog" {
		return nil
	}
	choices := append([]string(nil), targets...)
	if current.CatalogZone != "" && !slices.Contains(choices, current.CatalogZone) {
		choices = append(choices, current.CatalogZone)
	}
	slices.Sort(choices)
	return choices
}

// aliasZoneChoices returns the source zones offered in an alias zone's settings
// dialog. The zone's current source is always present so a source the account
// cannot otherwise read is not silently swapped for another zone on save.
func aliasZoneChoices(sources []string, current zonemodel.Zone) []string {
	if current.Type != "alias" {
		return nil
	}
	choices := append([]string(nil), sources...)
	if current.AliasZone != "" && !slices.Contains(choices, current.AliasZone) {
		choices = append(choices, current.AliasZone)
		slices.Sort(choices)
	}
	return choices
}

func (server *Server) zoneAuthorized(principal auth.Principal, permission string, current zonemodel.Zone) bool {
	return !server.securityEnabled || auth.Authorize(principal, permission, auth.ResourceZone, current.ID)
}

func durationOr(value, fallback time.Duration) string {
	if value <= 0 {
		value = fallback
	}
	return durationfmt.Format(value)
}

func zoneRecordRR(zone zonemodel.Zone, record zonemodel.Record) (dns.RR, error) {
	owner := strings.TrimSpace(record.Name)
	if owner == "" || owner == "@" {
		owner = dns.Fqdn(zone.Name)
	} else if !strings.HasSuffix(owner, ".") {
		owner = dns.Fqdn(owner + "." + zone.Name)
	}
	return dns.NewRR(fmt.Sprintf("%s %d IN %s %s", owner, record.TTL, record.Type, record.Value))
}

func (server *Server) zonesAPI(writer http.ResponseWriter, request *http.Request) {
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	zones := server.zones.Current().Zones
	if server.securityEnabled {
		zones = slices.DeleteFunc(append([]zonemodel.Zone(nil), zones...), func(current zonemodel.Zone) bool {
			return !auth.Authorize(principal, auth.PermissionZonesRead, auth.ResourceZone, current.ID)
		})
	}
	writeJSON(writer, http.StatusOK, zones)
}

func (server *Server) authorizeZoneRequest(request *http.Request, permission string, current zonemodel.Zone) bool {
	if !server.securityEnabled {
		return true
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	return auth.Authorize(principal, permission, auth.ResourceZone, current.ID)
}

func findZone(zones []zonemodel.Zone, name string) *zonemodel.Zone {
	index := slices.IndexFunc(zones, func(zone zonemodel.Zone) bool { return zone.Name == name })
	if index < 0 {
		return nil
	}
	return &zones[index]
}

func normalizeZoneName(name string) string {
	normalized, err := dnsname.Normalize(name)
	if err != nil {
		return strings.Trim(strings.ToLower(strings.TrimSpace(name)), ".")
	}
	return normalized
}

func zonePath(name string) string {
	return "/zones/" + url.PathEscape(normalizeZoneName(name))
}
