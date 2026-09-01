package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/dnsname"
	dnssecstate "github.com/drudge/sable/internal/dnssec"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/durationfmt"
	"github.com/drudge/sable/internal/forwarding"
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

type dnssecController interface {
	KeyStatus(context.Context, zonemodel.Zone) (dnssecstate.Status, error)
	RequestRollover(context.Context, zonemodel.Zone, string) error
}

func (server *Server) zonesPage(writer http.ResponseWriter, request *http.Request) {
	selected := request.PathValue("zone")
	if selected == "" {
		selected = request.URL.Query().Get("zone")
	}
	view := server.zonesView(request, "", "", selected)
	if err := pages.ZonesPage(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render zones page", "error", err)
	}
}

// catalogConsumerFormType is the value the create dialog submits for a catalog
// zone transferred from another server. It collapses to the "catalog" zone type
// once the form has been read, because the two roles differ only in whether the
// catalog has primary servers.
const catalogConsumerFormType = "secondary_catalog"

func (server *Server) zonesView(request *http.Request, message, errorMessage, selected string) pages.ZonesPageView {
	console := server.consoleView(request)
	zones := server.zones.Current().Zones
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	tsigKeys := server.tsigKeyNames(request.Context())
	aliasSources := make([]string, 0, len(zones))
	catalogTargets := make([]string, 0, len(zones))
	for _, zone := range zones {
		if server.securityEnabled && !auth.Authorize(principal, auth.PermissionZonesRead, auth.ResourceZone, zone.ID) {
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
	views := make([]pages.ZoneView, 0, len(zones))
	for _, zone := range zones {
		if server.securityEnabled && !auth.Authorize(principal, auth.PermissionZonesRead, auth.ResourceZone, zone.ID) {
			continue
		}
		zoneView := pages.ZoneView{
			ID:   zone.ID,
			Name: zone.Name, Type: zone.Type, DefaultTTL: zone.DefaultTTL, Disabled: zone.Disabled,
			ZoneTransfer: zone.ZoneTransfer, TransferACL: append([]string(nil), zone.TransferACL...), Notify: append([]string(nil), zone.Notify...),
			PrimaryServers: append([]string(nil), zone.PrimaryServers...), PrimaryProtocol: zone.PrimaryProtocol,
			AliasZone: zone.AliasZone, AliasSources: aliasZoneChoices(aliasSources, zone),
			CatalogZone: zone.CatalogZone, CatalogGroup: zone.CatalogGroup, CatalogMemberID: zone.CatalogMemberID,
			CatalogTargets:        catalogZoneChoices(catalogTargets, zone),
			CatalogRole:           catalogRoleLabel(zone),
			CatalogManager:        catalogManagingZone(zones, zone),
			CatalogMembers:        catalogMemberNames(zones, zone),
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
		views = append(views, zoneView)
	}
	if !slices.ContainsFunc(views, func(zone pages.ZoneView) bool { return zone.Name == selected }) {
		selected = ""
	}
	if history, ok := server.zones.(zoneRevisionStore); ok {
		for index := range views {
			zoneView := &views[index]
			if selected != "" && zoneView.Name != selected {
				continue
			}
			revisions, err := history.ListZoneRevisions(request.Context(), zoneView.Name, 20)
			if errors.Is(err, zonemodel.ErrRevisionHistoryUnavailable) {
				break
			}
			if err != nil {
				zoneView.HistoryError = "Change history is temporarily unavailable."
				server.logger.Warn("load zone revision history", "zone", zoneView.Name, "error", err)
				continue
			}
			zoneView.History = zoneRevisionViews(revisions, zoneView.Revision, console.TimeDisplay)
		}
	}
	return pages.ZonesPageView{
		Console: console, Zones: views, Selected: selected, Message: message, Error: errorMessage,
		CanCreate:    !server.securityEnabled || auth.Authorize(principal, auth.PermissionZonesCreate, "", ""),
		AliasSources: aliasSources,
		TSIGKeys:     tsigKeys,
	}
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

// catalogMemberNames lists the zones a catalog carries, so the console can show
// membership without making the operator read the raw PTR records.
func catalogMemberNames(zones []zonemodel.Zone, current zonemodel.Zone) []string {
	if current.Type != "catalog" {
		return nil
	}
	members := make([]string, 0)
	for _, candidate := range zones {
		if candidate.CatalogZone == current.Name {
			members = append(members, candidate.Name)
		}
	}
	slices.Sort(members)
	return members
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

func (server *Server) populateZoneDNSSECView(ctx context.Context, zone zonemodel.Zone, view *pages.ZoneView, display pages.TimeDisplay) {
	if server.dnssec != nil && zone.DNSSEC {
		status, err := server.dnssec.KeyStatus(ctx, zone)
		if err == nil {
			populateManagedKeyView(status, view, display)
			populateZoneSignatureExpiration(zone, view, display)
			return
		}
		server.logger.Warn("load DNSSEC key status", "zone", zone.Name, "error", err)
	}
	populateLegacyDNSSECView(zone, view, display)
}

func populateManagedKeyView(status dnssecstate.Status, view *pages.ZoneView, display pages.TimeDisplay) {
	view.DNSSECNextAction = status.NextAction
	view.DNSSECParentDSKeyTag = status.ParentDSKeyTag
	for _, key := range status.Keys {
		item := pages.DNSSECKeyView{
			Role: strings.ToUpper(key.Role), State: key.State, KeyTag: key.KeyTag,
			DNSKEY: key.DNSKEY, DS: key.DS,
		}
		if !key.ReadyAt.IsZero() {
			item.Timing = "ready " + pages.FormatDateTimeZoned(key.ReadyAt, display)
		} else if !key.RemoveAt.IsZero() {
			item.Timing = "remove after " + pages.FormatDateTimeZoned(key.RemoveAt, display)
		} else if !key.ActivatedAt.IsZero() {
			item.Timing = "active since " + pages.FormatDateTimeZoned(key.ActivatedAt, display)
		}
		view.DNSSECKeys = append(view.DNSSECKeys, item)
		if key.Role == dnssecstate.RoleKSK && key.State == dnssecstate.StateActive {
			view.DNSSECKeyTag, view.DNSSECDNSKEY, view.DNSSECDS = key.KeyTag, key.DNSKEY, key.DS
		}
	}
	view.DNSSEC = len(view.DNSSECKeys) > 0
}

func populateZoneSignatureExpiration(zone zonemodel.Zone, view *pages.ZoneView, display pages.TimeDisplay) {
	var expiration time.Time
	for _, record := range zone.Records {
		rr, err := zoneRecordRR(zone, record)
		if err != nil {
			continue
		}
		if signature, ok := rr.(*dns.RRSIG); ok {
			candidate := time.Unix(int64(signature.Expiration), 0)
			if expiration.IsZero() || candidate.Before(expiration) {
				expiration = candidate
			}
		}
	}
	if !expiration.IsZero() {
		view.DNSSECExpires = pages.FormatDateTimeZoned(expiration, display)
	}
}

func populateLegacyDNSSECView(zone zonemodel.Zone, view *pages.ZoneView, display pages.TimeDisplay) {
	var key *dns.DNSKEY
	var expiration time.Time
	hasSignature := false
	for _, record := range zone.Records {
		rr, err := zoneRecordRR(zone, record)
		if err != nil {
			continue
		}
		switch typed := rr.(type) {
		case *dns.DNSKEY:
			key = typed
		case *dns.RRSIG:
			hasSignature = true
			candidate := time.Unix(int64(typed.Expiration), 0)
			if expiration.IsZero() || candidate.Before(expiration) {
				expiration = candidate
			}
		}
	}
	if key == nil || !hasSignature {
		return
	}
	view.DNSSEC = true
	view.DNSSECKeyTag = key.KeyTag()
	view.DNSSECDNSKEY = key.String()
	if ds := key.ToDS(dns.SHA256); ds != nil {
		view.DNSSECDS = ds.String()
	}
	if !expiration.IsZero() {
		view.DNSSECExpires = pages.FormatDateTimeZoned(expiration, display)
	}
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

func (server *Server) updateZones(
	writer http.ResponseWriter,
	request *http.Request,
	selected *string,
	success string,
	mutate func(*[]zonemodel.Zone) error,
) {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.logZoneOperation(request, *selected, err)
		server.renderZoneMutation(writer, request, http.StatusBadRequest, *selected, "", "Invalid zone form.")
		return
	}
	if err := server.authorizeZoneMutation(request); err != nil {
		server.logZoneOperation(request, request.FormValue("zone"), err)
		server.renderZoneMutation(writer, request, http.StatusForbidden, normalizeZoneName(request.FormValue("zone")), "", err.Error())
		return
	}
	editor, ok := server.zones.(zoneEditor)
	if !ok {
		server.logZoneOperation(request, *selected, errors.New("zone catalog is read-only"))
		server.renderZoneMutation(writer, request, http.StatusNotImplemented, *selected, "", "This configuration source is read-only.")
		return
	}
	if err := editor.UpdateZones(request.Context(), mutate); err != nil {
		server.logZoneOperation(request, *selected, err)
		server.renderZoneMutation(writer, request, http.StatusUnprocessableEntity, *selected, "", err.Error())
		return
	}
	operationZone := *selected
	if operationZone == "" {
		operationZone = normalizeZoneName(request.FormValue("zone"))
	}
	server.logZoneOperation(request, operationZone, nil)
	server.auditZoneMutation(request, operationZone)
	server.notifyZoneChange(request.Context(), operationZone)
	server.renderZoneMutation(writer, request, http.StatusOK, *selected, success, "")
}

func (server *Server) authorizeZoneMutation(request *http.Request) error {
	if !server.securityEnabled {
		return nil
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	permission := map[string]string{
		"/ui/zones/add":               auth.PermissionZonesCreate,
		"/ui/zones/import-new":        auth.PermissionZonesCreate,
		"/ui/zones/delete":            auth.PermissionZonesDelete,
		"/ui/zones/settings":          auth.PermissionZonesSettings,
		"/ui/zones/toggle":            auth.PermissionZonesSettings,
		"/ui/zones/dnssec":            auth.PermissionZonesDNSSEC,
		"/ui/zones/dnssec/rollover":   auth.PermissionZonesDNSSEC,
		"/ui/zones/dnssec/confirm-ds": auth.PermissionZonesDNSSEC,
		"/ui/zones/resync":            auth.PermissionZonesTransfer,
		"/ui/zones/import":            auth.PermissionZonesImport,
		"/ui/zones/records/add":       auth.PermissionZonesRecords,
		"/ui/zones/records/update":    auth.PermissionZonesRecords,
		"/ui/zones/records/delete":    auth.PermissionZonesRecords,
		"/ui/zones/rollback":          auth.PermissionZonesRecords,
	}[request.URL.Path]
	if request.URL.Path == "/ui/zones/rollback" {
		if err := server.authorizeExistingZone(principal, auth.PermissionZonesRecords, request.FormValue("zone")); err != nil {
			return err
		}
		return server.authorizeExistingZone(principal, auth.PermissionZonesSettings, request.FormValue("zone"))
	}
	if request.URL.Path == "/ui/zones/clone" {
		if !auth.Authorize(principal, auth.PermissionZonesCreate, "", "") {
			return auth.ErrForbidden
		}
		return server.authorizeExistingZone(principal, auth.PermissionZonesRead, request.FormValue("zone"))
	}
	if permission == auth.PermissionZonesCreate {
		if auth.Authorize(principal, permission, "", "") {
			return nil
		}
		return auth.ErrForbidden
	}
	if permission == "" {
		return auth.ErrForbidden
	}
	return server.authorizeExistingZone(principal, permission, request.FormValue("zone"))
}

func (server *Server) authorizeExistingZone(principal auth.Principal, permission, name string) error {
	current := findZone(server.zones.Current().Zones, normalizeZoneName(name))
	if current == nil || !auth.Authorize(principal, permission, auth.ResourceZone, current.ID) {
		return auth.ErrForbidden
	}
	return nil
}

func (server *Server) logZoneOperation(request *http.Request, zoneName string, operationErr error) {
	attributes := []any{
		"operation", zoneMutationAction(request.URL.Path),
		"zone", zoneName,
		"client", requestClientIP(request),
	}
	if operationErr != nil {
		attributes = append(attributes, "error", operationErr)
		server.logger.Warn("zone operation failed", attributes...)
		return
	}
	server.logger.Info("zone operation completed", attributes...)
}

func zoneMutationAction(path string) string {
	actions := map[string]string{
		"/ui/zones/add":               "zone.create",
		"/ui/zones/delete":            "zone.delete",
		"/ui/zones/settings":          "zone.settings",
		"/ui/zones/toggle":            "zone.toggle",
		"/ui/zones/clone":             "zone.clone",
		"/ui/zones/resync":            "zone.resync",
		"/ui/zones/import":            "zone.import",
		"/ui/zones/import-new":        "zone.import_new",
		"/ui/zones/records/add":       "zone.record.create",
		"/ui/zones/records/update":    "zone.record.update",
		"/ui/zones/records/delete":    "zone.record.delete",
		"/ui/zones/dnssec":            "zone.dnssec.settings",
		"/ui/zones/dnssec/rollover":   "zone.dnssec.rollover",
		"/ui/zones/dnssec/confirm-ds": "zone.dnssec.confirm_ds",
		"/ui/zones/rollback":          "zone.rollback",
	}
	if action := actions[path]; action != "" {
		return action
	}
	return "zone.update"
}

func (server *Server) auditZoneMutation(request *http.Request, zone string) {
	recorder, ok := server.queries.(interface {
		RecordAuditEvent(context.Context, auth.AuditEvent) error
	})
	if !ok {
		return
	}
	action := zoneMutationAction(request.URL.Path)
	event := auth.AuditEvent{
		OccurredAt: time.Now(), Action: action, ClientIP: requestClientIP(request),
		UserAgent: request.UserAgent(), Details: "zone=" + zone,
	}
	if action == "zone.rollback" {
		event.Details += " revision=" + request.FormValue("revision")
	}
	if principal, ok := request.Context().Value(principalContextKey{}).(auth.Principal); ok && principal.UserID != 0 {
		event.UserID = &principal.UserID
	}
	if err := recorder.RecordAuditEvent(request.Context(), event); err != nil {
		server.logger.Warn("record zone audit event", "action", action, "zone", zone, "error", err)
	}
}

func (server *Server) notifyZoneChange(ctx context.Context, zoneName string) {
	if zoneName == "" {
		return
	}
	zone := findZone(server.zones.Current().Zones, zoneName)
	if zone == nil || zone.Disabled || len(zone.Notify) == 0 {
		return
	}
	notifier, ok := any(server.stats).(zoneNotifier)
	if !ok {
		return
	}
	for _, err := range notifier.NotifyZone(ctx, zone.Name, zone.Notify) {
		server.logger.Warn("notify secondary server", "zone", zone.Name, "error", err)
	}
}

func (server *Server) renderZoneMutation(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	selected, message, errorMessage string,
) {
	if request.Header.Get("HX-Request") == "true" {
		pushURL := "/zones"
		if selected != "" {
			pushURL = zonePath(selected)
		}
		writer.Header().Set("HX-Push-Url", pushURL)
	}
	if status != http.StatusOK && request.Header.Get("HX-Request") != "true" {
		writer.WriteHeader(status)
	}
	_ = pages.ZonesContent(server.zonesView(request, message, errorMessage, selected)).Render(request.Context(), writer)
}

func (server *Server) addZone(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "Authoritative zone created", func(zones *[]zonemodel.Zone) error {
		name, err := dnsname.Normalize(request.FormValue("name"))
		if err != nil {
			return fmt.Errorf("zone name: %w", err)
		}
		selected = name
		if slices.ContainsFunc(*zones, func(zone zonemodel.Zone) bool { return zone.Name == name }) {
			return errors.New("zone already exists")
		}
		zoneType := strings.ToLower(strings.TrimSpace(request.FormValue("type")))
		if zoneType == "" {
			zoneType = "primary"
		}
		// The two catalog roles are one zone type that differs only in whether
		// the catalog is transferred from somewhere else, but they are separate
		// choices in the form because they behave nothing alike.
		consumeCatalog := zoneType == catalogConsumerFormType
		if consumeCatalog {
			zoneType = "catalog"
		}
		if zoneType != "primary" && zoneType != "secondary" && zoneType != "stub" &&
			zoneType != "forwarder" && zoneType != "alias" && zoneType != "catalog" {
			return errors.New("unsupported zone type")
		}
		primaryNSValue := strings.TrimSpace(request.FormValue("primary_ns"))
		if primaryNSValue == "" {
			// RFC 9432 recommends an apex NS of "invalid." because a catalog
			// zone is only ever transferred, never resolved.
			primaryNSValue = "ns1." + name
			if zoneType == "catalog" {
				primaryNSValue = "invalid."
			}
		}
		primaryNS, err := dnsname.Normalize(primaryNSValue)
		if err != nil {
			return fmt.Errorf("primary name server: %w", err)
		}
		responsibleValue := strings.TrimSpace(request.FormValue("responsible"))
		if responsibleValue == "" {
			responsibleValue = "hostmaster@" + name
		}
		responsible, err := soaResponsibleName(responsibleValue)
		if err != nil {
			return err
		}
		ttl, err := formTTL(request.FormValue("default_ttl"), defaultZoneTTL)
		if err != nil {
			return err
		}
		serial := nextSOASerial(0, time.Now())
		zone := zonemodel.Zone{
			Name: name, Type: zoneType, DefaultTTL: ttl,
			TSIGKey: strings.TrimSpace(request.FormValue("tsig_key")),
		}
		if (zoneType == "forwarder" || zoneType == "stub") && request.Form.Has("dnssec_validation_present") {
			zone.DNSSECValidationDisabled = request.FormValue("dnssec_validation") != "true"
		}
		soa := zonemodel.Record{Name: "@", Type: "SOA", TTL: ttl, Value: fmt.Sprintf("%s %s %d 3600 600 1209600 %d", dns.Fqdn(primaryNS), responsible, serial, ttl)}
		switch zoneType {
		case "primary":
			zone.Records = []zonemodel.Record{soa, {Name: "@", Type: "NS", TTL: ttl, Value: dns.Fqdn(primaryNS)}}
		case "alias":
			source, aliasErr := aliasSourceZone(*zones, request.FormValue("alias_zone"), name)
			if aliasErr != nil {
				return aliasErr
			}
			zone.AliasZone = source
			// The mirrored records, including the apex NS set, are filled in
			// when the catalog reconciles this zone against its source.
			zone.Records = []zonemodel.Record{soa}
		case "forwarder":
			protocol := strings.ToLower(strings.TrimSpace(request.FormValue("forwarder_protocol")))
			if protocol == "" {
				protocol = "udp"
			}
			priority := strings.TrimSpace(request.FormValue("forwarder_priority"))
			if priority == "" {
				priority = "0"
			}
			forwarder, forwarderErr := forwarding.NewRecord(protocol, priority, request.FormValue("forwarder_address"))
			if forwarderErr != nil {
				return fmt.Errorf("forwarder: %w", forwarderErr)
			}
			zone.Records = []zonemodel.Record{soa, {Name: "@", Type: "FWD", TTL: ttl, Value: forwarder.String()}}
		case "catalog":
			zone.Records = []zonemodel.Record{soa, {Name: "@", Type: "NS", TTL: ttl, Value: dns.Fqdn(primaryNS)}}
			if !consumeCatalog {
				break
			}
			// A subscribed catalog is transferred exactly like a secondary, so
			// its first transfer happens here and the operator sees a bad
			// address or a rejected TSIG key immediately.
			protocol := strings.ToLower(strings.TrimSpace(request.FormValue("primary_protocol")))
			if protocol == "" {
				protocol = "tcp"
			}
			if protocol != "tcp" && protocol != "tls" {
				return errors.New("catalog zone transfer protocol must be TCP or DNS-over-TLS")
			}
			primaries, primaryErr := normalizeZonePrimaryServers(request.FormValue("primary_servers"), protocol)
			if primaryErr != nil {
				return primaryErr
			}
			synchronizer, ok := any(server.stats).(zoneSynchronizer)
			if !ok {
				return errors.New("zone synchronization is unavailable")
			}
			transferred, transferErr := synchronizer.FetchZone(request.Context(), name, "catalog", primaries, protocol, zone.TSIGKey)
			if transferErr != nil {
				return transferErr
			}
			zone.PrimaryServers, zone.PrimaryProtocol = primaries, protocol
			zone.Records = configuredZoneRecords(transferred)
			if _, parseErr := zonemodel.ParseCatalog(name, zone.Records); parseErr != nil {
				return fmt.Errorf("the transferred zone is not a usable catalog: %w", parseErr)
			}
		case "secondary", "stub":
			protocol := strings.ToLower(strings.TrimSpace(request.FormValue("primary_protocol")))
			if protocol == "" {
				if zoneType == "stub" {
					protocol = "udp"
				} else {
					protocol = "tcp"
				}
			}
			if zoneType == "secondary" && protocol != "tcp" && protocol != "tls" {
				return errors.New("secondary zone transfer protocol must be TCP or DNS-over-TLS")
			}
			if zoneType == "stub" && protocol != "udp" && protocol != "tcp" && protocol != "tls" {
				return errors.New("stub zone primary protocol must be UDP, TCP, or DNS-over-TLS")
			}
			primaries, primaryErr := normalizeZonePrimaryServers(request.FormValue("primary_servers"), protocol)
			if primaryErr != nil {
				return primaryErr
			}
			synchronizer, ok := any(server.stats).(zoneSynchronizer)
			if !ok {
				return errors.New("zone synchronization is unavailable")
			}
			transferred, transferErr := synchronizer.FetchZone(request.Context(), name, zoneType, primaries, protocol, zone.TSIGKey)
			if transferErr != nil {
				return transferErr
			}
			zone.PrimaryServers, zone.PrimaryProtocol = primaries, protocol
			zone.Records = configuredZoneRecords(transferred)
		}
		*zones = append(*zones, zone)
		return nil
	})
}

// aliasSourceZone resolves the zone an alias mirrors and reports the problem in
// the operator's own terms. Model validation covers the same ground for zones
// that arrive through other paths, but its message is written for a catalog
// rather than for the form the operator just submitted.
func aliasSourceZone(zones []zonemodel.Zone, value, aliasName string) (string, error) {
	source, err := dnsname.Normalize(value)
	if err != nil {
		return "", fmt.Errorf("source zone: %w", err)
	}
	if source == aliasName {
		return "", errors.New("an alias zone cannot mirror itself")
	}
	existing := findZone(zones, source)
	if existing == nil {
		return "", fmt.Errorf("zone %q was not found", source)
	}
	if existing.Type != "primary" && existing.Type != "secondary" {
		return "", fmt.Errorf("only primary and secondary zones can be mirrored, and %q is a %s zone", source, existing.Type)
	}
	return source, nil
}

func normalizeZonePrimaryServers(value, protocol string) ([]string, error) {
	raw := splitZoneSettingsList(value)
	if len(raw) == 0 {
		return nil, errors.New("at least one primary server is required")
	}
	result := make([]string, 0, len(raw))
	for _, target := range raw {
		record, err := forwarding.NewRecord(protocol, "0", target)
		if err != nil {
			return nil, fmt.Errorf("primary server %q: %w", target, err)
		}
		result = append(result, record.Address)
	}
	return result, nil
}

func configuredZoneRecords(records []dnsserver.ZoneRecord) []zonemodel.Record {
	result := make([]zonemodel.Record, 0, len(records))
	for _, record := range records {
		result = append(result, zonemodel.Record{Name: record.Name, Type: record.Type, Value: record.Value, TTL: record.TTL})
	}
	return result
}

func (server *Server) deleteZone(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "Authoritative zone deleted", func(zones *[]zonemodel.Zone) error {
		name := normalizeZoneName(request.FormValue("zone"))
		index := slices.IndexFunc(*zones, func(zone zonemodel.Zone) bool { return zone.Name == name })
		if index < 0 {
			return errors.New("zone was not found")
		}
		*zones = slices.Delete(*zones, index, index+1)
		return nil
	})
}

func (server *Server) updateZoneSettings(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "Zone settings updated", func(zones *[]zonemodel.Zone) error {
		selected = normalizeZoneName(request.FormValue("zone"))
		zone := findZone(*zones, selected)
		if zone == nil {
			return errors.New("zone was not found")
		}
		if owner := catalogManagingZone(*zones, *zone); owner != "" {
			// Every setting on a provisioned member is inherited from its
			// catalog and would be overwritten on the next refresh, so the form
			// says so rather than accepting an edit that silently reverts.
			return fmt.Errorf("this zone is managed by catalog %q; change it there instead", owner)
		}
		defaultTTL, err := formTTL(request.FormValue("default_ttl"), 0)
		if err != nil {
			return err
		}
		if defaultTTL == 0 {
			return errors.New("TTL must be a positive integer")
		}
		zone.DefaultTTL = defaultTTL
		zone.TSIGKey = strings.TrimSpace(request.FormValue("tsig_key"))
		zone.DynamicUpdates = zone.Type == "primary" && request.FormValue("dynamic_updates") == "true"
		if request.Form.Has("zone_transfer") {
			zone.ZoneTransfer = strings.ToLower(strings.TrimSpace(request.FormValue("zone_transfer")))
		}
		if request.Form.Has("transfer_acl") {
			zone.TransferACL = splitZoneSettingsList(request.FormValue("transfer_acl"))
		}
		if request.Form.Has("notify") {
			zone.Notify = splitZoneSettingsList(request.FormValue("notify"))
			for index, target := range zone.Notify {
				record, recordErr := forwarding.NewRecord("udp", "0", target)
				if recordErr != nil {
					return fmt.Errorf("notify server %q: %w", target, recordErr)
				}
				zone.Notify[index] = record.Address
			}
		}
		if zone.Type == "alias" && request.Form.Has("alias_zone") {
			source, aliasErr := aliasSourceZone(*zones, request.FormValue("alias_zone"), zone.Name)
			if aliasErr != nil {
				return aliasErr
			}
			zone.AliasZone = source
		}
		if request.Form.Has("catalog_zone") {
			catalogName, catalogErr := catalogPublisherZone(*zones, request.FormValue("catalog_zone"), *zone)
			if catalogErr != nil {
				return catalogErr
			}
			zone.CatalogZone = catalogName
			if catalogName == "" {
				zone.CatalogGroup = ""
			} else if request.Form.Has("catalog_group") {
				zone.CatalogGroup = strings.TrimSpace(request.FormValue("catalog_group"))
			}
		}
		if (zone.Type == "secondary" || zone.Type == "stub" || zone.Type == "catalog") && request.Form.Has("primary_servers") {
			protocol := strings.ToLower(strings.TrimSpace(request.FormValue("primary_protocol")))
			if (zone.Type == "secondary" || zone.Type == "catalog") && protocol != "tcp" && protocol != "tls" {
				return fmt.Errorf("%s zone transfer protocol must be TCP or DNS-over-TLS", zone.Type)
			}
			primaries, primaryErr := normalizeZonePrimaryServers(request.FormValue("primary_servers"), protocol)
			if primaryErr != nil {
				return primaryErr
			}
			if zone.Type == "catalog" && len(primaries) == 0 {
				// Dropping the last primary would silently turn a subscribed
				// catalog into one this server publishes, orphaning every zone
				// it provisioned.
				return errors.New("a subscribed catalog zone needs at least one primary server")
			}
			zone.PrimaryServers, zone.PrimaryProtocol = primaries, protocol
		}
		return nil
	})
}

// catalogManagingZone names the consumer catalog that provisioned a zone, or an
// empty string when the operator owns the zone themselves. Membership of a
// catalog this server publishes is an ordinary local setting, so it does not
// make the zone read-only.
func catalogManagingZone(zones []zonemodel.Zone, current zonemodel.Zone) string {
	if current.CatalogZone == "" {
		return ""
	}
	owner := findZone(zones, current.CatalogZone)
	if owner == nil || !zonemodel.IsConsumerCatalog(*owner) {
		return ""
	}
	return owner.Name
}

// catalogPublisherZone resolves the catalog a zone is published into and reports
// the problem in the operator's own terms. Model validation covers the same
// ground for zones that arrive through other paths.
func catalogPublisherZone(zones []zonemodel.Zone, value string, current zonemodel.Zone) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	catalogName, err := dnsname.Normalize(value)
	if err != nil {
		return "", fmt.Errorf("catalog zone: %w", err)
	}
	if current.Type == "catalog" {
		return "", errors.New("a catalog zone cannot be a member of another catalog")
	}
	existing := findZone(zones, catalogName)
	if existing == nil {
		return "", fmt.Errorf("catalog zone %q was not found", catalogName)
	}
	if existing.Type != "catalog" {
		return "", fmt.Errorf("zone %q is a %s zone, not a catalog zone", catalogName, existing.Type)
	}
	if zonemodel.IsConsumerCatalog(*existing) {
		return "", fmt.Errorf("catalog %q is subscribed from another server, so its membership is not set here", catalogName)
	}
	return catalogName, nil
}

func (server *Server) updateZoneDNSSEC(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "DNSSEC settings updated", func(zones *[]zonemodel.Zone) error {
		selected = normalizeZoneName(request.FormValue("zone"))
		zone := findZone(*zones, selected)
		if zone == nil {
			return errors.New("zone was not found")
		}
		// Forwarder and stub zones are answered upstream rather than signed, so
		// their DNSSEC dialog carries the validation switch instead. The paired
		// hidden field distinguishes an unchecked switch from a form that never
		// rendered one, so an unrelated submission cannot silently turn
		// validation off.
		if zone.Type == "forwarder" || zone.Type == "stub" {
			if request.Form.Has("dnssec_validation_present") {
				zone.DNSSECValidationDisabled = request.FormValue("dnssec_validation") != "true"
			}
			return nil
		}
		if zone.Type != "primary" {
			return errors.New("only primary zones can be signed by Sable")
		}
		enabled := request.FormValue("enabled") == "true"
		algorithm := strings.ToLower(strings.TrimSpace(request.FormValue("algorithm")))
		denial := strings.ToLower(strings.TrimSpace(request.FormValue("denial")))
		if enabled {
			switch algorithm {
			case "", "ed25519":
				algorithm = "ed25519"
			case "ecdsa-p256-sha256", "ecdsa-p384-sha384":
			default:
				return errors.New("unsupported DNSSEC signing algorithm")
			}
			if denial == "" {
				denial = "nsec"
			}
			if denial != "nsec" && denial != "nsec3" {
				return errors.New("unsupported DNSSEC denial mode")
			}
			if zone.DNSSEC && hasManagedZoneDNSSECRecords(*zone) && algorithm != zone.DNSSECAlgorithm {
				return errors.New("DNSSEC algorithm rollover is not supported; keep the current signing algorithm")
			}
		}
		iterations, err := strconv.ParseUint(strings.TrimSpace(request.FormValue("nsec3_iterations")), 10, 16)
		if request.FormValue("nsec3_iterations") == "" {
			iterations = 0
			err = nil
		}
		if err != nil || iterations != 0 {
			return errors.New("NSEC3 iterations must be 0")
		}
		zone.DNSSEC = enabled
		zone.DNSSECAlgorithm = algorithm
		zone.DNSSECDenial = denial
		zone.NSEC3Iterations = uint16(iterations)
		zone.NSEC3Salt = strings.ToUpper(strings.TrimSpace(request.FormValue("nsec3_salt")))
		if enabled {
			policies := []struct {
				name   string
				target *zonemodel.Duration
			}{
				{"ZSK lifetime", &zone.ZSKLifetime},
				{"KSK lifetime", &zone.KSKLifetime},
				{"key prepublication", &zone.KeyPrepublish},
				{"key retirement", &zone.KeyRetireAfter},
			}
			values := []string{
				request.FormValue("zsk_lifetime"), request.FormValue("ksk_lifetime"),
				request.FormValue("key_prepublish"), request.FormValue("key_retire_after"),
			}
			for index, policy := range policies {
				parsed, parseErr := durationfmt.Parse(values[index])
				if parseErr != nil || parsed <= 0 {
					return fmt.Errorf("%s must be a positive duration such as 30d", policy.name)
				}
				policy.target.Duration = parsed
			}
		}
		return nil
	})
}

func hasManagedZoneDNSSECRecords(zone zonemodel.Zone) bool {
	return slices.ContainsFunc(zone.Records, func(record zonemodel.Record) bool {
		return strings.HasPrefix(record.Comments, "sable:dnssec")
	})
}

func (server *Server) rolloverZoneDNSSECKey(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "DNSSEC key rollover started", func(zones *[]zonemodel.Zone) error {
		selected = normalizeZoneName(request.FormValue("zone"))
		zone := findZone(*zones, selected)
		if zone == nil || zone.Type != "primary" || !zone.DNSSEC {
			return errors.New("DNSSEC signing is not enabled for this primary zone")
		}
		if server.dnssec == nil {
			return errors.New("DNSSEC key management is unavailable")
		}
		role := strings.ToLower(strings.TrimSpace(request.FormValue("role")))
		return server.dnssec.RequestRollover(request.Context(), *zone, role)
	})
}

func (server *Server) confirmZoneDNSSECDS(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "Parent DS key confirmed", func(zones *[]zonemodel.Zone) error {
		selected = normalizeZoneName(request.FormValue("zone"))
		zone := findZone(*zones, selected)
		if zone == nil || zone.Type != "primary" || !zone.DNSSEC {
			return errors.New("DNSSEC signing is not enabled for this primary zone")
		}
		if server.dnssec == nil {
			return errors.New("DNSSEC key management is unavailable")
		}
		parsed, err := strconv.ParseUint(strings.TrimSpace(request.FormValue("key_tag")), 10, 16)
		if err != nil {
			return errors.New("a valid KSK key tag is required")
		}
		keyTag := uint16(parsed)
		status, err := server.dnssec.KeyStatus(request.Context(), *zone)
		if err != nil {
			return err
		}
		valid := slices.ContainsFunc(status.Keys, func(key dnssecstate.KeyStatus) bool {
			return key.Role == dnssecstate.RoleKSK && key.KeyTag == keyTag && (key.State == dnssecstate.StateActive || key.State == dnssecstate.StateReady)
		})
		if !valid {
			return errors.New("the selected KSK is not active or ready for parent DS publication")
		}
		zone.ParentDSKeyTag = keyTag
		return nil
	})
}

func splitZoneSettingsList(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' })
}

func (server *Server) cloneZone(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "Zone cloned", func(zones *[]zonemodel.Zone) error {
		sourceName := normalizeZoneName(request.FormValue("zone"))
		selected = sourceName
		source := findZone(*zones, sourceName)
		if source == nil {
			return errors.New("zone was not found")
		}
		if !zoneRecordsEditable(source.Type) {
			return errors.New("only primary and forwarder zones can be cloned")
		}
		name, err := dnsname.Normalize(request.FormValue("name"))
		if err != nil {
			return fmt.Errorf("zone name: %w", err)
		}
		if slices.ContainsFunc(*zones, func(zone zonemodel.Zone) bool { return zone.Name == name }) {
			return errors.New("zone already exists")
		}
		clone := *source
		clone.ID = ""
		clone.Name = name
		clone.Disabled = false
		clone.Records = append([]zonemodel.Record(nil), source.Records...)
		advanceSOASerial(&clone, time.Now())
		*zones = append(*zones, clone)
		selected = name
		return nil
	})
}

func (server *Server) resyncZone(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "Zone synchronized from its primary server", func(zones *[]zonemodel.Zone) error {
		selected = normalizeZoneName(request.FormValue("zone"))
		zone := findZone(*zones, selected)
		if zone == nil {
			return errors.New("zone was not found")
		}
		if zone.Type != "secondary" && zone.Type != "stub" {
			return errors.New("only secondary and stub zones can be synchronized")
		}
		synchronizer, ok := any(server.stats).(zoneSynchronizer)
		if !ok {
			return errors.New("zone synchronization is unavailable")
		}
		current := make([]dnsserver.ZoneRecord, 0, len(zone.Records))
		for _, record := range zone.Records {
			current = append(current, dnsserver.ZoneRecord{
				Name: record.Name, Type: record.Type, Value: record.Value, TTL: record.TTL,
				Disabled: record.Disabled, ExpiresAt: record.ExpiresAt,
			})
		}
		records, changed, err := synchronizer.RefreshZone(
			request.Context(), zone.Name, zone.Type, zone.PrimaryServers, zone.PrimaryProtocol, zone.TSIGKey, current,
		)
		if err != nil {
			return err
		}
		if changed {
			zone.Records = configuredZoneRecords(records)
		}
		return nil
	})
}

func zoneRecordsEditable(zoneType string) bool {
	return zoneType == "primary" || zoneType == "forwarder" || zoneType == ""
}

func (server *Server) toggleZone(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	enable := request.FormValue("action") == "enable"
	message := "Zone disabled"
	if enable {
		message = "Zone enabled"
	}
	server.updateZones(writer, request, &selected, message, func(zones *[]zonemodel.Zone) error {
		selected = normalizeZoneName(request.FormValue("zone"))
		zone := findZone(*zones, selected)
		if zone == nil {
			return errors.New("zone was not found")
		}
		zone.Disabled = !enable
		return nil
	})
}

func (server *Server) addZoneRecord(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "Record added and SOA serial advanced", func(zones *[]zonemodel.Zone) error {
		selected = normalizeZoneName(request.FormValue("zone"))
		zone := findZone(*zones, selected)
		if zone == nil {
			return errors.New("zone was not found")
		}
		if !zoneRecordsEditable(zone.Type) {
			return errors.New("records synchronized from a primary server are read-only")
		}
		ttl, err := formTTL(request.FormValue("ttl"), zone.DefaultTTL)
		if err != nil {
			return err
		}
		recordType := strings.ToUpper(strings.TrimSpace(request.FormValue("type")))
		if zone.Type == "forwarder" && recordType != "FWD" {
			return errors.New("forwarder zones accept only FWD records")
		}
		value, err := zoneRecordValueFromForm(request, recordType, "")
		if err != nil {
			return err
		}
		value = zonemodel.QualifyRecordValue(zone.Name, recordType, value)
		record := zonemodel.Record{
			Name:  normalizeZoneRecordOwner(zone.Name, request.FormValue("name")),
			Type:  recordType,
			Value: value, TTL: ttl,
			Comments: strings.TrimSpace(request.FormValue("comments")),
		}
		record.ExpiresAt, err = formExpiry(request.FormValue("expiry_ttl"), time.Now())
		if err != nil {
			return err
		}
		if record.Name == "" {
			record.Name = "@"
		}
		if record.Type == "SOA" {
			return errors.New("Sable manages the zone SOA record")
		}
		zone.Records = append(zone.Records, record)
		if err := zonemodel.CheckCNAMEExclusivity(*zone, record.Name, time.Now()); err != nil {
			return err
		}
		if record.Type == "NS" {
			if err := syncZoneNSGlue(zone, "", record.Value, request.FormValue("glue_addresses")); err != nil {
				return err
			}
		}
		advanceSOASerial(zone, time.Now())
		return nil
	})
}

func (server *Server) deleteZoneRecord(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "Record removed and SOA serial advanced", func(zones *[]zonemodel.Zone) error {
		selected = normalizeZoneName(request.FormValue("zone"))
		zone := findZone(*zones, selected)
		if zone == nil {
			return errors.New("zone was not found")
		}
		if !zoneRecordsEditable(zone.Type) {
			return errors.New("records synchronized from a primary server are read-only")
		}
		ttl, err := strconv.ParseUint(request.FormValue("ttl"), 10, 32)
		if err != nil {
			return errors.New("record TTL is invalid")
		}
		name := request.FormValue("name")
		recordType := request.FormValue("type")
		value := request.FormValue("value")
		if recordType == "SOA" {
			return errors.New("the zone SOA record cannot be removed")
		}
		index := slices.IndexFunc(zone.Records, func(record zonemodel.Record) bool {
			return record.Name == name && record.Type == recordType && record.Value == value && record.TTL == uint32(ttl)
		})
		if index < 0 {
			return errors.New("record was not found")
		}
		if strings.HasPrefix(zone.Records[index].Comments, "sable:dnssec") {
			return errors.New("DNSSEC records are managed automatically")
		}
		if err := recordSourceEditable(zone.Records[index]); err != nil {
			return err
		}
		zone.Records = slices.Delete(zone.Records, index, index+1)
		advanceSOASerial(zone, time.Now())
		return nil
	})
}

func (server *Server) updateZoneRecord(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "Record updated", func(zones *[]zonemodel.Zone) error {
		selected = normalizeZoneName(request.FormValue("zone"))
		zone := findZone(*zones, selected)
		if zone == nil {
			return errors.New("zone was not found")
		}
		if !zoneRecordsEditable(zone.Type) {
			return errors.New("records synchronized from a primary server are read-only")
		}
		originalTTL, err := strconv.ParseUint(request.FormValue("ttl"), 10, 32)
		if err != nil {
			return errors.New("record TTL is invalid")
		}
		originalName := request.FormValue("name")
		recordType := strings.ToUpper(strings.TrimSpace(request.FormValue("type")))
		originalValue := request.FormValue("value")
		index := slices.IndexFunc(zone.Records, func(record zonemodel.Record) bool {
			return record.Name == originalName && record.Type == recordType && record.Value == originalValue && record.TTL == uint32(originalTTL)
		})
		if index < 0 {
			return errors.New("record was not found")
		}
		if strings.HasPrefix(zone.Records[index].Comments, "sable:dnssec") {
			return errors.New("DNSSEC records are managed automatically")
		}
		if err := recordSourceEditable(zone.Records[index]); err != nil {
			return err
		}
		newTTL, err := formTTL(request.FormValue("new_ttl"), zone.DefaultTTL)
		if err != nil {
			return err
		}
		newName := normalizeZoneRecordOwner(zone.Name, request.FormValue("new_name"))
		if recordType == "SOA" && newName != "@" {
			return errors.New("the SOA record must remain at the zone apex")
		}
		newValue, err := zoneRecordValueFromForm(request, recordType, "new_")
		if err != nil {
			return err
		}
		newValue = zonemodel.QualifyRecordValue(zone.Name, recordType, newValue)
		expiresAt, err := formExpiry(request.FormValue("new_expiry_ttl"), time.Now())
		if err != nil {
			return err
		}
		zone.Records[index] = zonemodel.Record{
			Name: newName, Type: recordType, Value: newValue, TTL: newTTL,
			Comments: strings.TrimSpace(request.FormValue("new_comments")),
			Disabled: recordType != "SOA" && request.FormValue("enabled") != "true", ExpiresAt: expiresAt,
		}
		if err := zonemodel.CheckCNAMEExclusivity(*zone, newName, time.Now()); err != nil {
			return err
		}
		if recordType == "NS" {
			if err := syncZoneNSGlue(zone, originalValue, newValue, request.FormValue("new_glue_addresses")); err != nil {
				return err
			}
		}
		if recordType != "SOA" {
			advanceSOASerial(zone, time.Now())
		}
		return nil
	})
}

func zoneRecordValueFromForm(request *http.Request, recordType, prefix string) (string, error) {
	field := func(name string) string { return strings.TrimSpace(request.FormValue(prefix + name)) }
	required := func(name, label string) (string, error) {
		value := field(name)
		if value == "" {
			return "", fmt.Errorf("%s is required", label)
		}
		return value, nil
	}
	unsigned := func(name, label, fallback string, bits int) (string, error) {
		value := field(name)
		if value == "" {
			value = fallback
		}
		if _, err := strconv.ParseUint(value, 10, bits); err != nil {
			return "", fmt.Errorf("%s must be an unsigned integer", label)
		}
		return value, nil
	}

	switch recordType {
	case "A", "AAAA":
		address, err := required("value", map[string]string{"A": "IPv4 address", "AAAA": "IPv6 address"}[recordType])
		if err != nil {
			return "", err
		}
		parsed, err := netip.ParseAddr(address)
		if err != nil || (recordType == "A" && !parsed.Is4()) || (recordType == "AAAA" && !parsed.Is6()) {
			return "", fmt.Errorf("%s is not a valid %s address", address, recordType)
		}
		return parsed.String(), nil
	case "CNAME", "ANAME", "DNAME", "NS", "PTR":
		return required("value", map[string]string{
			"CNAME": "target host", "ANAME": "target host", "DNAME": "target host", "NS": "name server", "PTR": "domain name",
		}[recordType])
	case "MX":
		preference, err := unsigned("preference", "priority", "10", 16)
		if err != nil {
			return "", err
		}
		exchange, err := required("exchange", "mail server")
		if err != nil {
			return "", err
		}
		return preference + " " + exchange, nil
	case "TXT":
		text, err := required("text", "text value")
		if err != nil {
			return "", err
		}
		return quoteDNSString(text), nil
	case "SRV":
		priority, err := unsigned("priority", "priority", "0", 16)
		if err != nil {
			return "", err
		}
		weight, err := unsigned("weight", "weight", "0", 16)
		if err != nil {
			return "", err
		}
		port, err := unsigned("port", "port", "", 16)
		if err != nil {
			return "", err
		}
		target, err := required("target", "target host")
		if err != nil {
			return "", err
		}
		return strings.Join([]string{priority, weight, port, target}, " "), nil
	case "CAA":
		flags, err := unsigned("flags", "flags", "0", 8)
		if err != nil {
			return "", err
		}
		tag, err := required("tag", "tag")
		if err != nil {
			return "", err
		}
		value, err := required("ca_domain", "CA domain")
		if err != nil {
			return "", err
		}
		return flags + " " + tag + " " + quoteDNSString(value), nil
	case "DS":
		keyTag, err := unsigned("key_tag", "key tag", "", 16)
		if err != nil {
			return "", err
		}
		algorithm, err := unsigned("algorithm", "algorithm", "13", 8)
		if err != nil {
			return "", err
		}
		digestType, err := unsigned("digest_type", "digest type", "2", 8)
		if err != nil {
			return "", err
		}
		digest, err := required("digest", "digest")
		if err != nil {
			return "", err
		}
		return strings.Join([]string{keyTag, algorithm, digestType, digest}, " "), nil
	case "SSHFP":
		algorithm, err := unsigned("algorithm", "algorithm", "4", 8)
		if err != nil {
			return "", err
		}
		fingerprintType, err := unsigned("fingerprint_type", "fingerprint type", "2", 8)
		if err != nil {
			return "", err
		}
		fingerprint, err := required("fingerprint", "fingerprint")
		if err != nil {
			return "", err
		}
		return strings.Join([]string{algorithm, fingerprintType, fingerprint}, " "), nil
	case "TLSA":
		usage, err := unsigned("certificate_usage", "certificate usage", "3", 8)
		if err != nil {
			return "", err
		}
		selector, err := unsigned("selector", "selector", "1", 8)
		if err != nil {
			return "", err
		}
		matchingType, err := unsigned("matching_type", "matching type", "1", 8)
		if err != nil {
			return "", err
		}
		certificate, err := required("certificate", "certificate association data")
		if err != nil {
			return "", err
		}
		return strings.Join([]string{usage, selector, matchingType, certificate}, " "), nil
	case "SVCB", "HTTPS":
		priority, err := unsigned("svc_priority", "priority", "1", 16)
		if err != nil {
			return "", err
		}
		target, err := required("svc_target", "target name")
		if err != nil {
			return "", err
		}
		params, err := zoneServiceParameters(field("svc_params"))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(priority + " " + target + " " + params), nil
	case "URI":
		priority, err := unsigned("uri_priority", "priority", "0", 16)
		if err != nil {
			return "", err
		}
		weight, err := unsigned("uri_weight", "weight", "0", 16)
		if err != nil {
			return "", err
		}
		uri, err := required("uri", "URI")
		if err != nil {
			return "", err
		}
		return priority + " " + weight + " " + quoteDNSString(uri), nil
	case "NAPTR":
		order, err := unsigned("naptr_order", "order", "0", 16)
		if err != nil {
			return "", err
		}
		preference, err := unsigned("naptr_preference", "preference", "0", 16)
		if err != nil {
			return "", err
		}
		replacement := field("naptr_replacement")
		if replacement == "" {
			replacement = "."
		}
		return strings.Join([]string{
			order, preference, quoteDNSString(field("naptr_flags")), quoteDNSString(field("naptr_services")),
			quoteDNSString(field("naptr_regexp")), replacement,
		}, " "), nil
	case "SOA":
		primaryNS, err := required("primary_ns", "primary name server")
		if err != nil {
			return "", err
		}
		normalizedNS, err := dnsname.Normalize(primaryNS)
		if err != nil {
			return "", fmt.Errorf("primary name server: %w", err)
		}
		responsible, err := soaResponsibleName(field("responsible"))
		if err != nil {
			return "", err
		}
		serial, err := unsigned("serial", "serial", "1", 32)
		if err != nil {
			return "", err
		}
		refresh, err := unsigned("refresh", "refresh", "3600", 32)
		if err != nil {
			return "", err
		}
		retry, err := unsigned("retry", "retry", "600", 32)
		if err != nil {
			return "", err
		}
		expire, err := unsigned("expire", "expire", "1209600", 32)
		if err != nil {
			return "", err
		}
		minimum, err := unsigned("minimum", "minimum TTL", "300", 32)
		if err != nil {
			return "", err
		}
		return strings.Join([]string{dns.Fqdn(normalizedNS), responsible, serial, refresh, retry, expire, minimum}, " "), nil
	case "FWD":
		address, err := required("fwd_address", "forwarder address")
		if err != nil {
			return "", err
		}
		priority, err := unsigned("fwd_priority", "priority", "0", 16)
		if err != nil {
			return "", err
		}
		forwarder, err := forwarding.NewRecord(field("fwd_protocol"), priority, address)
		if err != nil {
			return "", err
		}
		return forwarder.String(), nil
	default:
		return required("value", "record value")
	}
}

func quoteDNSString(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

func zoneServiceParameters(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || !strings.Contains(value, "|") {
		return value, nil
	}
	parts := strings.Split(value, "|")
	if len(parts)%2 != 0 {
		return "", errors.New("service parameters must contain pipe-separated key and value pairs")
	}
	parameters := make([]string, 0, len(parts)/2)
	for index := 0; index < len(parts); index += 2 {
		key := strings.TrimSpace(parts[index])
		parameterValue := strings.TrimSpace(parts[index+1])
		if key == "" || parameterValue == "" {
			return "", errors.New("service parameter keys and values cannot be empty")
		}
		if key == "alpn" {
			parameterValue = quoteDNSString(parameterValue)
		}
		parameters = append(parameters, key+"="+parameterValue)
	}
	return strings.Join(parameters, " "), nil
}

func syncZoneNSGlue(zone *zonemodel.Zone, oldNameServer, newNameServer, addresses string) error {
	oldOwner, _ := relativeZoneOwner(zone.Name, oldNameServer)
	newOwner, inside := relativeZoneOwner(zone.Name, newNameServer)
	values := strings.FieldsFunc(addresses, func(character rune) bool {
		return character == ',' || character == ';' || character == ' ' || character == '\n' || character == '\t'
	})
	if len(values) > 0 && !inside {
		return errors.New("glue addresses can only be set for a name server inside this zone")
	}
	if oldOwner != "" {
		zone.Records = slices.DeleteFunc(zone.Records, func(record zonemodel.Record) bool {
			return record.Name == oldOwner && (record.Type == "A" || record.Type == "AAAA")
		})
	}
	seen := make(map[netip.Addr]struct{}, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return fmt.Errorf("glue address %q is invalid", value)
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		recordType := "AAAA"
		if address.Is4() {
			recordType = "A"
		}
		zone.Records = append(zone.Records, zonemodel.Record{
			Name: newOwner, Type: recordType, Value: address.String(), TTL: zone.DefaultTTL,
			Comments: "Glue record for " + strings.TrimSuffix(newNameServer, "."),
		})
	}
	return nil
}

func relativeZoneOwner(zoneName, target string) (string, bool) {
	target = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	if target == "" {
		return "", false
	}
	if target == zoneName {
		return "@", true
	}
	suffix := "." + zoneName
	if !strings.HasSuffix(target, suffix) {
		return "", false
	}
	return strings.TrimSuffix(target, suffix), true
}

func normalizeZoneRecordOwner(zoneName, owner string) string {
	owner = strings.TrimSpace(owner)
	if owner == "" || owner == "@" {
		return "@"
	}
	normalized := strings.TrimSuffix(strings.ToLower(owner), ".")
	if normalized == zoneName {
		return "@"
	}
	if suffix := "." + zoneName; strings.HasSuffix(normalized, suffix) {
		return strings.TrimSuffix(normalized, suffix)
	}
	return owner
}

func (server *Server) exportZone(writer http.ResponseWriter, request *http.Request) {
	name := normalizeZoneName(request.URL.Query().Get("zone"))
	zone := findZone(server.zones.Current().Zones, name)
	if zone == nil {
		http.Error(writer, "zone was not found", http.StatusNotFound)
		return
	}
	if !server.authorizeZoneRequest(request, auth.PermissionZonesExport, *zone) {
		http.Error(writer, "permission denied", http.StatusForbidden)
		return
	}
	writer.Header().Set("Content-Type", "text/dns; charset=utf-8")
	writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", zone.Name+".zone"))
	_, _ = fmt.Fprintf(writer, "$ORIGIN %s.\n$TTL %d\n", zone.Name, zone.DefaultTTL)
	for _, record := range zone.Records {
		_, _ = fmt.Fprintf(writer, "%s\t%d\tIN\t%s\t%s\n", record.Name, record.TTL, record.Type, record.Value)
	}
}

func (server *Server) zoneDS(writer http.ResponseWriter, request *http.Request) {
	name := normalizeZoneName(request.URL.Query().Get("zone"))
	requestedKeyTag, _ := strconv.ParseUint(strings.TrimSpace(request.URL.Query().Get("key_tag")), 10, 16)
	zone := findZone(server.zones.Current().Zones, name)
	if zone == nil {
		http.Error(writer, "zone was not found", http.StatusNotFound)
		return
	}
	if !server.authorizeZoneRequest(request, auth.PermissionZonesExport, *zone) {
		http.Error(writer, "permission denied", http.StatusForbidden)
		return
	}
	if requestedKeyTag == 0 && server.dnssec != nil && zone.DNSSEC {
		if status, err := server.dnssec.KeyStatus(request.Context(), *zone); err == nil {
			for _, key := range status.Keys {
				if key.Role == dnssecstate.RoleKSK && key.State == dnssecstate.StateActive {
					requestedKeyTag = uint64(key.KeyTag)
					break
				}
			}
		}
	}
	for _, record := range zone.Records {
		if record.Type != "DNSKEY" || !strings.HasPrefix(record.Comments, "sable:dnssec") {
			continue
		}
		rr, err := zoneRecordRR(*zone, record)
		if err != nil {
			continue
		}
		key, ok := rr.(*dns.DNSKEY)
		if !ok || key.Flags&dns.SEP == 0 || (requestedKeyTag != 0 && key.KeyTag() != uint16(requestedKeyTag)) {
			continue
		}
		ds := key.ToDS(dns.SHA256)
		if ds == nil {
			break
		}
		writer.Header().Set("Content-Type", "text/dns; charset=utf-8")
		writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", zone.Name+".ds"))
		_, _ = fmt.Fprintln(writer, ds.String())
		return
	}
	http.Error(writer, "zone is not signed by Sable", http.StatusNotFound)
}

func (server *Server) zoneDNSSECStatus(writer http.ResponseWriter, request *http.Request) {
	name := normalizeZoneName(request.URL.Query().Get("zone"))
	zone := findZone(server.zones.Current().Zones, name)
	if zone == nil {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "zone was not found"})
		return
	}
	if !server.authorizeZoneRequest(request, auth.PermissionZonesRead, *zone) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "permission denied"})
		return
	}
	if !zone.DNSSEC || server.dnssec == nil {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "zone is not managed by Sable DNSSEC"})
		return
	}
	status, err := server.dnssec.KeyStatus(request.Context(), *zone)
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusOK, status)
}

func (server *Server) importZone(writer http.ResponseWriter, request *http.Request) {
	zoneText, err := readZoneImportText(writer, request)
	selected := normalizeZoneName(request.FormValue("zone"))
	if err != nil {
		server.logZoneOperation(request, selected, err)
		server.renderZoneMutation(writer, request, http.StatusBadRequest, selected, "", err.Error())
		return
	}
	if err := server.authorizeZoneMutation(request); err != nil {
		server.logZoneOperation(request, selected, err)
		server.renderZoneMutation(writer, request, http.StatusForbidden, selected, "", err.Error())
		return
	}
	editor, ok := server.zones.(zoneEditor)
	if !ok {
		server.logZoneOperation(request, selected, errors.New("zone catalog is read-only"))
		server.renderZoneMutation(writer, request, http.StatusNotImplemented, selected, "", "This configuration source is read-only.")
		return
	}
	overwriteSets := request.FormValue("overwrite") == "true"
	overwriteZone := request.FormValue("overwrite_zone") == "true"
	overwriteSOASerial := request.FormValue("overwrite_soa_serial") == "true"
	var skippedAPPRecords []string
	err = editor.UpdateZones(request.Context(), func(zones *[]zonemodel.Zone) error {
		zone := findZone(*zones, selected)
		if zone == nil {
			return errors.New("zone was not found")
		}
		if !zoneRecordsEditable(zone.Type) {
			return errors.New("records synchronized from a primary server are read-only")
		}
		imported, skipped, err := parseZoneFile(*zone, strings.NewReader(zoneText))
		if err != nil {
			return err
		}
		skippedAPPRecords = skipped
		return mergeImportedRecords(zone, imported, overwriteSets, overwriteZone, overwriteSOASerial, time.Now())
	})
	if err != nil {
		server.logZoneOperation(request, selected, err)
		server.renderZoneMutation(writer, request, http.StatusUnprocessableEntity, selected, "", err.Error())
		return
	}
	server.logZoneOperation(request, selected, nil)
	server.auditZoneMutation(request, selected)
	server.notifyZoneChange(request.Context(), selected)
	message := zoneImportMessage("Records imported into "+selected, skippedAPPRecords)
	server.renderZoneMutation(writer, request, http.StatusOK, selected, message, "")
}

func (server *Server) importNewZone(writer http.ResponseWriter, request *http.Request) {
	zoneText, err := readZoneImportText(writer, request)
	if err != nil {
		server.logZoneOperation(request, "", err)
		server.renderZoneMutation(writer, request, http.StatusBadRequest, "", "", err.Error())
		return
	}
	if err := server.authorizeZoneMutation(request); err != nil {
		server.logZoneOperation(request, "", err)
		server.renderZoneMutation(writer, request, http.StatusForbidden, "", "", err.Error())
		return
	}
	editor, ok := server.zones.(zoneEditor)
	if !ok {
		server.logZoneOperation(request, "", errors.New("zone catalog is read-only"))
		server.renderZoneMutation(writer, request, http.StatusNotImplemented, "", "", "This configuration source is read-only.")
		return
	}
	selected := ""
	var skippedAPPRecords []string
	err = editor.UpdateZones(request.Context(), func(zones *[]zonemodel.Zone) error {
		name, err := importedZoneName(request.FormValue("zone"), zoneText)
		if err != nil {
			return err
		}
		selected = name
		if slices.ContainsFunc(*zones, func(zone zonemodel.Zone) bool { return zone.Name == name }) {
			return errors.New("zone already exists")
		}
		zone := zonemodel.Zone{Name: name, Type: "primary", DefaultTTL: defaultZoneTTL}
		imported, skipped, err := parseZoneFile(zone, strings.NewReader(zoneText))
		if err != nil {
			return err
		}
		skippedAPPRecords = skipped
		for _, record := range imported {
			if record.Name == "@" && record.Type == "SOA" && record.TTL > 0 {
				zone.DefaultTTL = record.TTL
				break
			}
		}
		if err := mergeImportedRecords(&zone, imported, false, true, true, time.Now()); err != nil {
			return err
		}
		*zones = append(*zones, zone)
		return nil
	})
	if err != nil {
		server.logZoneOperation(request, selected, err)
		server.renderZoneMutation(writer, request, http.StatusUnprocessableEntity, selected, "", err.Error())
		return
	}
	server.logZoneOperation(request, selected, nil)
	server.auditZoneMutation(request, selected)
	server.notifyZoneChange(request.Context(), selected)
	message := zoneImportMessage("Zone "+selected+" imported", skippedAPPRecords)
	server.renderZoneMutation(writer, request, http.StatusOK, selected, message, "")
}

func readZoneImportText(writer http.ResponseWriter, request *http.Request) (string, error) {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumZoneImportBytes+maximumFormBytes)
	if err := request.ParseMultipartForm(maximumZoneImportBytes); err != nil {
		return "", errors.New("the zone file is too large or invalid")
	}
	zoneText := strings.TrimSpace(request.FormValue("zone_text"))
	if zoneText != "" {
		return zoneText, nil
	}
	file, _, err := request.FormFile("file")
	if err != nil {
		return "", errors.New("paste or select a zone file to import")
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maximumZoneImportBytes+1))
	if err != nil || len(contents) > maximumZoneImportBytes {
		return "", errors.New("the selected zone file could not be read")
	}
	zoneText = strings.TrimSpace(string(contents))
	if zoneText == "" {
		return "", errors.New("the selected zone file is empty")
	}
	return zoneText, nil
}

func importedZoneName(supplied, contents string) (string, error) {
	candidate := strings.TrimSpace(supplied)
	if candidate == "" {
		for _, line := range strings.Split(contents, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.EqualFold(fields[0], "$ORIGIN") {
				candidate = fields[1]
				break
			}
		}
	}
	if candidate == "" {
		filtered, _ := filterTechnitiumAPPRecords(contents)
		parser := dns.NewZoneParser(strings.NewReader(filtered), ".", "zone import")
		parser.SetDefaultTTL(defaultZoneTTL)
		parser.SetIncludeAllowed(false)
		for record, ok := parser.Next(); ok; record, ok = parser.Next() {
			if record.Header().Rrtype == dns.TypeSOA {
				candidate = record.Header().Name
				break
			}
		}
	}
	if candidate == "" || candidate == "." || candidate == "@" {
		return "", errors.New("zone name could not be inferred; enter a Zone Name or include $ORIGIN in the file")
	}
	name, err := dnsname.Normalize(strings.TrimSuffix(candidate, "."))
	if err != nil {
		return "", fmt.Errorf("zone name: %w", err)
	}
	return name, nil
}

func zoneImportMessage(base string, skippedAPPRecords []string) string {
	if len(skippedAPPRecords) == 0 {
		return base
	}
	recordLabel := "records"
	if len(skippedAPPRecords) == 1 {
		recordLabel = "record"
	}
	return base + fmt.Sprintf("; skipped %d unsupported Technitium APP %s (%s)", len(skippedAPPRecords), recordLabel, strings.Join(skippedAPPRecords, ", "))
}

func parseZoneFile(zone zonemodel.Zone, reader io.Reader) ([]zonemodel.Record, []string, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, maximumZoneImportBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read zone file: %w", err)
	}
	if len(contents) > maximumZoneImportBytes {
		return nil, nil, errors.New("the zone file is too large")
	}
	filtered, skippedAPPRecords, customForwarders := filterTechnitiumZoneRecords(string(contents), zone)
	parser := dns.NewZoneParser(strings.NewReader(filtered), dns.Fqdn(zone.Name), "zone import")
	parser.SetDefaultTTL(zone.DefaultTTL)
	parser.SetIncludeAllowed(false)
	records := make([]zonemodel.Record, 0, 32)
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		header := rr.Header()
		if header.Class != dns.ClassINET {
			return nil, nil, fmt.Errorf("record %q must use the IN class", header.Name)
		}
		owner := strings.TrimSuffix(strings.ToLower(header.Name), ".")
		name := "@"
		if owner != zone.Name {
			suffix := "." + zone.Name
			if !strings.HasSuffix(owner, suffix) {
				return nil, nil, fmt.Errorf("record owner %q is outside zone %q", header.Name, zone.Name)
			}
			name = strings.TrimSuffix(owner, suffix)
		}
		value, err := zoneFileRecordValue(rr)
		if err != nil {
			return nil, nil, err
		}
		comment := strings.TrimSpace(strings.TrimPrefix(parser.Comment(), ";"))
		records = append(records, zonemodel.Record{
			Name: name, Type: dns.TypeToString[header.Rrtype], Value: value, TTL: header.Ttl, Comments: comment,
		})
	}
	if err := parser.Err(); err != nil {
		return nil, nil, fmt.Errorf("parse zone file: %w", err)
	}
	for _, record := range customForwarders {
		if _, err := forwarding.ParseRecord(record.Value); err != nil {
			return nil, nil, fmt.Errorf("invalid imported FWD record for %q: %w", record.Name, err)
		}
		records = append(records, record)
	}
	if len(records) == 0 {
		return nil, nil, errors.New("the zone file did not contain any supported records")
	}
	return records, skippedAPPRecords, nil
}

func filterTechnitiumAPPRecords(contents string) (string, []string) {
	filtered, skipped, _ := filterTechnitiumZoneRecords(contents, zonemodel.Zone{DefaultTTL: defaultZoneTTL})
	return filtered, skipped
}

func filterTechnitiumZoneRecords(contents string, zone zonemodel.Zone) (string, []string, []zonemodel.Record) {
	var filtered strings.Builder
	skipped := make([]string, 0, 2)
	forwarders := make([]zonemodel.Record, 0, 2)
	for _, line := range strings.SplitAfter(contents, "\n") {
		recordText, comment, _ := strings.Cut(line, ";")
		fields := strings.Fields(recordText)
		customField := -1
		for index := 1; len(fields) > 0 && !strings.HasPrefix(fields[0], "$") && index < len(fields) && index <= 3; index++ {
			if (strings.EqualFold(fields[index], "APP") || strings.EqualFold(fields[index], "FWD")) && zoneRecordPreamble(fields[1:index]) {
				customField = index
				break
			}
		}
		if customField >= 0 {
			if strings.EqualFold(fields[customField], "APP") {
				skipped = append(skipped, strings.TrimSuffix(fields[0], "."))
			} else {
				ttl := zone.DefaultTTL
				for _, field := range fields[1:customField] {
					if parsed, err := strconv.ParseUint(field, 10, 32); err == nil {
						ttl = uint32(parsed)
					}
				}
				forwarders = append(forwarders, zonemodel.Record{
					Name: normalizeZoneRecordOwner(zone.Name, fields[0]), Type: "FWD",
					Value: strings.Join(fields[customField+1:], " "), TTL: ttl,
					Comments: strings.TrimSpace(comment),
				})
			}
			if strings.HasSuffix(line, "\n") {
				filtered.WriteByte('\n')
			}
			continue
		}
		filtered.WriteString(line)
	}
	return filtered.String(), skipped, forwarders
}

func zoneRecordPreamble(fields []string) bool {
	for _, field := range fields {
		if _, found := dns.StringToClass[strings.ToUpper(field)]; found {
			continue
		}
		if _, err := strconv.ParseUint(field, 10, 32); err == nil {
			continue
		}
		return false
	}
	return true
}

func zoneFileRecordValue(record dns.RR) (string, error) {
	parts := strings.SplitN(record.String(), "\t", 5)
	if len(parts) == 5 {
		return strings.TrimSpace(parts[4]), nil
	}
	fields := strings.Fields(record.String())
	if len(fields) < 5 {
		return "", fmt.Errorf("could not render imported %s record", dns.TypeToString[record.Header().Rrtype])
	}
	return strings.Join(fields[4:], " "), nil
}

func mergeImportedRecords(zone *zonemodel.Zone, imported []zonemodel.Record, overwriteSets, overwriteZone, overwriteSOASerial bool, now time.Time) error {
	currentSerial := uint32(0)
	for _, record := range zone.Records {
		if record.Name == "@" && record.Type == "SOA" {
			currentSerial = zoneRecordSOASerial(record.Value)
			break
		}
	}
	importedSOA := -1
	for index, record := range imported {
		if record.Name == "@" && record.Type == "SOA" {
			if importedSOA >= 0 {
				return errors.New("the zone file contains more than one apex SOA record")
			}
			importedSOA = index
		}
	}
	if overwriteZone && importedSOA < 0 {
		return errors.New("overwriting the entire zone requires an apex SOA record")
	}
	if overwriteZone && zone.Type == "forwarder" && !slices.ContainsFunc(imported, func(record zonemodel.Record) bool {
		return record.Name == "@" && record.Type == "FWD"
	}) {
		return errors.New("overwriting a forwarder zone requires an apex FWD record")
	}
	if overwriteZone && zone.Type != "forwarder" && !slices.ContainsFunc(imported, func(record zonemodel.Record) bool {
		return record.Name == "@" && record.Type == "NS"
	}) {
		return errors.New("overwriting the entire zone requires an apex NS record")
	}
	if !overwriteSOASerial && currentSerial != 0 {
		for index := range imported {
			if imported[index].Name == "@" && imported[index].Type == "SOA" {
				imported[index].Value = replaceZoneRecordSOASerial(imported[index].Value, currentSerial)
			}
		}
	}
	merged := append([]zonemodel.Record(nil), zone.Records...)
	if overwriteZone {
		merged = nil
	} else if overwriteSets {
		sets := make(map[string]struct{}, len(imported))
		for _, record := range imported {
			sets[record.Name+"\x00"+record.Type] = struct{}{}
		}
		merged = slices.DeleteFunc(merged, func(record zonemodel.Record) bool {
			_, replace := sets[record.Name+"\x00"+record.Type]
			return replace
		})
	}
	for index, record := range imported {
		if !overwriteZone && !overwriteSets && index == importedSOA && currentSerial != 0 {
			if overwriteSOASerial {
				importedSerial := zoneRecordSOASerial(record.Value)
				for mergedIndex := range merged {
					if merged[mergedIndex].Name == "@" && merged[mergedIndex].Type == "SOA" {
						merged[mergedIndex].Value = replaceZoneRecordSOASerial(merged[mergedIndex].Value, importedSerial)
						break
					}
				}
			}
			continue
		}
		duplicate := slices.ContainsFunc(merged, func(existing zonemodel.Record) bool {
			return existing.Name == record.Name && existing.Type == record.Type && existing.Value == record.Value && existing.TTL == record.TTL
		})
		if !duplicate {
			merged = append(merged, record)
		}
	}
	zone.Records = merged
	// Only the names the import wrote are checked, so a conflict that predates
	// this import never blocks records elsewhere in the zone.
	checked := make(map[string]struct{}, len(imported))
	for _, record := range imported {
		if _, done := checked[record.Name]; done {
			continue
		}
		checked[record.Name] = struct{}{}
		if err := zonemodel.CheckCNAMEExclusivity(*zone, record.Name, now); err != nil {
			return err
		}
	}
	if !overwriteSOASerial || importedSOA < 0 {
		advanceSOASerial(zone, now)
	}
	return nil
}

func zoneRecordSOASerial(value string) uint32 {
	fields := strings.Fields(value)
	if len(fields) != 7 {
		return 0
	}
	serial, _ := strconv.ParseUint(fields[2], 10, 32)
	return uint32(serial)
}

func replaceZoneRecordSOASerial(value string, serial uint32) string {
	fields := strings.Fields(value)
	if len(fields) != 7 {
		return value
	}
	fields[2] = strconv.FormatUint(uint64(serial), 10)
	return strings.Join(fields, " ")
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

func formTTL(value string, fallback uint32) (uint32, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == 0 {
		return 0, errors.New("TTL must be a positive integer")
	}
	return uint32(parsed), nil
}

func formExpiry(value string, now time.Time) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" {
		return time.Time{}, nil
	}
	seconds, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return time.Time{}, errors.New("auto-expire must be a non-negative number of seconds")
	}
	return now.Add(time.Duration(seconds) * time.Second).UTC(), nil
}

func soaResponsibleName(value string) (string, error) {
	return zonemodel.ResponsibleName(value)
}

func advanceSOASerial(zone *zonemodel.Zone, now time.Time) {
	zonemodel.AdvanceSerial(zone, now)
}

func nextSOASerial(current uint32, now time.Time) uint32 {
	return zonemodel.NextSerial(current, now)
}

// recordSourceEditable refuses edits to records an integration owns. The next
// synchronization would revert the change, so failing loudly here is kinder
// than letting the edit disappear a minute later.
func recordSourceEditable(record zonemodel.Record) error {
	if record.Source == "" {
		return nil
	}
	return fmt.Errorf("this record is published by %s synchronization; change it in Integrations or in UniFi", zoneRecordSourceLabel(record.Source))
}
