package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/forwarding"
	"github.com/drudge/sable/internal/web/pages"
	zonemodel "github.com/drudge/sable/internal/zone"
)

func (server *Server) updateZones(
	writer http.ResponseWriter,
	request *http.Request,
	selected *string,
	success string,
	mutate func(*[]zonemodel.Zone) error,
) {
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

// authorizeZoneMutation checks the permissions the route declares for its
// zone change, against the exact zone the form names. A route that declares
// none is refused.
func (server *Server) authorizeZoneMutation(request *http.Request) error {
	if !server.securityEnabled {
		return nil
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	var mutation zoneMutation
	if current := requestRoute(request); current != nil {
		mutation = current.zone
	}
	if !mutation.create && len(mutation.perms) == 0 {
		return auth.ErrForbidden
	}
	if mutation.create && !auth.Authorize(principal, auth.PermissionZonesCreate, "", "") {
		return auth.ErrForbidden
	}
	permissions := mutation.perms
	if mutation.action == "zone.convert_primary" && request.FormValue("final_sync") == "true" {
		permissions = append([]string{auth.PermissionZonesTransfer}, permissions...)
	}
	for _, permission := range permissions {
		if err := server.authorizeExistingZone(principal, permission, request.FormValue("zone")); err != nil {
			return err
		}
	}
	return nil
}

func (server *Server) authorizeExistingZone(principal auth.Principal, permission, name string) error {
	current := findZone(server.zones.Current().Zones, normalizeZoneName(name))
	if current == nil || !auth.Authorize(principal, permission, auth.ResourceZone, current.ID) {
		return auth.ErrForbidden
	}
	return nil
}

func (server *Server) logZoneOperation(request *http.Request, zoneName string, operationErr error) {
	server.logZoneChange(requestActor(request, ""), zoneMutationAction(request), zoneName, operationErr)
}

// zoneMutationAction names the zone change a request makes, as its route
// declares it, for the log and the audit trail.
func zoneMutationAction(request *http.Request) string {
	if current := requestRoute(request); current != nil && current.zone.action != "" {
		return current.zone.action
	}
	return "zone.update"
}

func (server *Server) auditZoneMutation(request *http.Request, zone string) {
	action, details := zoneMutationAction(request), "zone="+zone
	if action == "zone.rollback" {
		details += " revision=" + request.FormValue("revision")
	}
	server.recordControlPlaneAudit(request, action, details)
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
	if tokenRequest(request.URL.Path) {
		if errorMessage != "" {
			apiError(writer, status, errorMessage)
		} else {
			writeJSON(writer, status, map[string]any{"message": message, "zone": findZone(server.zones.Current().Zones, selected)})
		}
		return
	}
	if request.Header.Get("HX-Request") == "true" {
		pushURL := "/zones"
		if selected != "" {
			pushURL = zonePath(selected)
		}
		writer.Header().Set("HX-Push-Url", pushURL)
	}
	writeFragmentStatus(writer, status)
	server.render(writer, request, pages.ZonesContent(server.zonesView(request, message, errorMessage, selected)))
}

func (server *Server) addZone(writer http.ResponseWriter, request *http.Request) {
	if !server.parseZoneForm(writer, request) {
		return
	}
	input := zoneCreate{
		Name: request.FormValue("name"), Type: request.FormValue("type"),
		PrimaryNS: request.FormValue("primary_ns"), Responsible: request.FormValue("responsible"),
		TSIGKey: request.FormValue("tsig_key"), AliasZone: request.FormValue("alias_zone"),
		ForwarderProtocol: request.FormValue("forwarder_protocol"), ForwarderPriority: request.FormValue("forwarder_priority"),
		ForwarderAddress: request.FormValue("forwarder_address"),
		PrimaryProtocol:  request.FormValue("primary_protocol"), PrimaryServers: request.FormValue("primary_servers"),
	}
	if request.Form.Has("dnssec_validation_present") {
		validation := request.FormValue("dnssec_validation") == "true"
		input.DNSSECValidation = &validation
	}
	ttl, err := formTTL(request.FormValue("default_ttl"), 0)
	input.DefaultTTL = ttl
	selected := normalizeZoneName(input.Name)
	if err == nil {
		var created zonemodel.Zone
		created, err = server.zoneService().CreateZone(request.Context(), requestActor(request, ""), input)
		if err == nil {
			selected = created.Name
		}
	}
	server.renderZoneChange(writer, request, selected, "Authoritative zone created", err)
}

// parseZoneForm parses a console zone form, and answers the request itself
// when it cannot.
func (server *Server) parseZoneForm(writer http.ResponseWriter, request *http.Request) bool {
	if err := request.ParseForm(); err != nil {
		server.logZoneOperation(request, "", err)
		server.renderZoneMutation(writer, request, http.StatusBadRequest, "", "", "Invalid zone form.")
		return false
	}
	return true
}

// recordFormError prefers the reason the zone refuses record changes to a
// problem reading the record form.
func (server *Server) recordFormError(request *http.Request, zoneName string, formErr error) error {
	if err := server.zoneService().RecordsWritable(requestActor(request, ""), zoneName); err != nil {
		return err
	}
	return formErr
}

// renderZoneChange shows the zone after a change the zone service made.
func (server *Server) renderZoneChange(writer http.ResponseWriter, request *http.Request, selected, message string, err error) {
	if err != nil {
		server.renderZoneMutation(writer, request, serviceStatus(err), selected, "", sentence(err.Error()))
		return
	}
	server.renderZoneMutation(writer, request, http.StatusOK, selected, message, "")
}

// newZoneSOA is the SOA record every new zone starts with.
func newZoneSOA(primaryNS, responsible string, ttl uint32, now time.Time) zonemodel.Record {
	return zonemodel.Record{Name: "@", Type: "SOA", TTL: ttl, Value: fmt.Sprintf(
		"%s %s %d 3600 600 1209600 %d", dns.Fqdn(primaryNS), responsible, nextSOASerial(0, now), ttl,
	)}
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
	if !server.parseZoneForm(writer, request) {
		return
	}
	_, err := server.zoneService().DeleteZone(request.Context(), requestActor(request, ""), request.FormValue("zone"))
	server.renderZoneChange(writer, request, "", "Authoritative zone deleted", err)
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
		zone.DynamicUpdates = zonemodel.AcceptsDynamicUpdates(zone.Type) && request.FormValue("dynamic_updates") == "true"
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
		if (zone.Type == "secondary" || zone.Type == zonemodel.TypeSecondaryForwarder || zone.Type == "stub" || zone.Type == "catalog") && request.Form.Has("primary_servers") {
			protocol := strings.ToLower(strings.TrimSpace(request.FormValue("primary_protocol")))
			if (zone.Type == "secondary" || zone.Type == zonemodel.TypeSecondaryForwarder || zone.Type == "catalog") && protocol != "tcp" && protocol != "tls" {
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
		if zone.Type != "secondary" && zone.Type != zonemodel.TypeSecondaryForwarder && zone.Type != "stub" {
			return errors.New("only secondary, secondary forwarder, and stub zones can be synchronized")
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
			candidate := *zone
			candidate.Records = configuredZoneRecords(records)
			if candidate.Type == zonemodel.TypeSecondaryForwarder {
				if err := zonemodel.PrepareTransferredForwarder(&candidate, true); err != nil {
					return err
				}
			}
			*zone = candidate
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
	if !server.parseZoneForm(writer, request) {
		return
	}
	zoneName := normalizeZoneName(request.FormValue("zone"))
	input, err := consoleRecordInput(request)
	if err != nil {
		err = server.recordFormError(request, zoneName, err)
	} else {
		var result recordChange
		result, err = server.zoneService().AddRecord(request.Context(), requestActor(request, ""), zoneName, input)
		if err == nil && !result.Changed {
			err = errors.New("that record already exists")
		}
	}
	server.renderZoneChange(writer, request, zoneName, "Record added and SOA serial advanced", err)
}

func (server *Server) deleteZoneRecord(writer http.ResponseWriter, request *http.Request) {
	if !server.parseZoneForm(writer, request) {
		return
	}
	zoneName := normalizeZoneName(request.FormValue("zone"))
	key, err := consoleRecordKey(request)
	if err != nil {
		err = server.recordFormError(request, zoneName, err)
	} else {
		_, err = server.zoneService().DeleteRecord(request.Context(), requestActor(request, ""), zoneName, key)
	}
	server.renderZoneChange(writer, request, zoneName, "Record removed and SOA serial advanced", err)
}

func (server *Server) updateZoneRecord(writer http.ResponseWriter, request *http.Request) {
	if !server.parseZoneForm(writer, request) {
		return
	}
	zoneName := normalizeZoneName(request.FormValue("zone"))
	update, err := consoleRecordUpdate(request)
	if err != nil {
		err = server.recordFormError(request, zoneName, err)
	} else {
		_, err = server.zoneService().UpdateRecord(request.Context(), requestActor(request, ""), zoneName, update)
	}
	server.renderZoneChange(writer, request, zoneName, "Record updated", err)
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
