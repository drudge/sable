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
	"github.com/drudge/sable/internal/forwarding"
	zonemodel "github.com/drudge/sable/internal/zone"
)

// zoneService makes zone and record changes for every caller. The console
// handlers and the MCP tools are thin adapters over it, so normalization,
// authorization, the replica check, the SOA serial, the audit trail, and
// NOTIFY happen the same way whichever one asked.
type zoneService struct{ server *Server }

func (server *Server) zoneService() zoneService { return zoneService{server} }

// actor is who asked for a change and through which surface, for
// authorization, the log, and the audit trail.
type actor struct {
	principal auth.Principal
	clientIP  string
	userAgent string
	via       string
}

func requestActor(request *http.Request, via string) actor {
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	return actor{principal: principal, clientIP: requestClientIP(request), userAgent: request.UserAgent(), via: via}
}

// audit is the one place a control-plane change reaches the audit trail.
func (server *Server) audit(ctx context.Context, who actor, action, details string) {
	recorder, ok := server.queries.(interface {
		RecordAuditEvent(context.Context, auth.AuditEvent) error
	})
	if !ok {
		return
	}
	if who.via != "" {
		details += " via=" + who.via
	}
	event := auth.AuditEvent{
		OccurredAt: time.Now(), Action: action, ClientIP: who.clientIP,
		UserAgent: who.userAgent, Details: details,
	}
	if who.principal.UserID != 0 {
		userID := who.principal.UserID
		event.UserID = &userID
	}
	if err := recorder.RecordAuditEvent(ctx, event); err != nil {
		server.logger.Warn("record audit event", "action", action, "error", err)
	}
}

func (server *Server) logZoneChange(who actor, action, zoneName string, operationErr error) {
	attributes := []any{"operation", action, "zone", zoneName, "client", who.clientIP}
	if who.via != "" {
		attributes = append(attributes, "via", who.via)
	}
	if operationErr != nil {
		server.logger.Warn("zone operation failed", append(attributes, "error", operationErr)...)
		return
	}
	server.logger.Info("zone operation completed", attributes...)
}

// serviceError is a refusal the caller shows as it is. status is the HTTP
// status the console answers with.
type serviceError struct {
	status  int
	message string
}

func (err *serviceError) Error() string { return err.message }

// missingRecordError is a record a change named that does not exist.
type missingRecordError struct{ message string }

func (err *missingRecordError) Error() string { return err.message }

func refuse(status int, format string, arguments ...any) error {
	return &serviceError{status: status, message: fmt.Sprintf(format, arguments...)}
}

// serviceStatus is the HTTP status for an error a service returned. Anything
// that is not a refusal is a change the zone or policy rules rejected.
func serviceStatus(err error) int {
	var refusal *serviceError
	if errors.As(err, &refusal) {
		return refusal.status
	}
	if missing := (*missingRecordError)(nil); errors.As(err, &missing) {
		return http.StatusNotFound
	}
	return http.StatusUnprocessableEntity
}

// authorized checks one permission, against a zone when one is given.
func (server *Server) authorized(who actor, permission string, zone *zonemodel.Zone) bool {
	if !server.securityEnabled {
		return true
	}
	if zone == nil {
		return auth.Authorize(who.principal, permission, "", "")
	}
	return auth.Authorize(who.principal, permission, auth.ResourceZone, zone.ID)
}

func (server *Server) refuseOnReplica() error {
	if server.mcpReplica() {
		return refuse(http.StatusForbidden, "%s", replicaWriteMessage)
	}
	return nil
}

func (server *Server) editableZones() (zoneEditor, error) {
	editor, ok := server.zones.(zoneEditor)
	if !ok {
		return nil, refuse(http.StatusNotImplemented, "this configuration source is read-only")
	}
	return editor, nil
}

// zoneFor finds the zone a change names and checks that who may make it. A
// zone they can neither change nor read answers exactly like a missing one,
// so a scoped token cannot probe for zone names.
func (service zoneService) zoneFor(who actor, name, permission string) (zonemodel.Zone, error) {
	server := service.server
	if err := server.refuseOnReplica(); err != nil {
		return zonemodel.Zone{}, err
	}
	normalized := normalizeZoneName(name)
	if normalized == "" {
		return zonemodel.Zone{}, refuse(http.StatusBadRequest, "zone is required")
	}
	current := findZone(server.zones.Current().Zones, normalized)
	if current != nil && server.authorized(who, permission, current) {
		return *current, nil
	}
	if current == nil || !server.authorized(who, auth.PermissionZonesRead, current) {
		return zonemodel.Zone{}, refuse(http.StatusNotFound, "zone %s was not found", normalized)
	}
	return zonemodel.Zone{}, refuse(http.StatusForbidden, "you need %s for zone %s", permission, normalized)
}

// finish logs a zone change and, when it changed something, audits it and
// notifies secondaries.
func (service zoneService) finish(ctx context.Context, who actor, action, zoneName string, changed bool, err error) {
	service.server.logZoneChange(who, action, zoneName, err)
	if err != nil || !changed {
		return
	}
	service.server.audit(ctx, who, action, "zone="+zoneName)
	service.server.notifyZoneChange(ctx, zoneName)
}

// zoneCreate is a new zone. Empty fields take the defaults every caller
// shares: ns1.<zone>, hostmaster@<zone>, and a five-minute TTL.
type zoneCreate struct {
	Name        string
	Type        string
	PrimaryNS   string
	Responsible string
	DefaultTTL  uint32
	TSIGKey     string
	// DNSSECValidation applies to forwarder and stub zones; nil keeps the
	// server-wide setting.
	DNSSECValidation  *bool
	AliasZone         string
	ForwarderProtocol string
	ForwarderPriority string
	ForwarderAddress  string
	PrimaryProtocol   string
	PrimaryServers    string
}

func (service zoneService) CreateZone(ctx context.Context, who actor, input zoneCreate) (zonemodel.Zone, error) {
	server := service.server
	if err := server.refuseOnReplica(); err != nil {
		return zonemodel.Zone{}, err
	}
	if !server.authorized(who, auth.PermissionZonesCreate, nil) {
		return zonemodel.Zone{}, refuse(http.StatusForbidden, "you need %s to create zones", auth.PermissionZonesCreate)
	}
	editor, err := server.editableZones()
	if err != nil {
		return zonemodel.Zone{}, err
	}
	name, err := dnsname.Normalize(input.Name)
	if err != nil {
		return zonemodel.Zone{}, fmt.Errorf("zone name: %w", err)
	}
	var created zonemodel.Zone
	err = editor.UpdateZones(ctx, func(zones *[]zonemodel.Zone) error {
		if findZone(*zones, name) != nil {
			return fmt.Errorf("zone %s already exists", name)
		}
		zone, err := service.newZone(ctx, *zones, name, input)
		if err != nil {
			return err
		}
		created = zone
		*zones = append(*zones, zone)
		return nil
	})
	service.finish(ctx, who, "zone.create", name, true, err)
	if err != nil {
		return zonemodel.Zone{}, err
	}
	if active := findZone(server.zones.Current().Zones, name); active != nil {
		created = *active
	}
	return created, nil
}

func (service zoneService) newZone(ctx context.Context, zones []zonemodel.Zone, name string, input zoneCreate) (zonemodel.Zone, error) {
	zoneType := strings.ToLower(strings.TrimSpace(input.Type))
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
		return zonemodel.Zone{}, errors.New("unsupported zone type")
	}
	primaryNSValue := strings.TrimSpace(input.PrimaryNS)
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
		return zonemodel.Zone{}, fmt.Errorf("primary name server: %w", err)
	}
	responsibleValue := strings.TrimSpace(input.Responsible)
	if responsibleValue == "" {
		responsibleValue = "hostmaster@" + name
	}
	responsible, err := soaResponsibleName(responsibleValue)
	if err != nil {
		return zonemodel.Zone{}, err
	}
	ttl := input.DefaultTTL
	if ttl == 0 {
		ttl = defaultZoneTTL
	}
	zone := zonemodel.Zone{Name: name, Type: zoneType, DefaultTTL: ttl, TSIGKey: strings.TrimSpace(input.TSIGKey)}
	if (zoneType == "forwarder" || zoneType == "stub") && input.DNSSECValidation != nil {
		zone.DNSSECValidationDisabled = !*input.DNSSECValidation
	}
	soa := newZoneSOA(primaryNS, responsible, ttl, time.Now())
	apexNS := zonemodel.Record{Name: "@", Type: "NS", TTL: ttl, Value: dns.Fqdn(primaryNS)}
	switch zoneType {
	case "primary":
		zone.Records = []zonemodel.Record{soa, apexNS}
	case "alias":
		source, err := aliasSourceZone(zones, input.AliasZone, name)
		if err != nil {
			return zonemodel.Zone{}, err
		}
		zone.AliasZone = source
		// The mirrored records, including the apex NS set, are filled in
		// when the catalog reconciles this zone against its source.
		zone.Records = []zonemodel.Record{soa}
	case "forwarder":
		protocol := strings.ToLower(strings.TrimSpace(input.ForwarderProtocol))
		if protocol == "" {
			protocol = "udp"
		}
		priority := strings.TrimSpace(input.ForwarderPriority)
		if priority == "" {
			priority = "0"
		}
		forwarder, err := forwarding.NewRecord(protocol, priority, input.ForwarderAddress)
		if err != nil {
			return zonemodel.Zone{}, fmt.Errorf("forwarder: %w", err)
		}
		zone.Records = []zonemodel.Record{soa, {Name: "@", Type: "FWD", TTL: ttl, Value: forwarder.String()}}
	case "catalog":
		zone.Records = []zonemodel.Record{soa, apexNS}
		if !consumeCatalog {
			break
		}
		// A subscribed catalog is transferred exactly like a secondary, so
		// its first transfer happens here and the operator sees a bad
		// address or a rejected TSIG key immediately.
		protocol := strings.ToLower(strings.TrimSpace(input.PrimaryProtocol))
		if protocol == "" {
			protocol = "tcp"
		}
		if protocol != "tcp" && protocol != "tls" {
			return zonemodel.Zone{}, errors.New("catalog zone transfer protocol must be TCP or DNS-over-TLS")
		}
		if err := service.transferNewZone(ctx, &zone, protocol, input.PrimaryServers); err != nil {
			return zonemodel.Zone{}, err
		}
		if _, err := zonemodel.ParseCatalog(name, zone.Records); err != nil {
			return zonemodel.Zone{}, fmt.Errorf("the transferred zone is not a usable catalog: %w", err)
		}
	case "secondary", "stub":
		protocol := strings.ToLower(strings.TrimSpace(input.PrimaryProtocol))
		if protocol == "" {
			protocol = "tcp"
			if zoneType == "stub" {
				protocol = "udp"
			}
		}
		if zoneType == "secondary" && protocol != "tcp" && protocol != "tls" {
			return zonemodel.Zone{}, errors.New("secondary zone transfer protocol must be TCP or DNS-over-TLS")
		}
		if zoneType == "stub" && protocol != "udp" && protocol != "tcp" && protocol != "tls" {
			return zonemodel.Zone{}, errors.New("stub zone primary protocol must be UDP, TCP, or DNS-over-TLS")
		}
		if err := service.transferNewZone(ctx, &zone, protocol, input.PrimaryServers); err != nil {
			return zonemodel.Zone{}, err
		}
	}
	return zone, nil
}

// transferNewZone fills a new secondary, stub, or subscribed catalog zone
// from its primary servers.
func (service zoneService) transferNewZone(ctx context.Context, zone *zonemodel.Zone, protocol, servers string) error {
	primaries, err := normalizeZonePrimaryServers(servers, protocol)
	if err != nil {
		return err
	}
	synchronizer, ok := any(service.server.stats).(zoneSynchronizer)
	if !ok {
		return errors.New("zone synchronization is unavailable")
	}
	transferred, err := synchronizer.FetchZone(ctx, zone.Name, zone.Type, primaries, protocol, zone.TSIGKey)
	if err != nil {
		return err
	}
	zone.PrimaryServers, zone.PrimaryProtocol = primaries, protocol
	zone.Records = configuredZoneRecords(transferred)
	return nil
}

func (service zoneService) DeleteZone(ctx context.Context, who actor, name string) (zonemodel.Zone, error) {
	current, err := service.zoneFor(who, name, auth.PermissionZonesDelete)
	if err != nil {
		return zonemodel.Zone{}, err
	}
	editor, err := service.server.editableZones()
	if err != nil {
		return zonemodel.Zone{}, err
	}
	err = editor.UpdateZones(ctx, func(zones *[]zonemodel.Zone) error {
		index := slices.IndexFunc(*zones, func(zone zonemodel.Zone) bool { return zone.Name == current.Name })
		// The zone ID pins the delete to the zone that was checked.
		if index < 0 || (*zones)[index].ID != current.ID {
			return refuse(http.StatusNotFound, "zone %s was not found", current.Name)
		}
		*zones = slices.Delete(*zones, index, index+1)
		return nil
	})
	service.finish(ctx, who, "zone.delete", current.Name, true, err)
	return current, err
}

// recordChange is what a record change did. Kept holds the records a set or
// an unchanged update left in place.
type recordChange struct {
	Zone    string
	Changed bool
	Serial  uint32
	Added   []zonemodel.Record
	Removed []zonemodel.Record
	Kept    []zonemodel.Record
}

// recordInput is a record to add. An empty name is the apex and a zero TTL
// is the zone default.
type recordInput struct {
	Name      string
	Type      string
	Value     string
	TTL       uint32
	Comment   string
	ExpiresAt time.Time
	// Glue holds the in-zone addresses of a new NS record's name server; nil
	// leaves glue alone.
	Glue *string
}

// recordKey names an existing record. Names and values match the way DNS
// compares them, so "www", "WWW.example.com." and "www.example.com" are the
// same owner. TTL is not part of a record's identity, but a nonzero TTL
// chooses between records that differ only in it.
type recordKey struct {
	Name  string
	Type  string
	Value string
	TTL   uint32
}

// recordUpdate changes the fields that are set. A zero TTL is the zone
// default.
type recordUpdate struct {
	Key       recordKey
	Name      *string
	Value     *string
	TTL       *uint32
	Comment   *string
	Enabled   *bool
	ExpiresAt *time.Time
	// Glue replaces the glue of an NS record's in-zone name server; nil
	// leaves it alone.
	Glue *string
}

// recordSet is the whole set of one type at one owner.
type recordSet struct {
	Name    string
	Type    string
	Values  []string
	TTL     uint32
	Comment string
}

func (service zoneService) AddRecord(ctx context.Context, who actor, zoneName string, input recordInput) (recordChange, error) {
	var added zonemodel.Record
	result, err := service.changeRecords(ctx, who, zoneName, "zone.record.create", func(zone *zonemodel.Zone) (bool, error) {
		record, err := newRecord(*zone, input)
		if err != nil {
			return false, err
		}
		added = record
		if index := slices.IndexFunc(zone.Records, func(existing zonemodel.Record) bool { return sameRecord(*zone, existing, record) }); index >= 0 {
			if zone.Records[index].Disabled {
				return false, errors.New("that record exists but is disabled; enable it instead")
			}
			return false, nil
		}
		zone.Records = append(zone.Records, record)
		if err := zonemodel.CheckCNAMEExclusivity(*zone, record.Name, time.Now()); err != nil {
			return false, err
		}
		if record.Type == "NS" && input.Glue != nil {
			if err := syncZoneNSGlue(zone, "", record.Value, *input.Glue); err != nil {
				return false, err
			}
		}
		return true, nil
	})
	if err == nil && result.Changed {
		result.Added = []zonemodel.Record{added}
	}
	return result, err
}

func (service zoneService) SetRecords(ctx context.Context, who actor, zoneName string, input recordSet) (recordChange, error) {
	if len(input.Values) == 0 {
		return recordChange{}, refuse(http.StatusBadRequest, "a record set needs at least one value; delete the records to remove them")
	}
	var added, removed, kept []zonemodel.Record
	result, err := service.changeRecords(ctx, who, zoneName, "zone.record.set", func(zone *zonemodel.Zone) (bool, error) {
		desired := make([]zonemodel.Record, 0, len(input.Values))
		for _, value := range input.Values {
			record, err := newRecord(*zone, recordInput{Name: input.Name, Type: input.Type, Value: value, TTL: input.TTL, Comment: input.Comment})
			if err != nil {
				return false, err
			}
			if !slices.ContainsFunc(desired, func(other zonemodel.Record) bool { return sameRecord(*zone, other, record) }) {
				desired = append(desired, record)
			}
		}
		if desired[0].Type == "CNAME" && len(desired) > 1 {
			return false, errors.New("a CNAME record set holds exactly one value")
		}
		owner := ownerFQDN(zone.Name, desired[0].Name)
		changed := false
		next := make([]zonemodel.Record, 0, len(zone.Records)+len(desired))
		matched := make([]bool, len(desired))
		for _, existing := range zone.Records {
			if existing.Type != desired[0].Type || ownerFQDN(zone.Name, existing.Name) != owner {
				next = append(next, existing)
				continue
			}
			if err := recordEditable(existing); err != nil {
				return false, err
			}
			index := slices.IndexFunc(desired, func(record zonemodel.Record) bool { return sameRecord(*zone, existing, record) })
			if index < 0 || matched[index] {
				removed = append(removed, existing)
				changed = true
				continue
			}
			matched[index] = true
			if input.TTL != 0 && existing.TTL != input.TTL {
				existing.TTL = input.TTL
				changed = true
			}
			if existing.Disabled {
				existing.Disabled = false
				changed = true
			}
			kept = append(kept, existing)
			next = append(next, existing)
		}
		for index, record := range desired {
			if matched[index] {
				continue
			}
			added = append(added, record)
			next = append(next, record)
			changed = true
		}
		zone.Records = next
		if !changed {
			return false, nil
		}
		return true, zonemodel.CheckCNAMEExclusivity(*zone, desired[0].Name, time.Now())
	})
	result.Added, result.Removed, result.Kept = added, removed, kept
	return result, err
}

func (service zoneService) UpdateRecord(ctx context.Context, who actor, zoneName string, update recordUpdate) (recordChange, error) {
	var before, after zonemodel.Record
	result, err := service.changeRecords(ctx, who, zoneName, "zone.record.update", func(zone *zonemodel.Zone) (bool, error) {
		index, err := findRecord(*zone, update.Key)
		if err != nil {
			return false, err
		}
		original := slices.Clone(zone.Records)
		before = zone.Records[index]
		after = before
		if update.Name != nil {
			after.Name = storedOwner(zone.Name, *update.Name)
		}
		if after.Type == "SOA" && after.Name != "@" {
			return false, errors.New("the SOA record must remain at the zone apex")
		}
		if update.Value != nil {
			if after.Value, err = updatedRecordValue(zone.Name, after.Type, *update.Value); err != nil {
				return false, err
			}
		}
		if update.TTL != nil {
			after.TTL = *update.TTL
			if after.TTL == 0 {
				after.TTL = zone.DefaultTTL
			}
		}
		if update.Comment != nil {
			after.Comments = strings.TrimSpace(*update.Comment)
		}
		if update.Enabled != nil {
			after.Disabled = !*update.Enabled
		}
		if after.Type == "SOA" && after.Disabled {
			return false, errors.New("the zone SOA record cannot be disabled")
		}
		if update.ExpiresAt != nil {
			after.ExpiresAt = *update.ExpiresAt
		}
		if after != before {
			if _, err := zonemodel.ParseRecord(*zone, after); err != nil {
				return false, err
			}
			zone.Records[index] = after
			if after.Name != before.Name || after.Value != before.Value {
				for other, record := range zone.Records {
					if other != index && sameRecord(*zone, record, after) {
						return false, errors.New("another record already has that name and value")
					}
				}
			}
			if err := zonemodel.CheckCNAMEExclusivity(*zone, after.Name, time.Now()); err != nil {
				return false, err
			}
		}
		if after.Type == "NS" && update.Glue != nil {
			if err := syncZoneNSGlue(zone, before.Value, after.Value, *update.Glue); err != nil {
				return false, err
			}
		}
		return !slices.Equal(original, zone.Records), nil
	})
	if err != nil {
		return result, err
	}
	if result.Changed {
		result.Removed = []zonemodel.Record{before}
		result.Added = []zonemodel.Record{after}
	} else {
		result.Kept = []zonemodel.Record{before}
	}
	return result, nil
}

func (service zoneService) DeleteRecord(ctx context.Context, who actor, zoneName string, key recordKey) (recordChange, error) {
	if strings.EqualFold(strings.TrimSpace(key.Type), "SOA") {
		return recordChange{}, refuse(http.StatusUnprocessableEntity, "Sable manages the zone SOA record automatically, so it cannot be removed")
	}
	var removed zonemodel.Record
	result, err := service.changeRecords(ctx, who, zoneName, "zone.record.delete", func(zone *zonemodel.Zone) (bool, error) {
		index, err := findRecord(*zone, key)
		if err != nil {
			return false, err
		}
		removed = zone.Records[index]
		zone.Records = slices.Delete(zone.Records, index, index+1)
		return true, nil
	})
	if err == nil {
		result.Removed = []zonemodel.Record{removed}
	}
	return result, err
}

// RecordsWritable says why who cannot change records in a zone, or nil when
// they can. A caller that fails to read a record from its input asks this
// first, so the more basic reason wins.
func (service zoneService) RecordsWritable(who actor, zoneName string) error {
	_, err := service.recordsZone(who, zoneName)
	return err
}

func (service zoneService) recordsZone(who actor, zoneName string) (zonemodel.Zone, error) {
	current, err := service.zoneFor(who, zoneName, auth.PermissionZonesRecords)
	if err != nil {
		return zonemodel.Zone{}, err
	}
	if !zoneRecordsEditable(current.Type) {
		return zonemodel.Zone{}, refuse(http.StatusUnprocessableEntity,
			"zone %s is a %s zone, so its records are read-only; only Primary and Forwarder zones have editable records", current.Name, current.Type)
	}
	return current, nil
}

// changeRecords applies one record change: zone-scoped authorization, the
// zone manager's validation and persistence, an SOA serial bump, the audit
// log, and NOTIFY to secondaries. The mutation reports whether it changed
// anything, so a repeated call leaves the serial and the audit log alone.
func (service zoneService) changeRecords(
	ctx context.Context,
	who actor,
	zoneName, action string,
	mutate func(*zonemodel.Zone) (bool, error),
) (recordChange, error) {
	server := service.server
	current, err := service.recordsZone(who, zoneName)
	if err != nil {
		return recordChange{}, err
	}
	editor, err := server.editableZones()
	if err != nil {
		return recordChange{}, err
	}
	changed := false
	err = editor.UpdateZones(ctx, func(zones *[]zonemodel.Zone) error {
		zone := findZone(*zones, current.Name)
		// The zone ID pins authorization to the zone that was checked, even if
		// it was deleted and recreated under the same name in the meantime.
		if zone == nil || zone.ID != current.ID {
			return refuse(http.StatusNotFound, "zone %s was not found", current.Name)
		}
		soa := apexSOA(*zone)
		var mutateErr error
		changed, mutateErr = mutate(zone)
		if mutateErr != nil || !changed {
			return mutateErr
		}
		// An edit to the SOA itself keeps the serial the operator chose.
		if apexSOA(*zone) == soa {
			advanceSOASerial(zone, time.Now())
		}
		return nil
	})
	service.finish(ctx, who, action, current.Name, changed, err)
	if err != nil {
		return recordChange{}, err
	}
	result := recordChange{Zone: current.Name, Changed: changed}
	if updated := findZone(server.zones.Current().Zones, current.Name); updated != nil {
		result.Serial = zoneRecordSOASerial(apexSOA(*updated))
	}
	return result, nil
}

// apexSOA is the value of the zone's SOA record.
func apexSOA(zone zonemodel.Zone) string {
	for _, record := range zone.Records {
		if record.Type == "SOA" && (record.Name == "@" || record.Name == "") {
			return record.Value
		}
	}
	return ""
}

// newRecord builds a record from input and checks it parses, so a bad value
// is reported against the field that caused it.
func newRecord(zone zonemodel.Zone, input recordInput) (zonemodel.Record, error) {
	recordType := strings.ToUpper(strings.TrimSpace(input.Type))
	if recordType == "" {
		return zonemodel.Record{}, errors.New("type is required")
	}
	value, err := recordValue(zone.Name, recordType, input.Value)
	if err != nil {
		return zonemodel.Record{}, err
	}
	ttl := input.TTL
	if ttl == 0 {
		ttl = zone.DefaultTTL
	}
	record := zonemodel.Record{
		Name: storedOwner(zone.Name, input.Name), Type: recordType, Value: value, TTL: ttl,
		Comments: strings.TrimSpace(input.Comment), ExpiresAt: input.ExpiresAt,
	}
	if _, err := zonemodel.ParseRecord(zone, record); err != nil {
		return zonemodel.Record{}, err
	}
	return record, nil
}

// recordValue stores a value the same way whoever typed it: canonical
// addresses, quoted TXT text, and bare in-zone targets qualified against the
// zone.
func recordValue(zoneName, recordType, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("value is required")
	}
	switch recordType {
	case "SOA":
		return "", errors.New("Sable manages the zone SOA record")
	case "RRSIG", "DNSKEY", "NSEC", "NSEC3", "NSEC3PARAM":
		return "", errors.New("DNSSEC records are managed automatically")
	case "A", "AAAA":
		address, err := netip.ParseAddr(value)
		if err != nil || (recordType == "A" && !address.Is4()) || (recordType == "AAAA" && !address.Is6()) {
			return "", fmt.Errorf("%s is not a valid %s address", value, recordType)
		}
		return address.String(), nil
	case "TXT", "SPF":
		if !strings.HasPrefix(value, `"`) {
			value = quoteDNSString(value)
		}
	}
	return zonemodel.QualifyRecordValue(zoneName, recordType, value), nil
}

// updatedRecordValue is recordValue for an edit, which may also change the
// SOA's timers and contact.
func updatedRecordValue(zoneName, recordType, value string) (string, error) {
	if recordType != "SOA" {
		return recordValue(zoneName, recordType, value)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("value is required")
	}
	return value, nil
}

// findRecord finds the one record a key names and checks it may be changed
// by hand.
func findRecord(zone zonemodel.Zone, key recordKey) (int, error) {
	recordType := strings.ToUpper(strings.TrimSpace(key.Type))
	target, err := newRecord(zone, recordInput{Name: key.Name, Type: recordType, Value: key.Value})
	if err != nil {
		// The stored value may predate today's input rules, or be one only
		// Sable writes, so fall back to an exact match before giving up.
		target = zonemodel.Record{Name: storedOwner(zone.Name, key.Name), Type: recordType, Value: strings.TrimSpace(key.Value)}
	}
	var matches []int
	for index, record := range zone.Records {
		if sameRecord(zone, record, target) {
			matches = append(matches, index)
		}
	}
	if len(matches) > 1 && key.TTL != 0 {
		if sameTTL := slices.DeleteFunc(slices.Clone(matches), func(index int) bool { return zone.Records[index].TTL != key.TTL }); len(sameTTL) > 0 {
			// Records that differ in nothing a caller can name are the same
			// to them, so the first one is the one they meant.
			matches = sameTTL[:1]
		}
	}
	switch len(matches) {
	case 0:
		return 0, &missingRecordError{fmt.Sprintf("no %s record %s with value %s was found in zone %s",
			recordType, ownerFQDN(zone.Name, key.Name), strings.TrimSpace(key.Value), zone.Name)}
	case 1:
	default:
		return 0, errors.New("more than one record matches; change it in the Sable console")
	}
	if err := recordEditable(zone.Records[matches[0]]); err != nil {
		return 0, err
	}
	return matches[0], nil
}

// recordEditable is the one check for whether a record may be changed by
// hand. Sable signs DNSSEC records itself, and an integration's next
// synchronization would revert an edit to a record it publishes.
func recordEditable(record zonemodel.Record) error {
	if strings.HasPrefix(record.Comments, "sable:dnssec") {
		return errors.New("DNSSEC records are managed automatically")
	}
	return recordSourceEditable(record)
}

// sameRecord compares owner, type, and data the way DNS does, so a value
// spelled with different case or spacing still finds the stored record. TTL
// is not part of a record's identity.
func sameRecord(zone zonemodel.Zone, left, right zonemodel.Record) bool {
	if left.Type != right.Type || ownerFQDN(zone.Name, left.Name) != ownerFQDN(zone.Name, right.Name) {
		return false
	}
	leftRR, leftErr := zonemodel.ParseRecord(zone, left)
	rightRR, rightErr := zonemodel.ParseRecord(zone, right)
	if leftErr != nil || rightErr != nil {
		return strings.TrimSpace(left.Value) == strings.TrimSpace(right.Value)
	}
	return dns.IsDuplicate(leftRR, rightRR)
}

// storedOwner is the lowercase owner name a record is stored under: @ for
// the apex, relative inside the zone.
func storedOwner(zoneName, name string) string {
	owner := normalizeZoneRecordOwner(zoneName, name)
	if owner == "" {
		return "@"
	}
	return strings.ToLower(owner)
}

// ownerFQDN expands an owner name the way the zone file does: @ is the apex,
// a trailing dot is absolute, and anything else is relative to the zone
// unless it already ends with the zone name.
func ownerFQDN(zoneName, name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch {
	case name == "" || name == "@":
		return dns.Fqdn(zoneName)
	case strings.HasSuffix(name, "."):
		return name
	case name == zoneName || strings.HasSuffix(name, "."+zoneName):
		return dns.Fqdn(name)
	default:
		return dns.Fqdn(name + "." + zoneName)
	}
}
