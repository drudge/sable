package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/dnsserver"
	zonemodel "github.com/drudge/sable/internal/zone"
)

const dynamicUpdateAuditQueueSize = 1_024

type dynamicUpdateConfiguration interface {
	UpdateZones(context.Context, func(*[]zonemodel.Zone) error) error
}

type dynamicUpdateDNS interface {
	NotifyZone(context.Context, string, []string) []error
}

type dynamicUpdateAuditor interface {
	RecordAuditEvent(context.Context, auth.AuditEvent) error
}

type dynamicZoneUpdater struct {
	configuration dynamicUpdateConfiguration
	dns           dynamicUpdateDNS
	auditor       dynamicUpdateAuditor
	logger        *slog.Logger
	now           func() time.Time
	auditEvents   chan dynamicUpdateAuditEvent
}

type dynamicUpdateAuditEvent struct {
	zone              string
	keyName           string
	source            string
	prerequisiteCount int
	updateCount       int
	result            dnsserver.ZoneUpdateResult
}

type updateRcodeError struct {
	rcode int
}

func (err updateRcodeError) Error() string { return dns.RcodeToString[err.rcode] }

var errDynamicUpdateNoChange = errors.New("dynamic update did not change the zone")

func newDynamicZoneUpdater(
	ctx context.Context,
	configuration dynamicUpdateConfiguration,
	dnsService dynamicUpdateDNS,
	auditor dynamicUpdateAuditor,
	logger *slog.Logger,
) *dynamicZoneUpdater {
	updater := &dynamicZoneUpdater{
		configuration: configuration, dns: dnsService, auditor: auditor, logger: logger, now: time.Now,
		auditEvents: make(chan dynamicUpdateAuditEvent, dynamicUpdateAuditQueueSize),
	}
	go updater.runAuditWorker(ctx)
	return updater
}

func (updater *dynamicZoneUpdater) Update(ctx context.Context, request dnsserver.ZoneUpdateRequest) dnsserver.ZoneUpdateResult {
	result := dnsserver.ZoneUpdateResult{Rcode: dns.RcodeServerFailure}
	var notifyTargets []string
	err := updater.configuration.UpdateZones(ctx, func(zones *[]zonemodel.Zone) error {
		zone := findConfiguredZone(*zones, request.Zone)
		if zone == nil || zone.Disabled || zone.Type != "primary" {
			return updateRcodeError{rcode: dns.RcodeNotAuth}
		}
		if !zone.DynamicUpdates || zone.TSIGKey == "" || !strings.EqualFold(dns.Fqdn(zone.TSIGKey), dns.Fqdn(request.KeyName)) {
			return updateRcodeError{rcode: dns.RcodeRefused}
		}

		changed, rcode, applyErr := applyDynamicZoneUpdate(zone, request.Prerequisites, request.Updates, updater.now())
		if applyErr != nil {
			if rcode != dns.RcodeSuccess {
				return updateRcodeError{rcode: rcode}
			}
			return applyErr
		}
		if rcode != dns.RcodeSuccess {
			return updateRcodeError{rcode: rcode}
		}
		if !changed {
			return errDynamicUpdateNoChange
		}
		notifyTargets = append([]string(nil), zone.Notify...)
		result.Changed = true
		return nil
	})

	switch {
	case err == nil:
		result.Rcode = dns.RcodeSuccess
	case errors.Is(err, errDynamicUpdateNoChange):
		result.Rcode = dns.RcodeSuccess
		result.Changed = false
	default:
		var rcodeErr updateRcodeError
		if errors.As(err, &rcodeErr) {
			result.Rcode = rcodeErr.rcode
		} else {
			updater.logger.Error("dynamic DNS update failed", "zone", request.Zone, "source", request.Source, "error", err)
		}
	}

	if result.Rcode == dns.RcodeSuccess && result.Changed && len(notifyTargets) > 0 {
		go updater.notify(request.Zone, notifyTargets)
	}
	return result
}

func (updater *dynamicZoneUpdater) notify(zone string, targets []string) {
	for _, err := range updater.dns.NotifyZone(context.Background(), zone, targets) {
		updater.logger.Warn("notify secondary server after dynamic update", "zone", zone, "error", err)
	}
}

func (updater *dynamicZoneUpdater) Audit(
	_ context.Context,
	request dnsserver.ZoneUpdateRequest,
	result dnsserver.ZoneUpdateResult,
) {
	event := dynamicUpdateAuditEvent{
		zone: request.Zone, keyName: request.KeyName, source: request.Source,
		prerequisiteCount: len(request.Prerequisites), updateCount: len(request.Updates), result: result,
	}
	select {
	case updater.auditEvents <- event:
	default:
		updater.logger.Warn("dynamic DNS update audit queue full", "zone", request.Zone)
	}
}

func (updater *dynamicZoneUpdater) runAuditWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-updater.auditEvents:
			updater.recordAudit(ctx, event)
		}
	}
}

func (updater *dynamicZoneUpdater) recordAudit(
	ctx context.Context,
	event dynamicUpdateAuditEvent,
) {
	action := "dns.update"
	if event.result.Rcode != dns.RcodeSuccess {
		action = "dns.update.failed"
	}
	details := fmt.Sprintf(
		"zone=%s key=%s prerequisites=%d updates=%d rcode=%s changed=%t",
		event.zone, event.keyName, event.prerequisiteCount, event.updateCount,
		dns.RcodeToString[event.result.Rcode], event.result.Changed,
	)
	if err := updater.auditor.RecordAuditEvent(ctx, auth.AuditEvent{
		OccurredAt: updater.now(), Action: action, ClientIP: event.source,
		UserAgent: "RFC 2136", Details: details,
	}); err != nil {
		updater.logger.Warn("record dynamic DNS update audit event", "zone", event.zone, "error", err)
	}
}

func findConfiguredZone(zones []zonemodel.Zone, name string) *zonemodel.Zone {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for index := range zones {
		if zones[index].Name == name {
			return &zones[index]
		}
	}
	return nil
}

func applyDynamicZoneUpdate(
	zone *zonemodel.Zone,
	prerequisites, updates []dns.RR,
	now time.Time,
) (bool, int, error) {
	records, err := activeZoneRRs(*zone, now)
	if err != nil {
		return false, dns.RcodeServerFailure, err
	}
	if rcode := evaluateUpdatePrerequisites(zone.Name, records, prerequisites); rcode != dns.RcodeSuccess {
		return false, rcode, nil
	}
	if rcode := validateUpdateOperations(zone.Name, updates); rcode != dns.RcodeSuccess {
		return false, rcode, nil
	}

	changed := false
	for _, update := range updates {
		operationChanged, applyErr := applyUpdateOperation(zone, update, now)
		if applyErr != nil {
			return false, dns.RcodeServerFailure, applyErr
		}
		changed = changed || operationChanged
	}
	if changed {
		if err := advanceDynamicSOASerial(zone); err != nil {
			return false, dns.RcodeServerFailure, err
		}
	}
	return changed, dns.RcodeSuccess, nil
}

func activeZoneRRs(zone zonemodel.Zone, now time.Time) ([]dns.RR, error) {
	records := make([]dns.RR, 0, len(zone.Records))
	for _, record := range zone.Records {
		if record.Disabled || (!record.ExpiresAt.IsZero() && !record.ExpiresAt.After(now)) {
			continue
		}
		rr, err := configuredRecordRR(zone, record)
		if err != nil {
			if record.Type == "FWD" {
				continue
			}
			return nil, err
		}
		records = append(records, rr)
	}
	return records, nil
}

func configuredRecordRR(zone zonemodel.Zone, record zonemodel.Record) (dns.RR, error) {
	owner, ok := absoluteUpdateOwner(zone.Name, record.Name)
	if !ok {
		return nil, fmt.Errorf("record owner %q is outside zone %q", record.Name, zone.Name)
	}
	recordType := strings.ToUpper(record.Type)
	value := record.Value
	if recordType == "ANAME" {
		recordType = "CNAME"
		value = dns.Fqdn(value)
	}
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", owner, record.TTL, recordType, value))
	if err != nil {
		return nil, fmt.Errorf("parse configured %s record: %w", record.Type, err)
	}
	return rr, nil
}

func evaluateUpdatePrerequisites(zone string, records, prerequisites []dns.RR) int {
	valueDependent := make(map[string][]dns.RR)
	for _, prerequisite := range prerequisites {
		header := prerequisite.Header()
		owner, ok := relativeUpdateOwner(zone, header.Name)
		if !ok {
			return dns.RcodeNotZone
		}
		_ = owner
		if header.Ttl != 0 {
			return dns.RcodeFormatError
		}
		switch header.Class {
		case dns.ClassANY:
			if !isEmptyUpdateMetaRecord(prerequisite) {
				return dns.RcodeFormatError
			}
			if header.Rrtype == dns.TypeANY {
				if !nameExists(records, header.Name) {
					return dns.RcodeNameError
				}
			} else if !rrsetExists(records, header.Name, header.Rrtype) {
				return dns.RcodeNXRrset
			}
		case dns.ClassNONE:
			if !isEmptyUpdateMetaRecord(prerequisite) {
				return dns.RcodeFormatError
			}
			if header.Rrtype == dns.TypeANY {
				if nameExists(records, header.Name) {
					return dns.RcodeYXDomain
				}
			} else if rrsetExists(records, header.Name, header.Rrtype) {
				return dns.RcodeYXRrset
			}
		case dns.ClassINET:
			if header.Rrtype == dns.TypeANY || isMetaRecordType(header.Rrtype) {
				return dns.RcodeFormatError
			}
			key := rrsetKey(header.Name, header.Rrtype)
			for _, existing := range valueDependent[key] {
				if equalUpdateRR(existing, prerequisite) {
					return dns.RcodeFormatError
				}
			}
			valueDependent[key] = append(valueDependent[key], prerequisite)
		default:
			return dns.RcodeFormatError
		}
	}
	for key, expected := range valueDependent {
		actual := rrsetByKey(records, key)
		if !equalUpdateRRSet(actual, expected) {
			return dns.RcodeNXRrset
		}
	}
	return dns.RcodeSuccess
}

func validateUpdateOperations(zone string, updates []dns.RR) int {
	for _, update := range updates {
		header := update.Header()
		if _, ok := relativeUpdateOwner(zone, header.Name); !ok {
			return dns.RcodeNotZone
		}
		switch header.Class {
		case dns.ClassINET:
			if header.Rrtype == dns.TypeANY || isMetaRecordType(header.Rrtype) {
				return dns.RcodeFormatError
			}
		case dns.ClassANY:
			if header.Ttl != 0 || !isEmptyUpdateMetaRecord(update) {
				return dns.RcodeFormatError
			}
		case dns.ClassNONE:
			if header.Ttl != 0 || header.Rrtype == dns.TypeANY || isMetaRecordType(header.Rrtype) || isEmptyUpdateMetaRecord(update) {
				return dns.RcodeFormatError
			}
		default:
			return dns.RcodeFormatError
		}
	}
	return dns.RcodeSuccess
}

func applyUpdateOperation(zone *zonemodel.Zone, update dns.RR, now time.Time) (bool, error) {
	header := update.Header()
	owner, _ := relativeUpdateOwner(zone.Name, header.Name)
	if header.Rrtype == dns.TypeSOA || (zone.DNSSEC && isManagedDNSSECType(header.Rrtype)) {
		return false, nil
	}

	switch header.Class {
	case dns.ClassINET:
		candidate, err := configuredRecordFromRR(zone.Name, update)
		if err != nil {
			return false, err
		}
		// RFC 2136 §3.4.2.2: an add that would leave a CNAME sharing its name
		// with other data is silently ignored rather than refused, and a new
		// CNAME replaces the one already at the name.
		if header.Rrtype == dns.TypeCNAME {
			if hasActiveConfiguredRecord(*zone, header.Name, now, zonemodel.ConflictsWithCNAME) {
				return false, nil
			}
		} else if zonemodel.ConflictsWithCNAME(dns.TypeToString[header.Rrtype]) {
			if hasActiveConfiguredRecord(*zone, header.Name, now, func(recordType string) bool { return recordType == "CNAME" }) {
				return false, nil
			}
		}
		changed := false
		for index := len(zone.Records) - 1; index >= 0; index-- {
			existing, parseErr := configuredRecordRR(*zone, zone.Records[index])
			if parseErr == nil && equalUpdateRR(existing, update) {
				if !zone.Records[index].Disabled && (zone.Records[index].ExpiresAt.IsZero() || zone.Records[index].ExpiresAt.After(now)) {
					return changed, nil
				}
				zone.Records = slices.Delete(zone.Records, index, index+1)
				changed = true
			}
		}
		if header.Rrtype == dns.TypeCNAME {
			changed = deleteConfiguredRecords(zone, func(record zonemodel.Record, rr dns.RR) bool {
				return strings.ToUpper(strings.TrimSpace(record.Type)) == "CNAME" && strings.EqualFold(rr.Header().Name, header.Name)
			}) || changed
		}
		zone.Records = append(zone.Records, candidate)
		return true, nil
	case dns.ClassANY:
		return deleteConfiguredRecords(zone, func(record zonemodel.Record, rr dns.RR) bool {
			if !strings.EqualFold(rr.Header().Name, header.Name) || record.Type == "SOA" {
				return false
			}
			if owner == "@" && record.Type == "NS" {
				return false
			}
			return header.Rrtype == dns.TypeANY || rr.Header().Rrtype == header.Rrtype
		}), nil
	case dns.ClassNONE:
		return deleteConfiguredRecords(zone, func(record zonemodel.Record, rr dns.RR) bool {
			if record.Type == "SOA" || !equalUpdateRR(rr, update) {
				return false
			}
			if owner == "@" && record.Type == "NS" {
				return activeApexNSCount(*zone, now) > 1
			}
			return true
		}), nil
	}
	return false, nil
}

func isManagedDNSSECType(recordType uint16) bool {
	return recordType == dns.TypeDNSKEY || recordType == dns.TypeRRSIG || recordType == dns.TypeNSEC ||
		recordType == dns.TypeNSEC3 || recordType == dns.TypeNSEC3PARAM
}

// hasActiveConfiguredRecord reports whether a served record at owner matches.
// It reads the configured type rather than the compiled RR so an ANAME is not
// mistaken for the CNAME it is flattened into.
func hasActiveConfiguredRecord(zone zonemodel.Zone, owner string, now time.Time, matches func(string) bool) bool {
	for _, record := range zone.Records {
		if record.Disabled || (!record.ExpiresAt.IsZero() && !record.ExpiresAt.After(now)) {
			continue
		}
		recordOwner, ok := absoluteUpdateOwner(zone.Name, record.Name)
		if !ok || !strings.EqualFold(recordOwner, owner) {
			continue
		}
		if matches(strings.ToUpper(strings.TrimSpace(record.Type))) {
			return true
		}
	}
	return false
}

func deleteConfiguredRecords(zone *zonemodel.Zone, remove func(zonemodel.Record, dns.RR) bool) bool {
	changed := false
	kept := zone.Records[:0]
	for _, record := range zone.Records {
		rr, err := configuredRecordRR(*zone, record)
		if err == nil && !record.Disabled && remove(record, rr) {
			changed = true
			continue
		}
		kept = append(kept, record)
	}
	zone.Records = kept
	return changed
}

func configuredRecordFromRR(zone string, rr dns.RR) (zonemodel.Record, error) {
	owner, ok := relativeUpdateOwner(zone, rr.Header().Name)
	if !ok {
		return zonemodel.Record{}, errors.New("record owner is outside the zone")
	}
	recordType := dns.TypeToString[rr.Header().Rrtype]
	if recordType == "" {
		return zonemodel.Record{}, fmt.Errorf("unsupported record type %d", rr.Header().Rrtype)
	}
	value := strings.TrimSpace(strings.TrimPrefix(rr.String(), rr.Header().String()))
	if value == "" {
		return zonemodel.Record{}, errors.New("record data is required")
	}
	return zonemodel.Record{Name: owner, Type: recordType, Value: value, TTL: rr.Header().Ttl}, nil
}

func advanceDynamicSOASerial(zone *zonemodel.Zone) error {
	for index := range zone.Records {
		record := &zone.Records[index]
		if record.Name != "@" || record.Type != "SOA" {
			continue
		}
		fields := strings.Fields(record.Value)
		if len(fields) != 7 {
			return errors.New("apex SOA record is malformed")
		}
		serial, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return errors.New("apex SOA serial is malformed")
		}
		fields[2] = strconv.FormatUint(uint64(uint32(serial)+1), 10)
		record.Value = strings.Join(fields, " ")
		return nil
	}
	return errors.New("apex SOA record is missing")
}

func activeApexNSCount(zone zonemodel.Zone, now time.Time) int {
	count := 0
	for _, record := range zone.Records {
		if record.Name == "@" && record.Type == "NS" && !record.Disabled &&
			(record.ExpiresAt.IsZero() || record.ExpiresAt.After(now)) {
			count++
		}
	}
	return count
}

func absoluteUpdateOwner(zone, owner string) (string, bool) {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	owner = strings.TrimSpace(strings.ToLower(owner))
	if owner == "" || owner == "@" {
		return dns.Fqdn(zone), true
	}
	if strings.HasSuffix(owner, ".") {
		name := strings.TrimSuffix(owner, ".")
		return dns.Fqdn(name), name == zone || strings.HasSuffix(name, "."+zone)
	}
	return dns.Fqdn(owner + "." + zone), true
}

func relativeUpdateOwner(zone, owner string) (string, bool) {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	owner = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(owner)), ".")
	if owner == zone {
		return "@", true
	}
	suffix := "." + zone
	if !strings.HasSuffix(owner, suffix) {
		return "", false
	}
	return strings.TrimSuffix(owner, suffix), true
}

func isEmptyUpdateMetaRecord(record dns.RR) bool {
	_, ok := record.(*dns.ANY)
	return ok
}

func isMetaRecordType(recordType uint16) bool {
	switch recordType {
	case dns.TypeOPT, dns.TypeTSIG, dns.TypeTKEY, dns.TypeAXFR, dns.TypeIXFR, dns.TypeMAILA, dns.TypeMAILB:
		return true
	default:
		return false
	}
}

func nameExists(records []dns.RR, name string) bool {
	return slices.ContainsFunc(records, func(record dns.RR) bool {
		return strings.EqualFold(record.Header().Name, name)
	})
}

func rrsetExists(records []dns.RR, name string, recordType uint16) bool {
	return slices.ContainsFunc(records, func(record dns.RR) bool {
		return strings.EqualFold(record.Header().Name, name) && record.Header().Rrtype == recordType
	})
}

func rrsetKey(name string, recordType uint16) string {
	return strings.ToLower(dns.Fqdn(name)) + "/" + strconv.FormatUint(uint64(recordType), 10)
}

func rrsetByKey(records []dns.RR, key string) []dns.RR {
	result := make([]dns.RR, 0)
	for _, record := range records {
		if rrsetKey(record.Header().Name, record.Header().Rrtype) == key {
			result = append(result, record)
		}
	}
	return result
}

func equalUpdateRR(left, right dns.RR) bool {
	left = dns.Copy(left)
	right = dns.Copy(right)
	left.Header().Class = dns.ClassINET
	right.Header().Class = dns.ClassINET
	return dns.IsDuplicate(left, right)
}

func equalUpdateRRSet(left, right []dns.RR) bool {
	if len(left) != len(right) {
		return false
	}
	for _, expected := range right {
		if !slices.ContainsFunc(left, func(actual dns.RR) bool { return equalUpdateRR(actual, expected) }) {
			return false
		}
	}
	return true
}
