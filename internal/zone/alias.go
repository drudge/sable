package zone

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// aliasExcludedTypes lists record types an alias zone never mirrors. The apex
// SOA belongs to the alias zone itself so its serial can advance independently,
// and the DNSSEC material of the source zone only ever covers the source owner
// names.
var aliasExcludedTypes = map[string]struct{}{
	"RRSIG": {}, "DNSKEY": {}, "NSEC": {}, "NSEC3": {}, "NSEC3PARAM": {},
	"CDS": {}, "CDNSKEY": {},
}

// MaterializeAliases republishes the records of every alias zone's source zone
// under the alias apex. It runs on every catalog mutation and at startup, so it
// must be idempotent: the SOA serial only advances when the mirrored record set
// actually changed.
//
// Record values are copied verbatim. An alias is meant to answer with the same
// set of records as its source, so a CNAME or MX target that points into the
// source zone keeps pointing there rather than being rewritten to the alias.
func MaterializeAliases(zones *[]Zone, now time.Time) error {
	if zones == nil {
		return nil
	}
	sources := make(map[string]*Zone, len(*zones))
	for index := range *zones {
		current := &(*zones)[index]
		if current.Type == "alias" {
			continue
		}
		sources[current.Name] = current
	}
	for index := range *zones {
		alias := &(*zones)[index]
		if alias.Type != "alias" {
			continue
		}
		source, found := sources[alias.AliasZone]
		if !found {
			// Validation reports the dangling reference with a better message.
			// Leaving the previously mirrored records in place keeps the zone
			// answering until an operator repairs the catalog.
			continue
		}
		if err := materializeAlias(alias, source, now); err != nil {
			return fmt.Errorf("mirror zone %q into alias zone %q: %w", source.Name, alias.Name, err)
		}
	}
	return nil
}

func materializeAlias(alias, source *Zone, now time.Time) error {
	mirrored := make([]Record, 0, len(source.Records))
	for _, record := range source.Records {
		recordType := strings.ToUpper(strings.TrimSpace(record.Type))
		if _, excluded := aliasExcludedTypes[recordType]; excluded {
			continue
		}
		owner, err := aliasRecordOwner(source.Name, record.Name)
		if err != nil {
			return err
		}
		if owner == "" {
			continue
		}
		if owner == "@" && recordType == "SOA" {
			continue
		}
		mirrored = append(mirrored, Record{
			Name: owner, Type: recordType, Value: record.Value, TTL: record.TTL,
			Comments: record.Comments, Disabled: record.Disabled,
			Source: SourceAlias, ExpiresAt: record.ExpiresAt,
		})
	}
	slices.SortFunc(mirrored, compareRecords)

	retained := make([]Record, 0, len(alias.Records)+len(mirrored))
	previous := make([]Record, 0, len(alias.Records))
	for _, record := range alias.Records {
		if record.Source == SourceAlias {
			previous = append(previous, record)
			continue
		}
		retained = append(retained, record)
	}
	slices.SortFunc(previous, compareRecords)
	if slices.EqualFunc(previous, mirrored, sameMirroredRecord) {
		return nil
	}
	alias.Records = append(retained, mirrored...)
	slices.SortFunc(alias.Records, compareRecords)
	AdvanceSerial(alias, now)
	return nil
}

// sameMirroredRecord compares two mirrored records. Expiry instants are
// compared by value rather than by struct equality so a record that round-tripped
// through the database does not read as a change against its in-memory source.
func sameMirroredRecord(left, right Record) bool {
	return left.Name == right.Name && left.Type == right.Type && left.Value == right.Value &&
		left.TTL == right.TTL && left.Comments == right.Comments && left.Disabled == right.Disabled &&
		left.ExpiresAt.Equal(right.ExpiresAt)
}

// aliasRecordOwner re-anchors a source record name so it lands under the alias
// apex. Names are normally stored relative to their zone already; a name stored
// as a fully qualified owner is converted back to its relative labels. A name
// outside the source zone cannot be mirrored and is dropped.
func aliasRecordOwner(sourceName, recordName string) (string, error) {
	recordName = strings.TrimSpace(recordName)
	if recordName == "" || recordName == "@" {
		return "@", nil
	}
	if !strings.HasSuffix(recordName, ".") {
		return strings.ToLower(recordName), nil
	}
	owner := strings.ToLower(strings.TrimSuffix(recordName, "."))
	if owner == sourceName {
		return "@", nil
	}
	if !strings.HasSuffix(owner, "."+sourceName) {
		return "", nil
	}
	return strings.TrimSuffix(owner, "."+sourceName), nil
}
