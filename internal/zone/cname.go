package zone

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// ConflictsWithCNAME reports whether a record type may not share an owner name
// with a CNAME record. RFC 1034 §3.6.2 requires a CNAME to be the only data at
// its name; RFC 4035 §2.5 and RFC 5155 exempt the signatures and
// denial-of-existence proofs DNSSEC attaches to every name. ANAME is not
// exempt: Sable flattens an ANAME into addresses instead of serving a CNAME,
// so it may share a name with address records, but next to a real CNAME the
// two would still answer differently by query type.
func ConflictsWithCNAME(recordType string) bool {
	switch strings.ToUpper(strings.TrimSpace(recordType)) {
	case "CNAME", "RRSIG", "NSEC", "NSEC3":
		return false
	}
	return true
}

// CheckCNAMEExclusivity reports whether the served records at name leave a
// CNAME coexisting with other data. Callers apply a write to the zone first
// and reject it on error, so the check covers both directions: adding a CNAME
// where records exist and adding a record where a CNAME exists. Disabled and
// expired records do not count because they are not answered, and enabling
// one later is itself a write that lands back here. Only the one name is
// examined, so a pre-existing conflict elsewhere in the zone never blocks an
// unrelated write.
func CheckCNAMEExclusivity(current Zone, name string, now time.Time) error {
	owner, err := recordOwner(current.Name, name)
	if err != nil {
		// An owner that does not parse matches no records; record validation
		// reports the malformed name with a better message.
		return nil
	}
	cnames, others := 0, 0
	for _, record := range current.Records {
		if !recordServes(record, now) {
			continue
		}
		recordOwnerName, ownerErr := recordOwner(current.Name, record.Name)
		if ownerErr != nil || recordOwnerName != owner {
			continue
		}
		if strings.ToUpper(strings.TrimSpace(record.Type)) == "CNAME" {
			cnames++
		} else if ConflictsWithCNAME(record.Type) {
			others++
		}
	}
	display := strings.TrimSuffix(owner, ".")
	if cnames > 0 && others > 0 {
		return fmt.Errorf("a CNAME record cannot share the name %q with other records: a CNAME must be the only record at its name (RFC 1034)", display)
	}
	if cnames > 1 {
		return fmt.Errorf("%q already has a CNAME record, and a name can hold only one", display)
	}
	return nil
}

// CNAMEConflicts lists the owner names whose served records violate CNAME
// exclusivity. Zones that predate the write-time check load unchanged, so this
// lets startup surface the conflicts as warnings instead of refusing the zone.
func CNAMEConflicts(current Zone, now time.Time) []string {
	cnames := make(map[string]int)
	others := make(map[string]int)
	for _, record := range current.Records {
		if !recordServes(record, now) {
			continue
		}
		owner, err := recordOwner(current.Name, record.Name)
		if err != nil {
			continue
		}
		if strings.ToUpper(strings.TrimSpace(record.Type)) == "CNAME" {
			cnames[owner]++
		} else if ConflictsWithCNAME(record.Type) {
			others[owner]++
		}
	}
	var conflicted []string
	for owner, count := range cnames {
		if count > 1 || others[owner] > 0 {
			conflicted = append(conflicted, strings.TrimSuffix(owner, "."))
		}
	}
	slices.Sort(conflicted)
	return conflicted
}

// recordServes reports whether a record is currently answered: enabled and not
// past its expiry.
func recordServes(record Record, now time.Time) bool {
	return !record.Disabled && (record.ExpiresAt.IsZero() || record.ExpiresAt.After(now))
}
