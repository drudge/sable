package zone

import (
	"strings"
	"time"
)

// AddressClaims maps each owner name, as a lowercase FQDN without the trailing
// dot, where a record no integration owns already decides what an address
// lookup returns: an A, AAAA, CNAME, or FWD record. The value is that record's
// type. An integration publishing addresses leaves these names alone. Beside a
// CNAME, an address would break RFC 1034 §3.6.2; beside the operator's own
// addresses or forwarding, it would quietly change the answer they chose.
// Disabled and expired records do not count because they are not answered.
func AddressClaims(current Zone, now time.Time) map[string]string {
	claims := make(map[string]string)
	for _, record := range current.Records {
		if record.Source != "" || !recordServes(record, now) {
			continue
		}
		recordType := strings.ToUpper(strings.TrimSpace(record.Type))
		switch recordType {
		case "A", "AAAA", "CNAME", "FWD":
		default:
			continue
		}
		owner, err := recordOwner(current.Name, record.Name)
		if err != nil {
			continue
		}
		claims[strings.TrimSuffix(owner, ".")] = recordType
	}
	return claims
}

// RecordFQDN returns a record's owner as a lowercase FQDN without the trailing
// dot, resolving a relative name or @ against the zone it belongs to.
func RecordFQDN(zoneName, recordName string) (string, error) {
	owner, err := recordOwner(zoneName, recordName)
	return strings.TrimSuffix(owner, "."), err
}
