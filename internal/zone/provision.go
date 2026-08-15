package zone

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/dnsname"
)

// NewPrimary builds an empty primary zone with the apex SOA and NS records the
// console creates by hand. Integrations that provision zones on the operator's
// behalf use this so an automatically created zone is indistinguishable from
// one added through the UI.
func NewPrimary(name string, ttl uint32, primaryNS, responsible string, now time.Time) (Zone, error) {
	normalized, err := dnsname.Normalize(name)
	if err != nil {
		return Zone{}, fmt.Errorf("zone name: %w", err)
	}
	if ttl == 0 {
		ttl = defaultTTL
	}
	if strings.TrimSpace(primaryNS) == "" {
		primaryNS = "ns1." + normalized
	}
	nameServer, err := dnsname.Normalize(primaryNS)
	if err != nil {
		return Zone{}, fmt.Errorf("primary name server: %w", err)
	}
	if strings.TrimSpace(responsible) == "" {
		responsible = "hostmaster@" + normalized
	}
	mailbox, err := ResponsibleName(responsible)
	if err != nil {
		return Zone{}, err
	}
	serial := NextSerial(0, now)
	return Zone{
		Name: normalized, Type: "primary", DefaultTTL: ttl,
		Records: []Record{
			{
				Name: "@", Type: "SOA", TTL: ttl,
				Value: fmt.Sprintf("%s %s %d 3600 600 1209600 %d", dns.Fqdn(nameServer), mailbox, serial, ttl),
			},
			{Name: "@", Type: "NS", TTL: ttl, Value: dns.Fqdn(nameServer)},
		},
	}, nil
}

// ResponsibleName converts a responsible mailbox into SOA RNAME form.
func ResponsibleName(value string) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "", fmt.Errorf("responsible email is required")
	}
	if at := strings.IndexByte(value, '@'); at >= 0 {
		if at == 0 || at == len(value)-1 || strings.Contains(value[at+1:], "@") {
			return "", fmt.Errorf("responsible email is invalid")
		}
		value = value[:at] + "." + value[at+1:]
	}
	normalized, err := dnsname.Normalize(value)
	if err != nil {
		return "", fmt.Errorf("responsible email: %w", err)
	}
	return dns.Fqdn(normalized), nil
}

// AdvanceSerial bumps the apex SOA serial. It is a no-op when the zone has no
// parsable apex SOA, which validation reports separately.
func AdvanceSerial(zone *Zone, now time.Time) {
	for index := range zone.Records {
		record := &zone.Records[index]
		if record.Name != "@" || record.Type != "SOA" {
			continue
		}
		fields := strings.Fields(record.Value)
		if len(fields) != 7 {
			return
		}
		current, _ := strconv.ParseUint(fields[2], 10, 32)
		fields[2] = strconv.FormatUint(uint64(NextSerial(uint32(current), now)), 10)
		record.Value = strings.Join(fields, " ")
		return
	}
}

// NextSerial returns the next date-based SOA serial, falling back to an
// increment when the current serial already covers today.
func NextSerial(current uint32, now time.Time) uint32 {
	dateSerial, _ := strconv.ParseUint(now.UTC().Format("20060102")+"01", 10, 32)
	if current >= uint32(dateSerial) {
		return current + 1
	}
	return uint32(dateSerial)
}
