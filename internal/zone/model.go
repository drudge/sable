package zone

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/forwarding"
)

const (
	defaultTTL           = 300
	defaultZSKLifetime   = 30 * 24 * time.Hour
	defaultKSKLifetime   = 365 * 24 * time.Hour
	defaultKeyPrepublish = 24 * time.Hour
	defaultKeyRetirement = 7 * 24 * time.Hour
)

// Duration preserves the convenient Duration field used by the control plane
// while keeping zone persistence independent from the TOML configuration model.
type Duration struct {
	Duration time.Duration `json:"-"`
}

func (duration Duration) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(duration.Duration.String())), nil
}

func (duration *Duration) UnmarshalJSON(value []byte) error {
	text, err := strconv.Unquote(string(value))
	if err != nil {
		return fmt.Errorf("decode duration: %w", err)
	}
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("parse duration: %w", err)
	}
	duration.Duration = parsed
	return nil
}

type Zone struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	DefaultTTL      uint32   `json:"default_ttl"`
	Disabled        bool     `json:"disabled,omitempty"`
	ZoneTransfer    string   `json:"zone_transfer,omitempty"`
	TransferACL     []string `json:"transfer_acl,omitempty"`
	Notify          []string `json:"notify,omitempty"`
	PrimaryServers  []string `json:"primary_servers,omitempty"`
	PrimaryProtocol string   `json:"primary_protocol,omitempty"`
	// AliasZone names the zone an alias zone mirrors. Every record of the source
	// zone is republished under this zone's apex whenever the source changes, so
	// an internal and an external name can answer with one set of records.
	AliasZone      string `json:"alias_zone,omitempty"`
	TSIGKey        string `json:"tsig_key,omitempty"`
	DynamicUpdates bool   `json:"dynamic_updates,omitempty"`
	DNSSEC         bool   `json:"dnssec,omitempty"`
	// DNSSECValidationDisabled turns the zone subtree into a local negative
	// trust anchor. Private forwarders commonly serve an unsigned split-horizon
	// copy of a delegated name, which a validator can only report as bogus
	// because the upstream never returns the RRSIGs that prove insecurity.
	// The flag is stored inverted so existing zones keep validating.
	DNSSECValidationDisabled bool     `json:"dnssec_validation_disabled,omitempty"`
	DNSSECAlgorithm          string   `json:"dnssec_algorithm,omitempty"`
	DNSSECDenial             string   `json:"dnssec_denial,omitempty"`
	NSEC3Iterations          uint16   `json:"dnssec_nsec3_iterations,omitempty"`
	NSEC3Salt                string   `json:"dnssec_nsec3_salt,omitempty"`
	ZSKLifetime              Duration `json:"dnssec_zsk_lifetime,omitempty"`
	KSKLifetime              Duration `json:"dnssec_ksk_lifetime,omitempty"`
	KeyPrepublish            Duration `json:"dnssec_key_prepublish,omitempty"`
	KeyRetireAfter           Duration `json:"dnssec_key_retire_after,omitempty"`
	ParentDSKeyTag           uint16   `json:"dnssec_parent_ds_key_tag,omitempty"`
	Records                  []Record `json:"records"`
	Revision                 uint64   `json:"revision"`
}

type Record struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	TTL      uint32 `json:"ttl"`
	Comments string `json:"comments,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
	// Source names the integration that owns this record. An empty source means
	// a human or a dynamic update created it. Integrations reconcile only the
	// records carrying their own source, so a destructive resync can never
	// remove hand-authored records from the same zone.
	Source    string    `json:"source,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// SourceUniFi marks records maintained by the UniFi host synchronizer.
const SourceUniFi = "unifi"

// SourceAlias marks records an alias zone mirrors from its source zone. They
// are replaced wholesale on every reconciliation, so nothing else may claim
// this source.
const SourceAlias = "alias"

// RecordID returns the compact, deterministic identifier used by control-plane
// URLs. TTL and presentation metadata are intentionally excluded so those
// edits do not change the record's URL.
func RecordID(record Record) string {
	identity := record.Name + "\x00" + record.Type + "\x00" + record.Value
	digest := sha256.Sum256([]byte(identity))
	return base64.RawURLEncoding.EncodeToString(digest[:12])
}

type Snapshot struct {
	Zones    []Zone
	Revision uint64
	LoadedAt time.Time
}

func Clone(zones []Zone) []Zone {
	cloned := make([]Zone, len(zones))
	for index, current := range zones {
		cloned[index] = current
		cloned[index].TransferACL = append([]string(nil), current.TransferACL...)
		cloned[index].Notify = append([]string(nil), current.Notify...)
		cloned[index].PrimaryServers = append([]string(nil), current.PrimaryServers...)
		cloned[index].Records = append([]Record(nil), current.Records...)
	}
	return cloned
}

func NormalizeAll(zones []Zone) {
	for index := range zones {
		Normalize(&zones[index])
	}
	slices.SortFunc(zones, func(left, right Zone) int { return strings.Compare(left.Name, right.Name) })
}

func Normalize(zone *Zone) {
	zone.Name = normalizeDomain(zone.Name)
	zone.Type = strings.ToLower(strings.TrimSpace(zone.Type))
	if zone.Type == "" {
		zone.Type = "primary"
	}
	zone.DNSSECAlgorithm = strings.ToLower(strings.TrimSpace(zone.DNSSECAlgorithm))
	zone.DNSSECDenial = strings.ToLower(strings.TrimSpace(zone.DNSSECDenial))
	zone.NSEC3Salt = strings.ToUpper(strings.TrimSpace(zone.NSEC3Salt))
	if zone.NSEC3Salt == "-" {
		zone.NSEC3Salt = ""
	}
	if zone.DNSSEC && zone.DNSSECAlgorithm == "" {
		zone.DNSSECAlgorithm = "ed25519"
	}
	if zone.DNSSEC && zone.DNSSECDenial == "" {
		zone.DNSSECDenial = "nsec"
	}
	if zone.DNSSEC && zone.ZSKLifetime.Duration <= 0 {
		zone.ZSKLifetime.Duration = defaultZSKLifetime
	}
	if zone.DNSSEC && zone.KSKLifetime.Duration <= 0 {
		zone.KSKLifetime.Duration = defaultKSKLifetime
	}
	if zone.DNSSEC && zone.KeyPrepublish.Duration <= 0 {
		zone.KeyPrepublish.Duration = defaultKeyPrepublish
	}
	if zone.DNSSEC && zone.KeyRetireAfter.Duration <= 0 {
		zone.KeyRetireAfter.Duration = defaultKeyRetirement
	}
	zone.ZoneTransfer = strings.ToLower(strings.TrimSpace(zone.ZoneTransfer))
	if zone.ZoneTransfer == "" {
		zone.ZoneTransfer = "deny"
	}
	zone.TransferACL = uniqueTrimmed(zone.TransferACL)
	zone.Notify = normalizeNotifyTargets(zone.Notify)
	zone.PrimaryProtocol = strings.ToLower(strings.TrimSpace(zone.PrimaryProtocol))
	if zone.Type == "secondary" && zone.PrimaryProtocol == "" {
		zone.PrimaryProtocol = "tcp"
	}
	if zone.Type == "stub" && zone.PrimaryProtocol == "" {
		zone.PrimaryProtocol = "udp"
	}
	zone.PrimaryServers = normalizePrimaryServers(zone.PrimaryServers, zone.PrimaryProtocol)
	if zone.Type == "alias" {
		zone.AliasZone = normalizeDomain(zone.AliasZone)
	} else {
		zone.AliasZone = ""
	}
	if strings.TrimSpace(zone.TSIGKey) != "" {
		zone.TSIGKey = strings.ToLower(dns.Fqdn(strings.TrimSpace(zone.TSIGKey)))
	}
	if zone.DefaultTTL == 0 {
		zone.DefaultTTL = defaultTTL
	}
	for index := range zone.Records {
		record := &zone.Records[index]
		record.Name = normalizeRecordName(record.Name)
		record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
		record.Value = strings.TrimSpace(record.Value)
		record.Comments = strings.TrimSpace(record.Comments)
		record.Source = strings.ToLower(strings.TrimSpace(record.Source))
		if record.TTL == 0 {
			record.TTL = zone.DefaultTTL
		}
	}
	slices.SortFunc(zone.Records, compareRecords)
}

func ValidateAll(zones []Zone, tsigKeyNames []string) error {
	keys := make(map[string]struct{}, len(tsigKeyNames))
	for _, name := range tsigKeyNames {
		keys[strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))] = struct{}{}
	}
	types := make(map[string]string, len(zones))
	for _, current := range zones {
		types[current.Name] = current.Type
	}
	seen := make(map[string]struct{}, len(zones))
	var validationErrors []error
	for index, current := range zones {
		field := fmt.Sprintf("zone %q", current.Name)
		if current.Name == "" {
			validationErrors = append(validationErrors, fmt.Errorf("zones[%d].name is required", index))
			continue
		}
		if _, err := dnsname.Normalize(current.Name); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("%s: %w", field, err))
		}
		if _, duplicate := seen[current.Name]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("duplicate authoritative zone %q", current.Name))
		}
		seen[current.Name] = struct{}{}
		validationErrors = append(validationErrors, validateZone(field, current, keys, types)...)
	}
	return errors.Join(validationErrors...)
}

func validateZone(field string, current Zone, tsigKeys map[string]struct{}, zoneTypes map[string]string) []error {
	var result []error
	if current.Type != "primary" && current.Type != "secondary" && current.Type != "stub" && current.Type != "forwarder" && current.Type != "alias" {
		result = append(result, fmt.Errorf("%s type must be primary, secondary, stub, forwarder, or alias", field))
	}
	if current.DefaultTTL == 0 {
		result = append(result, fmt.Errorf("%s default TTL must be positive", field))
	}
	if current.ZoneTransfer != "deny" && current.ZoneTransfer != "allow" && current.ZoneTransfer != "private" && current.ZoneTransfer != "acl" {
		result = append(result, fmt.Errorf("%s zone transfer must be deny, allow, private, or acl", field))
	}
	if current.ZoneTransfer == "acl" && len(current.TransferACL) == 0 {
		result = append(result, fmt.Errorf("%s transfer ACL is required when zone transfer is acl", field))
	}
	if current.TSIGKey != "" {
		if _, found := tsigKeys[current.TSIGKey]; !found {
			result = append(result, fmt.Errorf("%s references unknown TSIG key %q", field, current.TSIGKey))
		}
	}
	if current.DynamicUpdates && (current.Type != "primary" || current.TSIGKey == "") {
		result = append(result, fmt.Errorf("%s dynamic updates require a primary zone and TSIG key", field))
	}
	if current.DNSSECValidationDisabled && current.Type != "forwarder" && current.Type != "stub" {
		result = append(result, fmt.Errorf("%s DNSSEC validation can only be disabled for forwarder or stub zones", field))
	}
	result = append(result, validateDNSSEC(field, current)...)
	for index, value := range current.TransferACL {
		if _, err := netip.ParsePrefix(value); err != nil {
			if address, addressErr := netip.ParseAddr(value); addressErr != nil || address.Zone() != "" {
				result = append(result, fmt.Errorf("%s transfer ACL entry %d must be an IP address or CIDR network", field, index))
			}
		}
	}
	for index, address := range current.Notify {
		if err := validateAddress(address); err != nil {
			result = append(result, fmt.Errorf("%s notify target %d: %w", field, index, err))
		}
	}
	if current.Type == "secondary" || current.Type == "stub" {
		result = append(result, validateManagedZone(field, current)...)
	}
	result = append(result, validateAliasZone(field, current, zoneTypes)...)
	result = append(result, validateRecords(field, current)...)
	return result
}

func validateAliasZone(field string, current Zone, zoneTypes map[string]string) []error {
	if current.Type != "alias" {
		if current.AliasZone != "" {
			return []error{fmt.Errorf("%s only alias zones may name a source zone", field)}
		}
		return nil
	}
	if current.AliasZone == "" {
		return []error{fmt.Errorf("%s must name the zone it mirrors", field)}
	}
	if current.AliasZone == current.Name {
		return []error{fmt.Errorf("%s cannot mirror itself", field)}
	}
	sourceType, found := zoneTypes[current.AliasZone]
	if !found {
		return []error{fmt.Errorf("%s mirrors unknown zone %q", field, current.AliasZone)}
	}
	// Chained aliases would need the mirrors resolved in dependency order and
	// could form cycles. Stub and forwarder zones hold routing metadata rather
	// than a record set worth republishing, so the source has to be a zone Sable
	// already answers from its own records.
	if sourceType != "primary" && sourceType != "secondary" {
		return []error{fmt.Errorf("%s can only mirror a primary or secondary zone, and %q is a %s zone", field, current.AliasZone, sourceType)}
	}
	return nil
}

func validateDNSSEC(field string, current Zone) []error {
	if !current.DNSSEC {
		return nil
	}
	var result []error
	if current.Type != "primary" {
		result = append(result, fmt.Errorf("%s DNSSEC signing is only supported for primary zones", field))
	}
	if current.DNSSECAlgorithm != "ed25519" && current.DNSSECAlgorithm != "ecdsa-p256-sha256" && current.DNSSECAlgorithm != "ecdsa-p384-sha384" {
		result = append(result, fmt.Errorf("%s has an unsupported DNSSEC algorithm", field))
	}
	if current.DNSSECDenial != "nsec" && current.DNSSECDenial != "nsec3" {
		result = append(result, fmt.Errorf("%s DNSSEC denial must be nsec or nsec3", field))
	}
	if current.DNSSECDenial == "nsec3" {
		if current.NSEC3Iterations != 0 {
			result = append(result, fmt.Errorf("%s NSEC3 iterations must be 0", field))
		}
		if len(current.NSEC3Salt) > 64 || len(current.NSEC3Salt)%2 != 0 {
			result = append(result, fmt.Errorf("%s NSEC3 salt must contain at most 32 bytes as hexadecimal", field))
		} else if _, err := hex.DecodeString(current.NSEC3Salt); err != nil {
			result = append(result, fmt.Errorf("%s NSEC3 salt must be hexadecimal", field))
		}
	}
	maximumTTL := current.DefaultTTL
	for _, record := range current.Records {
		maximumTTL = max(maximumTTL, record.TTL)
	}
	minimumDelay := time.Duration(maximumTTL) * time.Second
	if current.KeyPrepublish.Duration < minimumDelay || current.KeyRetireAfter.Duration < minimumDelay {
		result = append(result, fmt.Errorf("%s DNSSEC publication and retirement windows must be at least the maximum zone TTL", field))
	}
	if current.ZSKLifetime.Duration <= current.KeyPrepublish.Duration+current.KeyRetireAfter.Duration || current.KSKLifetime.Duration <= current.KeyPrepublish.Duration+current.KeyRetireAfter.Duration {
		result = append(result, fmt.Errorf("%s DNSSEC key lifetimes must exceed publication and retirement windows", field))
	}
	return result
}

func validateManagedZone(field string, current Zone) []error {
	var result []error
	if len(current.PrimaryServers) == 0 {
		result = append(result, fmt.Errorf("%s must have at least one primary server", field))
	}
	if current.PrimaryProtocol != "udp" && current.PrimaryProtocol != "tcp" && current.PrimaryProtocol != "tls" {
		result = append(result, fmt.Errorf("%s primary protocol must be udp, tcp, or tls", field))
	}
	if current.Type == "secondary" && current.PrimaryProtocol == "udp" {
		result = append(result, fmt.Errorf("%s secondary primary protocol must be tcp or tls", field))
	}
	for index, address := range current.PrimaryServers {
		if err := validateAddress(address); err != nil {
			result = append(result, fmt.Errorf("%s primary server %d: %w", field, index, err))
		}
	}
	return result
}

func validateRecords(field string, current Zone) []error {
	var result []error
	soaRecords := 0
	hasApexNS := false
	hasApexForwarder := false
	seen := make(map[string]struct{}, len(current.Records))
	for index, record := range current.Records {
		rr, err := ParseRecord(current, record)
		if err != nil {
			result = append(result, fmt.Errorf("%s record %d: %w", field, index, err))
			continue
		}
		owner := strings.TrimSuffix(strings.ToLower(rr.Header().Name), ".")
		if owner != current.Name && !strings.HasSuffix(owner, "."+current.Name) {
			result = append(result, fmt.Errorf("%s record %d owner must be inside the zone", field, index))
		}
		key := strings.ToLower(rr.String())
		if _, duplicate := seen[key]; duplicate {
			result = append(result, fmt.Errorf("%s record %d duplicates another record", field, index))
		}
		seen[key] = struct{}{}
		if owner == current.Name && rr.Header().Rrtype == dns.TypeSOA {
			soaRecords++
			if soa, ok := rr.(*dns.SOA); ok && (soa.Refresh == 0 || soa.Retry == 0 || soa.Expire == 0) {
				result = append(result, fmt.Errorf("%s SOA refresh, retry, and expire must be positive", field))
			}
		}
		hasApexNS = hasApexNS || owner == current.Name && rr.Header().Rrtype == dns.TypeNS
		hasApexForwarder = hasApexForwarder || owner == current.Name && strings.EqualFold(record.Type, "FWD") && !record.Disabled
		if current.DNSSEC && !record.ExpiresAt.IsZero() {
			result = append(result, fmt.Errorf("%s expiring records are not supported in a DNSSEC-signed zone", field))
		}
	}
	if soaRecords != 1 {
		result = append(result, fmt.Errorf("%s must contain exactly one apex SOA record", field))
	}
	if current.Type != "forwarder" && !hasApexNS {
		result = append(result, fmt.Errorf("%s must contain at least one apex NS record", field))
	}
	if current.Type == "forwarder" && !hasApexForwarder {
		result = append(result, fmt.Errorf("%s must contain at least one active apex FWD record", field))
	}
	return result
}

func ParseRecord(current Zone, record Record) (dns.RR, error) {
	owner, err := recordOwner(current.Name, record.Name)
	if err != nil {
		return nil, err
	}
	recordType := strings.ToUpper(strings.TrimSpace(record.Type))
	ttl := record.TTL
	if ttl == 0 {
		ttl = current.DefaultTTL
	}
	switch recordType {
	case "ANAME":
		target, normalizeErr := dnsname.Normalize(record.Value)
		if normalizeErr != nil {
			return nil, fmt.Errorf("invalid ANAME target: %w", normalizeErr)
		}
		return dns.NewRR(fmt.Sprintf("%s %d IN CNAME %s", owner, ttl, dns.Fqdn(target)))
	case "FWD":
		forwarder, parseErr := forwarding.ParseRecord(record.Value)
		if parseErr != nil {
			return nil, parseErr
		}
		return &dns.TXT{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}, Txt: []string{forwarder.String()}}, nil
	}
	if _, found := dns.StringToType[recordType]; !found {
		return nil, fmt.Errorf("unsupported record type %q", record.Type)
	}
	if strings.TrimSpace(record.Value) == "" {
		return nil, errors.New("value is required")
	}
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", owner, ttl, recordType, record.Value))
	if err != nil {
		return nil, fmt.Errorf("invalid %s record: %w", recordType, err)
	}
	return rr, nil
}

func recordOwner(zoneName, recordName string) (string, error) {
	recordName = strings.TrimSpace(recordName)
	if recordName == "" || recordName == "@" {
		return dns.Fqdn(zoneName), nil
	}
	if recordName == "*" {
		return dns.Fqdn("*." + zoneName), nil
	}
	if strings.HasSuffix(recordName, ".") {
		normalized, err := dnsname.NormalizeOwner(recordName)
		return dns.Fqdn(normalized), err
	}
	normalized, err := dnsname.NormalizeOwner(recordName)
	return dns.Fqdn(normalized + "." + zoneName), err
}

func normalizeDomain(value string) string {
	normalized, err := dnsname.Normalize(value)
	if err != nil {
		return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	}
	return normalized
}

func normalizeRecordName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "@" {
		return "@"
	}
	return strings.ToLower(value)
}

func uniqueTrimmed(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func normalizeNotifyTargets(values []string) []string {
	values = uniqueTrimmed(values)
	for index, value := range values {
		if host, port, err := net.SplitHostPort(value); err == nil {
			values[index] = net.JoinHostPort(strings.ToLower(strings.TrimSuffix(host, ".")), port)
			continue
		}
		values[index] = strings.ToLower(strings.TrimSuffix(value, "."))
	}
	return values
}

func normalizePrimaryServers(values []string, protocol string) []string {
	values = uniqueTrimmed(values)
	if protocol == "" {
		protocol = "tcp"
	}
	for index, value := range values {
		if record, err := forwarding.NewRecord(protocol, "0", value); err == nil {
			values[index] = record.Address
		}
	}
	return values
}

func validateAddress(address string) error {
	if strings.TrimSpace(address) == "" {
		return errors.New("address is required")
	}
	if _, _, err := net.SplitHostPort(address); err == nil {
		return nil
	}
	if parsed := net.ParseIP(address); parsed != nil {
		return nil
	}
	if !strings.Contains(address, ":") && !strings.ContainsAny(address, " /@") {
		return nil
	}
	return fmt.Errorf("invalid address %q", address)
}

func compareRecords(left, right Record) int {
	if compared := strings.Compare(left.Name, right.Name); compared != 0 {
		return compared
	}
	if compared := strings.Compare(left.Type, right.Type); compared != 0 {
		return compared
	}
	if left.TTL < right.TTL {
		return -1
	}
	if left.TTL > right.TTL {
		return 1
	}
	return strings.Compare(left.Value, right.Value)
}
