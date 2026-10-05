package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/forwarding"
	zonemodel "github.com/drudge/sable/internal/zone"
)

func consoleRecordInput(request *http.Request) (recordInput, error) {
	ttl, err := formTTL(request.FormValue("ttl"), 0)
	if err != nil {
		return recordInput{}, err
	}
	recordType := strings.ToUpper(strings.TrimSpace(request.FormValue("type")))
	value, err := zoneRecordValueFromForm(request, recordType, "")
	if err != nil {
		return recordInput{}, err
	}
	expiresAt, err := formExpiry(request.FormValue("expiry_ttl"), time.Now())
	if err != nil {
		return recordInput{}, err
	}
	glue := request.FormValue("glue_addresses")
	return recordInput{
		Name: request.FormValue("name"), Type: recordType, Value: value, TTL: ttl,
		Comment: request.FormValue("comments"), ExpiresAt: expiresAt, Glue: &glue,
	}, nil
}

// consoleRecordKey is the record a row's form names. Its TTL picks between
// records that differ in nothing else.
func consoleRecordKey(request *http.Request) (recordKey, error) {
	ttl, err := strconv.ParseUint(request.FormValue("ttl"), 10, 32)
	if err != nil {
		return recordKey{}, errors.New("record TTL is invalid")
	}
	return recordKey{
		Name: request.FormValue("name"), Type: request.FormValue("type"),
		Value: request.FormValue("value"), TTL: uint32(ttl),
	}, nil
}

// consoleRecordUpdate reads the record edit form, which always sends every
// field.
func consoleRecordUpdate(request *http.Request) (recordUpdate, error) {
	key, err := consoleRecordKey(request)
	if err != nil {
		return recordUpdate{}, err
	}
	recordType := strings.ToUpper(strings.TrimSpace(key.Type))
	key.Type = recordType
	ttl, err := formTTL(request.FormValue("new_ttl"), 0)
	if err != nil {
		return recordUpdate{}, err
	}
	value, err := zoneRecordValueFromForm(request, recordType, "new_")
	if err != nil {
		return recordUpdate{}, err
	}
	expiresAt, err := formExpiry(request.FormValue("new_expiry_ttl"), time.Now())
	if err != nil {
		return recordUpdate{}, err
	}
	name, comment, glue := request.FormValue("new_name"), request.FormValue("new_comments"), request.FormValue("new_glue_addresses")
	enabled := recordType == "SOA" || request.FormValue("enabled") == "true"
	return recordUpdate{
		Key: key, Name: &name, Value: &value, TTL: &ttl, Comment: &comment,
		Enabled: &enabled, ExpiresAt: &expiresAt, Glue: &glue,
	}, nil
}

func zoneRecordValueFromForm(request *http.Request, recordType, prefix string) (string, error) {
	form := &recordForm{request: request, prefix: prefix}
	switch recordType {
	case "A", "AAAA":
		address := form.required("value", map[string]string{"A": "IPv4 address", "AAAA": "IPv6 address"}[recordType])
		if form.err != nil {
			return "", form.err
		}
		parsed, err := netip.ParseAddr(address)
		if err != nil || (recordType == "A" && !parsed.Is4()) || (recordType == "AAAA" && !parsed.Is6()) {
			return "", fmt.Errorf("%s is not a valid %s address", address, recordType)
		}
		return parsed.String(), nil
	case "CNAME", "ANAME", "DNAME", "NS", "PTR":
		return form.value(form.required("value", map[string]string{
			"CNAME": "target host", "ANAME": "target host", "DNAME": "target host", "NS": "name server", "PTR": "domain name",
		}[recordType]))
	case "MX":
		return form.value(form.unsigned("preference", "priority", "10", 16), form.required("exchange", "mail server"))
	case "TXT":
		return form.value(quoteDNSString(form.required("text", "text value")))
	case "SRV":
		return form.value(
			form.unsigned("priority", "priority", "0", 16), form.unsigned("weight", "weight", "0", 16),
			form.unsigned("port", "port", "", 16), form.required("target", "target host"),
		)
	case "CAA":
		return form.value(
			form.unsigned("flags", "flags", "0", 8), form.required("tag", "tag"),
			quoteDNSString(form.required("ca_domain", "CA domain")),
		)
	case "DS":
		return form.value(
			form.unsigned("key_tag", "key tag", "", 16), form.unsigned("algorithm", "algorithm", "13", 8),
			form.unsigned("digest_type", "digest type", "2", 8), form.required("digest", "digest"),
		)
	case "SSHFP":
		return form.value(
			form.unsigned("algorithm", "algorithm", "4", 8), form.unsigned("fingerprint_type", "fingerprint type", "2", 8),
			form.required("fingerprint", "fingerprint"),
		)
	case "TLSA":
		return form.value(
			form.unsigned("certificate_usage", "certificate usage", "3", 8), form.unsigned("selector", "selector", "1", 8),
			form.unsigned("matching_type", "matching type", "1", 8), form.required("certificate", "certificate association data"),
		)
	case "SVCB", "HTTPS":
		return form.serviceBinding()
	case "URI":
		return form.value(
			form.unsigned("uri_priority", "priority", "0", 16), form.unsigned("uri_weight", "weight", "0", 16),
			quoteDNSString(form.required("uri", "URI")),
		)
	case "NAPTR":
		return form.naptr()
	case "SOA":
		return form.soa()
	case "FWD":
		return form.forwarder()
	default:
		return form.value(form.required("value", "record value"))
	}
}

// recordForm reads one record's typed fields from the record editor. The
// first problem sticks: later reads return "" and value reports it, so a
// record's fields can be read in a row and checked once.
type recordForm struct {
	request *http.Request
	prefix  string
	err     error
}

func (form *recordForm) field(name string) string {
	return strings.TrimSpace(form.request.FormValue(form.prefix + name))
}

func (form *recordForm) required(name, label string) string {
	if form.err != nil {
		return ""
	}
	value := form.field(name)
	if value == "" {
		form.err = fmt.Errorf("%s is required", label)
	}
	return value
}

// unsigned reads an unsigned integer of the given size, using fallback when
// the field is blank.
func (form *recordForm) unsigned(name, label, fallback string, bits int) string {
	if form.err != nil {
		return ""
	}
	value := form.field(name)
	if value == "" {
		value = fallback
	}
	if _, err := strconv.ParseUint(value, 10, bits); err != nil {
		form.err = fmt.Errorf("%s must be an unsigned integer", label)
		return ""
	}
	return value
}

// value joins the record's fields with spaces, or reports the first problem
// reading them.
func (form *recordForm) value(fields ...string) (string, error) {
	if form.err != nil {
		return "", form.err
	}
	return strings.Join(fields, " "), nil
}

func (form *recordForm) serviceBinding() (string, error) {
	priority, target := form.unsigned("svc_priority", "priority", "1", 16), form.required("svc_target", "target name")
	if form.err != nil {
		return "", form.err
	}
	params, err := zoneServiceParameters(form.field("svc_params"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(priority + " " + target + " " + params), nil
}

func (form *recordForm) naptr() (string, error) {
	order, preference := form.unsigned("naptr_order", "order", "0", 16), form.unsigned("naptr_preference", "preference", "0", 16)
	replacement := form.field("naptr_replacement")
	if replacement == "" {
		replacement = "."
	}
	return form.value(
		order, preference, quoteDNSString(form.field("naptr_flags")), quoteDNSString(form.field("naptr_services")),
		quoteDNSString(form.field("naptr_regexp")), replacement,
	)
}

func (form *recordForm) soa() (string, error) {
	primaryNS := form.required("primary_ns", "primary name server")
	if form.err != nil {
		return "", form.err
	}
	normalizedNS, err := dnsname.Normalize(primaryNS)
	if err != nil {
		return "", fmt.Errorf("primary name server: %w", err)
	}
	responsible, err := soaResponsibleName(form.field("responsible"))
	if err != nil {
		return "", err
	}
	return form.value(
		dns.Fqdn(normalizedNS), responsible,
		form.unsigned("serial", "serial", "1", 32), form.unsigned("refresh", "refresh", "3600", 32),
		form.unsigned("retry", "retry", "600", 32), form.unsigned("expire", "expire", "1209600", 32),
		form.unsigned("minimum", "minimum TTL", "300", 32),
	)
}

func (form *recordForm) forwarder() (string, error) {
	address, priority := form.required("fwd_address", "forwarder address"), form.unsigned("fwd_priority", "priority", "0", 16)
	if form.err != nil {
		return "", form.err
	}
	forwarder, err := forwarding.NewRecord(form.field("fwd_protocol"), priority, address)
	if err != nil {
		return "", err
	}
	return forwarder.String(), nil
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
