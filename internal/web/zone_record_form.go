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
