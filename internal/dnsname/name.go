package dnsname

import (
	"errors"
	"net"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

func Normalize(name string) (string, error) {
	name = strings.Trim(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return "", errors.New("domain name is empty")
	}
	if net.ParseIP(name) != nil {
		return "", errors.New("IP address is not a domain name")
	}
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", err
	}
	if _, valid := dns.IsDomainName(dns.Fqdn(ascii)); !valid {
		return "", errors.New("invalid DNS name")
	}
	return ascii, nil
}

// NormalizeOwner normalizes a DNS owner name while allowing service labels
// such as _https._tcp and a leading wildcard. Those labels are valid in DNS
// records even though they are not valid host names under IDNA lookup rules.
func NormalizeOwner(name string) (string, error) {
	name = strings.Trim(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return "", errors.New("DNS owner name is empty")
	}
	if net.ParseIP(name) != nil {
		return "", errors.New("IP address is not a DNS owner name")
	}
	labels := strings.Split(name, ".")
	for index, label := range labels {
		if label == "*" || strings.Contains(label, "_") {
			if !isASCII(label) {
				return "", errors.New("service and wildcard labels must use ASCII characters")
			}
			continue
		}
		ascii, err := idna.Lookup.ToASCII(label)
		if err != nil {
			return "", err
		}
		labels[index] = ascii
	}
	normalized := strings.Join(labels, ".")
	if _, valid := dns.IsDomainName(dns.Fqdn(normalized)); !valid {
		return "", errors.New("invalid DNS owner name")
	}
	return normalized, nil
}

func isASCII(value string) bool {
	for _, character := range value {
		if character > 127 {
			return false
		}
	}
	return true
}
