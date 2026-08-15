package unifi

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/drudge/sable/internal/dnsname"
)

// DefaultHostnameTemplate keeps each network in its own subtree, which is what
// makes it safe to map several networks onto one zone.
const DefaultHostnameTemplate = "{{host}}.{{network}}.{{zone}}"

var (
	placeholderPattern = regexp.MustCompile(`{{\s*([a-z]+)\s*}}`)
	unsafeRunePattern  = regexp.MustCompile(`[^a-z0-9-]`)
	repeatedDashes     = regexp.MustCompile(`-{2,}`)
	// Apostrophes are stripped rather than replaced so "Nick's iPhone" becomes
	// "nicks-iphone" instead of "nick-s-iphone".
	apostrophePattern = regexp.MustCompile(`['\x{2018}\x{2019}]`)
)

// SanitizeLabel reduces a UniFi display name to a single DNS label. UniFi lets
// people name a device anything at all, so this is deliberately aggressive: it
// keeps letters, digits, and separating hyphens and discards everything else.
// An empty result means the name carried no usable characters.
func SanitizeLabel(value string) string {
	label := strings.ToLower(strings.TrimSpace(value))
	label = apostrophePattern.ReplaceAllString(label, "")
	label = strings.Map(func(character rune) rune {
		if character == '_' || character == ' ' || character == '\t' || character == '.' {
			return '-'
		}
		return character
	}, label)
	label = unsafeRunePattern.ReplaceAllString(label, "")
	label = repeatedDashes.ReplaceAllString(label, "-")
	label = strings.Trim(label, "-")
	if len(label) > 63 {
		label = strings.Trim(label[:63], "-")
	}
	return label
}

// Template renders the fully qualified name for a synchronized host.
type Template struct {
	text string
}

// ParseTemplate validates a hostname template. A template must place the host
// somewhere and must end in the zone, so every rendered name lands inside the
// zone Sable is authoritative for.
func ParseTemplate(text string) (Template, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		text = DefaultHostnameTemplate
	}
	for _, match := range placeholderPattern.FindAllStringSubmatch(text, -1) {
		switch match[1] {
		case "host", "network", "zone":
		default:
			return Template{}, fmt.Errorf("unknown template placeholder {{%s}}", match[1])
		}
	}
	normalized := placeholderPattern.ReplaceAllString(text, "{{$1}}")
	if !strings.Contains(normalized, "{{host}}") {
		return Template{}, errors.New("hostname template must contain {{host}}")
	}
	if !strings.HasSuffix(normalized, "{{zone}}") {
		return Template{}, errors.New("hostname template must end with {{zone}}")
	}
	stripped := strings.NewReplacer("{{host}}", "", "{{network}}", "", "{{zone}}", "").Replace(normalized)
	if strings.Trim(stripped, ".-") != "" {
		return Template{}, errors.New("hostname template may only join placeholders with dots and hyphens")
	}
	return Template{text: normalized}, nil
}

// String returns the normalized template text for persistence and display.
func (template Template) String() string {
	if template.text == "" {
		return DefaultHostnameTemplate
	}
	return template.text
}

// UsesNetwork reports whether rendered names are separated by network. Two
// networks sharing a zone need this or their hosts collide.
func (template Template) UsesNetwork() bool {
	return strings.Contains(template.String(), "{{network}}")
}

// Render produces the fully qualified name for one host. Host and network are
// sanitized first, and empty parts collapse so a network with an unusable name
// does not produce an empty label.
func (template Template) Render(host, network, zone string) (string, error) {
	hostLabel := SanitizeLabel(host)
	if hostLabel == "" {
		return "", errors.New("host name has no usable DNS characters")
	}
	zone = strings.Trim(strings.ToLower(strings.TrimSpace(zone)), ".")
	if zone == "" {
		return "", errors.New("zone is required")
	}
	replaced := strings.NewReplacer(
		"{{host}}", hostLabel,
		"{{network}}", SanitizeLabel(network),
		"{{zone}}", zone,
	).Replace(template.String())
	parts := make([]string, 0, strings.Count(replaced, ".")+1)
	for _, part := range strings.Split(replaced, ".") {
		part = strings.Trim(part, "-")
		if part != "" {
			parts = append(parts, part)
		}
	}
	return dnsname.Normalize(strings.Join(parts, "."))
}

// RelativeOwner converts a rendered name into the owner name Sable stores on a
// record, which is relative to the zone apex.
func RelativeOwner(fqdn, zone string) string {
	fqdn = strings.Trim(strings.ToLower(fqdn), ".")
	zone = strings.Trim(strings.ToLower(zone), ".")
	if fqdn == zone {
		return "@"
	}
	if trimmed := strings.TrimSuffix(fqdn, "."+zone); trimmed != fqdn {
		return trimmed
	}
	return fqdn
}
