package blocking

import (
	"slices"
	"strings"

	"github.com/drudge/sable/internal/dnsname"
)

// AllowRules applies the configured allowed domains the way the resolver does
// at query time: a plain entry allows exactly that name, and a "*." entry
// allows every name below it but not the name it is written against.
type AllowRules struct {
	exact    map[string]struct{}
	wildcard map[string]struct{}
}

// NewAllowRules normalizes the configured allowed domains. Entries the
// resolver would reject are skipped here too.
func NewAllowRules(domains []string) AllowRules {
	rules := AllowRules{exact: map[string]struct{}{}, wildcard: map[string]struct{}{}}
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		wildcard := strings.HasPrefix(domain, "*.")
		normalized, err := dnsname.Normalize(strings.TrimPrefix(domain, "*."))
		if err != nil || normalized == "" {
			continue
		}
		if wildcard {
			rules.wildcard[normalized] = struct{}{}
		} else {
			rules.exact[normalized] = struct{}{}
		}
	}
	return rules
}

// Empty reports whether no domain is allowed.
func (rules AllowRules) Empty() bool { return len(rules.exact) == 0 && len(rules.wildcard) == 0 }

// Exact returns the names allowed one at a time, sorted.
func (rules AllowRules) Exact() []string { return sortedKeys(rules.exact) }

// Suffixes returns the domains whose subdomains are allowed, sorted.
func (rules AllowRules) Suffixes() []string { return sortedKeys(rules.wildcard) }

// Match returns the rule that allows a name as it is written in the
// configuration, or an empty string when no rule does. Exact rules win, just as
// they do when a query is answered.
func (rules AllowRules) Match(name string) string {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if _, found := rules.exact[name]; found {
		return name
	}
	for {
		_, rest, cut := strings.Cut(name, ".")
		if !cut || rest == "" {
			return ""
		}
		if _, found := rules.wildcard[rest]; found {
			return "*." + rest
		}
		name = rest
	}
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
