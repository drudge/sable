package dnsserver

import (
	"fmt"
	"slices"
	"strings"

	"github.com/drudge/sable/internal/dnsname"
)

// RuleSetPolicy is a blocking policy for some clients instead of everyone. A
// client none of them name gets the global policy.
type RuleSetPolicy struct {
	Name string
	// Off turns blocking off for the set's clients.
	Off bool
	// Lists names the block-list sources that apply to the set's clients.
	Lists []string
	// Domains and AllowedDomains apply to the set's clients on top of the
	// global blocked and allowed domains, and win over them.
	Domains        []string
	AllowedDomains []string
	// Clients are the IP addresses, CIDR networks and hardware addresses the
	// set applies to.
	Clients []string
}

// ruleSet is a RuleSetPolicy compiled against the runtime's block lists.
type ruleSet struct {
	name string
	off  bool
	// applies says, for each owner set, whether any of its sources is one the
	// rule set uses. Nil means every owner set applies. sources holds, per
	// owner set, the sources the rule set uses, for attribution.
	applies []bool
	sources [][]string
	blocked map[string]uint32
	allowed allowList
}

// allowList holds allowed names: exact ones, and wildcards that allow every
// subdomain of a name but not the name itself.
type allowList struct {
	exact    map[string]struct{}
	wildcard map[string]struct{}
}

func compileAllowList(domains []string) (allowList, error) {
	list := allowList{exact: make(map[string]struct{}, len(domains)), wildcard: make(map[string]struct{}, len(domains))}
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		wildcard := strings.HasPrefix(domain, "*.")
		normalized, err := dnsname.Normalize(strings.TrimPrefix(domain, "*."))
		if err != nil {
			return allowList{}, fmt.Errorf("invalid allowed domain %q: %w", domain, err)
		}
		if wildcard {
			list.wildcard[normalized] = struct{}{}
		} else {
			list.exact[normalized] = struct{}{}
		}
	}
	return list, nil
}

// match returns the rule that allows name, or "".
func (list allowList) match(name string) string {
	if len(list.exact) == 0 && len(list.wildcard) == 0 {
		return ""
	}
	name = normalizeName(name)
	if _, found := list.exact[name]; found {
		return name
	}
	for {
		separator := strings.IndexByte(name, '.')
		if separator < 0 {
			return ""
		}
		name = name[separator+1:]
		if _, found := list.wildcard[name]; found {
			return "*." + name
		}
	}
}

// compileRuleSets builds the rule sets and the table that picks one for a
// client. Owner sets must already be in place.
func (runtime *Runtime) compileRuleSets(configuration RuntimeConfig) error {
	policies := configuration.RuleSets
	sets := make([]ruleSet, 0, len(policies))
	var clients clientTable[int]
	for index, policy := range policies {
		set, err := runtime.compileRuleSet(policy)
		if err != nil {
			return err
		}
		sets = append(sets, set)
		for _, value := range policy.Clients {
			// The first set to name a client keeps it.
			if err := clients.add(value, index); err != nil {
				return fmt.Errorf("rule set %q: invalid client %q", policy.Name, value)
			}
		}
	}
	clients.sort()
	runtime.ruleSets = sets
	runtime.ruleSetClients = clients
	runtime.defaultSet = nil
	if configuration.DefaultLists != nil {
		applies, sources := ownerSetsUsing(runtime.blockedOwners, configuration.DefaultLists)
		runtime.defaultSet = &ruleSet{applies: applies, sources: sources}
	}
	return nil
}

func (runtime *Runtime) compileRuleSet(policy RuleSetPolicy) (ruleSet, error) {
	set := ruleSet{name: policy.Name, off: policy.Off}
	if policy.Off {
		return set, nil
	}
	blocked := make(map[string]uint32, len(policy.Domains))
	for _, domain := range policy.Domains {
		normalized, err := dnsname.Normalize(strings.TrimPrefix(strings.TrimSpace(domain), "*."))
		if err != nil {
			return ruleSet{}, fmt.Errorf("rule set %q: invalid blocked domain %q: %w", policy.Name, domain, err)
		}
		blocked[normalized] = 0
	}
	allowed, err := compileAllowList(policy.AllowedDomains)
	if err != nil {
		return ruleSet{}, fmt.Errorf("rule set %q: %w", policy.Name, err)
	}
	set.blocked, set.allowed = blocked, allowed
	set.applies, set.sources = ownerSetsUsing(runtime.blockedOwners, policy.Lists)
	return set, nil
}

// ownerSetsUsing works out which owner sets a rule set using lists applies,
// and which of each one's sources it uses. Owner set zero carries no
// attribution, so a domain without any still applies everywhere.
func ownerSetsUsing(owners [][]string, lists []string) ([]bool, [][]string) {
	applies := make([]bool, max(len(owners), 1))
	sources := make([][]string, len(applies))
	applies[0] = true
	for index := 1; index < len(owners); index++ {
		var used []string
		for _, source := range owners[index] {
			if slices.Contains(lists, source) {
				used = append(used, source)
			}
		}
		if len(used) == len(owners[index]) {
			used = owners[index]
		}
		applies[index], sources[index] = len(used) > 0, used
	}
	return applies, sources
}

// ruleSetFor picks the rule set for a client. Without one it falls back to
// the default set, which is nil when every list applies.
func (runtime *Runtime) ruleSetFor(client policyClient, identified bool) *ruleSet {
	if !identified {
		return runtime.defaultSet
	}
	if index, found := runtime.ruleSetClients.lookup(client); found {
		return &runtime.ruleSets[index]
	}
	return runtime.defaultSet
}

// ownerSources names the sources behind an owner set that the rule set uses.
func (set *ruleSet) ownerSources(runtime *Runtime, owner uint32) []string {
	if set == nil || set.applies == nil {
		return runtime.blockedSources(owner)
	}
	if int(owner) >= len(set.sources) {
		return nil
	}
	return set.sources[owner]
}

// allowedRule returns the rule set's own rule that allows name, or "".
func (set *ruleSet) allowedRule(name string) string {
	if set == nil {
		return ""
	}
	return set.allowed.match(name)
}

// ownerMask is the owner sets a client's rule set applies, nil for all.
func (set *ruleSet) ownerMask() []bool {
	if set == nil {
		return nil
	}
	return set.applies
}
