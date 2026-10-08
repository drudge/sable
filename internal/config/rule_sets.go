package config

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// maximumRuleSetNameLength bounds a rule set's name so it fits the console's
// tables and drawers, as a device name does.
const maximumRuleSetNameLength = maximumClientNameLength

// DefaultRuleSetName is what the console calls the policy for devices without
// a rule set. No rule set may take it.
const DefaultRuleSetName = "Default"

// RuleSet is a blocking policy that devices join through their [[clients]]
// entry. The operator's own blocked and allowed domains apply to every rule
// set; a rule set picks its block lists and adds domains of its own, which
// win over the global ones.
type RuleSet struct {
	Name           string   `toml:"name"`
	Lists          []string `toml:"lists"`
	Domains        []string `toml:"domains,omitempty"`
	AllowedDomains []string `toml:"allowed_domains,omitempty"`
}

func cloneRuleSets(sets []RuleSet) []RuleSet {
	if sets == nil {
		return nil
	}
	cloned := make([]RuleSet, len(sets))
	for index, set := range sets {
		cloned[index] = RuleSet{
			Name:           set.Name,
			Lists:          append([]string(nil), set.Lists...),
			Domains:        append([]string(nil), set.Domains...),
			AllowedDomains: append([]string(nil), set.AllowedDomains...),
		}
	}
	return cloned
}

func (settings *Blocking) normalizeRuleSets() {
	settings.DefaultLists = sortedUnique(settings.DefaultLists)
	for index := range settings.RuleSets {
		set := &settings.RuleSets[index]
		set.Name = strings.TrimSpace(set.Name)
		set.Lists = sortedUnique(set.Lists)
		set.Domains = normalizePolicyDomains(set.Domains)
		set.AllowedDomains = normalizePolicyDomains(set.AllowedDomains)
	}
	slices.SortFunc(settings.RuleSets, func(left, right RuleSet) int {
		return strings.Compare(left.Name, right.Name)
	})
}

func sortedUnique(values []string) []string {
	unique := uniqueTrimmed(values)
	slices.Sort(unique)
	return unique
}

// validateRuleSets checks each rule set's name, and that every list a rule
// set or the default policy names exists.
func (settings Blocking) validateRuleSets() []error {
	var validationErrors []error
	lists := make(map[string]struct{}, len(settings.Lists))
	for _, list := range settings.Lists {
		lists[list.Name] = struct{}{}
	}
	checkLists := func(field string, names []string) {
		for index, name := range names {
			if _, found := lists[name]; !found {
				validationErrors = append(validationErrors, fmt.Errorf("%s[%d] names no block list called %q", field, index, name))
			}
		}
	}
	checkLists("blocking.default_lists", settings.DefaultLists)
	seen := make(map[string]int, len(settings.RuleSets))
	for index, set := range settings.RuleSets {
		field := fmt.Sprintf("blocking.rule_sets[%d]", index)
		if err := validateRuleSetName(field, set.Name); err != nil {
			validationErrors = append(validationErrors, err)
		} else if previous, taken := seen[strings.ToLower(set.Name)]; taken {
			validationErrors = append(validationErrors, fmt.Errorf("%s.name %q is already used by blocking.rule_sets[%d]", field, set.Name, previous))
		} else {
			seen[strings.ToLower(set.Name)] = index
		}
		checkLists(field+".lists", set.Lists)
		validationErrors = append(validationErrors, validatePolicyDomains(field+".domains", set.Domains)...)
		validationErrors = append(validationErrors, validatePolicyDomains(field+".allowed_domains", set.AllowedDomains)...)
	}
	return validationErrors
}

func validateRuleSetName(field, name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%s.name is required", field)
	case strings.EqualFold(name, DefaultRuleSetName):
		return fmt.Errorf("%s.name %q is reserved for devices without a rule set", field, name)
	case len([]rune(name)) > maximumRuleSetNameLength:
		return fmt.Errorf("%s.name must be at most %d characters", field, maximumRuleSetNameLength)
	case strings.IndexFunc(name, unicode.IsControl) >= 0:
		return fmt.Errorf("%s.name must not contain control characters", field)
	}
	return nil
}

// validateClientRuleSets checks that every device's rule set exists.
func validateClientRuleSets(clients []Client, sets []RuleSet) []error {
	var validationErrors []error
	for index, client := range clients {
		if client.RuleSet == "" {
			continue
		}
		if !slices.ContainsFunc(sets, func(set RuleSet) bool { return set.Name == client.RuleSet }) {
			validationErrors = append(validationErrors, fmt.Errorf("clients[%d].rule_set names no rule set called %q", index, client.RuleSet))
		}
	}
	return validationErrors
}
