package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/drudge/sable/internal/insights/services"
)

// maximumRuleSetNameLength bounds a rule set's name so it fits the console's
// tables and drawers, as a device name does.
const maximumRuleSetNameLength = maximumClientNameLength

// DefaultRuleSetName is what the console calls the policy for devices without
// a rule set. No rule set may take it.
const DefaultRuleSetName = "Default"

// NoBlockingRuleSetName is the rule set the old bypass_clients move into.
const NoBlockingRuleSetName = "No Blocking"

// RuleSet is a blocking policy that devices join through their [[clients]]
// entry. The operator's own blocked and allowed domains apply to every rule
// set; a rule set picks its block lists and adds domains of its own, which
// win over the global ones.
type RuleSet struct {
	Name string `toml:"name"`
	// Off turns blocking off for the rule set's devices: no block list or
	// blocked domain applies to them, though a hold still does. The rule set
	// keeps its lists and domains for when blocking is turned back on.
	Off            bool     `toml:"off,omitempty"`
	Lists          []string `toml:"lists"`
	Domains        []string `toml:"domains,omitempty"`
	AllowedDomains []string `toml:"allowed_domains,omitempty"`
	// Apps are apps from the catalog Insights names apps by, such as
	// "youtube". Each blocks every domain the app owns, as if it were one of
	// the rule set's own blocked domains.
	Apps []string `toml:"apps,omitempty"`
}

func cloneRuleSets(sets []RuleSet) []RuleSet {
	if sets == nil {
		return nil
	}
	cloned := make([]RuleSet, len(sets))
	for index, set := range sets {
		cloned[index] = RuleSet{
			Name:           set.Name,
			Off:            set.Off,
			Lists:          append([]string(nil), set.Lists...),
			Domains:        append([]string(nil), set.Domains...),
			AllowedDomains: append([]string(nil), set.AllowedDomains...),
			Apps:           append([]string(nil), set.Apps...),
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
		set.Apps = sortedUnique(set.Apps)
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
		for appIndex, app := range set.Apps {
			if _, found := services.Find(app); !found {
				validationErrors = append(validationErrors, fmt.Errorf("%s.apps[%d] names no app called %q", field, appIndex, app))
			}
		}
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

// SaveRuleSet adds a rule set, or replaces the one called original. A rename
// carries the rule set's devices with it.
func (configuration *Config) SaveRuleSet(original string, set RuleSet) error {
	set.Name = strings.TrimSpace(set.Name)
	if err := validateRuleSetName("rule set", set.Name); err != nil {
		return err
	}
	sets := configuration.Blocking.RuleSets
	index := -1
	if original != "" {
		index = slices.IndexFunc(sets, func(existing RuleSet) bool { return existing.Name == original })
		if index < 0 {
			return fmt.Errorf("no rule set is called %q", original)
		}
	}
	for position, existing := range sets {
		if position != index && strings.EqualFold(existing.Name, set.Name) {
			return fmt.Errorf("a rule set called %q already exists", existing.Name)
		}
	}
	sets = cloneRuleSets(sets)
	if index < 0 {
		sets = append(sets, set)
	} else {
		sets[index] = set
		configuration.renameClientRuleSet(original, set.Name)
	}
	configuration.Blocking.RuleSets = sets
	return nil
}

// DeleteRuleSet removes a rule set. Its devices go back to the default
// policy, and an entry with nothing else to say about its device goes too.
func (configuration *Config) DeleteRuleSet(name string) error {
	index := slices.IndexFunc(configuration.Blocking.RuleSets, func(set RuleSet) bool { return set.Name == name })
	if index < 0 {
		return fmt.Errorf("no rule set is called %q", name)
	}
	configuration.Blocking.RuleSets = slices.Delete(cloneRuleSets(configuration.Blocking.RuleSets), index, index+1)
	configuration.renameClientRuleSet(name, "")
	return nil
}

// renameClientRuleSet moves every device in one rule set to another, or to
// none when to is empty.
func (configuration *Config) renameClientRuleSet(from, to string) {
	if from == to {
		return
	}
	clients := make([]Client, 0, len(configuration.Clients))
	for _, client := range configuration.Clients {
		if client.RuleSet == from {
			client.RuleSet = to
			if client.Name == "" && client.Type == "" && client.RuleSet == "" {
				continue
			}
		}
		clients = append(clients, client)
	}
	configuration.Clients = clients
}

// RemoveList removes a block list, and takes it out of every rule set and
// the default policy. It refuses to remove the default policy's only list,
// since no lists there means every list.
func (settings *Blocking) RemoveList(name string) error {
	index := slices.IndexFunc(settings.Lists, func(list BlockList) bool { return list.Name == name })
	if index < 0 {
		return errors.New("block list was not found")
	}
	if len(settings.DefaultLists) == 1 && settings.DefaultLists[0] == name {
		return fmt.Errorf("%s is the only block list for devices without a rule set; choose another in Rule Sets first", name)
	}
	settings.Lists = slices.Delete(slices.Clone(settings.Lists), index, index+1)
	settings.DefaultLists = slices.DeleteFunc(slices.Clone(settings.DefaultLists), func(list string) bool { return list == name })
	settings.RuleSets = cloneRuleSets(settings.RuleSets)
	for position := range settings.RuleSets {
		set := &settings.RuleSets[position]
		set.Lists = slices.DeleteFunc(set.Lists, func(list string) bool { return list == name })
	}
	return nil
}

// migrateBypassClients moves the old bypass_clients into a rule set with
// blocking off, one [[clients]] entry per address or network, so there is one
// way to turn blocking off for a device. A bypass used to win over a rule set
// that named the same address, so the entry moves to the new rule set. An
// entry Sable cannot read stays behind for validation to report.
func (configuration *Config) migrateBypassClients() {
	if len(configuration.Blocking.BypassClients) == 0 {
		return
	}
	name := configuration.Blocking.noBlockingRuleSet()
	var unreadable []string
	for _, entry := range uniqueTrimmed(configuration.Blocking.BypassClients) {
		clients, err := SetClientRuleSet(configuration.Clients, Client{Address: entry, RuleSet: name})
		if err != nil {
			unreadable = append(unreadable, entry)
			continue
		}
		configuration.Clients = clients
	}
	configuration.Blocking.BypassClients = unreadable
}

// noBlockingRuleSet returns the name of a rule set with blocking off for the
// old bypass clients, adding one when there is none by that name.
func (settings *Blocking) noBlockingRuleSet() string {
	name := NoBlockingRuleSetName
	for suffix := 2; ; suffix++ {
		index := slices.IndexFunc(settings.RuleSets, func(set RuleSet) bool { return strings.EqualFold(set.Name, name) })
		if index < 0 {
			settings.RuleSets = append(cloneRuleSets(settings.RuleSets), RuleSet{Name: name, Off: true})
			return name
		}
		if settings.RuleSets[index].Off {
			return settings.RuleSets[index].Name
		}
		name = fmt.Sprintf("%s %d", NoBlockingRuleSetName, suffix)
	}
}
