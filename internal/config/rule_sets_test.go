package config

import (
	"slices"
	"strings"
	"testing"
)

func TestRuleSetsValidateAndNormalize(t *testing.T) {
	t.Parallel()
	configuration := Defaults()
	configuration.Blocking.Lists = []BlockList{{Name: "Ads", Path: "ads.txt"}, {Name: "Strict", Path: "strict.txt"}}
	configuration.Blocking.DefaultLists = []string{" Ads ", "Ads"}
	configuration.Blocking.RuleSets = []RuleSet{
		{Name: " Work ", Domains: []string{"Tracker.Example."}},
		{Name: "Kids", Lists: []string{"Strict", "Ads"}, AllowedDomains: []string{"*.School.Example"}},
	}
	configuration.Clients = []Client{{MAC: "da:a1:19:00:00:01", RuleSet: " Kids "}}
	configuration.normalize()
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
	blocking := configuration.Blocking
	if !slices.Equal(blocking.DefaultLists, []string{"Ads"}) || blocking.RuleSets[0].Name != "Kids" ||
		!slices.Equal(blocking.RuleSets[0].Lists, []string{"Ads", "Strict"}) ||
		!slices.Equal(blocking.RuleSets[0].AllowedDomains, []string{"*.school.example"}) ||
		!slices.Equal(blocking.RuleSets[1].Domains, []string{"tracker.example"}) || configuration.Clients[0].RuleSet != "Kids" {
		t.Fatalf("normalized rule sets = %+v, clients = %+v", blocking.RuleSets, configuration.Clients)
	}
	cloned := cloneConfig(configuration)
	cloned.Blocking.RuleSets[0].Lists[0] = "changed"
	if configuration.Blocking.RuleSets[0].Lists[0] != "Ads" {
		t.Fatal("Clone shared a rule set's lists")
	}

	for _, test := range []struct {
		change func(*Config)
		want   string
	}{
		{func(c *Config) { c.Blocking.RuleSets = append(c.Blocking.RuleSets, RuleSet{}) }, "rule_sets[2].name is required"},
		{func(c *Config) { c.Blocking.RuleSets[1].Name = "default" }, "reserved"},
		{func(c *Config) { c.Blocking.RuleSets[1].Name = "kids" }, `"kids" is already used`},
		{func(c *Config) { c.Blocking.RuleSets[0].Lists = []string{"Missing"} }, `names no block list called "Missing"`},
		{func(c *Config) { c.Blocking.DefaultLists = []string{"Missing"} }, "blocking.default_lists[0]"},
		{func(c *Config) { c.Blocking.RuleSets[0].Domains = []string{"bad..example"} }, "rule_sets[0].domains[0]"},
		{func(c *Config) { c.Clients[0].RuleSet = "Guests" }, `names no rule set called "Guests"`},
	} {
		candidate := cloneConfig(configuration)
		test.change(&candidate)
		if err := candidate.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("Validate() error = %v, want %q", err, test.want)
		}
	}
}

func TestClientWithOnlyRuleSetIsKept(t *testing.T) {
	t.Parallel()
	clients := []Client{{Address: "192.0.2.20", Name: "Switch", RuleSet: "Kids"}}
	updated, err := SetClientName(clients, Client{Address: "192.0.2.20"})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 1 || updated[0].RuleSet != "Kids" || updated[0].Name != "" {
		t.Fatalf("clients after removing the name = %+v, want the rule set kept", updated)
	}
}
