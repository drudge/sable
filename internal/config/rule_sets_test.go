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
		{Name: "Kids", Lists: []string{"Strict", "Ads"}, AllowedDomains: []string{"*.School.Example"}, Apps: []string{" youtube", "tiktok", "youtube"}},
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
		!slices.Equal(blocking.RuleSets[0].Apps, []string{"tiktok", "youtube"}) ||
		!slices.Equal(blocking.RuleSets[1].Domains, []string{"tracker.example"}) || configuration.Clients[0].RuleSet != "Kids" {
		t.Fatalf("normalized rule sets = %+v, clients = %+v", blocking.RuleSets, configuration.Clients)
	}
	cloned := cloneConfig(configuration)
	cloned.Blocking.RuleSets[0].Lists[0] = "changed"
	cloned.Blocking.RuleSets[0].Apps[0] = "changed"
	if configuration.Blocking.RuleSets[0].Lists[0] != "Ads" || configuration.Blocking.RuleSets[0].Apps[0] != "tiktok" {
		t.Fatal("Clone shared a rule set's lists or apps")
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
		{func(c *Config) { c.Blocking.RuleSets[0].Apps = []string{"YouTube"} }, `rule_sets[0].apps[0] names no app called "YouTube"`},
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

func TestSaveAndDeleteRuleSetsCarryTheirDevices(t *testing.T) {
	t.Parallel()
	configuration := Defaults()
	configuration.Blocking.Lists = []BlockList{{Name: "Ads", Path: "ads.txt"}}
	configuration.Blocking.RuleSets = []RuleSet{{Name: "Kids", Lists: []string{"Ads"}}}
	configuration.Clients = []Client{
		{MAC: "da:a1:19:00:00:01", Name: "Emma's iPad", RuleSet: "Kids"},
		{Address: "192.0.2.20", RuleSet: "Kids"},
		{Address: "192.0.2.30", Name: "Printer"},
	}

	if err := configuration.SaveRuleSet("", RuleSet{Name: " Work "}); err != nil || configuration.Blocking.RuleSets[1].Name != "Work" {
		t.Fatalf("SaveRuleSet(new) = %v, sets %+v", err, configuration.Blocking.RuleSets)
	}
	if err := configuration.SaveRuleSet("", RuleSet{Name: "kids"}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("SaveRuleSet(duplicate) = %v", err)
	}
	if err := configuration.SaveRuleSet("Guests", RuleSet{Name: "Guests"}); err == nil || !strings.Contains(err.Error(), "no rule set") {
		t.Fatalf("SaveRuleSet(missing) = %v", err)
	}
	if err := configuration.SaveRuleSet("", RuleSet{Name: "Default"}); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("SaveRuleSet(Default) = %v", err)
	}
	// A rename keeps the devices; renaming to its own name in another case is fine.
	if err := configuration.SaveRuleSet("Kids", RuleSet{Name: "Children", Domains: []string{"games.example"}}); err != nil {
		t.Fatal(err)
	}
	if configuration.Clients[0].RuleSet != "Children" || configuration.Clients[1].RuleSet != "Children" || configuration.Blocking.RuleSets[0].Domains[0] != "games.example" {
		t.Fatalf("after rename: clients %+v, sets %+v", configuration.Clients, configuration.Blocking.RuleSets)
	}
	configuration.normalize()
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}

	if err := configuration.DeleteRuleSet("Children"); err != nil {
		t.Fatal(err)
	}
	// The address entry said only which rule set it used, so it goes.
	if len(configuration.Clients) != 2 || slices.ContainsFunc(configuration.Clients, func(client Client) bool { return client.RuleSet != "" }) ||
		len(configuration.Blocking.RuleSets) != 1 {
		t.Fatalf("after delete: clients %+v, sets %+v", configuration.Clients, configuration.Blocking.RuleSets)
	}
	if err := configuration.DeleteRuleSet("Children"); err == nil {
		t.Fatal("DeleteRuleSet() deleted a rule set twice")
	}
}

func TestRemoveListLeavesRuleSetsValid(t *testing.T) {
	t.Parallel()
	blocking := Blocking{
		Lists:        []BlockList{{Name: "Ads"}, {Name: "Strict"}},
		DefaultLists: []string{"Ads", "Strict"},
		RuleSets:     []RuleSet{{Name: "Kids", Lists: []string{"Ads", "Strict"}}},
	}
	// The manager hands out shared slices, so the change must not write to them.
	shared := blocking.RuleSets
	if err := blocking.RemoveList("Strict"); err != nil {
		t.Fatal(err)
	}
	if len(blocking.Lists) != 1 || !slices.Equal(blocking.DefaultLists, []string{"Ads"}) || !slices.Equal(blocking.RuleSets[0].Lists, []string{"Ads"}) {
		t.Fatalf("after RemoveList: %+v", blocking)
	}
	if !slices.Equal(shared[0].Lists, []string{"Ads", "Strict"}) {
		t.Fatal("RemoveList changed a rule set it was given")
	}
	// Removing the default policy's only list would turn every list on.
	if err := blocking.RemoveList("Ads"); err == nil || !strings.Contains(err.Error(), "only block list") {
		t.Fatalf("RemoveList(only default) = %v", err)
	}
	if err := blocking.RemoveList("Missing"); err == nil {
		t.Fatal("RemoveList() removed a list that isn't there")
	}
}

func TestBypassClientsMoveIntoARuleSetWithBlockingOff(t *testing.T) {
	t.Parallel()
	loaded, err := Decode(strings.NewReader(`
[blocking]
bypass_clients = [" 10.0.0.0/8 ", "192.0.2.1", "10.0.0.0/8"]

[[blocking.rule_sets]]
name = "No Blocking"
lists = []

[[blocking.rule_sets]]
name = "Kids"
lists = []

[[clients]]
address = "192.0.2.1"
name = "Printer"
rule_set = "Kids"
`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	blocking := loaded.Blocking
	if len(blocking.BypassClients) != 0 {
		t.Fatalf("bypass clients = %v, want them moved", blocking.BypassClients)
	}
	// The operator's own "No Blocking" keeps blocking on, so the bypass takes
	// the next free name.
	index := slices.IndexFunc(blocking.RuleSets, func(set RuleSet) bool { return set.Name == "No Blocking 2" })
	if index < 0 || !blocking.RuleSets[index].Off {
		t.Fatalf("rule sets = %+v, want No Blocking 2 with blocking off", blocking.RuleSets)
	}
	want := []Client{
		{Address: "10.0.0.0/8", RuleSet: "No Blocking 2"},
		{Address: "192.0.2.1", Name: "Printer", RuleSet: "No Blocking 2"},
	}
	if !slices.Equal(loaded.Clients, want) {
		t.Fatalf("clients = %+v, want %+v", loaded.Clients, want)
	}

	// Saved again, the old key is gone and nothing moves twice.
	saved, err := Marshal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(saved), "bypass_clients") {
		t.Fatalf("saved configuration still has bypass_clients:\n%s", saved)
	}
	reloaded, err := Decode(strings.NewReader(string(saved)))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(reloaded.Clients, want) || len(reloaded.Blocking.RuleSets) != 3 {
		t.Fatalf("reloaded clients = %+v, rule sets = %+v", reloaded.Clients, reloaded.Blocking.RuleSets)
	}
}
