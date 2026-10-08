package app

import (
	"slices"
	"testing"

	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/config"
)

func TestRuntimeRuleSetsJoinDevicesNamedByAddress(t *testing.T) {
	t.Parallel()
	configuration := config.Defaults()
	configuration.Blocking.RuleSets = []config.RuleSet{{Name: "Kids", Lists: []string{"Strict"}}, {Name: "Work"}}
	configuration.Clients = []config.Client{
		{Name: "Emma's iPad", MAC: "da:a1:19:00:00:01", RuleSet: "Kids"},
		{Name: "Leo's Switch", Address: "192.0.2.20", RuleSet: "Kids"},
		{Name: "Guest Wi-Fi", Address: "10.20.40.0/24", RuleSet: "Kids"},
		{Name: "Printer", Address: "192.0.2.9"},
	}
	sets := runtimeRuleSets(configuration)
	if len(sets) != 2 || sets[0].Name != "Kids" || !slices.Equal(sets[0].Clients, []string{"192.0.2.20", "10.20.40.0/24"}) {
		t.Fatalf("runtime rule sets = %+v", sets)
	}
	if !slices.Equal(sets[0].Lists, []string{"Strict", blockcompiler.CustomSourceName}) ||
		!slices.Equal(sets[1].Lists, []string{blockcompiler.CustomSourceName}) || sets[1].Clients != nil {
		t.Fatalf("rule set lists = %v and %v, want the operator's domains in each", sets[0].Lists, sets[1].Lists)
	}
	if got := defaultLists(nil); got != nil {
		t.Fatalf("defaultLists(nil) = %v, want every list", got)
	}
	if got := defaultLists([]string{"Ads"}); !slices.Equal(got, []string{"Ads", blockcompiler.CustomSourceName}) {
		t.Fatalf("defaultLists(Ads) = %v", got)
	}
}
