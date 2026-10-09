package main

import (
	"slices"

	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/config"
)

// applyPrimaryFixture turns a default configuration into Vandelay Industries'
// resolver: the block lists the office subscribes to, the domains it blocks by
// hand, and the UniFi networks it publishes as DNS.
func applyPrimaryFixture(configuration *config.Config, controllerURL string) {
	configuration.Resolver.Routes = []config.ForwardRoute{{
		Domain:     "partners.kruger-industrial.com",
		Forwarders: []string{"10.20.10.20:53"},
	}}
	configuration.Blocking = blockingFixture()
	configuration.Clients = slices.Clone(ruleSetClients)
	configuration.UniFi = unifiFixture(controllerURL)
}

func blockingFixture() config.Blocking {
	blocking := config.Defaults().Blocking
	blocking.Enabled = true
	blocking.Domains = blockedDomains
	blocking.AllowedDomains = allowedDomains
	blocking.RuleSets = slices.Clone(ruleSetsFixture)
	blocking.Lists = make([]config.BlockList, 0, len(blockListSources))
	for _, source := range blockListSources {
		blocking.Lists = append(blocking.Lists, config.BlockList{
			Name:   source.Name,
			URL:    source.URL,
			Path:   blockcompiler.CachePath(source.URL),
			Format: "auto",
		})
	}
	return blocking
}

func unifiFixture(controllerURL string) config.UniFi {
	settings := config.UniFi{
		Enabled:       true,
		ControllerURL: controllerURL,
		Site:          "default",
		Interval:      config.Duration{Duration: unifiSyncInterval},
		Sources:       []string{"reservations", "active"},
	}
	for _, network := range unifiNetworks {
		// A network without a zone is discovered but deliberately left
		// unpublished, which is what Vandelay does with its guest network.
		if network.Zone == "" {
			continue
		}
		settings.Networks = append(settings.Networks, config.UniFiNetwork{
			ID:               network.ID,
			Name:             network.Name,
			Zone:             network.Zone,
			HostnameTemplate: "{{host}}.{{zone}}",
			TTL:              300,
			Reverse:          true,
			Enabled:          true,
		})
	}
	return settings
}

// ruleSetsFixture gives the warehouse floor, the IoT gear, and guests their
// own blocking, which the Rule Sets tab shows.
var ruleSetsFixture = []config.RuleSet{
	{Name: "Guests", Lists: []string{"OISD Big"}, Domains: []string{"bittorrent.com"}},
	{Name: "IoT", Lists: []string{"Steven Black Unified"}, AllowedDomains: []string{"*.ubnt.com"}},
	{Name: config.NoBlockingRuleSetName, Off: true},
	{Name: "Warehouse", Lists: []string{"AdGuard DNS Filter", "OISD Big"}, Domains: []string{"espn.com"}, Apps: []string{"netflix", "tiktok", "youtube"}},
}

// ruleSetClients puts devices in those rule sets: by hardware address, so
// UniFi's names label them, the guest network by its range, and the
// payroll server by its address.
var ruleSetClients = []config.Client{
	{MAC: "00:05:12:66:22:e1", RuleSet: "Warehouse"},
	{MAC: "00:05:12:66:22:e2", RuleSet: "Warehouse"},
	{MAC: "00:07:4d:22:07:b5", RuleSet: "Warehouse"},
	{MAC: "9c:8e:cd:33:0c:c2", RuleSet: "IoT"},
	{MAC: "9c:8e:cd:33:0c:c3", RuleSet: "IoT"},
	{MAC: "a4:cf:12:33:0c:c5", RuleSet: "IoT"},
	{Address: "10.20.40.0/24", RuleSet: "Guests"},
	{Address: "10.20.10.20", RuleSet: config.NoBlockingRuleSetName},
}
