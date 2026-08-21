package main

import (
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
	configuration.UniFi = unifiFixture(controllerURL)
}

func blockingFixture() config.Blocking {
	blocking := config.Defaults().Blocking
	blocking.Enabled = true
	blocking.Domains = blockedDomains
	blocking.AllowedDomains = allowedDomains
	blocking.BypassClients = []string{"10.20.10.20"}
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
