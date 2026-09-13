package web

import (
	"errors"
	"strings"

	"github.com/drudge/sable/internal/forwarding"
	zonemodel "github.com/drudge/sable/internal/zone"
)

func prepareCatalogForwarder(current *zonemodel.Zone) error {
	var validation *bool
	hasApexForwarder := false
	hasApexNS := false
	for index := range current.Records {
		record := &current.Records[index]
		if strings.EqualFold(record.Type, forwarding.TechnitiumForwarderType) {
			forwarder, enabled, err := forwarding.ParseTechnitiumRecord(record.Value)
			if err != nil {
				return err
			}
			if validation != nil && *validation != enabled {
				return errors.New("mixed per-record DNSSEC validation settings cannot be represented by Sable's zone-wide setting")
			}
			validation = &enabled
			record.Type = "FWD"
			record.Value = forwarder.String()
		}
		apex := record.Name == "@" || strings.EqualFold(strings.TrimSuffix(record.Name, "."), current.Name)
		hasApexForwarder = hasApexForwarder || apex && strings.EqualFold(record.Type, "FWD")
		hasApexNS = hasApexNS || apex && strings.EqualFold(record.Type, "NS")
	}
	// Authoritative zones can contain forwarding records too. Only an apex
	// forwarder without authoritative NS records identifies a Forwarder zone.
	if !hasApexForwarder || hasApexNS {
		if validation != nil {
			return errors.New("Technitium forwarding records in authoritative zones require separate migration")
		}
		return nil
	}
	current.Type = "forwarder"
	current.PrimaryServers = nil
	current.PrimaryProtocol = ""
	current.TSIGKey = ""
	if validation != nil {
		current.DNSSECValidationDisabled = !*validation
	}
	return nil
}
