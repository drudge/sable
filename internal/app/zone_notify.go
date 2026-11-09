package app

import (
	"context"
	"log/slog"
	"slices"

	"github.com/drudge/sable/internal/zone"
)

// zoneNotifier sends NOTIFY (RFC 1996 §3) for a zone to its secondaries.
type zoneNotifier interface {
	NotifyZone(context.Context, string, []string) []error
}

// zoneSerials maps each zone with an apex SOA to its serial, so a background
// writer can tell afterward which zones it changed.
func zoneSerials(zones []zone.Zone) map[string]uint32 {
	serials := make(map[string]uint32, len(zones))
	for _, current := range zones {
		if serial, ok := zone.Serial(current); ok {
			serials[current.Name] = serial
		}
	}
	return serials
}

// advancedZones lists the zones whose serial is not the one in before,
// counting a zone that did not exist before as advanced.
func advancedZones(before map[string]uint32, zones []zone.Zone) []string {
	var names []string
	for _, current := range zones {
		serial, ok := zone.Serial(current)
		if !ok {
			continue
		}
		if previous, existed := before[current.Name]; !existed || previous != serial {
			names = append(names, current.Name)
		}
	}
	return names
}

// notifyZones sends NOTIFY to the notify targets of each named zone. A
// disabled zone serves nothing, so a secondary has nothing to fetch from it.
func notifyZones(ctx context.Context, notifier zoneNotifier, zones []zone.Zone, names []string, logger *slog.Logger, why string) {
	for _, current := range zones {
		if current.Disabled || len(current.Notify) == 0 || !slices.Contains(names, current.Name) {
			continue
		}
		for _, err := range notifier.NotifyZone(ctx, current.Name, current.Notify) {
			logger.Warn("notify secondary server after "+why, "zone", current.Name, "error", err)
		}
	}
}
