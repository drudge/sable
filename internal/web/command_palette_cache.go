package web

import (
	"net/url"
	"sort"
	"sync"

	"github.com/drudge/sable/internal/web/pages"
	"github.com/drudge/sable/internal/zone"
)

// zoneRefSource is the zone manager's read that skips the deep copy Current
// makes. Callers must not change the zones it returns.
type zoneRefSource interface {
	CurrentRef() zone.Snapshot
}

// currentZonesRef returns the active zones for read-only use.
func (server *Server) currentZonesRef() zone.Snapshot {
	if source, ok := server.zones.(zoneRefSource); ok {
		return source.CurrentRef()
	}
	return server.zones.Current()
}

// commandZoneEntry holds the palette commands for one zone. The zone ID lets
// each request drop the zones its principal can't read.
type commandZoneEntry struct {
	zoneID   string
	commands []pages.CommandEntityView
}

// commandZoneCache keeps the zone commands for one zone revision. Every
// console page and fragment draws the palette, and rebuilding it means sorting
// and formatting every zone.
type commandZoneCache struct {
	mu       sync.Mutex
	valid    bool
	revision uint64
	entries  []commandZoneEntry
}

func (server *Server) commandZoneEntries() []commandZoneEntry {
	source, cacheable := server.zones.(zoneRefSource)
	if !cacheable {
		return buildCommandZoneEntries(server.zones.Current().Zones)
	}
	snapshot := source.CurrentRef()
	cache := &server.commandZones
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !cache.valid || cache.revision != snapshot.Revision {
		cache.entries = buildCommandZoneEntries(snapshot.Zones)
		cache.valid, cache.revision = true, snapshot.Revision
	}
	return cache.entries
}

func buildCommandZoneEntries(zones []zone.Zone) []commandZoneEntry {
	sorted := append([]zone.Zone(nil), zones...)
	sort.SliceStable(sorted, func(left, right int) bool { return sorted[left].Name < sorted[right].Name })
	entries := make([]commandZoneEntry, 0, len(sorted))
	for _, current := range sorted {
		description := commandZoneDescription(current.Type)
		if current.Disabled {
			description += " · Disabled"
		}
		route := "/zones/" + url.PathEscape(current.Name)
		commands := []pages.CommandEntityView{
			{
				ID: commandZoneID("command-entity-zone-", current.ID), Label: current.Name, Description: description, Icon: "globe", Kind: "Zone",
				Keywords: "dns zone " + current.Type, Href: route,
			},
			{
				ID: commandZoneID("command-entity-zone-search-", current.ID), Label: "Search in " + current.Name, Description: "Filter records in this zone", Icon: "search", Kind: "Search",
				Keywords: "dns zone records " + current.Type, Route: route, Focus: "[data-record-search]",
				SearchPrompt: "Search records in " + current.Name + "…",
			},
		}
		if current.Revision > 0 {
			commands = append(commands, pages.CommandEntityView{
				ID: commandZoneID("command-entity-zone-history-", current.ID), Label: "View history for " + current.Name, Description: "Review revisions and restore an earlier zone state", Icon: "clock", Kind: "Action",
				Keywords: "dns zone history revisions changes change control rollback restore " + current.Type,
				Route:    route, Dialog: "zone-history-dialog",
			})
		}
		entries = append(entries, commandZoneEntry{zoneID: current.ID, commands: commands})
	}
	return entries
}

// commandZoneID leaves a zone without an ID unnamed, so the palette numbers
// it by position.
func commandZoneID(prefix, zoneID string) string {
	if zoneID == "" {
		return ""
	}
	return prefix + zoneID
}
