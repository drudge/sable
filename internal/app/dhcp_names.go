package app

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/unifi"
	"github.com/drudge/sable/internal/zone"
)

// dhcpName is one name DHCP wants published: a named reservation or an
// active lease, in the zone of the scope it belongs to.
type dhcpName struct {
	fqdn     string
	domain   string
	address  netip.Addr
	reserved bool
	boundAt  time.Time
	ttl      uint32
	// reverse is the zone its PTR goes in; empty when the scope has none.
	reverse string
}

// beats reports whether name keeps the owner name from other. A reservation
// beats a lease; between two leases the newest binding wins, not the newest
// renewal, so a device gets its name back after its private MAC rotates.
// The lower address breaks a tie so every node picks the same winner.
func (name dhcpName) beats(other dhcpName) bool {
	switch {
	case name.reserved != other.reserved:
		return name.reserved
	case !name.boundAt.Equal(other.boundAt):
		return name.boundAt.After(other.boundAt)
	}
	return name.address.Less(other.address)
}

// dhcpNamePlan is the record set DHCP wants and, for each lease that lost
// its name, the address of the winner the lease table shows as "name in use by".
type dhcpNamePlan struct {
	zones   map[string]*desiredZone
	inUseBy map[netip.Addr]netip.Addr
	// reserved holds the FQDNs of named reservations, which outrank a UniFi
	// record; a lease's name yields to one.
	reserved map[string]bool
}

// desiredDHCPRecords builds the A and PTR records DHCP publishes from the
// configuration and the known leases. The set is rebuilt from state every
// time, so a release, expiry, decline, host name change, or DHCP turned off
// all remove a record on the next reconcile and a missed event can't strand
// one. A renewal leaves the set as it was. No DHCID is written: RFC 4701 and
// RFC 4703 settle conflicts between servers that don't share state, and
// Sable owns both the leases and the zone.
func desiredDHCPRecords(settings config.DHCP, leases []store.DHCPLease, now time.Time) dhcpNamePlan {
	plan := dhcpNamePlan{
		zones: make(map[string]*desiredZone), inUseBy: make(map[netip.Addr]netip.Addr), reserved: make(map[string]bool),
	}
	if !settings.Enabled {
		return plan
	}
	winners := make(map[string]dhcpName)
	offer := func(name dhcpName) {
		held, found := winners[name.fqdn]
		if !found || name.beats(held) {
			winners[name.fqdn] = name
		}
	}
	for _, scope := range settings.Scopes {
		for _, name := range dhcpScopeNames(scope, leases, now) {
			offer(name)
		}
	}
	for _, scope := range settings.Scopes {
		for _, name := range dhcpScopeNames(scope, leases, now) {
			if winner := winners[name.fqdn]; winner.address != name.address {
				plan.inUseBy[name.address] = winner.address
			}
		}
	}
	// One PTR per address (D37): when two names still point at one address,
	// the one that would win the name also wins the PTR, so the plan never
	// holds two records for one owner and type and can't flap.
	pointers := make(map[netip.Addr]dhcpName)
	for _, name := range winners {
		if held, found := pointers[name.address]; !found || name.beats(held) {
			pointers[name.address] = name
		}
	}
	for _, name := range winners {
		plan.add(name, pointers[name.address].fqdn == name.fqdn)
	}
	for _, entry := range plan.zones {
		slices.SortFunc(entry.records, compareZoneRecords)
	}
	return plan
}

// dhcpScopeNames lists the names one scope asks for: each named reservation,
// with or without a live lease, and each active lease with a usable label.
// A lease from a MAC with a named reservation is left to the reservation. A
// lease on an address reserved for another MAC publishes nothing (D37): the
// reservation owns the address, and the lease only lasts until its client
// renews. A lease outside the scope's subnet, left over from a renumbered
// scope, publishes nothing either: its PTR belongs to no zone this scope owns.
func dhcpScopeNames(scope config.DHCPScope, leases []store.DHCPLease, now time.Time) []dhcpName {
	subnet, err := netip.ParsePrefix(scope.Subnet)
	if err != nil || !scope.Serves() || !scope.RegistersNames() || scope.Domain == "" {
		return nil
	}
	base := dhcpName{domain: scope.Domain, ttl: uint32(scope.RecordTTL() / time.Second)}
	if scope.PublishesReverse() {
		base.reverse, _ = dnsname.ReverseZone(subnet)
	}
	var names []dhcpName
	named := make(map[string]bool)
	reservedFor := make(map[netip.Addr]string)
	for _, reservation := range scope.Reservations {
		address, err := netip.ParseAddr(reservation.Address)
		if err != nil {
			continue
		}
		reservedFor[address] = strings.ToLower(reservation.MAC)
		label := dhcpLabel(reservation.Name, true)
		if label == "" {
			continue
		}
		named[strings.ToLower(reservation.MAC)] = true
		name := base
		name.fqdn, name.address, name.reserved = label+"."+scope.Domain, address, true
		names = append(names, name)
	}
	for _, lease := range leases {
		label := dhcpLabel(lease.Hostname, false)
		mac := strings.ToLower(lease.MAC)
		owner, reserved := reservedFor[lease.Address]
		if lease.ScopeID != scope.ID || label == "" || named[mac] || (reserved && owner != mac) ||
			!subnet.Contains(lease.Address) || !dhcpLeaseHolds(lease, now) {
			continue
		}
		name := base
		name.fqdn, name.address, name.boundAt = label+"."+scope.Domain, lease.Address, lease.BoundAt
		names = append(names, name)
	}
	return names
}

// dhcpRefusedLeaseLabels are names a lease never takes (D39). A client
// that calls itself wpad would become every browser's proxy auto-config host
// (WPAD), and isatap every Windows host's IPv6 tunnel router; Microsoft DNS
// blocks both by default (its global query block list). An operator can
// still give either to a reservation.
var dhcpRefusedLeaseLabels = map[string]bool{"wpad": true, "isatap": true}

// dhcpLabel cleans a lease's host name, or a reservation's name when
// reserved, to the one DNS label it publishes. Empty means it publishes
// nothing. The engine answers the client FQDN option with the same rule.
func dhcpLabel(name string, reserved bool) string {
	label := unifi.SanitizeLabel(name)
	if !reserved && dhcpRefusedLeaseLabels[label] {
		return ""
	}
	return label
}

// dhcpLeaseHolds reports whether a lease is bound to its client at now.
func dhcpLeaseHolds(lease store.DHCPLease, now time.Time) bool {
	return lease.State == store.DHCPLeaseActive && now.Before(lease.ExpiresAt)
}

// add puts a winning name's A record in its scope's zone, and with pointer
// its PTR in the reverse zone when the scope publishes one (RFC 1035 §3.5).
func (plan dhcpNamePlan) add(name dhcpName, pointer bool) {
	if name.reserved {
		plan.reserved[name.fqdn] = true
	}
	forward := plan.ensure(name.domain, name.ttl)
	forward.records = append(forward.records, zone.Record{
		Name: unifi.RelativeOwner(name.fqdn, name.domain), Type: "A",
		Value: name.address.String(), TTL: name.ttl, Source: zone.SourceDHCP,
	})
	if !pointer || name.reverse == "" {
		return
	}
	owner, err := dnsname.ReverseName(name.address)
	if err != nil {
		return
	}
	reverse := plan.ensure(name.reverse, name.ttl)
	reverse.records = append(reverse.records, zone.Record{
		Name: unifi.RelativeOwner(owner, name.reverse), Type: "PTR",
		Value: name.fqdn + ".", TTL: name.ttl, Source: zone.SourceDHCP,
	})
}

func (plan dhcpNamePlan) ensure(name string, ttl uint32) *desiredZone {
	entry, found := plan.zones[name]
	if !found {
		entry = &desiredZone{name: name, ttl: ttl}
		plan.zones[name] = entry
	}
	return entry
}

func compareZoneRecords(left, right zone.Record) int {
	return compareUniFiPlanRecords(planRecord("", left), planRecord("", right))
}

// planDHCPZones writes the wanted DHCP records into the zone list and reports
// what changed. The collision order is: a hand-authored record, then a
// reservation, then a UniFi record, then a lease. Records with another
// source are never touched. Forward zones go first so a PTR is published only
// for a name that got its address (RFC 1912 §2.1). Every zone the plan no
// longer covers loses its DHCP records, so turning DHCP off or moving a scope
// to another domain leaves nothing behind. A zone whose records didn't change
// keeps its serial, so a renewal never publishes a revision.
func planDHCPZones(zones *[]zone.Zone, wanted dhcpNamePlan, now time.Time) unifi.Plan {
	var plan unifi.Plan
	forwardNames, reverseNames := splitUniFiZoneNames(wanted.zones)
	published := make(map[string]bool)
	for _, name := range forwardNames {
		entry := wanted.zones[name]
		target := writableUniFiZone(zones, entry, true, now, &plan)
		if target == nil {
			continue
		}
		records := unclaimedUniFiRecords(*target, entry.records, now, &plan)
		records = wanted.yieldToUniFi(*target, records, &plan)
		for _, record := range records {
			if fqdn, err := zone.RecordFQDN(name, record.Name); err == nil {
				published[fqdn] = true
			}
		}
		publishSourcedRecords(target, records, zone.SourceDHCP, now, &plan)
	}
	for _, name := range reverseNames {
		entry := wanted.zones[name]
		records := publishedPTRs(entry.records, published)
		if target := writableUniFiZone(zones, entry, len(records) > 0, now, &plan); target != nil {
			publishSourcedRecords(target, records, zone.SourceDHCP, now, &plan)
		}
	}
	for index := range *zones {
		target := &(*zones)[index]
		if _, covered := wanted.zones[target.Name]; !covered && zone.AcceptsDynamicUpdates(target.Type) {
			publishSourcedRecords(target, nil, zone.SourceDHCP, now, &plan)
		}
	}
	return plan
}

// yieldToUniFi drops each lease's record whose name a UniFi record already
// answers. A reservation's record stays: it outranks UniFi, and the UniFi
// sync leaves that name to it.
func (wanted dhcpNamePlan) yieldToUniFi(target zone.Zone, records []zone.Record, plan *unifi.Plan) []zone.Record {
	unifiNames := make(map[string]bool)
	for _, record := range target.Records {
		if record.Source != zone.SourceUniFi {
			continue
		}
		if fqdn, err := zone.RecordFQDN(target.Name, record.Name); err == nil {
			unifiNames[fqdn] = true
		}
	}
	return slices.DeleteFunc(records, func(record zone.Record) bool {
		fqdn, err := zone.RecordFQDN(target.Name, record.Name)
		if err != nil || wanted.reserved[fqdn] || !unifiNames[fqdn] {
			return false
		}
		plan.Skipped = append(plan.Skipped, fqdn+" already has a UniFi record")
		return true
	})
}

// dhcpServed reports whether this node serves the DHCP settings, given its
// cluster role for DHCP (dhcpClusterRole): enabled, and outside a cluster
// (D32). DHCP's names publish, and the UniFi sync yields to them, only where
// this holds (D38). Slice 8 changes only this predicate.
func dhcpServed(settings config.DHCP, role string) bool {
	return settings.Enabled && role == ""
}

// dhcpServedSettings returns the settings when this node serves them, and
// DHCP turned off otherwise, so a node that doesn't serve DHCP removes its
// names as it would with DHCP off.
func dhcpServedSettings(settings config.DHCP, role func() string) config.DHCP {
	current := ""
	if role != nil {
		current = role()
	}
	if !dhcpServed(settings, current) {
		return config.DHCP{}
	}
	return settings
}

// dhcpReservedNames lists the FQDNs named reservations publish, for the UniFi
// sync to leave alone.
func dhcpReservedNames(settings config.DHCP) map[string]bool {
	names := make(map[string]bool)
	if !settings.Enabled {
		return names
	}
	for _, scope := range settings.Scopes {
		for _, name := range dhcpScopeNames(scope, nil, time.Time{}) {
			names[name.fqdn] = true
		}
	}
	return names
}
