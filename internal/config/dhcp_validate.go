package config

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/dnsname"
)

// DHCP bounds. A client retransmits its DISCOVER after 4 s randomised by
// ±1 s (RFC 2131 §4.1), so the offer delay and probe together stay under 3 s.
const (
	minimumDHCPLease      = 2 * time.Minute
	maximumDHCPLease      = 365 * 24 * time.Hour
	minimumDHCPRecordTTL  = 10 * time.Second
	maximumDHCPRecordTTL  = 24 * time.Hour
	minimumDHCPV6OnlyWait = 300 * time.Second // MIN_V6ONLY_WAIT, RFC 8925 §3.4
	maximumDHCPOfferWait  = 2 * time.Second
	maximumDHCPOfferTotal = 2500 * time.Millisecond
	maximumDHCPV6OnlyWait = math.MaxUint32 * time.Second // option 108 is 32-bit seconds
	maximumDHCPServerName = 63                           // sname is 64 octets with its NUL (RFC 2131 §2)
	maximumDHCPBootFile   = 127                          // file is 128 octets with its NUL
)

// Validate reports every problem with the DHCP settings that the file alone
// can show. Cluster membership is checked by ValidateNodes.
func (settings DHCP) Validate() error {
	return errors.Join(settings.validate()...)
}

func (settings DHCP) validate() []error {
	var problems []error
	if settings.Enabled && len(settings.Scopes) == 0 {
		problems = append(problems, errors.New("dhcp.enabled requires at least one scope"))
	}
	ids := make(map[string]int, len(settings.Scopes))
	subnets := make([]netip.Prefix, len(settings.Scopes))
	for index, scope := range settings.Scopes {
		field := fmt.Sprintf("dhcp.scopes[%d]", index)
		problems = append(problems, scope.validate(field)...)
		if key := strings.ToLower(scope.ID); key != "" {
			if first, seen := ids[key]; seen {
				problems = append(problems, fmt.Errorf("%s.id duplicates scopes[%d]", field, first))
			} else {
				ids[key] = index
			}
		}
		subnets[index], _ = netip.ParsePrefix(scope.Subnet)
		for other := range index {
			if subnets[index].IsValid() && subnets[other].IsValid() && subnets[index].Overlaps(subnets[other]) {
				problems = append(problems, fmt.Errorf("%s.subnet overlaps scopes[%d]", field, other))
			}
		}
	}
	return append(problems, validateDHCPReservationNames(settings.Scopes)...)
}

// validateDHCPReservationNames keeps a reservation name to one owner per
// domain, across scopes: each publishes name.domain, and two would race for
// the record. A scope's own duplicates are reported with its reservations.
func validateDHCPReservationNames(scopes []DHCPScope) []error {
	var problems []error
	owners := map[string]string{}
	for scopeIndex, scope := range scopes {
		domain, err := dnsname.Normalize(scope.Domain)
		if scope.Domain == "" || err != nil {
			continue
		}
		local := map[string]bool{}
		for index, reservation := range scope.Reservations {
			name := strings.ToLower(reservation.Name)
			if name == "" || local[name] {
				continue
			}
			local[name] = true
			item := fmt.Sprintf("dhcp.scopes[%d].reservations[%d]", scopeIndex, index)
			if first, found := owners[name+"."+domain]; found {
				problems = append(problems, fmt.Errorf("%s.name %s.%s is already reserved by %s", item, name, domain, first))
			} else {
				owners[name+"."+domain] = item
			}
		}
	}
	return problems
}

// ValidateNodes checks that every range names a current cluster member, and
// that none names a node when this server isn't clustered.
func (settings DHCP) ValidateNodes(members []string) error {
	var problems []error
	for scopeIndex, scope := range settings.Scopes {
		for rangeIndex, pool := range scope.Ranges {
			field := fmt.Sprintf("dhcp.scopes[%d].ranges[%d].node", scopeIndex, rangeIndex)
			switch {
			case pool.Node == "":
			case len(members) == 0:
				problems = append(problems, fmt.Errorf("%s is set but this server is not in a cluster", field))
			case !slices.Contains(members, pool.Node):
				problems = append(problems, fmt.Errorf("%s %q is not a cluster member", field, pool.Node))
			}
		}
	}
	return errors.Join(problems...)
}

func (scope DHCPScope) validate(field string) []error {
	problems := scope.validateIdentity(field)
	problems = append(problems, scope.validateTimers(field)...)
	problems = append(problems, validateIPv4List(field+".dns", scope.DNS)...)
	problems = append(problems, validateIPv4List(field+".ntp", scope.NTP)...)
	problems = append(problems, validateDHCPBoot(field+".boot", scope.Boot)...)
	problems = append(problems, validateDHCPOptions(field, scope.Options)...)
	subnet, err := netip.ParsePrefix(scope.Subnet)
	if err != nil || !subnet.Addr().Is4() {
		return append(problems, fmt.Errorf("%s.subnet must be an IPv4 prefix such as 192.168.1.0/24", field))
	}
	if subnet.Bits() < 8 || subnet.Bits() > 30 {
		return append(problems, fmt.Errorf("%s.subnet must be between /8 and /30", field))
	}
	if len(scope.Ranges) == 0 && len(scope.Reservations) == 0 {
		problems = append(problems, fmt.Errorf("%s needs at least one range or reservation", field))
	}
	if scope.ReservedOnly && len(scope.Reservations) == 0 {
		problems = append(problems, fmt.Errorf("%s.reserved_only needs at least one reservation", field))
	}
	ranges, rangeProblems := validateDHCPRanges(field, subnet, scope.Ranges)
	problems = append(problems, rangeProblems...)
	var router netip.Addr
	if scope.Router != "" {
		address, problem := hostAddressIn(field+".router", subnet, scope.Router)
		if problem != nil {
			problems = append(problems, problem)
		} else if inside := rangeContaining(ranges, address); inside >= 0 {
			problems = append(problems, fmt.Errorf("%s.router is inside ranges[%d]", field, inside))
		}
		router = address
	}
	problems = append(problems, validateDHCPRoutes(field, subnet, scope.Routes)...)
	return append(problems, validateDHCPReservations(field, subnet, router, scope.Reservations)...)
}

func (scope DHCPScope) validateIdentity(field string) []error {
	var problems []error
	if scope.ID == "" {
		problems = append(problems, fmt.Errorf("%s.id is required", field))
	} else if !isHostLabel(scope.ID) {
		problems = append(problems, fmt.Errorf("%s.id must be lowercase letters, digits, and hyphens", field))
	}
	if scope.Name == "" {
		problems = append(problems, fmt.Errorf("%s.name is required", field))
	}
	if scope.Domain != "" {
		if _, err := dnsname.Normalize(scope.Domain); err != nil {
			problems = append(problems, fmt.Errorf("%s.domain: %w", field, err))
		}
	}
	for index, name := range scope.Search {
		if _, err := dnsname.Normalize(name); err != nil {
			problems = append(problems, fmt.Errorf("%s.search[%d]: %w", field, index, err))
		}
	}
	return problems
}

func (scope DHCPScope) validateTimers(field string) []error {
	var problems []error
	between := func(key string, value, low, high time.Duration) {
		if value != 0 && (value < low || value > high) {
			problems = append(problems, fmt.Errorf("%s.%s must be between %s and %s", field, key, Duration{low}, Duration{high}))
		}
	}
	between("lease", scope.Lease.Duration, minimumDHCPLease, maximumDHCPLease)
	between("ttl", scope.TTL.Duration, minimumDHCPRecordTTL, maximumDHCPRecordTTL)
	between("offer_delay", scope.OfferDelay.Duration, time.Nanosecond, maximumDHCPOfferWait)
	if scope.ConflictProbe != nil {
		between("conflict_probe", scope.ConflictProbe.Duration, time.Nanosecond, maximumDHCPOfferWait)
	}
	if wait := scope.IPv6OnlyPreferred.Duration; wait != 0 && wait < minimumDHCPV6OnlyWait {
		problems = append(problems, fmt.Errorf("%s.ipv6_only_preferred must be at least %s", field, Duration{minimumDHCPV6OnlyWait}))
	} else if wait > maximumDHCPV6OnlyWait {
		problems = append(problems, fmt.Errorf("%s.ipv6_only_preferred must be at most %d seconds", field, uint32(math.MaxUint32)))
	}
	if total := scope.OfferDelay.Duration + scope.ConflictProbeTimeout(); total > maximumDHCPOfferTotal {
		problems = append(problems, fmt.Errorf("%s.offer_delay and conflict_probe together must be at most %s, not %s",
			field, Duration{maximumDHCPOfferTotal}, Duration{total}))
	}
	return problems
}

func validateIPv4List(field string, values []string) []error {
	var problems []error
	for index, value := range values {
		if address, err := netip.ParseAddr(value); err != nil || !address.Is4() {
			problems = append(problems, fmt.Errorf("%s[%d] must be an IPv4 address", field, index))
		}
	}
	return problems
}

func validateDHCPBoot(field string, boot *DHCPBoot) []error {
	if boot == nil {
		return nil
	}
	var problems []error
	if address, err := netip.ParseAddr(boot.NextServer); boot.NextServer != "" && (err != nil || !address.Is4()) {
		problems = append(problems, fmt.Errorf("%s.next_server must be an IPv4 address", field))
	}
	if len(boot.ServerName) > maximumDHCPServerName {
		problems = append(problems, fmt.Errorf("%s.server_name must be at most %d bytes", field, maximumDHCPServerName))
	}
	if len(boot.File) > maximumDHCPBootFile {
		problems = append(problems, fmt.Errorf("%s.file must be at most %d bytes", field, maximumDHCPBootFile))
	}
	return problems
}

type addressRange struct{ start, end netip.Addr }

func validateDHCPRanges(field string, subnet netip.Prefix, ranges []DHCPRange) ([]addressRange, []error) {
	var problems []error
	parsed := make([]addressRange, len(ranges))
	for index, pool := range ranges {
		item := fmt.Sprintf("%s.ranges[%d]", field, index)
		start, startProblem := hostAddressIn(item+".start", subnet, pool.Start)
		end, endProblem := hostAddressIn(item+".end", subnet, pool.End)
		if startProblem != nil || endProblem != nil {
			problems = append(problems, errors.Join(startProblem, endProblem))
			continue
		}
		if end.Less(start) {
			problems = append(problems, fmt.Errorf("%s starts after it ends", item))
			continue
		}
		parsed[index] = addressRange{start, end}
		for other := range index {
			if parsed[other].start.IsValid() && !end.Less(parsed[other].start) && !parsed[other].end.Less(start) {
				problems = append(problems, fmt.Errorf("%s overlaps ranges[%d]", item, other))
			}
		}
	}
	return parsed, problems
}

// validateDHCPRoutes checks option 121 routes. Each router must be on-link
// for the client (RFC 3442 §2 sends only the router's address).
func validateDHCPRoutes(field string, subnet netip.Prefix, routes []DHCPRoute) []error {
	var problems []error
	for index, route := range routes {
		item := fmt.Sprintf("%s.routes[%d]", field, index)
		if to, err := netip.ParsePrefix(route.To); err != nil || !to.Addr().Is4() {
			problems = append(problems, fmt.Errorf("%s.to must be an IPv4 prefix", item))
		}
		if _, problem := hostAddressIn(item+".via", subnet, route.Via); problem != nil {
			problems = append(problems, problem)
		}
	}
	return problems
}

func validateDHCPReservations(field string, subnet netip.Prefix, router netip.Addr, reservations []DHCPReservation) []error {
	var problems []error
	macs := make(map[string]int, len(reservations))
	addresses := make(map[string]int, len(reservations))
	names := make(map[string]int, len(reservations))
	unique := func(seen map[string]int, key, item, what string, index int) {
		if first, found := seen[key]; found {
			problems = append(problems, fmt.Errorf("%s.%s duplicates reservations[%d]", item, what, first))
		} else {
			seen[key] = index
		}
	}
	for index, reservation := range reservations {
		item := fmt.Sprintf("%s.reservations[%d]", field, index)
		if hardware, err := net.ParseMAC(reservation.MAC); err != nil || len(hardware) != 6 {
			problems = append(problems, fmt.Errorf("%s.mac must be a 48-bit MAC address", item))
		} else {
			unique(macs, reservation.MAC, item, "mac", index)
		}
		if address, problem := hostAddressIn(item+".address", subnet, reservation.Address); problem != nil {
			problems = append(problems, problem)
		} else if address == router {
			problems = append(problems, fmt.Errorf("%s.address is the router", item))
		} else {
			unique(addresses, address.String(), item, "address", index)
		}
		if reservation.Name == "" {
			continue
		}
		if !isHostLabel(reservation.Name) {
			problems = append(problems, fmt.Errorf("%s.name must be a single DNS label of letters, digits, and hyphens", item))
		} else {
			unique(names, reservation.Name, item, "name", index)
		}
	}
	return problems
}

// hostAddressIn parses an IPv4 address a client can hold in subnet: not the
// network or broadcast address (RFC 919, RFC 922).
func hostAddressIn(field string, subnet netip.Prefix, value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() {
		return netip.Addr{}, fmt.Errorf("%s must be an IPv4 address", field)
	}
	if !subnet.Contains(address) {
		return netip.Addr{}, fmt.Errorf("%s must be inside %s", field, subnet)
	}
	if address == subnet.Addr() || address == broadcastAddress(subnet) {
		return netip.Addr{}, fmt.Errorf("%s is the subnet's network or broadcast address", field)
	}
	return address, nil
}

func broadcastAddress(subnet netip.Prefix) netip.Addr {
	octets := subnet.Addr().As4()
	for bit := subnet.Bits(); bit < 32; bit++ {
		octets[bit/8] |= 0x80 >> (bit % 8)
	}
	return netip.AddrFrom4(octets)
}

func rangeContaining(ranges []addressRange, address netip.Addr) int {
	for index, pool := range ranges {
		if pool.start.IsValid() && !address.Less(pool.start) && !pool.end.Less(address) {
			return index
		}
	}
	return -1
}

// isHostLabel reports whether label is one lowercase host name label
// (RFC 1123 §2.1).
func isHostLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, character := range label {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
			return false
		}
	}
	_, valid := dns.IsDomainName(label + ".")
	return valid
}
