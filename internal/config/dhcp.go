package config

import (
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/drudge/sable/internal/dnsname"
)

// Defaults for the DHCP scope keys a file may leave out.
const (
	DefaultDHCPLeaseTime     = 24 * time.Hour
	DefaultDHCPRecordTTL     = 5 * time.Minute
	DefaultDHCPConflictProbe = 500 * time.Millisecond
)

// DHCP configures the DHCPv4 server (RFC 2131). Scopes and reservations are
// configuration, so they validate, replicate, and back up like the rest of the
// file; leases live in the store. Every key is omitted while unset, so a node
// that predates DHCP can still decode a file that never used it.
type DHCP struct {
	Enabled bool        `toml:"enabled,omitempty" json:"enabled"`
	Scopes  []DHCPScope `toml:"scopes,omitempty" json:"scopes,omitempty"`
}

// DHCPScope is one IPv4 subnet. A node serves it on whichever interface has an
// address in the subnet, and for relayed requests whose giaddr falls inside it
// (RFC 2131 §4.3.1). Option numbers are from RFC 2132 unless noted.
type DHCPScope struct {
	// ID is stable; leases refer to it, so a rename keeps them.
	ID      string `toml:"id" json:"id"`
	Name    string `toml:"name" json:"name"`
	Subnet  string `toml:"subnet" json:"subnet"`
	Enabled *bool  `toml:"enabled,omitempty" json:"enabled,omitempty"`

	Lease  Duration `toml:"lease,omitempty" json:"lease,omitempty"`   // option 51
	Router string   `toml:"router,omitempty" json:"router,omitempty"` // option 3
	// DNS is option 6. Empty means every cluster node's address on the subnet.
	DNS []string `toml:"dns,omitempty" json:"dns,omitempty"`
	// Domain is option 15 and the zone lease names register in. The client
	// never picks the zone (RFC 4702 §5).
	Domain string      `toml:"domain,omitempty" json:"domain,omitempty"`
	Search []string    `toml:"search,omitempty" json:"search,omitempty"` // option 119 (RFC 3397)
	NTP    []string    `toml:"ntp,omitempty" json:"ntp,omitempty"`       // option 42
	Routes []DHCPRoute `toml:"routes,omitempty" json:"routes,omitempty"` // option 121 (RFC 3442)

	RegisterNames *bool    `toml:"register_names,omitempty" json:"register_names,omitempty"`
	Reverse       *bool    `toml:"reverse,omitempty" json:"reverse,omitempty"`
	TTL           Duration `toml:"ttl,omitempty" json:"ttl,omitempty"`
	// IPv6OnlyPreferred answers option 108 (RFC 8925) when set.
	IPv6OnlyPreferred Duration `toml:"ipv6_only_preferred,omitempty" json:"ipv6_only_preferred,omitempty"`

	ReservedOnly    bool      `toml:"reserved_only,omitempty" json:"reserved_only,omitempty"`
	IgnoreClientID  bool      `toml:"ignore_client_id,omitempty" json:"ignore_client_id,omitempty"`
	BlockRandomMACs bool      `toml:"block_random_macs,omitempty" json:"block_random_macs,omitempty"`
	OfferDelay      Duration  `toml:"offer_delay,omitempty" json:"offer_delay,omitempty"`
	ConflictProbe   *Duration `toml:"conflict_probe,omitempty" json:"conflict_probe,omitempty"`

	Boot         *DHCPBoot         `toml:"boot,omitempty" json:"boot,omitempty"`
	Ranges       []DHCPRange       `toml:"ranges,omitempty" json:"ranges,omitempty"`
	Reservations []DHCPReservation `toml:"reservations,omitempty" json:"reservations,omitempty"`
	Options      []DHCPOption      `toml:"options,omitempty" json:"options,omitempty"`
}

// DHCPRoute is one classless static route (RFC 3442).
type DHCPRoute struct {
	To  string `toml:"to" json:"to"`
	Via string `toml:"via" json:"via"`
}

// DHCPBoot is what a PXE client needs: siaddr and option 150 (RFC 5859),
// option 66, and option 67 (RFC 2132 §9.4, §9.5).
type DHCPBoot struct {
	NextServer string `toml:"next_server,omitempty" json:"next_server,omitempty"`
	ServerName string `toml:"server_name,omitempty" json:"server_name,omitempty"`
	File       string `toml:"file,omitempty" json:"file,omitempty"`
}

// DHCPRange is an inclusive pool of dynamic addresses. In a cluster each range
// is pinned to one node ID and served only by that node, whatever its role.
// An exclusion is the gap between two ranges.
type DHCPRange struct {
	Start string `toml:"start" json:"start"`
	End   string `toml:"end" json:"end"`
	Node  string `toml:"node,omitempty" json:"node,omitempty"`
}

// DHCPReservation binds a hardware address to a fixed address. Every node
// answers reservations, and a named one always publishes its records.
type DHCPReservation struct {
	MAC     string `toml:"mac" json:"mac"`
	Address string `toml:"address" json:"address"`
	Name    string `toml:"name,omitempty" json:"name,omitempty"`
	Comment string `toml:"comment,omitempty" json:"comment,omitempty"`
}

// DHCPOption is an option without a field of its own. Value is typed by code;
// a code with no known type takes Hex instead.
type DHCPOption struct {
	Code  int      `toml:"code" json:"code"`
	Value []string `toml:"value,omitempty" json:"value,omitempty"`
	Hex   string   `toml:"hex,omitempty" json:"hex,omitempty"`
}

// IsZero reports whether nothing is configured, so the section can stay out
// of a replicated snapshot that an older node must decode.
func (settings DHCP) IsZero() bool {
	return !settings.Enabled && len(settings.Scopes) == 0
}

// Serves reports whether the scope is on. Unset means on.
func (scope DHCPScope) Serves() bool { return scope.Enabled == nil || *scope.Enabled }

// RegistersNames reports whether leases publish A records. Unset means yes.
func (scope DHCPScope) RegistersNames() bool {
	return scope.RegisterNames == nil || *scope.RegisterNames
}

// PublishesReverse reports whether leases publish PTR records. Unset means yes.
func (scope DHCPScope) PublishesReverse() bool { return scope.Reverse == nil || *scope.Reverse }

// LeaseDuration is the lease the scope hands out.
func (scope DHCPScope) LeaseDuration() time.Duration {
	return durationOr(scope.Lease.Duration, DefaultDHCPLeaseTime)
}

// RecordTTL is the TTL of the records a lease publishes.
func (scope DHCPScope) RecordTTL() time.Duration {
	return durationOr(scope.TTL.Duration, DefaultDHCPRecordTTL)
}

// ConflictProbeTimeout is how long to wait for a probe reply before an OFFER
// (RFC 2131 §4.4.1). Zero turns probing off.
func (scope DHCPScope) ConflictProbeTimeout() time.Duration {
	if scope.ConflictProbe == nil {
		return DefaultDHCPConflictProbe
	}
	return scope.ConflictProbe.Duration
}

func durationOr(value, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	return value
}

// Normalize canonicalizes every scope in place, as loading a file does.
func (settings *DHCP) Normalize() {
	for index := range settings.Scopes {
		settings.Scopes[index].normalize()
	}
}

// normalize canonicalizes what has one canonical form and leaves anything
// unparsable as written, so validation can name it.
func (scope *DHCPScope) normalize() {
	scope.ID = strings.TrimSpace(scope.ID)
	scope.Name = strings.TrimSpace(scope.Name)
	scope.Subnet = canonicalPrefix(scope.Subnet)
	scope.Router = canonicalAddress(scope.Router)
	scope.Domain = canonicalName(scope.Domain)
	canonicalizeEach(scope.DNS, canonicalAddress)
	canonicalizeEach(scope.NTP, canonicalAddress)
	canonicalizeEach(scope.Search, canonicalName)
	for index := range scope.Routes {
		scope.Routes[index].To = canonicalPrefix(scope.Routes[index].To)
		scope.Routes[index].Via = canonicalAddress(scope.Routes[index].Via)
	}
	if scope.Boot != nil {
		scope.Boot.NextServer = canonicalAddress(scope.Boot.NextServer)
		scope.Boot.ServerName = strings.TrimSpace(scope.Boot.ServerName)
		scope.Boot.File = strings.TrimSpace(scope.Boot.File)
	}
	for index := range scope.Ranges {
		pool := &scope.Ranges[index]
		pool.Start, pool.End = canonicalAddress(pool.Start), canonicalAddress(pool.End)
		pool.Node = strings.TrimSpace(pool.Node)
	}
	for index := range scope.Reservations {
		reservation := &scope.Reservations[index]
		if hardware, err := net.ParseMAC(strings.TrimSpace(reservation.MAC)); err == nil {
			reservation.MAC = hardware.String()
		}
		reservation.Address = canonicalAddress(reservation.Address)
		reservation.Name = strings.ToLower(strings.TrimSpace(reservation.Name))
		reservation.Comment = strings.TrimSpace(reservation.Comment)
	}
	for index := range scope.Options {
		scope.Options[index].Hex = strings.ToLower(strings.TrimSpace(scope.Options[index].Hex))
		canonicalizeEach(scope.Options[index].Value, strings.TrimSpace)
	}
}

func canonicalizeEach(values []string, canonical func(string) string) {
	for index := range values {
		values[index] = canonical(values[index])
	}
}

func canonicalAddress(value string) string {
	value = strings.TrimSpace(value)
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Unmap().String()
	}
	return value
}

func canonicalPrefix(value string) string {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked().String()
	}
	return value
}

func canonicalName(value string) string {
	if name, err := dnsname.Normalize(value); err == nil {
		return name
	}
	return strings.TrimSpace(value)
}
