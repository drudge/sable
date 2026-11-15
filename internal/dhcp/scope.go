package dhcp

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
)

// scope is a config.DHCPScope compiled for one node: its subnet, the ranges
// this node allocates from, its reservations, and its options pre-encoded.
type scope struct {
	id           string
	subnet       netip.Prefix
	ranges       []span                // this node's ranges only
	reservations map[string]netip.Addr // lowercase MAC to address
	reservedBy   map[netip.Addr]string // address to lowercase MAC
	// reservedNames is each named reservation's name, by lowercase MAC.
	reservedNames map[string]string
	// domain is the zone lease names register in; empty when the scope
	// registers none.
	domain       string
	lease        time.Duration
	dns          []netip.Addr
	routerSet    bool
	options      []Option // every configured option but 108, by code
	v6OnlyWait   uint32
	v6OnlySet    bool
	nextServer   netip.Addr
	serverName   string
	bootFile     string
	flags        scopeFlags
	offerDelay   time.Duration
	probeTimeout time.Duration
}

type scopeFlags struct {
	reservedOnly, ignoreClientID, blockRandomMACs bool
}

// span is an inclusive range of addresses as integers.
type span struct{ first, last uint32 }

func (pool span) size() uint32 { return pool.last - pool.first + 1 }

func compileScope(settings config.DHCPScope, node string) (*scope, error) {
	subnet, err := netip.ParsePrefix(settings.Subnet)
	if err != nil {
		return nil, fmt.Errorf("scope %s: %w", settings.ID, err)
	}
	compiled := &scope{
		id: settings.ID, subnet: subnet.Masked(), lease: settings.LeaseDuration(),
		reservations: map[string]netip.Addr{}, reservedBy: map[netip.Addr]string{},
		reservedNames: map[string]string{},
		flags: scopeFlags{
			reservedOnly: settings.ReservedOnly, ignoreClientID: settings.IgnoreClientID,
			blockRandomMACs: settings.BlockRandomMACs,
		},
		offerDelay: settings.OfferDelay.Duration, probeTimeout: settings.ConflictProbeTimeout(),
		routerSet: settings.Router != "",
	}
	if settings.RegistersNames() {
		compiled.domain = strings.TrimSuffix(settings.Domain, ".")
	}
	for _, pool := range settings.Ranges {
		if pool.Node != "" && pool.Node != node {
			continue
		}
		first, last := netip.MustParseAddr(pool.Start), netip.MustParseAddr(pool.End)
		compiled.ranges = append(compiled.ranges, span{toUint(first), toUint(last)})
	}
	for _, reservation := range settings.Reservations {
		hardware, err := net.ParseMAC(reservation.MAC)
		if err != nil {
			return nil, fmt.Errorf("scope %s: %w", settings.ID, err)
		}
		address := netip.MustParseAddr(reservation.Address)
		compiled.reservations[strings.ToLower(hardware.String())] = address
		compiled.reservedBy[address] = strings.ToLower(hardware.String())
		if reservation.Name != "" {
			compiled.reservedNames[strings.ToLower(hardware.String())] = reservation.Name
		}
	}
	if err := compiled.compileOptions(settings); err != nil {
		return nil, fmt.Errorf("scope %s: %w", settings.ID, err)
	}
	return compiled, nil
}

// inRanges reports whether this node allocates address.
func (compiled *scope) inRanges(address netip.Addr) bool {
	value := toUint(address)
	for _, pool := range compiled.ranges {
		if value >= pool.first && value <= pool.last {
			return true
		}
	}
	return false
}

func toUint(address netip.Addr) uint32 {
	octets := address.As4()
	return uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3])
}

func fromUint(value uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}
