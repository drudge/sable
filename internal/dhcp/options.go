package dhcp

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/config"
)

// basicOptions go in every OFFER and ACK, asked for or not: clients that
// send no parameter request list still need an address plan (RFC 2131 §4.3.1
// lets a server send options the client didn't ask for).
var basicOptions = []uint8{optionSubnetMask, optionRouter, optionDNS, optionDomain, optionBroadcast}

// compileOptions encodes the scope's options once, so a reply only picks.
func (compiled *scope) compileOptions(settings config.DHCPScope) error {
	add := func(code uint8, data []byte) {
		if len(data) > 0 {
			compiled.options = append(compiled.options, Option{Code: code, Data: data})
		}
	}
	add(optionSubnetMask, net.CIDRMask(compiled.subnet.Bits(), 32))
	router := parseAddrs([]string{settings.Router})
	add(optionRouter, packAddrs(router))
	compiled.dns = parseAddrs(settings.DNS)
	add(optionDomain, []byte(strings.TrimSuffix(settings.Domain, ".")))
	broadcast := toUint(compiled.subnet.Addr()) | ^uint32(0)>>compiled.subnet.Bits()
	add(optionBroadcast, packAddrs([]netip.Addr{fromUint(broadcast)}))
	add(optionNTP, packAddrs(parseAddrs(settings.NTP)))
	search, err := packSearch(settings.Search)
	if err != nil {
		return err
	}
	add(optionSearch, search)
	add(optionRoutes, packRoutes(settings.Routes, router))
	if boot := settings.Boot; boot != nil {
		compiled.nextServer = parseAddr(boot.NextServer)
		compiled.serverName, compiled.bootFile = boot.ServerName, boot.File
		add(optionTFTPServer, []byte(boot.ServerName))
		add(optionBootFile, []byte(boot.File))
		add(optionTFTPAddresses, packAddrs(parseAddrs([]string{boot.NextServer})))
	}
	for _, option := range settings.Options {
		data, err := option.Encode()
		if err != nil {
			return err
		}
		add(uint8(option.Code), data)
	}
	if wait := settings.IPv6OnlyPreferred.Duration; wait > 0 {
		compiled.v6OnlySet, compiled.v6OnlyWait = true, uint32(wait.Seconds())
	}
	return nil
}

// packRoutes encodes option 121 (RFC 3442): the prefix width, the prefix's
// significant octets, then the router. A client that takes option 121
// ignores option 3, so the scope's router is added as the default route when
// the routes don't name one.
func packRoutes(routes []config.DHCPRoute, router []netip.Addr) []byte {
	if len(routes) == 0 {
		return nil
	}
	var data []byte
	hasDefault := false
	for _, route := range routes {
		prefix := netip.MustParsePrefix(route.To).Masked()
		hasDefault = hasDefault || prefix.Bits() == 0
		data = appendRoute(data, prefix, netip.MustParseAddr(route.Via))
	}
	if !hasDefault && len(router) == 1 {
		data = appendRoute(data, netip.MustParsePrefix("0.0.0.0/0"), router[0])
	}
	return data
}

func appendRoute(data []byte, prefix netip.Prefix, via netip.Addr) []byte {
	octets, gateway := prefix.Addr().As4(), via.As4()
	data = append(data, byte(prefix.Bits()))
	data = append(data, octets[:(prefix.Bits()+7)/8]...)
	return append(data, gateway[:]...)
}

// packSearch encodes option 119 as uncompressed RFC 1035 names (RFC 3397 §2).
func packSearch(names []string) ([]byte, error) {
	var data []byte
	for _, name := range names {
		buffer := make([]byte, 256)
		length, err := dns.PackDomainName(dns.Fqdn(name), buffer, 0, nil, false)
		if err != nil {
			return nil, err
		}
		data = append(data, buffer[:length]...)
	}
	return data, nil
}

// replyOptions picks the options for an OFFER or ACK, in the order they
// claim room in a small reply: the basics (DNS among them), then whatever
// else the client asked for (everything when it sent no list). Option 108
// is the caller's, as a required option (RFC 8925 §3.3). Codes the caller
// already set win.
func (compiled *scope) replyOptions(request Packet, serverID netip.Addr) []Option {
	asked, listed := request.Option(optionParameters)
	dnsServers := compiled.dns
	if len(dnsServers) == 0 && serverID.IsValid() {
		dnsServers = []netip.Addr{serverID}
	}
	basics := []Option{{Code: optionDNS, Data: packAddrs(dnsServers)}}
	var others []Option
	for _, option := range compiled.options {
		switch {
		case slices.Contains(basicOptions, option.Code):
			basics = append(basics, option)
		case !listed || slices.Contains(asked, option.Code):
			others = append(others, option)
		}
		if option.Code == optionRoutes && slices.Contains(asked, optionMSRoutes) {
			others = append(others, Option{Code: optionMSRoutes, Data: option.Data})
		}
	}
	return append(basics, others...)
}

// fitOptions keeps the required options and as many others as fit in the
// client's maximum message size (RFC 2132 §9.10), less the IP and UDP
// headers, the fixed fields, the cookie, and the end option.
func fitOptions(request Packet, required, optional []Option) []Option {
	limit := 576
	if data, found := request.Option(optionMaxSize); found && len(data) == 2 {
		limit = max(limit, int(binary.BigEndian.Uint16(data)))
	}
	budget := limit - 28 - 236 - 4 - 1
	options := slices.Clone(required)
	for _, option := range options {
		budget -= optionSize(option)
	}
	for _, option := range optional {
		if slices.ContainsFunc(options, func(have Option) bool { return have.Code == option.Code }) {
			continue
		}
		if size := optionSize(option); size <= budget {
			options = append(options, option)
			budget -= size
		}
	}
	return options
}

// optionSize is the option's size on the wire, split every 255 octets.
func optionSize(option Option) int {
	chunks := max(1, (len(option.Data)+254)/255)
	return 2*chunks + len(option.Data)
}

func parseAddr(value string) netip.Addr {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}
	}
	return address
}

func parseAddrs(values []string) []netip.Addr {
	var addresses []netip.Addr
	for _, value := range values {
		if address := parseAddr(value); address.Is4() {
			addresses = append(addresses, address)
		}
	}
	return addresses
}

func packAddrs(addresses []netip.Addr) []byte {
	data := make([]byte, 0, 4*len(addresses))
	for _, address := range addresses {
		if address = address.Unmap(); !address.Is4() {
			continue
		}
		octets := address.As4()
		data = append(data, octets[:]...)
	}
	return data
}
