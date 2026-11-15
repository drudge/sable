package dhcpimport

import (
	"net"
	"net/netip"
	"regexp"
	"strings"
)

// leaseTime matches a dnsmasq lease time field: seconds, or a number with
// m, h, d or w, or "infinite" (dnsmasq(8), --dhcp-host).
var leaseTime = regexp.MustCompile(`^(\d+[smhdw]?|infinite)$`)

// parseDnsmasq reads every dhcp-host line. Fields can come in any order;
// each is told apart by its shape the way dnsmasq does. Tags, client IDs,
// IPv6 addresses and lease times aren't reservations' business in Sable and
// are passed over.
func parseDnsmasq(text string) Result {
	result := Result{Format: FormatDnsmasq}
	for number, line := range strings.Split(text, "\n") {
		line, _, _ = strings.Cut(line, "#")
		value, ok := strings.CutPrefix(strings.TrimLeft(strings.TrimSpace(line), "-"), "dhcp-host=")
		if !ok {
			continue
		}
		parseDhcpHost(&result, number+1, value)
	}
	return result
}

func parseDhcpHost(result *Result, line int, value string) {
	var macs []string
	var address, name string
	for _, field := range strings.Split(value, ",") {
		field = strings.TrimSpace(field)
		switch {
		case field == "":
		case field == "ignore":
			result.problem(line, "the host is set to be ignored")
			return
		case strings.HasPrefix(field, "id:"), strings.HasPrefix(field, "set:"), strings.HasPrefix(field, "tag:"), strings.HasPrefix(field, "["):
		case isMAC(field):
			macs = append(macs, field)
		case isIPv4(field):
			address = field
		case leaseTime.MatchString(field):
		default:
			name = field
		}
	}
	if len(macs) == 0 || address == "" {
		result.problem(line, "needs a hardware address and an IPv4 address")
		return
	}
	if len(macs) > 1 {
		result.problem(line, "%s shares %s; a reservation has one hardware address, so only %s is imported", strings.Join(macs[1:], ", "), address, macs[0])
	}
	result.add(line, macs[0], address, name, "")
}

func isMAC(field string) bool {
	hardware, err := net.ParseMAC(field)
	return err == nil && len(hardware) == 6
}

func isIPv4(field string) bool {
	address, err := netip.ParseAddr(field)
	return err == nil && address.Is4()
}
