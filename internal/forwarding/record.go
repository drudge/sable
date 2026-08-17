package forwarding

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type Record struct {
	Protocol string
	Priority uint16
	Address  string
}

func ParseRecord(value string) (Record, error) {
	fields := strings.Fields(value)
	if len(fields) != 3 {
		return Record{}, errors.New("FWD value must contain protocol, priority, and forwarder address")
	}
	protocol := strings.ToLower(fields[0])
	if !supportedProtocol(protocol) {
		return Record{}, fmt.Errorf("unsupported FWD protocol %q", fields[0])
	}
	priority, err := strconv.ParseUint(fields[1], 10, 16)
	if err != nil {
		return Record{}, errors.New("FWD priority must be an unsigned 16-bit integer")
	}
	address, err := normalizeAddress(fields[2], protocol)
	if err != nil {
		return Record{}, err
	}
	return Record{Protocol: protocol, Priority: uint16(priority), Address: address}, nil
}

func NewRecord(protocol, priority, address string) (Record, error) {
	return ParseRecord(strings.Join([]string{protocol, priority, address}, " "))
}

func (record Record) String() string {
	return fmt.Sprintf("%s %d %s", record.Protocol, record.Priority, record.Address)
}

func (record Record) Endpoint() string { return record.Protocol + "://" + record.Address }

func ParseEndpoint(value string) (protocol, address string, err error) {
	protocol = "udp"
	address = strings.TrimSpace(value)
	if parsedProtocol, parsedAddress, found := strings.Cut(address, "://"); found {
		protocol = strings.ToLower(parsedProtocol)
		address = parsedAddress
	}
	if !supportedProtocol(protocol) {
		return "", "", fmt.Errorf("unsupported forwarding protocol %q", protocol)
	}
	address, err = normalizeAddress(address, protocol)
	return protocol, address, err
}

func normalizeAddress(value, protocol string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("forwarder address is required")
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return net.JoinHostPort(address.String(), defaultPort(protocol)), nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		if strings.Contains(value, ":") {
			return "", fmt.Errorf("invalid forwarder address %q: %w", value, err)
		}
		host, port = value, defaultPort(protocol)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("forwarder host is required")
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return "", errors.New("forwarder port must be between 1 and 65535")
	}
	return net.JoinHostPort(host, port), nil
}

// supportedProtocol reports whether a forwarder can be reached over the named
// transport. "tls" is DNS-over-TLS and "quic" is RFC 9250 DNS-over-QUIC.
func supportedProtocol(protocol string) bool {
	switch protocol {
	case "udp", "tcp", "tls", "quic":
		return true
	default:
		return false
	}
}

func defaultPort(protocol string) string {
	if protocol == "tls" || protocol == "quic" {
		return "853"
	}
	return "53"
}
