package forwarding

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ThisServer selects the local resolver's default recursion or forwarding path.
const ThisServer = "this-server"

// Record is an FWD record: a forwarder and its priority among the name's
// other forwarders.
type Record struct {
	Upstream
	Priority uint16
}

// ParseRecord reads "protocol priority forwarder [(bootstrap)]". The
// forwarder may repeat its scheme, so "https 0 https://dns.quad9.net/dns-query
// (9.9.9.9)" and "https 0 dns.quad9.net (9.9.9.9)" are the same record.
func ParseRecord(value string) (Record, error) {
	fields := strings.Fields(value)
	if len(fields) < 3 {
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
	if len(fields) == 3 && strings.EqualFold(fields[2], ThisServer) {
		if protocol != "udp" {
			return Record{}, errors.New("this-server forwarding requires udp")
		}
		return Record{Upstream: Upstream{Protocol: protocol, Address: ThisServer}, Priority: uint16(priority)}, nil
	}
	upstream, err := parseUpstream(strings.Join(fields[2:], " "), protocol)
	if err != nil {
		return Record{}, err
	}
	// DoT and DoQ records named by host name predate bootstrap addresses and
	// still load; CheckBootstrap refuses new ones. DoH never had them.
	if upstream.Protocol == "https" && upstream.NeedsBootstrap() {
		return Record{}, ErrNeedsBootstrap
	}
	return Record{Upstream: upstream, Priority: uint16(priority)}, nil
}

// CheckRecordBootstrap refuses a new FWD record whose encrypted forwarder is
// named by host name with no bootstrap address.
func CheckRecordBootstrap(value string) error {
	record, err := ParseRecord(value)
	if err != nil {
		return err
	}
	if record.NeedsBootstrap() {
		return ErrNeedsBootstrap
	}
	return nil
}

func NewRecord(protocol, priority, address string) (Record, error) {
	return ParseRecord(strings.Join([]string{protocol, priority, address}, " "))
}

func (record Record) String() string {
	return fmt.Sprintf("%s %d %s%s", record.Protocol, record.Priority, record.target(), record.bootstrapSuffix())
}

// Endpoint is the forwarder as resolver.forwarders writes it.
func (record Record) Endpoint() string {
	if record.Address == ThisServer {
		return ThisServer
	}
	return record.Upstream.String()
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
	if err := validHost(host); err != nil {
		return "", err
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return "", errors.New("forwarder port must be between 1 and 65535")
	}
	return net.JoinHostPort(host, port), nil
}

// supportedProtocol reports whether a forwarder can be reached over the named
// transport: "tls" is DNS over TLS (RFC 7858), "quic" is DNS over QUIC
// (RFC 9250), and "https" is DNS over HTTPS (RFC 8484).
func supportedProtocol(protocol string) bool {
	switch protocol {
	case "udp", "tcp", "tls", "quic", "https":
		return true
	default:
		return false
	}
}

func defaultPort(protocol string) string {
	switch protocol {
	case "tls", "quic":
		return "853"
	case "https":
		return "443"
	}
	return "53"
}
