package forwarding

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// DoHPath is the request path a DNS over HTTPS forwarder uses when its URL
// names none. RFC 8484 §3 leaves the URI template to the server; /dns-query
// is the path every major public resolver and RFC 8484's own examples use.
const DoHPath = "/dns-query"

// Upstream is one parsed forwarder: where to send queries, over what, and,
// for an encrypted transport, which address to dial when the host is a name.
//
// The bootstrap address is written after the forwarder in parentheses, as
// Technitium does: "https://dns.quad9.net/dns-query (9.9.9.9)" or
// "tls://dns.quad9.net (2620:fe::fe)". Sable dials the bootstrap address and
// still authenticates the server against the host name, which is what the
// encrypted transports authenticate (RFC 8484 §10 relies on RFC 2818 HTTPS
// identity checks; RFC 7858 §4.2 and RFC 9250 §4.1 authenticate DoT and DoQ by
// name too). Without it a name has to be looked up through the system
// resolver, which on a Sable host is usually Sable itself.
type Upstream struct {
	// Protocol is udp, tcp, tls (RFC 7858), quic (RFC 9250), or https
	// (RFC 8484).
	Protocol string
	// Address is host:port. The host may be a name.
	Address string
	// Path and Query are the DNS over HTTPS request target.
	Path  string
	Query string
	// Bootstrap is the address to dial instead of looking up the host.
	Bootstrap netip.Addr
}

// Parse reads a forwarder written as [scheme://]host[:port][/path] [(ip)].
// A forwarder with no scheme is plain DNS over UDP.
func Parse(value string) (Upstream, error) {
	return parseUpstream(value, "")
}

// ParseEndpoint returns a forwarder's protocol and host:port.
func ParseEndpoint(value string) (protocol, address string, err error) {
	upstream, err := Parse(value)
	return upstream.Protocol, upstream.Address, err
}

func parseUpstream(value, protocol string) (Upstream, error) {
	target, bootstrap, err := splitBootstrap(strings.TrimSpace(value))
	if err != nil {
		return Upstream{}, err
	}
	if scheme, rest, found := strings.Cut(target, "://"); found {
		scheme = strings.ToLower(scheme)
		if protocol != "" && scheme != protocol {
			return Upstream{}, fmt.Errorf("forwarder %q does not match protocol %q", target, protocol)
		}
		protocol, target = scheme, rest
	}
	if protocol == "" {
		protocol = "udp"
	}
	if !supportedProtocol(protocol) {
		if protocol == "http" || protocol == "h3" {
			return Upstream{}, errors.New("DNS over HTTPS forwarders must use https://")
		}
		return Upstream{}, fmt.Errorf("unsupported forwarding protocol %q", protocol)
	}
	upstream := Upstream{Protocol: protocol}
	if protocol == "https" {
		upstream, err = parseDoH(target)
	} else {
		upstream.Address, err = normalizeAddress(target, protocol)
	}
	if err != nil {
		return Upstream{}, err
	}
	if bootstrap != "" {
		if upstream.Bootstrap, err = parseBootstrap(bootstrap, upstream); err != nil {
			return Upstream{}, err
		}
	}
	return upstream, nil
}

// splitBootstrap separates "forwarder (address)" into its two parts.
func splitBootstrap(value string) (target, bootstrap string, err error) {
	open := strings.IndexByte(value, '(')
	if open < 0 {
		if strings.IndexByte(value, ')') >= 0 {
			return "", "", fmt.Errorf("invalid forwarder %q", value)
		}
		return value, "", nil
	}
	if !strings.HasSuffix(value, ")") || strings.Count(value, "(") != 1 || strings.Count(value, ")") != 1 {
		return "", "", fmt.Errorf("invalid forwarder %q: write the bootstrap address last, in parentheses", value)
	}
	bootstrap = strings.TrimSpace(value[open+1 : len(value)-1])
	if bootstrap == "" {
		return "", "", errors.New("the bootstrap address in parentheses is empty")
	}
	return strings.TrimSpace(value[:open]), bootstrap, nil
}

// parseBootstrap accepts 9.9.9.9, 2620:fe::fe, [2620:fe::fe], and, as
// Technitium writes it, the same with the forwarder's own port.
func parseBootstrap(value string, upstream Upstream) (netip.Addr, error) {
	if upstream.Protocol == "udp" || upstream.Protocol == "tcp" {
		return netip.Addr{}, errors.New("a bootstrap address only applies to tls://, quic://, and https:// forwarders")
	}
	address, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
	if err != nil {
		addressPort, portErr := netip.ParseAddrPort(value)
		if portErr != nil {
			return netip.Addr{}, fmt.Errorf("bootstrap address %q must be an IPv4 or IPv6 address", value)
		}
		if _, port, _ := net.SplitHostPort(upstream.Address); strconv.Itoa(int(addressPort.Port())) != port {
			return netip.Addr{}, fmt.Errorf("bootstrap address %q uses a different port than the forwarder", value)
		}
		address = addressPort.Addr()
	}
	return address.Unmap(), nil
}

// parseDoH reads an RFC 8484 URI template without its scheme. Sable only
// POSTs (RFC 8484 §4.1), so the template's {?dns} variable is never used and a
// URL that still carries one is refused rather than sent literally.
func parseDoH(value string) (Upstream, error) {
	if value == "" {
		return Upstream{}, errors.New("forwarder address is required")
	}
	parsed, err := url.Parse("https://" + value)
	if err != nil {
		return Upstream{}, fmt.Errorf("invalid DNS over HTTPS URL %q", "https://"+value)
	}
	if parsed.User != nil || parsed.Fragment != "" || strings.Contains(value, "#") {
		return Upstream{}, errors.New("DNS over HTTPS URLs must not contain credentials or a fragment")
	}
	if strings.ContainsAny(parsed.Path+parsed.RawQuery, "{} \t") {
		return Upstream{}, errors.New("DNS over HTTPS URLs must be a plain URL, not a URI template")
	}
	host := parsed.Hostname()
	if err := validHost(host); err != nil {
		return Upstream{}, err
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	if parsedPort, portErr := strconv.ParseUint(port, 10, 16); portErr != nil || parsedPort == 0 {
		return Upstream{}, errors.New("forwarder port must be between 1 and 65535")
	}
	if address, addrErr := netip.ParseAddr(host); addrErr == nil {
		host = address.String()
	} else {
		host = strings.ToLower(host)
	}
	path := parsed.EscapedPath()
	if path == "" || path == "/" {
		path = DoHPath
	}
	return Upstream{
		Protocol: "https", Address: net.JoinHostPort(host, port), Path: path, Query: parsed.RawQuery,
	}, nil
}

// Host is the name or address the server is authenticated as.
func (upstream Upstream) Host() string {
	host, _, err := net.SplitHostPort(upstream.Address)
	if err != nil {
		return upstream.Address
	}
	return host
}

// DialAddress is the host:port to connect to: the bootstrap address when
// there is one, and Address otherwise.
func (upstream Upstream) DialAddress() string {
	if !upstream.Bootstrap.IsValid() {
		return upstream.Address
	}
	_, port, _ := net.SplitHostPort(upstream.Address)
	return net.JoinHostPort(upstream.Bootstrap.String(), port)
}

// NeedsBootstrap reports an encrypted forwarder named by host name with no
// bootstrap address, which can only be reached by looking the name up through
// the system resolver.
func (upstream Upstream) NeedsBootstrap() bool {
	switch upstream.Protocol {
	case "tls", "quic", "https":
	default:
		return false
	}
	if upstream.Bootstrap.IsValid() || upstream.Address == ThisServer {
		return false
	}
	_, err := netip.ParseAddr(upstream.Host())
	return err != nil
}

// URL is the DNS over HTTPS request URL.
func (upstream Upstream) URL() string {
	host := upstream.Address
	if hostname, port, err := net.SplitHostPort(upstream.Address); err == nil && port == "443" {
		host = hostname
		if strings.Contains(hostname, ":") {
			host = "[" + hostname + "]"
		}
	}
	target := "https://" + host + upstream.Path
	if upstream.Query != "" {
		target += "?" + upstream.Query
	}
	return target
}

// target is the forwarder without its scheme or bootstrap address, as an FWD
// record writes it.
func (upstream Upstream) target() string {
	if upstream.Protocol == "https" {
		return upstream.URL()
	}
	return upstream.Address
}

func (upstream Upstream) bootstrapSuffix() string {
	if !upstream.Bootstrap.IsValid() {
		return ""
	}
	return " (" + upstream.Bootstrap.String() + ")"
}

// String writes the forwarder in its canonical form, which Parse reads back.
func (upstream Upstream) String() string {
	if upstream.Protocol == "https" {
		return upstream.URL() + upstream.bootstrapSuffix()
	}
	return upstream.Protocol + "://" + upstream.Address + upstream.bootstrapSuffix()
}

// ErrNeedsBootstrap is why a new encrypted forwarder named by host name is
// refused.
var ErrNeedsBootstrap = errors.New("an encrypted forwarder named by host name needs its IP address in parentheses after it, " +
	"as in https://dns.quad9.net/dns-query (9.9.9.9), so Sable doesn't look the name up through itself")

// CheckBootstrap refuses a new forwarder that NeedsBootstrap.
func CheckBootstrap(value string) error {
	upstream, err := Parse(value)
	if err != nil {
		return err
	}
	if upstream.NeedsBootstrap() {
		return fmt.Errorf("%s: %w", value, ErrNeedsBootstrap)
	}
	return nil
}

func validHost(host string) error {
	if host == "" {
		return errors.New("forwarder host is required")
	}
	if strings.ContainsAny(host, "/\\()@?#{} \t\r\n") {
		return fmt.Errorf("invalid forwarder host %q", host)
	}
	return nil
}
