package web

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/drudge/sable/internal/cluster"
	"github.com/miekg/dns"
)

const clusterResolverPrefix = "cluster-node:"

type resolverPreset struct {
	name  string
	plain string
	tls   string
	https string
	quic  string
}

type resolvedDNSServer struct {
	address string
	tlsName string
	dialIP  string
}

var resolverPresets = map[string]resolverPreset{
	"cloudflare": {name: "Cloudflare", plain: "1.1.1.1:53", tls: "one.one.one.one:853", https: "https://cloudflare-dns.com/dns-query"},
	"google":     {name: "Google", plain: "8.8.8.8:53", tls: "dns.google:853", https: "https://dns.google/dns-query"},
	"quad9":      {name: "Quad9", plain: "9.9.9.9:53", tls: "dns.quad9.net:853", https: "https://dns.quad9.net/dns-query"},
	"opendns":    {name: "OpenDNS", plain: "208.67.222.222:53"},
	"adguard":    {name: "AdGuard DNS", plain: "94.140.14.14:53", tls: "dns.adguard-dns.com:853", https: "https://dns.adguard-dns.com/dns-query", quic: "dns.adguard-dns.com:853"},
	"root-a":     {name: "a.root-servers.net", plain: "198.41.0.4:53"},
	"root-b":     {name: "b.root-servers.net", plain: "170.247.170.2:53"},
	"root-c":     {name: "c.root-servers.net", plain: "192.33.4.12:53"},
	"root-d":     {name: "d.root-servers.net", plain: "199.7.91.13:53"},
	"root-e":     {name: "e.root-servers.net", plain: "192.203.230.10:53"},
	"root-f":     {name: "f.root-servers.net", plain: "192.5.5.241:53"},
	"root-g":     {name: "g.root-servers.net", plain: "192.112.36.4:53"},
	"root-h":     {name: "h.root-servers.net", plain: "198.97.190.53:53"},
	"root-i":     {name: "i.root-servers.net", plain: "192.36.148.17:53"},
	"root-j":     {name: "j.root-servers.net", plain: "192.58.128.30:53"},
	"root-k":     {name: "k.root-servers.net", plain: "193.0.14.129:53"},
	"root-l":     {name: "l.root-servers.net", plain: "199.7.83.42:53"},
	"root-m":     {name: "m.root-servers.net", plain: "202.12.27.33:53"},
}

func resolveDNSClientServer(preset, custom, customName, customIP, local, transport string) (resolvedDNSServer, error) {
	preset = strings.TrimSpace(preset)
	transport = strings.TrimSpace(transport)

	switch preset {
	case "", "custom":
		if server := strings.TrimSpace(custom); server != "" {
			return resolvedDNSServer{address: server}, nil
		}
		return resolveCustomDNSServer(customName, customIP, transport)
	case "this-server", "recursive-resolver":
		switch transport {
		case "udp", "tcp":
			if server := strings.TrimSpace(local); server != "" {
				return resolvedDNSServer{address: server}, nil
			}
			return resolvedDNSServer{}, fmt.Errorf("this Sable server has no DNS listener")
		case "doh":
			endpoint, err := url.Parse(strings.TrimSpace(local))
			if err == nil && endpoint.Scheme == "https" && endpoint.Host != "" {
				return resolvedDNSServer{address: endpoint.String()}, nil
			}
		}
		return resolvedDNSServer{}, fmt.Errorf("%s does not have a known %s endpoint; choose Custom and enter its encrypted DNS address", localResolverName(preset), transportName(transport))
	case "system-dns":
		if transport != "udp" && transport != "tcp" {
			return resolvedDNSServer{}, fmt.Errorf("System DNS does not have a known %s endpoint; choose a specific resolver", transportName(transport))
		}
		configuration, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return resolvedDNSServer{}, fmt.Errorf("discover System DNS server: %w", err)
		}
		if len(configuration.Servers) == 0 {
			return resolvedDNSServer{}, fmt.Errorf("discover System DNS server: no resolver addresses found")
		}
		return resolvedDNSServer{address: net.JoinHostPort(configuration.Servers[0], configuration.Port)}, nil
	}

	selected, ok := resolverPresets[preset]
	if !ok {
		return resolvedDNSServer{}, fmt.Errorf("unknown DNS resolver %q", preset)
	}
	switch transport {
	case "udp", "tcp":
		return resolvedDNSServer{address: selected.plain}, nil
	case "tcp-tls":
		if selected.tls != "" {
			return resolvedDNSServer{address: selected.tls}, nil
		}
	case "doh":
		if selected.https != "" {
			return resolvedDNSServer{address: selected.https}, nil
		}
	case "quic":
		if selected.quic != "" {
			return resolvedDNSServer{address: selected.quic}, nil
		}
	default:
		return resolvedDNSServer{}, fmt.Errorf("unknown DNS transport %q", transport)
	}
	return resolvedDNSServer{}, fmt.Errorf("%s does not publish a supported %s endpoint; choose another resolver or Custom", selected.name, transportName(transport))
}

func resolveClusterDNSClientServer(preset string, state cluster.State, local, transport string) (resolvedDNSServer, error) {
	nodeID := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(preset), clusterResolverPrefix))
	if nodeID == "" || !strings.HasPrefix(strings.TrimSpace(preset), clusterResolverPrefix) {
		return resolvedDNSServer{}, fmt.Errorf("cluster DNS node is invalid")
	}
	if transport != "udp" && transport != "tcp" {
		return resolvedDNSServer{}, fmt.Errorf("cluster nodes do not advertise a known %s endpoint; use UDP or TCP, or configure a Custom encrypted DNS endpoint", transportName(transport))
	}
	for _, node := range state.Nodes {
		if node.ID != nodeID {
			continue
		}
		if node.ID == state.NodeID {
			if listener := strings.TrimSpace(local); listener != "" {
				return resolvedDNSServer{address: listener}, nil
			}
			return resolvedDNSServer{}, fmt.Errorf("this cluster node has no DNS listener")
		}
		if len(node.Addresses) == 0 {
			return resolvedDNSServer{}, fmt.Errorf("cluster node %q does not advertise a DNS service address", node.Name)
		}
		return resolvedDNSServer{address: dnsServiceEndpoint(node.Addresses[0])}, nil
	}
	return resolvedDNSServer{}, fmt.Errorf("cluster DNS node is no longer a member of this cluster")
}

func dnsServiceEndpoint(address string) string {
	address = strings.TrimSpace(address)
	if parsed, err := netip.ParseAddrPort(address); err == nil {
		return parsed.String()
	}
	return net.JoinHostPort(address, "53")
}

func resolveCustomDNSServer(name, ip, transport string) (resolvedDNSServer, error) {
	name = strings.TrimSpace(name)
	ip = strings.TrimSpace(ip)
	if name == "" && ip == "" {
		return resolvedDNSServer{}, fmt.Errorf("custom DNS server is required")
	}
	if name != "" {
		if strings.Contains(name, "://") || strings.ContainsAny(name, " /()") {
			return resolvedDNSServer{}, fmt.Errorf("custom DNS server name must be a hostname")
		}
		name = strings.TrimSuffix(name, ".")
	}
	if ip != "" && net.ParseIP(ip) == nil {
		return resolvedDNSServer{}, fmt.Errorf("custom DNS server IP address is invalid")
	}

	target := ip
	if target == "" {
		target = name
	}
	switch transport {
	case "udp", "tcp":
		return resolvedDNSServer{address: net.JoinHostPort(target, "53")}, nil
	case "tcp-tls", "quic":
		return resolvedDNSServer{address: net.JoinHostPort(target, "853"), tlsName: name}, nil
	case "doh":
		host := name
		if host == "" {
			host = urlHost(ip)
		}
		return resolvedDNSServer{
			address: (&url.URL{Scheme: "https", Host: host, Path: "/dns-query"}).String(),
			dialIP:  ipIfPinned(name, ip),
		}, nil
	default:
		return resolvedDNSServer{}, fmt.Errorf("unknown DNS transport %q", transport)
	}
}

func urlHost(ip string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}

func ipIfPinned(name, ip string) string {
	if name != "" {
		return ip
	}
	return ""
}

func localResolverName(preset string) string {
	if preset == "recursive-resolver" {
		return "Recursive Resolver"
	}
	return "This Server"
}

func transportName(transport string) string {
	switch transport {
	case "tcp-tls":
		return "DNS-over-TLS"
	case "doh":
		return "DNS-over-HTTPS"
	case "quic":
		return "DNS-over-QUIC"
	default:
		return strings.ToUpper(transport)
	}
}
