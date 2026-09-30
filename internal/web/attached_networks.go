package web

import (
	"net/netip"

	"github.com/drudge/sable/internal/clientaccess"
	"github.com/drudge/sable/internal/localnet"
	"github.com/drudge/sable/internal/web/pages"
)

// attachedNetworkSource is the IPv6 networks private recursion admits
// besides the fixed private ranges: this node's own and the lead's.
type attachedNetworkSource interface {
	Networks() []localnet.Network
	Prefixes() []netip.Prefix
}

// SetAttachedNetworks lets Settings show, and Insights check, the networks
// private recursion admits.
func (server *Server) SetAttachedNetworks(networks attachedNetworkSource) {
	server.attachedNetworks = networks
}

// attachedNetworkViews lists the networks for Settings → Recursion, with
// the interface each is on, or the node that shared it.
func (server *Server) attachedNetworkViews() []pages.AttachedNetworkView {
	if server.attachedNetworks == nil {
		return nil
	}
	networks := server.attachedNetworks.Networks()
	views := make([]pages.AttachedNetworkView, 0, len(networks))
	for _, network := range networks {
		source := network.Interface
		if network.Node != "" {
			source = "from " + network.Node
		}
		views = append(views, pages.AttachedNetworkView{Prefix: network.Prefix.String(), Source: source})
	}
	return views
}

// recursionAllows reports whether the recursion policy in force admits a
// client address, counting the networks private recursion covers. A policy
// that doesn't compile admits nobody.
func (server *Server) recursionAllows() func(string) bool {
	resolver := server.config.Current().Config.Resolver
	policy, err := clientaccess.Compile(resolver.Recursion, resolver.RecursionClients)
	if err != nil {
		return func(string) bool { return false }
	}
	var attached []netip.Prefix
	if server.attachedNetworks != nil {
		attached = server.attachedNetworks.Prefixes()
	}
	return func(address string) bool { return policy.AllowsFrom(address, attached) }
}

// onAttachedNetwork reports whether an address is on a network Sable is
// attached to, whatever the recursion policy.
func (server *Server) onAttachedNetwork() func(string) bool {
	var attached []netip.Prefix
	if server.attachedNetworks != nil {
		attached = server.attachedNetworks.Prefixes()
	}
	return func(address string) bool {
		parsed, err := netip.ParseAddr(address)
		if err != nil {
			return false
		}
		parsed = parsed.Unmap().WithZone("")
		for _, network := range attached {
			if network.Contains(parsed) {
				return true
			}
		}
		return false
	}
}
