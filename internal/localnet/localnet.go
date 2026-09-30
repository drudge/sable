// Package localnet finds the IPv6 networks a Sable node is attached to, so
// private recursion can include LAN devices whose addresses come from an
// ISP's delegated prefix rather than a private range.
package localnet

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

const (
	// RefreshInterval is how often the interfaces are read again, which also
	// catches a new prefix after the ISP renumbers.
	RefreshInterval = 30 * time.Second
	// leadFreshness is how long networks the cluster lead shared stay in use
	// without a newer copy. A replica hears from the lead every few seconds,
	// so an older copy means this node leads now or left the cluster.
	leadFreshness = 2 * time.Minute
	// shortestPrefix leaves out an on-link network broader than any LAN.
	shortestPrefix = 48
	// lanPrefix is the size of every IPv6 LAN. An address on a longer
	// prefix, such as a DHCPv6 /128, stands for the /64 it sits in.
	lanPrefix = 64
)

// Network is an IPv6 network a Sable node is attached to. Interface is set
// for this node's own networks, and Node for ones the cluster lead shared.
type Network struct {
	Prefix    netip.Prefix
	Interface string
	Node      string
}

// Interface is what Detect needs to know about one network interface.
type Interface struct {
	Name      string
	Flags     net.Flags
	Addresses []netip.Prefix
}

// cgnat is the shared address space some networks number their LAN from.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Detect returns the global IPv6 networks on interfaces that look like a LAN:
// up, not loopback or point-to-point, and also holding a private IPv4, shared
// (100.64.0.0/10), or unique-local IPv6 address. A hosting provider can put
// many customers on one on-link prefix, and a server there has only public
// addresses, so its networks are left out.
func Detect(interfaces []Interface) []Network {
	found := make([]Network, 0)
	for _, candidate := range interfaces {
		if candidate.Flags&net.FlagUp == 0 || candidate.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		lan := false
		prefixes := make([]netip.Prefix, 0, len(candidate.Addresses))
		for _, address := range candidate.Addresses {
			ip := address.Addr().Unmap()
			switch {
			case ip.Is4() && (ip.IsPrivate() || cgnat.Contains(ip)):
				lan = true
			case ip.Is6() && ip.IsPrivate():
				lan = true
			case ip.Is6() && ip.IsGlobalUnicast() && address.Bits() >= shortestPrefix:
				bits := min(address.Bits(), lanPrefix)
				prefixes = append(prefixes, netip.PrefixFrom(ip.WithZone(""), bits).Masked())
			}
		}
		if !lan {
			continue
		}
		for _, prefix := range prefixes {
			if !slices.ContainsFunc(found, func(network Network) bool { return network.Prefix == prefix }) {
				found = append(found, Network{Prefix: prefix, Interface: candidate.Name})
			}
		}
	}
	return found
}

// ReadInterfaces lists this host's interfaces and their addresses.
func ReadInterfaces() ([]Interface, error) {
	system, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	interfaces := make([]Interface, 0, len(system))
	for _, current := range system {
		addresses, err := current.Addrs()
		if err != nil {
			continue
		}
		read := Interface{Name: current.Name, Flags: current.Flags}
		for _, address := range addresses {
			network, ok := address.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(network.IP)
			if !ok {
				continue
			}
			bits, _ := network.Mask.Size()
			if ip.Is4In6() && bits >= 96 {
				ip, bits = ip.Unmap(), bits-96
			}
			read.Addresses = append(read.Addresses, netip.PrefixFrom(ip, bits))
		}
		interfaces = append(interfaces, read)
	}
	return interfaces, nil
}

// Watcher keeps the networks this node is attached to, and the ones the
// cluster lead shared, and hands their prefixes to the DNS handler whenever
// they change. It reads interfaces in the background, never on a lookup.
type Watcher struct {
	publish func([]netip.Prefix)
	now     func() time.Time
	// updating keeps two updates from publishing out of order.
	updating sync.Mutex

	mu        sync.RWMutex
	own       []Network
	lead      []Network
	leadAt    time.Time
	published []netip.Prefix
}

// NewWatcher returns a watcher that hands every change to publish.
func NewWatcher(publish func([]netip.Prefix)) *Watcher {
	return &Watcher{publish: publish, now: time.Now}
}

// Run reads the interfaces now and every RefreshInterval until ctx ends.
func (watcher *Watcher) Run(ctx context.Context, read func() ([]Interface, error), logger *slog.Logger) {
	ticker := time.NewTicker(RefreshInterval)
	defer ticker.Stop()
	reported := false
	for {
		if err := watcher.Refresh(read); err != nil && !reported && logger != nil {
			// A host that can't list its interfaces fails the same way every
			// time, so the first failure is enough to explain it.
			logger.Warn("read network interfaces for private recursion", "error", err)
			reported = true
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Refresh reads the interfaces once and publishes what changed. A failed read
// keeps the networks already known.
func (watcher *Watcher) Refresh(read func() ([]Interface, error)) error {
	interfaces, err := read()
	if err != nil {
		watcher.update(nil, false)
		return err
	}
	watcher.update(Detect(interfaces), true)
	return nil
}

// SetLead records the networks the cluster lead shared. A lead too old to
// share any sends nothing, which clears them.
func (watcher *Watcher) SetLead(node string, prefixes []netip.Prefix) {
	watcher.mu.Lock()
	watcher.lead = watcher.lead[:0]
	for _, prefix := range prefixes {
		watcher.lead = append(watcher.lead, Network{Prefix: prefix.Masked(), Node: node})
	}
	watcher.leadAt = watcher.now()
	watcher.mu.Unlock()
	watcher.update(nil, false)
}

// Own returns the prefixes of this node's own networks, which a lead shares.
func (watcher *Watcher) Own() []netip.Prefix {
	watcher.mu.RLock()
	defer watcher.mu.RUnlock()
	prefixes := make([]netip.Prefix, 0, len(watcher.own))
	for _, network := range watcher.own {
		prefixes = append(prefixes, network.Prefix)
	}
	return prefixes
}

// Networks returns every network private recursion covers: this node's own
// first, then the lead's that this node doesn't already have.
func (watcher *Watcher) Networks() []Network {
	watcher.mu.RLock()
	defer watcher.mu.RUnlock()
	return watcher.networksLocked()
}

// Prefixes returns the prefixes of every network private recursion covers.
func (watcher *Watcher) Prefixes() []netip.Prefix {
	watcher.mu.RLock()
	defer watcher.mu.RUnlock()
	return slices.Clone(watcher.published)
}

func (watcher *Watcher) networksLocked() []Network {
	networks := slices.Clone(watcher.own)
	if watcher.leadAt.IsZero() || watcher.now().Sub(watcher.leadAt) > leadFreshness {
		return networks
	}
	for _, shared := range watcher.lead {
		if !slices.ContainsFunc(networks, func(network Network) bool { return network.Prefix == shared.Prefix }) {
			networks = append(networks, shared)
		}
	}
	return networks
}

// update takes a new reading of this node's own networks, when replace is
// set, and publishes the prefixes if they changed.
func (watcher *Watcher) update(own []Network, replace bool) {
	watcher.updating.Lock()
	defer watcher.updating.Unlock()
	watcher.mu.Lock()
	if replace {
		watcher.own = own
	}
	networks := watcher.networksLocked()
	prefixes := make([]netip.Prefix, 0, len(networks))
	for _, network := range networks {
		prefixes = append(prefixes, network.Prefix)
	}
	changed := !slices.Equal(prefixes, watcher.published)
	if changed {
		watcher.published = prefixes
	}
	watcher.mu.Unlock()
	if changed && watcher.publish != nil {
		watcher.publish(slices.Clone(prefixes))
	}
}
