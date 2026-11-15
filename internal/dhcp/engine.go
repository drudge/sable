package dhcp

import (
	"encoding/hex"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/config"
)

const (
	// offerHold is how long an offered address waits for the client's
	// REQUEST before another client may have it.
	offerHold = time.Minute
	// maxOffersPerScope caps outstanding offers, so a DISCOVER flood can't
	// reserve a whole pool.
	maxOffersPerScope = 1024
	// declineHold is how long an address someone else answered for, or a
	// client declined, stays out of the pool (RFC 2131 §4.3.3).
	declineHold = time.Hour
)

// Engine answers DHCP requests for one node. It's safe for concurrent use;
// the caller owns the sockets and the store.
type Engine struct {
	mutex   sync.Mutex
	node    string
	scopes  []*scope
	leases  map[netip.Addr]*Lease
	clients map[clientRef]netip.Addr
	offers  map[clientRef]offer
	labeler Labeler
}

// clientRef names a client within a scope (RFC 2131 §4.2: a binding is the
// client identifier, or the hardware address, and the subnet).
type clientRef struct{ scope, key string }

type offer struct {
	address netip.Addr
	expires time.Time
}

// New compiles the scopes that are on, for node. The settings must already
// have passed validation.
func New(settings config.DHCP, node string) (*Engine, error) {
	engine := &Engine{
		node: node, leases: map[netip.Addr]*Lease{},
		clients: map[clientRef]netip.Addr{}, offers: map[clientRef]offer{},
	}
	for _, settingsScope := range settings.Scopes {
		if !settingsScope.Serves() {
			continue
		}
		compiled, err := compileScope(settingsScope, node)
		if err != nil {
			return nil, err
		}
		engine.scopes = append(engine.scopes, compiled)
	}
	return engine, nil
}

// Rescope takes from's scopes and keeps this engine's leases, bindings and
// offers, for a change to reservations alone (D48). An offer of an address
// now reserved is withdrawn, since its client would be NAKed for it.
func (engine *Engine) Rescope(from *Engine) {
	from.mutex.Lock()
	scopes := from.scopes
	from.mutex.Unlock()
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	engine.scopes = scopes
	for ref, pending := range engine.offers {
		compiled := engine.scope(ref.scope)
		if compiled == nil {
			delete(engine.offers, ref)
			continue
		}
		if _, reserved := compiled.reservedBy[pending.address]; reserved {
			delete(engine.offers, ref)
		}
	}
}

// scope returns the scope with id, or nil.
func (engine *Engine) scope(id string) *scope {
	for _, compiled := range engine.scopes {
		if compiled.id == id {
			return compiled
		}
	}
	return nil
}

// SetLabeler sets the rule that names a lease, so the option 81 reply
// (RFC 4702 §4) carries the name the namer publishes. Without one the
// engine tells clients it registers nothing.
func (engine *Engine) SetLabeler(labeler Labeler) {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	engine.labeler = labeler
}

// Load replaces the lease view: this node's leases and the other nodes'
// mirrored ones. An address can have a row from more than one node after a
// range takeover (the offline owner's and the new one's); the most recently
// bound row wins whatever order they come in, so a node never forgets a
// lease it granted (RFC 2131 §4.3.1: an address isn't offered while bound).
func (engine *Engine) Load(leases []Lease) {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	engine.leases = make(map[netip.Addr]*Lease, len(leases))
	engine.clients = make(map[clientRef]netip.Addr, len(leases))
	for index := range leases {
		if old := engine.leases[leases[index].Address]; old != nil && !newerLease(leases[index], *old) {
			continue
		}
		engine.remember(leases[index])
	}
}

// newerLease reports whether lease was bound after old, or at the same
// moment but runs longer.
func newerLease(lease, old Lease) bool {
	if !lease.BoundAt.Equal(old.BoundAt) {
		return lease.BoundAt.After(old.BoundAt)
	}
	return lease.ExpiresAt.After(old.ExpiresAt)
}

// Leases returns a copy of the lease view, to carry across a reload.
func (engine *Engine) Leases() []Lease {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	leases := make([]Lease, 0, len(engine.leases))
	for _, lease := range engine.leases {
		leases = append(leases, *lease)
	}
	return leases
}

// remember puts lease in the view. A client that loses its address to
// another drops out of the client index, so the index never holds more
// entries than there are leases (rotating MACs would grow it otherwise).
func (engine *Engine) remember(lease Lease) *Lease {
	if old := engine.leases[lease.Address]; old != nil {
		oldRef := clientRef{old.ScopeID, old.ClientKey}
		if oldRef != (clientRef{lease.ScopeID, lease.ClientKey}) && engine.clients[oldRef] == lease.Address {
			delete(engine.clients, oldRef)
		}
	}
	stored := &lease
	engine.leases[lease.Address] = stored
	engine.clients[clientRef{lease.ScopeID, lease.ClientKey}] = lease.Address
	return stored
}

// Remove ends this node's lease on address now, for an operator removing it,
// and returns the row to save; nil when the address has no lease that holds
// it. A declined address goes back to the pool too. The row stays, as after a
// RELEASE (RFC 2131 §4.3.4), so the client is offered the same address when
// it next asks, unless another client takes it first. A pending offer of the
// address is dropped so it can't be acknowledged afterward.
func (engine *Engine) Remove(now time.Time, address netip.Addr) *Lease {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	lease := engine.leases[address]
	if lease == nil || lease.NodeID != engine.node || !lease.holds(now) {
		return nil
	}
	for ref, pending := range engine.offers {
		if pending.address == address {
			delete(engine.offers, ref)
		}
	}
	lease.State, lease.ExpiresAt = LeaseReleased, now
	removed := *lease
	return &removed
}

// Conflict takes an address out of the pool for an hour after a probe found
// another holder, and returns the lease to save. holder names what answered:
// "echo", or the hardware address the neighbor table showed.
func (engine *Engine) Conflict(now time.Time, address netip.Addr, holder string) *Lease {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	for _, compiled := range engine.scopes {
		if compiled.subnet.Contains(address) {
			for ref, pending := range engine.offers {
				if pending.address == address {
					delete(engine.offers, ref)
				}
			}
			return engine.decline(now, compiled, address, "conflict:"+holder)
		}
	}
	return nil
}

func (engine *Engine) decline(now time.Time, compiled *scope, address netip.Addr, key string) *Lease {
	lease := engine.remember(Lease{
		NodeID: engine.node, Address: address, ScopeID: compiled.id, ClientKey: key,
		State: LeaseDeclined, BoundAt: now, ExpiresAt: now.Add(declineHold),
	})
	copied := *lease
	return &copied
}

// Handle answers one request that arrived on meta's link at now.
func (engine *Engine) Handle(now time.Time, request Packet, meta Meta) Result {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	compiled, serverID := engine.scopeFor(request, meta)
	if compiled == nil {
		return Result{Drop: "no scope for this link"}
	}
	if !validHardware(request) {
		return Result{Drop: "bad hardware address"}
	}
	if compiled.flags.blockRandomMACs && randomMAC(request) && !compiled.reserved(request) {
		return Result{Drop: "locally administered MAC"}
	}
	exchange := &exchange{engine: engine, scope: compiled, serverID: serverID, request: request, now: now,
		ref: clientRef{compiled.id, clientKey(request, compiled.flags.ignoreClientID || compiled.reserved(request))}}
	switch request.MessageType() {
	case Discover:
		return exchange.answerDiscover()
	case Request:
		return exchange.answerRequest()
	case Decline:
		return exchange.answerDecline()
	case Release:
		return exchange.answerRelease()
	case Inform:
		return exchange.answerInform()
	}
	return Result{Drop: "not a client message"}
}

// scopeFor finds the scope for the request's link: the relay's giaddr when
// relayed (RFC 2131 §4.3.1); the scope holding ciaddr for a request routed
// to this node by unicast; else the arrival interface's subnet. The server
// identifier is this node's address on that link, or the one the client sent
// to.
func (engine *Engine) scopeFor(request Packet, meta Meta) (*scope, netip.Addr) {
	if request.GIAddr.Is4() && !request.GIAddr.IsUnspecified() {
		return engine.relayedScope(request.GIAddr, meta)
	}
	if compiled, serverID := engine.routedScope(request, meta); compiled != nil {
		return compiled, serverID
	}
	for _, compiled := range engine.scopes {
		for _, local := range meta.Addrs {
			if address := local.Addr().Unmap(); compiled.subnet.Contains(address) {
				return compiled, address
			}
		}
	}
	return nil, netip.Addr{}
}

func (engine *Engine) relayedScope(giaddr netip.Addr, meta Meta) (*scope, netip.Addr) {
	serverID := firstIPv4(meta.Addrs)
	if !serverID.IsValid() {
		return nil, netip.Addr{}
	}
	for _, compiled := range engine.scopes {
		if compiled.subnet.Contains(giaddr) {
			return compiled, serverID
		}
	}
	return nil, netip.Addr{}
}

// routedScope is the scope holding ciaddr for a request that came to this
// node by unicast with no relay: a RENEWING client trusts its ciaddr (RFC 2131
// §4.3.2, §4.4.5), and a relay that forwards broadcasts only leaves its
// renewals to routing (D106). A broadcast keeps the arrival link's scope, so
// a client that moved links and rebinds with its old address is NAKed.
func (engine *Engine) routedScope(request Packet, meta Meta) (*scope, netip.Addr) {
	to, unicast := meta.unicast()
	if !unicast || isZero(request.CIAddr) {
		return nil, netip.Addr{}
	}
	for _, compiled := range engine.scopes {
		if compiled.subnet.Contains(request.CIAddr) {
			return compiled, to
		}
	}
	return nil, netip.Addr{}
}

// firstIPv4 is the link's first IPv4 address, the server identifier for a
// relayed request (RFC 2132 §9.7 is four octets). Interfaces often list an
// IPv6 address first.
func firstIPv4(addrs []netip.Prefix) netip.Addr {
	for _, local := range addrs {
		if address := local.Addr().Unmap(); address.Is4() {
			return address
		}
	}
	return netip.Addr{}
}

// clientKey is the client identifier when the client sent one and the scope
// honours it, else the hardware type and address (RFC 2131 §4.2), as hex.
// A reserved client is keyed by hardware address, since the reservation is,
// so a PXE-to-OS identifier change renews its own lease (D16).
func clientKey(request Packet, ignoreClientID bool) string {
	if id, found := request.Option(optionClientID); found && len(id) > 0 && !ignoreClientID {
		return hex.EncodeToString(id)
	}
	return hex.EncodeToString(append([]byte{request.HType}, request.CHAddr...))
}

func validHardware(request Packet) bool {
	return len(request.CHAddr) > 0 && len(request.CHAddr) <= 16
}

// randomMAC reports an Ethernet address with the locally administered bit
// set (IEEE 802 §8.2.2), which private-address clients use.
func randomMAC(request Packet) bool {
	return request.HType == 1 && len(request.CHAddr) == 6 && request.CHAddr[0]&0x02 != 0
}

func (compiled *scope) reservation(request Packet) (netip.Addr, bool) {
	address, found := compiled.reservations[strings.ToLower(request.CHAddr.String())]
	return address, found && request.HType == 1
}

func (compiled *scope) reserved(request Packet) bool {
	_, found := compiled.reservation(request)
	return found
}
