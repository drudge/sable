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

// Load replaces the lease view: this node's leases and the other nodes'
// mirrored ones.
func (engine *Engine) Load(leases []Lease) {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	engine.leases = make(map[netip.Addr]*Lease, len(leases))
	engine.clients = make(map[clientRef]netip.Addr, len(leases))
	for index := range leases {
		engine.remember(leases[index])
	}
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

func (engine *Engine) remember(lease Lease) *Lease {
	stored := &lease
	engine.leases[lease.Address] = stored
	engine.clients[clientRef{lease.ScopeID, lease.ClientKey}] = lease.Address
	return stored
}

// Conflict takes an address out of the pool for an hour after a probe found
// another holder, and returns the lease to save.
func (engine *Engine) Conflict(now time.Time, address netip.Addr) *Lease {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	for _, compiled := range engine.scopes {
		if compiled.subnet.Contains(address) {
			for ref, pending := range engine.offers {
				if pending.address == address {
					delete(engine.offers, ref)
				}
			}
			return engine.decline(now, compiled, address, "conflict")
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
		ref: clientRef{compiled.id, clientKey(request, compiled.flags.ignoreClientID)}}
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
// relayed (RFC 2131 §4.3.1), else the arrival interface's subnet. The server
// identifier is this node's address on that link.
func (engine *Engine) scopeFor(request Packet, meta Meta) (*scope, netip.Addr) {
	relayed := request.GIAddr.Is4() && !request.GIAddr.IsUnspecified()
	for _, compiled := range engine.scopes {
		if relayed {
			if compiled.subnet.Contains(request.GIAddr) && len(meta.Addrs) > 0 {
				return compiled, meta.Addrs[0].Addr()
			}
			continue
		}
		for _, local := range meta.Addrs {
			if compiled.subnet.Contains(local.Addr()) {
				return compiled, local.Addr()
			}
		}
	}
	return nil, netip.Addr{}
}

// clientKey is the client identifier when the client sent one and the scope
// honours it, else the hardware type and address (RFC 2131 §4.2), as hex.
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
