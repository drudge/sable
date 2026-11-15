package dhcp

import (
	"encoding/hex"
	"net/netip"
	"slices"
	"time"
)

// exchange is one request being answered: the scope, this node's address on
// the link, and the client's binding name.
type exchange struct {
	engine   *Engine
	scope    *scope
	serverID netip.Addr
	request  Packet
	now      time.Time
	ref      clientRef
}

// discover answers a DISCOVER with an OFFER (RFC 2131 §4.3.1).
func (exchange *exchange) answerDiscover() Result {
	if exchange.v6Only() {
		// RFC 8925 §3.3: offer 0.0.0.0 with option 108 and hold nothing.
		return Result{Reply: exchange.reply(Offer, netip.IPv4Unspecified()), Destination: exchange.destination(),
			Delay: exchange.scope.offerDelay}
	}
	pending, wasPending := exchange.engine.offers[exchange.ref]
	address, reserved := exchange.allocate()
	if !address.IsValid() {
		return Result{Drop: "no free address"}
	}
	if !exchange.holdOffer(address) {
		return Result{Drop: "too many outstanding offers"}
	}
	result := Result{Reply: exchange.reply(Offer, address), Destination: exchange.destination(),
		Delay: exchange.scope.offerDelay}
	// Probe a new binding once: not a reservation, not the client's own
	// lease, and not an offer it already had (a retransmitted DISCOVER).
	repeat := wasPending && pending.address == address
	if lease := exchange.engine.leases[address]; !reserved && !repeat && (lease == nil || !exchange.owns(lease)) {
		result.Probe, result.ProbeTimeout = address, exchange.scope.probeTimeout
		if result.ProbeTimeout == 0 {
			result.Probe = netip.Addr{}
		}
	}
	return result
}

// request answers a REQUEST in each state RFC 2131 Table 4 tells apart.
func (exchange *exchange) answerRequest() Result {
	serverID, selecting := exchange.addrOption(optionServerID)
	requested, hasRequested := exchange.addrOption(optionRequestedIP)
	ciaddr := exchange.request.CIAddr
	switch {
	case selecting && serverID != exchange.serverID:
		// The client took another server's offer (RFC 2131 §4.3.2).
		delete(exchange.engine.offers, exchange.ref)
		return Result{Drop: "client chose another server"}
	case selecting && hasRequested:
		return exchange.verify(requested)
	case selecting:
		return Result{Drop: "SELECTING request without a requested address"}
	case hasRequested && isZero(ciaddr):
		return exchange.verify(requested) // INIT-REBOOT
	case !hasRequested && !isZero(ciaddr):
		return exchange.verify(ciaddr) // RENEWING or REBINDING
	}
	return Result{Drop: "malformed request"}
}

// verify ACKs, NAKs, or ignores a request for address. It NAKs only an
// address that's off-link or belongs to another client, and stays silent for
// an on-link address this node doesn't allocate (RFC 2131 §4.3.2), so nodes
// that split a subnet never NAK each other's clients.
func (exchange *exchange) verify(address netip.Addr) Result {
	compiled := exchange.scope
	if !compiled.subnet.Contains(address) {
		return exchange.nak("requested address is not on this network")
	}
	// The server never NAKs its own offer: a reserved client whose reservation
	// is taken was offered a pool address and moves at a later renewal (D17).
	if reservation, found := compiled.reservation(exchange.request); found && reservation != address &&
		exchange.available(reservation) {
		return exchange.nak("this client has a reserved address")
	}
	if owner, found := compiled.reservedBy[address]; found && owner != macKey(exchange.request) {
		return exchange.nak("address is reserved for another client")
	}
	if lease := exchange.engine.leases[address]; lease != nil && lease.holds(exchange.now) && !exchange.owns(lease) {
		return exchange.nak("address is bound to another client")
	}
	if reservation, found := compiled.reservation(exchange.request); found && reservation == address {
		return exchange.ack(address)
	}
	if compiled.flags.reservedOnly {
		return Result{Drop: "scope serves reserved clients only"}
	}
	if !compiled.inRanges(address) || exchange.isServerAddress(address) {
		return Result{Drop: "address is not in this node's ranges"}
	}
	return exchange.ack(address)
}

// ack binds address to the client and returns the lease to save first.
func (exchange *exchange) ack(address netip.Addr) Result {
	request := exchange.request
	lease := Lease{
		NodeID: exchange.engine.node, Address: address, ScopeID: exchange.scope.id,
		ClientKey: exchange.ref.key, MAC: request.CHAddr.String(),
		State: LeaseActive, BoundAt: exchange.now, ExpiresAt: exchange.now.Add(exchange.scope.lease),
	}
	if id, found := request.Option(optionClientID); found {
		lease.ClientID = hex.EncodeToString(id)
	}
	lease.Hostname = exchange.clientName()
	if relay, found := request.Option(optionRelayInfo); found {
		lease.Relay = hex.EncodeToString(relay)
	}
	if vendor, found := request.Option(optionVendorClass); found {
		lease.VendorClass = cleanText(vendor)
	}
	save := exchange.releaseOthers(address)
	save = append(save, *exchange.engine.remember(lease))
	delete(exchange.engine.offers, exchange.ref)
	return Result{Reply: exchange.reply(Ack, address), Destination: exchange.destination(), Save: save}
}

// releaseOthers ends the client's active leases other than address, so it
// never holds two (D19). A reserved client's leases are found by MAC, since
// one it took before the reservation is keyed by its client identifier (F13).
func (exchange *exchange) releaseOthers(address netip.Addr) []Lease {
	var held []*Lease
	if previous, found := exchange.engine.clients[exchange.ref]; found {
		held = append(held, exchange.engine.leases[previous])
	}
	if exchange.scope.reserved(exchange.request) {
		for _, lease := range exchange.engine.leases {
			if lease.ScopeID == exchange.scope.id && lease.ClientKey != exchange.ref.key && exchange.owns(lease) {
				held = append(held, lease)
			}
		}
	}
	var save []Lease
	for _, old := range held {
		if old != nil && old.Address != address && exchange.owns(old) && old.State == LeaseActive {
			old.State, old.ExpiresAt = LeaseReleased, exchange.now
			save = append(save, *old)
		}
	}
	return save
}

func (exchange *exchange) nak(message string) Result {
	reply := exchange.reply(Nak, netip.IPv4Unspecified())
	reply.Options = append(reply.Options, Option{Code: optionMessage, Data: []byte(message)})
	delete(exchange.engine.offers, exchange.ref)
	if exchange.relayed() {
		// RFC 2131 §4.3.2: the relay broadcasts a NAK to the client.
		reply.Flags |= broadcastFlag
		return Result{Reply: reply, Destination: ToRelay}
	}
	return Result{Reply: reply, Destination: ToBroadcast}
}

// decline takes a client's address out of the pool (RFC 2131 §4.3.3).
func (exchange *exchange) answerDecline() Result {
	if serverID, found := exchange.addrOption(optionServerID); found && serverID != exchange.serverID {
		return Result{Drop: "decline for another server"}
	}
	address, found := exchange.addrOption(optionRequestedIP)
	lease := exchange.engine.leases[address]
	if !found || lease == nil || !exchange.owns(lease) || lease.NodeID != exchange.engine.node {
		return Result{Drop: "decline for an address the client doesn't hold"}
	}
	declined := exchange.engine.decline(exchange.now, exchange.scope, address, exchange.ref.key)
	return Result{Save: []Lease{*declined}, Drop: "declined"}
}

// release ends the client's lease early and keeps the row, so the client
// gets the same address back (RFC 2131 §4.3.4).
func (exchange *exchange) answerRelease() Result {
	if serverID, found := exchange.addrOption(optionServerID); found && serverID != exchange.serverID {
		return Result{Drop: "release for another server"}
	}
	lease := exchange.engine.leases[exchange.request.CIAddr]
	if lease == nil || !exchange.owns(lease) || lease.State != LeaseActive || lease.NodeID != exchange.engine.node {
		return Result{Drop: "release for an address the client doesn't hold"}
	}
	lease.State, lease.ExpiresAt = LeaseReleased, exchange.now
	return Result{Save: []Lease{*lease}, Drop: "released"}
}

// inform answers with configuration and no lease (RFC 2131 §4.3.5).
func (exchange *exchange) answerInform() Result {
	reply := exchange.reply(Ack, netip.IPv4Unspecified())
	switch {
	case exchange.relayed():
		return Result{Reply: reply, Destination: ToRelay}
	case !isZero(exchange.request.CIAddr):
		return Result{Reply: reply, Destination: ToClient}
	}
	return Result{Reply: reply, Destination: ToBroadcast}
}

func (exchange *exchange) v6Only() bool {
	asked, _ := exchange.request.Option(optionParameters)
	return exchange.scope.v6OnlySet && slices.Contains(asked, optionV6OnlyPrefer)
}

func (exchange *exchange) relayed() bool { return !isZero(exchange.request.GIAddr) }

func (exchange *exchange) addrOption(code uint8) (netip.Addr, bool) {
	data, found := exchange.request.Option(code)
	if !found || len(data) != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(data)), true
}

func isZero(address netip.Addr) bool { return !address.IsValid() || address.IsUnspecified() }
