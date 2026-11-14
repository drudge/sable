package dhcp

import (
	"hash/fnv"
	"net/netip"
	"slices"
	"strings"
)

// allocate picks the address to offer, in the design's order: the
// reservation, a pending offer, the client's previous address, the address
// it asked for (option 50), then a walk from a hash of the client key, so a
// client gets the same address even after the lease table is lost.
func (exchange *exchange) allocate() (address netip.Addr, reserved bool) {
	if reservation, found := exchange.scope.reservation(exchange.request); found {
		if exchange.available(reservation) {
			return reservation, true
		}
	}
	if exchange.scope.flags.reservedOnly {
		return netip.Addr{}, false
	}
	if pending, found := exchange.engine.offers[exchange.ref]; found && exchange.now.Before(pending.expires) {
		return pending.address, false
	}
	if previous, found := exchange.engine.clients[exchange.ref]; found && exchange.dynamic(previous) {
		return previous, false
	}
	if requested, found := exchange.addrOption(optionRequestedIP); found && exchange.dynamic(requested) {
		return requested, false
	}
	return exchange.walk(), false
}

// walk looks through this node's ranges from the client's hash point:
// first for an address nobody has held, then for any it may have.
func (exchange *exchange) walk() netip.Addr {
	var total uint64
	for _, pool := range exchange.scope.ranges {
		total += uint64(pool.size())
	}
	if total == 0 {
		return netip.Addr{}
	}
	hash := fnv.New64a()
	hash.Write([]byte(exchange.ref.key))
	start := hash.Sum64() % total
	for _, untouchedOnly := range []bool{true, false} {
		for step := range total {
			address := exchange.scope.nth((start + step) % total)
			if untouchedOnly && exchange.engine.leases[address] != nil {
				continue
			}
			if exchange.dynamic(address) {
				return address
			}
		}
	}
	return netip.Addr{}
}

// nth is the index-th address across this node's ranges.
func (compiled *scope) nth(index uint64) netip.Addr {
	for _, pool := range compiled.ranges {
		if index < uint64(pool.size()) {
			return fromUint(pool.first + uint32(index))
		}
		index -= uint64(pool.size())
	}
	return netip.Addr{}
}

// dynamic reports whether this node may hand address to the client from its
// ranges: in a range, not reserved, and free for this client.
func (exchange *exchange) dynamic(address netip.Addr) bool {
	if !exchange.scope.inRanges(address) {
		return false
	}
	if _, found := exchange.scope.reservedBy[address]; found {
		return false
	}
	return exchange.available(address)
}

// available reports whether no other client holds or was offered address,
// and it isn't one of the server's own.
func (exchange *exchange) available(address netip.Addr) bool {
	if exchange.isServerAddress(address) {
		return false
	}
	if lease := exchange.engine.leases[address]; lease != nil && lease.ClientKey != exchange.ref.key && lease.holds(exchange.now) {
		return false
	}
	if lease := exchange.engine.leases[address]; lease != nil && lease.State == LeaseDeclined && lease.holds(exchange.now) {
		return false
	}
	for ref, pending := range exchange.engine.offers {
		if pending.address == address && ref != exchange.ref && exchange.now.Before(pending.expires) {
			return false
		}
	}
	return true
}

func (exchange *exchange) isServerAddress(address netip.Addr) bool {
	return address == exchange.serverID || slices.Contains(exchange.scope.dns, address)
}

// holdOffer keeps address for the client until offerHold passes, within the
// scope's cap on outstanding offers.
func (exchange *exchange) holdOffer(address netip.Addr) bool {
	engine := exchange.engine
	count := 0
	for ref, pending := range engine.offers {
		switch {
		case !exchange.now.Before(pending.expires):
			delete(engine.offers, ref)
		case ref.scope == exchange.scope.id && ref != exchange.ref:
			count++
		}
	}
	if count >= maxOffersPerScope {
		return false
	}
	engine.offers[exchange.ref] = offer{address: address, expires: exchange.now.Add(offerHold)}
	return true
}

func macKey(request Packet) string { return strings.ToLower(request.CHAddr.String()) }
