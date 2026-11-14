package dhcp

import (
	"encoding/binary"
	"net/netip"
	"slices"
)

// reply builds a BOOTREPLY to the request with the fields RFC 2131 Table 3
// sets for each message type.
func (exchange *exchange) reply(kind MessageType, yiaddr netip.Addr) *Packet {
	request := exchange.request
	reply := &Packet{
		Op: 2, HType: request.HType, XID: request.XID, Flags: request.Flags,
		CIAddr: netip.IPv4Unspecified(), YIAddr: yiaddr, SIAddr: netip.IPv4Unspecified(),
		GIAddr: request.GIAddr, CHAddr: slices.Clone(request.CHAddr),
	}
	if !reply.GIAddr.IsValid() {
		reply.GIAddr = netip.IPv4Unspecified()
	}
	if kind == Ack && request.CIAddr.IsValid() {
		reply.CIAddr = request.CIAddr // RENEWING, REBINDING, INFORM
	}
	required := []Option{
		{Code: optionMessageType, Data: []byte{byte(kind)}},
		{Code: optionServerID, Data: packAddrs([]netip.Addr{exchange.serverID})},
	}
	// RFC 6842 §3: echo the client identifier; RFC 3046 §2.2: echo option 82.
	for _, code := range []uint8{optionClientID, optionRelayInfo} {
		if data, found := request.Option(code); found {
			required = append(required, Option{Code: code, Data: data})
		}
	}
	if kind == Nak {
		reply.Options = required
		return reply
	}
	exchange.addBoot(reply)
	leased := !isZero(yiaddr)
	if leased {
		required = append(required, leaseOptions(exchange.scope)...)
	}
	reply.Options = fitOptions(request, required, exchange.scope.replyOptions(request, exchange.serverID))
	return reply
}

// addBoot fills siaddr, sname, and file for a PXE client (RFC 2131 §2).
func (exchange *exchange) addBoot(reply *Packet) {
	compiled := exchange.scope
	if compiled.nextServer.IsValid() {
		reply.SIAddr = compiled.nextServer
	}
	reply.SName, reply.File = compiled.serverName, compiled.bootFile
}

// leaseOptions are the lease time and the renewal and rebinding times at
// 0.5 and 0.875 of it (RFC 2131 §4.4.5).
func leaseOptions(compiled *scope) []Option {
	seconds := uint32(compiled.lease.Seconds())
	return []Option{
		{Code: optionLeaseTime, Data: binary.BigEndian.AppendUint32(nil, seconds)},
		{Code: optionRenewal, Data: binary.BigEndian.AppendUint32(nil, seconds/2)},
		{Code: optionRebinding, Data: binary.BigEndian.AppendUint32(nil, seconds/8*7)},
	}
}

// destination is where an OFFER or ACK goes (RFC 2131 §4.1): the relay, the
// client's own address, a broadcast when the client asked for one, else
// unicast to yiaddr at chaddr.
func (exchange *exchange) destination() Destination {
	request := exchange.request
	switch {
	case exchange.relayed():
		return ToRelay
	case !isZero(request.CIAddr):
		return ToClient
	case request.Flags&broadcastFlag != 0:
		return ToBroadcast
	}
	return ToHardware
}
