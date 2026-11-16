package web

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
)

// DHCPNetwork is an IPv4 network this server has an address on: the setup
// flow offers each one as a scope.
type DHCPNetwork struct {
	Interface string `json:"interface"`
	// Prefix is the server's address on the network and its length.
	Prefix netip.Prefix `json:"prefix"`
	// Gateway is the interface's default route, when it has one.
	Gateway netip.Addr `json:"gateway,omitzero"`
}

// DHCPOtherServer is another DHCP server that answered a probe's DISCOVER.
type DHCPOtherServer struct {
	Interface string `json:"interface"`
	// Server is the OFFER's server identifier (RFC 2132 §9.7).
	Server  netip.Addr `json:"server"`
	Offered netip.Addr `json:"offered"`
}

// dhcpNetworkView is a host network and the scope the setup flow suggests
// for it.
type dhcpNetworkView struct {
	DHCPNetwork
	Suggested config.DHCPScope `json:"suggested"`
}

// dhcpProbeRefusal is why Turn On didn't: another server answered, or the
// probe couldn't go out. Either way the operator may turn it on anyway.
type dhcpProbeRefusal struct {
	others []DHCPOtherServer
	err    error
}

func (refusal *dhcpProbeRefusal) Error() string {
	if len(refusal.others) == 0 {
		return fmt.Sprintf("Sable couldn't check for another DHCP server (%v). Turn it on anyway only if you know none answers on this network.", refusal.err)
	}
	var seen []string
	for _, other := range refusal.others {
		seen = append(seen, fmt.Sprintf("%s on %s (offered %s)", other.Server, other.Interface, other.Offered))
	}
	return "Another DHCP server answers: " + strings.Join(seen, ", ") + ". Turn its DHCP off first, or devices get conflicting leases."
}

// Networks lists the networks this server is on, with a suggested scope for
// each. A network that already has a scope isn't listed.
func (service dhcpService) Networks(who actor) ([]dhcpNetworkView, error) {
	if err := service.allowed(who, auth.PermissionDHCPRead); err != nil {
		return nil, err
	}
	if service.server.dhcp == nil {
		return nil, nil
	}
	networks, err := service.server.dhcp.Networks()
	if err != nil {
		return nil, err
	}
	settings := service.server.config.Current().Config.DHCP
	taken := map[string]bool{}
	for _, scope := range settings.Scopes {
		taken[scope.ID] = true
		if subnet, err := netip.ParsePrefix(scope.Subnet); err == nil {
			taken[subnet.Masked().String()] = true
		}
	}
	var views []dhcpNetworkView
	for _, network := range networks {
		if taken[network.Prefix.Masked().String()] {
			continue
		}
		id := dhcpSuggestedID(network.Interface, taken)
		taken[id] = true
		views = append(views, dhcpNetworkView{DHCPNetwork: network, Suggested: dhcpSuggestedScope(network, id)})
	}
	return views, nil
}

// Probe broadcasts a DISCOVER out of each network a scope serves and returns
// the other servers that answered (docs/design/dhcp.md §4).
func (service dhcpService) Probe(ctx context.Context, who actor) ([]DHCPOtherServer, error) {
	if err := service.allowed(who, auth.PermissionDHCPWrite); err != nil {
		return nil, err
	}
	return service.probe(ctx)
}

func (service dhcpService) probe(ctx context.Context) ([]DHCPOtherServer, error) {
	if service.server.dhcp == nil {
		return nil, refuse(http.StatusNotImplemented, "DHCP isn't available on this server")
	}
	settings := service.server.config.Current().Config.DHCP
	if len(settings.Scopes) == 0 {
		return nil, refuse(http.StatusUnprocessableEntity, "Add a scope first; the probe goes out of the networks scopes serve")
	}
	return service.server.dhcp.FindOthers(ctx, settings)
}

// checkNoOthers is Turn On's probe: it refuses while another server answers
// or the probe can't run, unless force says to turn on anyway.
func (service dhcpService) checkNoOthers(ctx context.Context, force bool) error {
	if force || service.server.config.Current().Config.DHCP.Enabled {
		return nil
	}
	others, err := service.probe(ctx)
	var refusal *serviceError
	switch {
	case errors.As(err, &refusal):
		return err
	case len(others) > 0 || err != nil:
		return &dhcpProbeRefusal{others: others, err: err}
	}
	return nil
}

// dhcpSuggestedID is lan for the first network, and the interface's name
// after that.
func dhcpSuggestedID(device string, taken map[string]bool) string {
	if !taken["lan"] {
		return "lan"
	}
	id := config.DHCPScopeID(device)
	for suffix := 2; id == "" || taken[id]; suffix++ {
		id = fmt.Sprintf("lan%d", suffix)
	}
	return id
}

// dhcpSuggestedScope hands out .100 to .199 on a /24 or larger, like a home
// router, and the top half of a smaller network, leaving out the server's
// own address and the router's. The router is the interface's default
// gateway when it's on the network. A network with no host left to hand out
// gets no range, and the dialog asks for one.
func dhcpSuggestedScope(network DHCPNetwork, id string) config.DHCPScope {
	subnet := network.Prefix.Masked()
	first := dhcpUint32(subnet.Addr())
	size := uint32(1) << (32 - subnet.Bits())
	start, end := first+100, first+199
	if size < 256 {
		start, end = first+size/2, first+size-2
	}
	scope := config.DHCPScope{ID: id, Name: strings.ToUpper(id), Subnet: subnet.String()}
	taken := []uint32{dhcpUint32(network.Prefix.Addr())}
	if network.Gateway.IsValid() && subnet.Contains(network.Gateway) && network.Gateway != network.Prefix.Addr() {
		scope.Router = network.Gateway.String()
		taken = append(taken, dhcpUint32(network.Gateway))
	}
	low, high, ok := dhcpLongestRun(start, end, taken)
	if !ok {
		// A tiny network's half held only taken addresses: use its other hosts.
		low, high, ok = dhcpLongestRun(first+1, first+size-2, taken)
	}
	if ok {
		scope.Ranges = []config.DHCPRange{{Start: dhcpAddr(low).String(), End: dhcpAddr(high).String()}}
	}
	return scope
}

// dhcpLongestRun is the longest run of start-end once the taken addresses
// are cut out of it, the upper one on a tie. ok is false when taken covers
// all of it (F46, F47).
func dhcpLongestRun(start, end uint32, taken []uint32) (low, high uint32, ok bool) {
	taken = slices.Sorted(slices.Values(taken))
	keep := func(from, to uint32) {
		if from <= to && (!ok || to-from >= high-low) {
			low, high, ok = from, to, true
		}
	}
	from := start
	for _, address := range taken {
		if address < from || address > end {
			continue
		}
		if address > from {
			keep(from, address-1)
		}
		from = address + 1
	}
	keep(from, end)
	return low, high, ok
}

func dhcpUint32(address netip.Addr) uint32 {
	bytes := address.As4()
	return binary.BigEndian.Uint32(bytes[:])
}

func dhcpAddr(value uint32) netip.Addr {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], value)
	return netip.AddrFrom4(bytes)
}

func (server *Server) dhcpProbeAPI(writer http.ResponseWriter, request *http.Request) {
	// A probe that couldn't go out of an interface still reports what the
	// others found, with why in error.
	others, err := server.dhcpService().Probe(request.Context(), requestActor(request, ""))
	if refusal := (*serviceError)(nil); errors.As(err, &refusal) {
		apiError(writer, refusal.status, err.Error())
		return
	}
	body := map[string]any{"others": others}
	if err != nil {
		body["error"] = err.Error()
	}
	writeJSON(writer, http.StatusOK, body)
}

func (server *Server) dhcpNetworksAPI(writer http.ResponseWriter, request *http.Request) {
	networks, err := server.dhcpService().Networks(requestActor(request, ""))
	if err != nil {
		apiError(writer, serviceStatus(err), err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"networks": networks})
}
