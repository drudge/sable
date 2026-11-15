package web

import (
	"encoding/json"
	"net/http"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
)

// mcpDHCPTools are adapters over dhcpService. They're off until an operator
// adds them, since a lease names each device on the network.
var mcpDHCPTools = []mcpTool{
	{
		Name:        "get_dhcp_status",
		Title:       "Get DHCP status",
		Description: "Show whether the DHCP server is on and answering, its counters, and its scopes, ranges, options, and reservations.",
		InputSchema: mcpObjectSchema(nil, nil),
		Annotations: mcpToolAnnotations{Title: "Get DHCP status", ReadOnlyHint: true, IdempotentHint: true},
		call:        (*Server).mcpDHCPStatus,
		section:     "dhcp",
		grant:       auth.PermissionDHCPRead,
	},
	{
		Name:  "list_dhcp_leases",
		Title: "List DHCP leases",
		Description: "List the leases that hold an address now: address, hardware address, host name, the name " +
			"registered in DNS, expiry, and whether the device has a reservation.",
		InputSchema: mcpObjectSchema(map[string]any{
			"scope": mcpString("Optional scope ID to list only that scope's leases."),
		}, nil),
		Annotations: mcpToolAnnotations{Title: "List DHCP leases", ReadOnlyHint: true, IdempotentHint: true},
		call:        (*Server).mcpListDHCPLeases,
		section:     "dhcp",
		grant:       auth.PermissionDHCPRead,
	},
	{
		Name:  "set_dhcp_reservation",
		Title: "Reserve a DHCP address",
		Description: "Give a device a fixed address in a scope, by hardware address. A device that already has a " +
			"reservation in the scope gets this one instead. A named reservation publishes its A and PTR records.",
		InputSchema: mcpObjectSchema(map[string]any{
			"scope":   mcpString("Scope ID, as get_dhcp_status shows it."),
			"mac":     mcpString("Hardware address, for example 00:11:22:33:44:55."),
			"address": mcpString("IPv4 address inside the scope's subnet."),
			"name":    mcpString("Optional host name to publish, a single DNS label such as printer."),
			"comment": mcpString("Optional note shown beside the reservation in Sable."),
		}, []string{"scope", "mac", "address"}),
		Annotations: mcpToolAnnotations{Title: "Reserve a DHCP address", IdempotentHint: true},
		call:        (*Server).mcpSetDHCPReservation,
		section:     "dhcp",
		grant:       auth.PermissionDHCPWrite,
	},
	{
		Name:        "remove_dhcp_reservation",
		Title:       "Remove a DHCP reservation",
		Description: "Take a device's reservation out of a scope. Its next renewal gets an address from the pool.",
		InputSchema: mcpObjectSchema(map[string]any{
			"scope": mcpString("Scope ID, as get_dhcp_status shows it."),
			"mac":   mcpString("Hardware address, for example 00:11:22:33:44:55."),
		}, []string{"scope", "mac"}),
		Annotations: mcpToolAnnotations{Title: "Remove a DHCP reservation", DestructiveHint: true},
		call:        (*Server).mcpRemoveDHCPReservation,
		section:     "dhcp",
		grant:       auth.PermissionDHCPWrite,
	},
}

func (server *Server) mcpDHCPStatus(request *http.Request, arguments json.RawMessage) (any, error) {
	if err := decodeMCPArguments(arguments, &struct{}{}); err != nil {
		return nil, err
	}
	return server.dhcpService().State(requestActor(request, "mcp"))
}

func (server *Server) mcpListDHCPLeases(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Scope string `json:"scope"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	leases, err := server.dhcpService().Leases(request.Context(), requestActor(request, "mcp"), input.Scope)
	if err != nil {
		return nil, err
	}
	return map[string]any{"leases": leases}, nil
}

func (server *Server) mcpSetDHCPReservation(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Scope   string `json:"scope"`
		MAC     string `json:"mac"`
		Address string `json:"address"`
		Name    string `json:"name"`
		Comment string `json:"comment"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	reservation, err := server.dhcpService().SetReservation(request.Context(), requestActor(request, "mcp"), input.Scope, config.DHCPReservation{
		MAC: input.MAC, Address: input.Address, Name: input.Name, Comment: input.Comment,
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"reservation": reservation, "message": "Reserved " + reservation.Address + " for " + reservation.MAC}, nil
}

func (server *Server) mcpRemoveDHCPReservation(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Scope string `json:"scope"`
		MAC   string `json:"mac"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	if err := server.dhcpService().RemoveReservation(request.Context(), requestActor(request, "mcp"), input.Scope, input.MAC); err != nil {
		return nil, err
	}
	return map[string]any{"message": "Removed the reservation for " + input.MAC}, nil
}
