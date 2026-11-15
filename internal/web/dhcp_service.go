package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
)

// DHCPStatus is how the DHCP server is doing on this node.
type DHCPStatus struct {
	Enabled bool `json:"enabled"`
	// Serving is true while the server holds port 67 and answers.
	Serving bool `json:"serving"`
	// Clustered is true when DHCP is enabled on a cluster node, which holds
	// the settings and doesn't serve them yet.
	Clustered   bool   `json:"clustered"`
	Received    uint64 `json:"received"`
	Replied     uint64 `json:"replied"`
	Dropped     uint64 `json:"dropped"`
	Conflicts   uint64 `json:"conflicts"`
	StoreFailed uint64 `json:"store_failed"`
}

// dhcpController is the process's DHCP server, as the console sees it.
type dhcpController interface {
	Status() DHCPStatus
	Leases(context.Context) ([]store.DHCPLease, error)
	RemoveLease(context.Context, netip.Addr) (bool, error)
	// Networks lists the IPv4 networks this host has an address on.
	Networks() ([]DHCPNetwork, error)
	// FindOthers probes the networks settings' scopes serve for another
	// DHCP server. An error says which interfaces it couldn't go out of.
	FindOthers(context.Context, config.DHCP) ([]DHCPOtherServer, error)
}

// SetDHCPController attaches the DHCP server to the console.
func (server *Server) SetDHCPController(controller dhcpController) {
	server.dhcp = controller
}

// dhcpService reads and changes DHCP for every caller: the console, the JSON
// API, and MCP. Settings and reservations live in [dhcp], so they validate,
// replicate, and back up with the rest of the configuration.
type dhcpService struct{ server *Server }

func (server *Server) dhcpService() dhcpService { return dhcpService{server} }

// dhcpState is the server's status beside its settings.
type dhcpState struct {
	Status   DHCPStatus  `json:"status"`
	Settings config.DHCP `json:"settings"`
}

// dhcpLeaseView is one lease that holds its address.
type dhcpLeaseView struct {
	Address     string    `json:"address"`
	Scope       string    `json:"scope"`
	MAC         string    `json:"mac"`
	ClientID    string    `json:"client_id,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`
	Name        string    `json:"name,omitempty"`
	State       string    `json:"state"`
	BoundAt     time.Time `json:"bound_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Node        string    `json:"node"`
	Relay       string    `json:"relay,omitempty"`
	VendorClass string    `json:"vendor_class,omitempty"`
	Reserved    bool      `json:"reserved"`
}

func (service dhcpService) State(who actor) (dhcpState, error) {
	if err := service.allowed(who, auth.PermissionDHCPRead); err != nil {
		return dhcpState{}, err
	}
	state := dhcpState{Settings: service.server.config.Current().Config.DHCP}
	if service.server.dhcp != nil {
		state.Status = service.server.dhcp.Status()
	}
	return state, nil
}

// Leases lists the leases that hold an address now, in scope when one is
// named, ordered by address.
func (service dhcpService) Leases(ctx context.Context, who actor, scope string) ([]dhcpLeaseView, error) {
	if err := service.allowed(who, auth.PermissionDHCPRead); err != nil {
		return nil, err
	}
	rows, err := service.rows(ctx)
	if err != nil {
		return nil, err
	}
	reserved := dhcpReservedMACs(service.server.config.Current().Config.DHCP)
	views := []dhcpLeaseView{}
	now := time.Now()
	for _, row := range rows {
		if !dhcpRowHolds(row, now) || (scope != "" && row.ScopeID != scope) {
			continue
		}
		views = append(views, dhcpLeaseView{
			Address: row.Address.String(), Scope: row.ScopeID, MAC: row.MAC, ClientID: row.ClientID,
			Hostname: row.Hostname, Name: row.Label, State: string(row.State), BoundAt: row.BoundAt,
			ExpiresAt: row.ExpiresAt, Node: row.NodeID, Relay: row.Relay, VendorClass: row.VendorClass,
			Reserved: reserved[row.ScopeID+"|"+row.MAC],
		})
	}
	slices.SortFunc(views, func(left, right dhcpLeaseView) int {
		return netip.MustParseAddr(left.Address).Compare(netip.MustParseAddr(right.Address))
	})
	return views, nil
}

// Save replaces the [dhcp] settings.
//
// Saving needs settings.write as well as dhcp.write (D47): a scope's domain
// creates a Primary zone, and its router and resolvers go to every client.
func (service dhcpService) Save(ctx context.Context, who actor, settings config.DHCP) error {
	if err := service.allowed(who, auth.PermissionSettingsWrite); err != nil {
		return err
	}
	return service.update(ctx, who, "dhcp.settings.update", "DHCP settings saved", func(current *config.DHCP) error {
		*current = settings
		return nil
	})
}

// Scope returns the settings of the scope with id.
func (service dhcpService) Scope(who actor, id string) (config.DHCPScope, error) {
	state, err := service.State(who)
	if err != nil {
		return config.DHCPScope{}, err
	}
	scope, err := dhcpScope(&state.Settings, id)
	if err != nil {
		return config.DHCPScope{}, err
	}
	return *scope, nil
}

// SetScope adds the scope with id, or replaces its settings. The scope keeps
// the reservations it has, since they're set one at a time with
// SetReservation. Like Save, it needs settings.write (D47).
func (service dhcpService) SetScope(ctx context.Context, who actor, id string, scope config.DHCPScope) (config.DHCPScope, error) {
	if err := service.allowed(who, auth.PermissionSettingsWrite); err != nil {
		return config.DHCPScope{}, err
	}
	scope.ID = strings.TrimSpace(id)
	err := service.update(ctx, who, "dhcp.scope.set", "saved DHCP scope "+scope.ID, func(settings *config.DHCP) error {
		current, err := dhcpScope(settings, scope.ID)
		if err != nil {
			scope.Reservations = nil
			settings.Scopes = append(settings.Scopes, scope)
			return nil
		}
		scope.Reservations = current.Reservations
		*current = scope
		return nil
	})
	if err != nil {
		return config.DHCPScope{}, err
	}
	saved := service.server.config.Current().Config.DHCP
	if current, _ := dhcpScope(&saved, scope.ID); current != nil {
		return *current, nil
	}
	return scope, nil
}

// RemoveScope takes the scope with id, and its reservations, out of [dhcp].
// Its leases stay in the store until they expire.
func (service dhcpService) RemoveScope(ctx context.Context, who actor, id string) error {
	if err := service.allowed(who, auth.PermissionSettingsWrite); err != nil {
		return err
	}
	return service.update(ctx, who, "dhcp.scope.remove", "removed DHCP scope "+id, func(settings *config.DHCP) error {
		if _, err := dhcpScope(settings, id); err != nil {
			return err
		}
		settings.Scopes = slices.DeleteFunc(settings.Scopes, func(scope config.DHCPScope) bool { return scope.ID == id })
		return nil
	})
}

// SetEnabled turns the DHCP server on or off, keeping its scopes. Like Save,
// it needs settings.write (D47): turning it on hands out every scope's
// router and resolvers.
func (service dhcpService) SetEnabled(ctx context.Context, who actor, enabled, force bool) error {
	if err := service.allowed(who, auth.PermissionSettingsWrite); err != nil {
		return err
	}
	if enabled {
		if err := service.checkNoOthers(ctx, force); err != nil {
			return err
		}
	}
	action := map[bool]string{true: "dhcp.enable", false: "dhcp.disable"}[enabled]
	return service.update(ctx, who, action, action, func(settings *config.DHCP) error {
		settings.Enabled = enabled
		return nil
	})
}

// RemoveLease ends this node's lease on address. The client keeps using it
// until it next renews, when it's offered an address again (RFC 2131 §4.4.5).
func (service dhcpService) RemoveLease(ctx context.Context, who actor, raw string) error {
	if err := service.ready(who); err != nil {
		return err
	}
	address, err := dhcpAddress(raw)
	if err != nil {
		return err
	}
	if service.server.dhcp == nil {
		return refuse(http.StatusNotImplemented, "DHCP isn't available on this server")
	}
	removed, err := service.server.dhcp.RemoveLease(ctx, address)
	if err != nil {
		service.server.logger.Warn("remove DHCP lease failed", "address", address, "error", err)
		return refuse(http.StatusServiceUnavailable, "the lease on %s wasn't removed; try again", address)
	}
	if !removed {
		return refuse(http.StatusNotFound, "%s has no lease on this node", address)
	}
	service.finish(ctx, who, "dhcp.lease.remove", "removed the lease on "+address.String())
	return nil
}

// Reserve turns the lease on address into a reservation for its client, named
// name, or the name the lease registered when name is empty.
func (service dhcpService) Reserve(ctx context.Context, who actor, raw, name, comment string) (config.DHCPReservation, error) {
	if err := service.ready(who); err != nil {
		return config.DHCPReservation{}, err
	}
	address, err := dhcpAddress(raw)
	if err != nil {
		return config.DHCPReservation{}, err
	}
	rows, err := service.rows(ctx)
	if err != nil {
		return config.DHCPReservation{}, err
	}
	now := time.Now()
	index := slices.IndexFunc(rows, func(row store.DHCPLease) bool {
		return row.Address == address && row.State == store.DHCPLeaseActive && dhcpRowHolds(row, now)
	})
	if index < 0 {
		return config.DHCPReservation{}, refuse(http.StatusNotFound, "%s has no active lease", address)
	}
	lease := rows[index]
	if strings.TrimSpace(name) == "" {
		name = lease.Label
	}
	reservation := config.DHCPReservation{MAC: lease.MAC, Address: address.String(), Name: name, Comment: comment}
	return service.SetReservation(ctx, who, lease.ScopeID, reservation)
}

// SetReservation adds the reservation for its MAC to scope, or replaces the
// one that MAC already has.
func (service dhcpService) SetReservation(ctx context.Context, who actor, scope string, reservation config.DHCPReservation) (config.DHCPReservation, error) {
	hardware, err := net.ParseMAC(strings.TrimSpace(reservation.MAC))
	if err != nil || len(hardware) != 6 {
		return config.DHCPReservation{}, refuse(http.StatusUnprocessableEntity, "mac must be a 6-byte hardware address, like 00:11:22:33:44:55")
	}
	reservation.MAC = hardware.String()
	err = service.update(ctx, who, "dhcp.reservation.set", "reserved "+reservation.Address+" for "+reservation.MAC, func(settings *config.DHCP) error {
		target, err := dhcpScope(settings, scope)
		if err != nil {
			return err
		}
		index := slices.IndexFunc(target.Reservations, func(current config.DHCPReservation) bool { return current.MAC == reservation.MAC })
		if index < 0 {
			target.Reservations = append(target.Reservations, reservation)
		} else {
			target.Reservations[index] = reservation
		}
		return nil
	})
	if err != nil {
		return config.DHCPReservation{}, err
	}
	saved := service.server.config.Current().Config.DHCP
	if scopeSettings, _ := dhcpScope(&saved, scope); scopeSettings != nil {
		if index := slices.IndexFunc(scopeSettings.Reservations, func(current config.DHCPReservation) bool { return current.MAC == reservation.MAC }); index >= 0 {
			return scopeSettings.Reservations[index], nil
		}
	}
	return reservation, nil
}

// RemoveReservation takes mac's reservation out of scope.
func (service dhcpService) RemoveReservation(ctx context.Context, who actor, scope, mac string) error {
	hardware, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil {
		return refuse(http.StatusUnprocessableEntity, "mac must be a hardware address, like 00:11:22:33:44:55")
	}
	normalized := hardware.String()
	return service.update(ctx, who, "dhcp.reservation.remove", "removed the reservation for "+normalized, func(settings *config.DHCP) error {
		target, err := dhcpScope(settings, scope)
		if err != nil {
			return err
		}
		before := len(target.Reservations)
		target.Reservations = slices.DeleteFunc(target.Reservations, func(current config.DHCPReservation) bool { return current.MAC == normalized })
		if len(target.Reservations) == before {
			return refuse(http.StatusNotFound, "%s has no reservation in scope %s", normalized, scope)
		}
		return nil
	})
}

// update runs one change to [dhcp]: it copies the settings, applies mutate,
// normalizes and validates the result, and saves it through the
// configuration manager, which refuses DHCP on a cluster primary.
func (service dhcpService) update(ctx context.Context, who actor, action, message string, mutate func(*config.DHCP) error) error {
	if err := service.ready(who); err != nil {
		return err
	}
	editor, ok := service.server.config.(settingsEditor)
	if !ok {
		return refuse(http.StatusNotImplemented, "this configuration source is read-only")
	}
	err := editor.Update(ctx, func(configuration *config.Config) error {
		settings := dhcpClone(configuration.DHCP)
		if err := mutate(&settings); err != nil {
			return err
		}
		settings.Normalize()
		if err := settings.Validate(); err != nil {
			return refuse(http.StatusUnprocessableEntity, "%s", err.Error())
		}
		configuration.DHCP = settings
		return nil
	})
	if err != nil {
		var refusal *serviceError
		if !errors.As(err, &refusal) {
			service.server.logger.Warn("DHCP change failed", "operation", action, "error", err)
			return refuse(http.StatusUnprocessableEntity, "%s", err.Error())
		}
		return err
	}
	service.finish(ctx, who, action, message)
	return nil
}

func (service dhcpService) finish(ctx context.Context, who actor, action, message string) {
	service.server.logger.Info("DHCP change completed", "operation", action, "client", who.clientIP, "user", who.principal.Username)
	service.server.audit(ctx, who, action, message)
}

func (service dhcpService) ready(who actor) error {
	if err := service.server.refuseOnReplica(); err != nil {
		return err
	}
	return service.allowed(who, auth.PermissionDHCPWrite)
}

func (service dhcpService) allowed(who actor, permission string) error {
	if !service.server.authorized(who, permission, nil) {
		return refuse(http.StatusForbidden, "you need %s for DHCP", permission)
	}
	return nil
}

func (service dhcpService) rows(ctx context.Context) ([]store.DHCPLease, error) {
	if service.server.dhcp == nil {
		return nil, nil
	}
	rows, err := service.server.dhcp.Leases(ctx)
	if err != nil {
		service.server.logger.Warn("read DHCP leases failed", "error", err)
		return nil, refuse(http.StatusServiceUnavailable, "the lease store isn't answering; try again")
	}
	return rows, nil
}

func dhcpAddress(raw string) (netip.Addr, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !address.Is4() {
		return netip.Addr{}, refuse(http.StatusUnprocessableEntity, "address must be an IPv4 address")
	}
	return address, nil
}

func dhcpScope(settings *config.DHCP, id string) (*config.DHCPScope, error) {
	for index := range settings.Scopes {
		if settings.Scopes[index].ID == strings.TrimSpace(id) {
			return &settings.Scopes[index], nil
		}
	}
	return nil, refuse(http.StatusNotFound, "there's no DHCP scope %q", id)
}

// dhcpClone copies settings deeply enough that a change to its scopes or
// their reservations can't reach the snapshot it came from.
func dhcpClone(settings config.DHCP) config.DHCP {
	settings.Scopes = slices.Clone(settings.Scopes)
	for index := range settings.Scopes {
		settings.Scopes[index].Reservations = slices.Clone(settings.Scopes[index].Reservations)
	}
	return settings
}

// dhcpRowHolds reports whether a lease row holds its address at now: active
// and declined rows do until they expire.
func dhcpRowHolds(row store.DHCPLease, now time.Time) bool {
	return (row.State == store.DHCPLeaseActive || row.State == store.DHCPLeaseDeclined) && now.Before(row.ExpiresAt)
}

func dhcpReservedMACs(settings config.DHCP) map[string]bool {
	reserved := map[string]bool{}
	for _, scope := range settings.Scopes {
		for _, reservation := range scope.Reservations {
			reserved[scope.ID+"|"+reservation.MAC] = true
		}
	}
	return reserved
}
