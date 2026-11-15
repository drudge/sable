package web

import (
	"net/http"
	"slices"
	"strings"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web/pages"
)

// dhcpPage shows the DHCP server's leases and reservations.
func (server *Server) dhcpPage(writer http.ResponseWriter, request *http.Request) {
	server.renderDHCP(writer, request, "")
}

func (server *Server) reserveDHCPLease(writer http.ResponseWriter, request *http.Request) {
	server.dhcpMutation(writer, request, "#dhcp-notice", func(service dhcpService, who actor) (string, error) {
		address := request.FormValue("address")
		reservation, err := service.Reserve(request.Context(), who, address, request.FormValue("name"), "")
		if err != nil {
			return "", err
		}
		return "Reserved " + reservation.Address + " for " + dhcpReservationName(reservation), nil
	})
}

func (server *Server) removeDHCPLease(writer http.ResponseWriter, request *http.Request) {
	server.dhcpMutation(writer, request, "#dhcp-notice", func(service dhcpService, who actor) (string, error) {
		address := strings.TrimSpace(request.FormValue("address"))
		if err := service.RemoveLease(request.Context(), who, address); err != nil {
			return "", err
		}
		return "Removed the lease on " + address, nil
	})
}

// saveDHCPReservation adds a reservation, or replaces the one its MAC address
// already has in the scope.
func (server *Server) saveDHCPReservation(writer http.ResponseWriter, request *http.Request) {
	scope, mac := request.FormValue("scope"), request.FormValue("mac")
	notice := "#" + pages.DHCPReservationNoticeID(scope, mac, request.FormValue("new") != "")
	server.dhcpMutation(writer, request, notice, func(service dhcpService, who actor) (string, error) {
		reservation, err := service.SetReservation(request.Context(), who, scope, config.DHCPReservation{
			MAC: mac, Address: strings.TrimSpace(request.FormValue("address")),
			Name: strings.TrimSpace(request.FormValue("name")), Comment: strings.TrimSpace(request.FormValue("comment")),
		})
		if err != nil {
			return "", err
		}
		return "Saved the reservation for " + dhcpReservationName(reservation), nil
	})
}

func (server *Server) deleteDHCPReservation(writer http.ResponseWriter, request *http.Request) {
	server.dhcpMutation(writer, request, "#dhcp-notice", func(service dhcpService, who actor) (string, error) {
		mac := request.FormValue("mac")
		if err := service.RemoveReservation(request.Context(), who, request.FormValue("scope"), mac); err != nil {
			return "", err
		}
		return "Removed the reservation for " + mac, nil
	})
}

// dhcpMutation runs one change and shows the page again, or shows why the
// change was refused in notice, leaving the page as it was.
func (server *Server) dhcpMutation(writer http.ResponseWriter, request *http.Request, notice string, change func(dhcpService, actor) (string, error)) {
	message, err := change(server.dhcpService(), requestActor(request, ""))
	if err != nil {
		server.renderFormProblem(writer, request, notice, err)
		return
	}
	server.renderDHCP(writer, request, message)
}

func (server *Server) renderDHCP(writer http.ResponseWriter, request *http.Request, message string) {
	view := server.dhcpPageView(request)
	view.Message = message
	if request.Header.Get("HX-Request") == "true" {
		server.render(writer, request, pages.DHCPContent(view))
		return
	}
	server.render(writer, request, pages.DHCPPage(view))
}

// dhcpPageView reads the settings and leases once each.
func (server *Server) dhcpPageView(request *http.Request) pages.DHCPPageView {
	tab := request.FormValue("tab")
	if !slices.Contains(pages.DHCPTabs(), tab) {
		tab = pages.DHCPTabs()[0]
	}
	view := pages.DHCPPageView{Console: server.consoleView(request), ActiveTab: tab}
	who := requestActor(request, "")
	service := server.dhcpService()
	state, err := service.State(who)
	if err != nil {
		view.Error = sentence(err.Error())
		return view
	}
	view.Status = pages.DHCPStatusView{Enabled: state.Status.Enabled || state.Settings.Enabled, Serving: state.Status.Serving,
		Clustered: state.Status.Clustered || (server.cluster != nil && server.cluster.Snapshot().Initialized), Received: state.Status.Received, Replied: state.Status.Replied}
	view.CanWrite = service.allowed(who, auth.PermissionDHCPWrite) == nil && !view.Console.ControlPlaneReadOnly
	view.CanConfigure = view.CanWrite && service.allowed(who, auth.PermissionSettingsWrite) == nil
	leases, err := service.Leases(request.Context(), who, "")
	if err != nil {
		server.logger.Warn("read DHCP leases for the console", "error", err)
		view.Error = "The leases couldn't be read. Try again in a moment."
	}
	held := map[string]dhcpLeaseView{}
	for _, lease := range leases {
		held[lease.Scope+"|"+lease.MAC] = lease
		view.Leases = append(view.Leases, pages.DHCPLeaseRow{Address: lease.Address, Scope: lease.Scope, MAC: lease.MAC,
			Name: dhcpLeaseName(lease), Expires: lease.ExpiresAt, Reserved: lease.Reserved})
	}
	for _, scope := range state.Settings.Scopes {
		scopeView := dhcpScopeView(scope)
		for _, reservation := range scope.Reservations {
			row := pages.DHCPReservationRow{Scope: scope.ID, MAC: reservation.MAC, Address: reservation.Address, Name: reservation.Name, Comment: reservation.Comment}
			if lease, ok := held[scope.ID+"|"+reservation.MAC]; ok {
				row.LeaseExpires = lease.ExpiresAt
			}
			scopeView.Reservations = append(scopeView.Reservations, row)
		}
		view.Scopes = append(view.Scopes, scopeView)
	}
	return view
}

// dhcpLeaseName is the name a lease registered, or the host name its client
// sent when it registered none.
func dhcpLeaseName(lease dhcpLeaseView) string {
	if lease.Name != "" {
		return lease.Name
	}
	return lease.Hostname
}

func dhcpReservationName(reservation config.DHCPReservation) string {
	if reservation.Name != "" {
		return reservation.Name
	}
	return reservation.MAC
}

// dhcpScopeView is what the Scopes tab and scope dialog show of a scope.
func dhcpScopeView(scope config.DHCPScope) pages.DHCPScopeView {
	view := pages.DHCPScopeView{ID: scope.ID, Name: scope.Name, Subnet: scope.Subnet, Router: scope.Router,
		Domain: scope.Domain, DNS: strings.Join(scope.DNS, ", ")}
	if scope.Lease.Duration > 0 {
		view.Lease = scope.Lease.String()
	}
	if len(scope.Ranges) > 0 {
		view.RangeStart, view.RangeEnd, view.MoreRanges = scope.Ranges[0].Start, scope.Ranges[0].End, len(scope.Ranges)-1
	}
	return view
}
