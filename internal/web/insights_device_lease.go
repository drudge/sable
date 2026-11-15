package web

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/web/pages"
)

// deviceLease finds the active lease device holds now: by its hardware
// address, or by one of its addresses only when Insights knows no hardware
// address for it, so an address that has passed to another client (or was
// declined) never shows as this device's. It is nil when there is none or the
// operator can't read DHCP.
func (server *Server) deviceLease(request *http.Request, console pages.DashboardView, device pages.InsightDeviceView) *pages.InsightDeviceLeaseView {
	who := requestActor(request, "")
	leases, err := server.dhcpService().Leases(request.Context(), who, "")
	if err != nil || len(leases) == 0 {
		return nil
	}
	index := slices.IndexFunc(leases, func(lease dhcpLeaseView) bool {
		if lease.State != string(store.DHCPLeaseActive) {
			return false
		}
		if device.MAC != "" {
			return strings.EqualFold(lease.MAC, device.MAC)
		}
		return slices.ContainsFunc(device.Addresses, func(address pages.InsightDeviceAddressView) bool { return address.Address == lease.Address })
	})
	if index < 0 {
		return nil
	}
	lease := leases[index]
	scope := lease.Scope
	for _, candidate := range server.config.Current().Config.DHCP.Scopes {
		if candidate.ID == lease.Scope && candidate.Name != "" {
			scope = candidate.Name
		}
	}
	canWrite := server.authorized(who, auth.PermissionDHCPWrite, nil) && !console.ControlPlaneReadOnly
	return &pages.InsightDeviceLeaseView{
		Address: lease.Address, Scope: scope, ExpiresAt: lease.ExpiresAt, Reserved: lease.Reserved,
		CanReserve: canWrite && !lease.Reserved,
	}
}

// reserveInsightsDevice turns a device's lease into a reservation from its
// drawer, the same as Reserve on the DHCP page.
func (server *Server) reserveInsightsDevice(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanLogs {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	if err := request.ParseForm(); err != nil {
		writeFragmentStatus(writer, http.StatusBadRequest)
		return
	}
	window := insightsWindow(request.FormValue("range"), time.Now())
	key := request.FormValue("key")
	reservation, err := server.dhcpService().Reserve(request.Context(), requestActor(request, ""), request.FormValue("address"), "", "")
	if err != nil {
		writeFragmentStatus(writer, serviceStatus(err))
		server.renderDeviceDrawer(writer, request, console, window, key, "", "", sentence(err.Error()))
		return
	}
	writer.Header().Set("HX-Trigger", "insightsChanged")
	message := "Reserved " + reservation.Address + " for " + dhcpReservationName(reservation) + "."
	server.renderDeviceDrawer(writer, request, console, window, key, "", message, "")
}
