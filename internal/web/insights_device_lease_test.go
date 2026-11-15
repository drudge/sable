package web

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
)

// withDeviceLease serves DHCP on the Insights test network and gives the
// test laptop a lease on 10.0.0.5.
func (server insightsTestServer) withDeviceLease(t *testing.T) {
	t.Helper()
	server.withConfig(t, func(configuration *config.Config) {
		configuration.DHCP = config.DHCP{Enabled: true, Scopes: []config.DHCPScope{{
			ID: "lan", Name: "LAN", Subnet: "10.0.0.0/24", Router: "10.0.0.1",
			Ranges: []config.DHCPRange{{Start: "10.0.0.2", End: "10.0.0.99"}},
		}}}
	})
	now := time.Now()
	server.SetDHCPController(&testDHCPController{leases: []store.DHCPLease{{
		NodeID: "node-a", Address: netip.MustParseAddr("10.0.0.5"), ScopeID: "lan", ClientKey: "013c:22:fb:01:02:03",
		MAC: "3c:22:fb:01:02:03", Hostname: "laptop", Label: "laptop", State: store.DHCPLeaseActive,
		BoundAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}}})
}

func TestDeviceDrawerShowsTheLeaseAndReservesIt(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	server.withDeviceLease(t)
	drawer := func(session string) string {
		t.Helper()
		return server.get(t, session, "/ui/insights/device?range=day&key="+url.QueryEscape(insightsTestLaptop), true).Body.String()
	}

	body := drawer("everything")
	for _, want := range []string{`id="insight-device-lease"`, "DHCP Lease", "10.0.0.5", "LAN", `data-device-reserve="10.0.0.5"`} {
		if !strings.Contains(body, want) {
			t.Errorf("drawer lacks %q", want)
		}
	}
	// Without dhcp.read the drawer says nothing about DHCP, and without
	// dhcp.write it can't reserve.
	if body := drawer("logs-reader"); strings.Contains(body, `id="insight-device-lease"`) {
		t.Errorf("drawer shows the lease without dhcp.read")
	}
	form := url.Values{"key": {insightsTestLaptop}, "range": {"day"}, "address": {"10.0.0.5"}}
	if response := server.post(t, "logs-reader", "/ui/insights/devices/reserve", form); response.Code != http.StatusForbidden {
		t.Fatalf("reserve without dhcp.write = %d", response.Code)
	}

	response := server.post(t, "everything", "/ui/insights/devices/reserve", form)
	body = response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "Reserved 10.0.0.5 for laptop") || strings.Contains(body, "data-device-reserve") || !strings.Contains(body, ">Reserved<") {
		t.Fatalf("reserve = %d:\n%s", response.Code, body)
	}
	reservations := server.config.Current().Config.DHCP.Scopes[0].Reservations
	if len(reservations) != 1 || reservations[0].MAC != "3c:22:fb:01:02:03" || reservations[0].Address != "10.0.0.5" || reservations[0].Name != "laptop" {
		t.Fatalf("reservations = %+v", reservations)
	}

	// A lease that is gone by the time Reserve arrives says so in the drawer.
	form.Set("address", "10.0.0.6")
	response = server.post(t, "everything", "/ui/insights/devices/reserve", form)
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "10.0.0.6 has no active lease") {
		t.Fatalf("reserve a missing lease = %d:\n%s", response.Code, response.Body.String())
	}
}

// A device's drawer shows only its own lease: when another client now holds
// an address the laptop used, or the address was declined, the laptop has no
// lease to show or reserve (F60).
func TestDeviceDrawerIgnoresAnotherClientsLease(t *testing.T) {
	t.Parallel()
	for _, row := range []store.DHCPLease{
		{ClientKey: "01aa:bb:cc:00:00:01", MAC: "aa:bb:cc:00:00:01", Hostname: "phone", State: store.DHCPLeaseActive},
		{ClientKey: "declined", State: store.DHCPLeaseDeclined},
	} {
		server := newInsightsTestServer(t)
		server.withDeviceLease(t)
		now := time.Now()
		row.NodeID, row.Address, row.ScopeID = "node-a", netip.MustParseAddr("10.0.0.5"), "lan"
		row.BoundAt, row.ExpiresAt = now.Add(-time.Minute), now.Add(time.Hour)
		server.SetDHCPController(&testDHCPController{leases: []store.DHCPLease{row}})
		body := server.get(t, "everything", "/ui/insights/device?range=day&key="+url.QueryEscape(insightsTestLaptop), true).Body.String()
		if strings.Contains(body, `id="insight-device-lease"`) || strings.Contains(body, "data-device-reserve") {
			t.Errorf("%s lease on 10.0.0.5 shows in the laptop's drawer", row.State)
		}
	}
}
