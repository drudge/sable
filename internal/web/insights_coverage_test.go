package web

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/unifi"
)

// silentTestServer is the Insights test server with UniFi finding devices: a
// TV on a guest network that hands out 1.1.1.1, online and busy for two days
// without a lookup, and the laptop, which asks Sable all the time.
func silentTestServer(t *testing.T) insightsTestServer {
	t.Helper()
	server := newInsightsTestServer(t)
	server.updateTestConfiguration(t, func(configuration *config.Config) {
		configuration.UniFi = config.UniFi{
			Enabled: true, ControllerURL: "https://unifi.example", Site: "default", FindDevices: true,
			Interval: config.Duration{Duration: 2 * time.Minute}, Sources: []string{"active"},
		}
	})
	guest := unifi.Network{
		ID: "net-guest", Name: "Guest", Gateway: netip.MustParseAddr("10.0.50.1"), DHCP: true,
		DHCPDNS: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
	}
	lan := unifi.Network{ID: "net-lan", Name: "Default", Gateway: netip.MustParseAddr("10.0.0.1"), DHCP: true, DHCPDNS: []netip.Addr{netip.MustParseAddr("10.0.0.53")}}
	station := func(mac, name, network, address string, bytes uint64) unifi.Station {
		return unifi.Station{MAC: mac, Name: name, NetworkID: network, Address: netip.MustParseAddr(address), Uptime: 48 * time.Hour, Bytes: bytes}
	}
	read := func(at time.Time, bytes uint64) {
		t.Helper()
		inventory := unifi.Inventory{
			Networks: []unifi.Network{lan, guest},
			Stations: []unifi.Station{
				station("52:54:00:aa:bb:01", "Living Room TV", "net-guest", "10.0.50.20", bytes),
				station("3c:22:fb:01:02:03", "Laptop", "net-lan", "10.0.0.5", bytes),
			},
		}
		for index := range inventory.Stations {
			inventory.Stations[index].Uptime -= server.now.Sub(at)
		}
		if err := server.store.RecordUniFiReading(context.Background(), inventory, at); err != nil {
			t.Fatal(err)
		}
	}
	read(server.now.Add(-25*time.Hour), 100_000_000)
	read(server.now.Add(-time.Minute), 900_000_000)
	return server
}

// The TV shows up as one rolled-up finding with its network's DNS as the
// reason, the guest network is reported on its own, and the Devices tab lists
// the TV under Not Using Sable with the line its drawer shows.
func TestInsightsReportDevicesThatDontUseSable(t *testing.T) {
	t.Parallel()
	server := silentTestServer(t)
	body := server.get(t, "everything", "/ui/insights/overview?range=day&tab=devices", true).Body.String()
	for _, expected := range []string{
		`<span class="insight-finding-title">Not using Sable</span>`, " doesn&#39;t use Sable",
		"Guest network hands out 1.1.1.1 for DNS, not Sable",
		"Its DHCP gives devices 1.1.1.1 for DNS, so their lookups skip Sable.",
		`<option value="not-using-sable">Not Using Sable</option>`,
		`data-list-tags="named not-using-sable"`,
		`href="/insights?tab=devices&amp;show=not-using-sable"`,
		`name="member" value="devices.not-using-sable/device:mac:52:54:00:aa:bb:01"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("Insights is missing %q", expected)
		}
	}
	if strings.Contains(body, "Laptop") {
		t.Error("a device that asks Sable was reported")
	}
	drawer := server.get(t, "everything", "/ui/insights/device?key="+url.QueryEscape("mac:52:54:00:aa:bb:01")+"&range=day", true).Body.String()
	if !strings.Contains(drawer, "UniFi sees traffic, but no lookups reached Sable in 24 hours.") || !strings.Contains(drawer, "Not using Sable") {
		t.Fatalf("the TV's drawer does not say it skips Sable: %s", drawer)
	}
	// The drawer offers the TV's own link, though it sent nothing, and the
	// link opens the page that loads this drawer.
	if !strings.Contains(drawer, `data-copy-url="/insights/devices/mac:52:54:00:aa:bb:01?range=day"`) {
		t.Fatal("the silent TV's drawer offers no link to itself")
	}
	if linked := server.get(t, "everything", "/insights/devices/mac:52:54:00:aa:bb:01?range=day", false); linked.Code != http.StatusOK ||
		!strings.Contains(linked.Body.String(), `data-drawer-content="/ui/insights/device"`) {
		t.Fatalf("a link to the silent TV = %d", linked.Code)
	}
}

// That's Normal on the rolled-up finding marks each device it lists, so the
// finding goes away, the device can be shown again from the hidden list, and
// a device not yet marked would bring the finding back.
func TestInsightsSilentDevicesCanBeMarkedNormalOneByOne(t *testing.T) {
	t.Parallel()
	server := silentTestServer(t)
	form := url.Values{
		"id": {devices.NotUsingSableID}, "label": {"Living Room TV doesn't use Sable"}, "action": {"normal"},
		"member": {devices.NotUsingSableDeviceID("mac:52:54:00:aa:bb:01")}, "member_label": {"Living Room TV"},
	}
	if response := server.post(t, "everything", "/ui/insights/feedback", form); response.Code != http.StatusNoContent {
		t.Fatalf("marking normal = %d", response.Code)
	}
	body := server.get(t, "everything", "/ui/insights/overview?range=day", true).Body.String()
	if strings.Contains(body, `<span class="insight-finding-title">Not using Sable</span>`) {
		t.Fatal("the rolled-up finding still lists a device marked normal")
	}
	if !strings.Contains(body, "Doesn&#39;t use Sable: Living Room TV") {
		t.Fatal("the device marked normal is not in the hidden list")
	}
	feedback, err := server.store.InsightFeedback(context.Background(), time.Now())
	if err != nil || len(feedback) != 1 || feedback[0].FindingID != devices.NotUsingSableDeviceID("mac:52:54:00:aa:bb:01") {
		t.Fatalf("feedback = %+v, %v, want the device's own entry and none for the rolled-up finding", feedback, err)
	}
	form.Set("member", "blocking.past-block/domain:ads.example")
	if response := server.post(t, "everything", "/ui/insights/feedback", form); response.Code != http.StatusBadRequest {
		t.Fatalf("marking another finding through a member = %d", response.Code)
	}
}
