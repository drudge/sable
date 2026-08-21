package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/unifi"
	zonemodel "github.com/drudge/sable/internal/zone"
)

type testUniFiController struct {
	inventory      unifi.Inventory
	inventoryError error
	plan           unifi.Plan
	previewError   error
	status         unifi.Status
	credentials    unifi.Credentials
	configured     bool
	syncs          int
	forgotten      int
	previewedWith  config.UniFi
}

func (controller *testUniFiController) Status() unifi.Status { return controller.status }

func (controller *testUniFiController) SyncNow() { controller.syncs++ }

func (controller *testUniFiController) Preview(_ context.Context, settings config.UniFi) (unifi.Plan, error) {
	controller.previewedWith = settings
	if controller.previewError != nil {
		return unifi.Plan{}, controller.previewError
	}
	return controller.plan, nil
}

func (controller *testUniFiController) Inventory(context.Context, config.UniFi) (unifi.Inventory, error) {
	if controller.inventoryError != nil {
		return unifi.Inventory{}, controller.inventoryError
	}
	return controller.inventory, nil
}

func (controller *testUniFiController) PutCredentials(_ context.Context, credentials unifi.Credentials) error {
	controller.credentials, controller.configured = credentials, true
	return nil
}

func (controller *testUniFiController) StoredCredentials(context.Context) (unifi.Credentials, bool) {
	return controller.credentials, controller.configured
}

func (controller *testUniFiController) ForgetCredentials(context.Context) error {
	controller.credentials, controller.configured = unifi.Credentials{}, false
	controller.forgotten++
	return nil
}

func testUniFiInventory() unifi.Inventory {
	return unifi.Inventory{
		Networks: []unifi.Network{
			{ID: "net-lan", Name: "Default", Slug: "default", Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}},
			{ID: "net-iot", Name: "IoT", Slug: "iot", Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.30.0/24")}},
		},
		Hosts: []unifi.Host{
			{MAC: "aa:01", Hostname: "Printer", Address: netip.MustParseAddr("192.168.1.10"), NetworkID: "net-lan", Reserved: true},
		},
	}
}

func newIntegrationsTestServer(t *testing.T, controller *testUniFiController) (*Server, *editableTestConfiguration) {
	t.Helper()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration,
		configuration.zoneStore(),
		"sqlite",
		testQueryLog{},
		testQueryLog{},
		func(context.Context) error { return nil },
		nil,
		false,
		false,
		false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if controller != nil {
		server.SetUniFiController(controller)
	}
	return server, configuration
}

func postIntegrations(server *Server, path string, form url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

func TestIntegrationsPageOffersUniFiSetup(t *testing.T) {
	t.Parallel()
	server, _ := newIntegrationsTestServer(t, &testUniFiController{})

	page := serveRequest(server, http.MethodGet, "/integrations")

	body := page.Body.String()
	if page.Code != http.StatusOK {
		t.Fatalf("apps page = %d", page.Code)
	}
	for _, expected := range []string{"UniFi Host Sync", "Not set up", "Set Up UniFi Sync", "/integrations?setup=unifi"} {
		if !strings.Contains(body, expected) {
			t.Errorf("apps page does not contain %q", expected)
		}
	}
}

func TestUniFiWizardWalksFromConnectionToEnabled(t *testing.T) {
	t.Parallel()
	controller := &testUniFiController{
		inventory: testUniFiInventory(),
		plan: unifi.Plan{
			CreatedZones: []string{"clients.example.test", "1.168.192.in-addr.arpa"},
			Added: []unifi.PlanRecord{
				{Zone: "clients.example.test", Name: "printer.default", Type: "A", Value: "192.168.1.10"},
			},
			Publishing: []unifi.PlanRecord{
				{Zone: "clients.example.test", Name: "printer.default", Type: "A", Value: "192.168.1.10"},
			},
			Hosts: 1,
		},
	}
	server, configuration := newIntegrationsTestServer(t, controller)

	connect := postIntegrations(server, "/ui/integrations/unifi/wizard", url.Values{
		"wizard_step": {"connect"}, "controller_url": {"https://192.168.1.1/"}, "site": {"default"},
		"auth_mode": {"api-key"}, "api_key": {"unifi-secret"},
	})
	if connect.Code != http.StatusOK {
		t.Fatalf("connect step = %d %s", connect.Code, connect.Body.String())
	}
	if controller.credentials.APIKey != "unifi-secret" {
		t.Fatalf("connect step stored credentials %+v", controller.credentials)
	}
	if strings.Contains(connect.Body.String(), "unifi-secret") {
		t.Fatal("the wizard echoed the API key back into the page")
	}
	for _, expected := range []string{"Default", "IoT", "192.168.1.0/24", "Map Zones", "Fixed-IP reservations", "Sync Interval"} {
		if !strings.Contains(connect.Body.String(), expected) {
			t.Errorf("networks step does not contain %q", expected)
		}
	}

	zones := postIntegrations(server, "/ui/integrations/unifi/wizard", url.Values{
		"wizard_step": {"networks"}, "controller_url": {"https://192.168.1.1"}, "site": {"default"},
		"auth_mode": {"api-key"}, "interval": {"2m"},
		"source_reservations": {"true"}, "source_active": {"true"},
		"network": {"net-lan"},
	})
	if zones.Code != http.StatusOK {
		t.Fatalf("zones step = %d %s", zones.Code, zones.Body.String())
	}
	for _, expected := range []string{"Review Changes", `name="zone_0"`, `name="network_id_0"`, "Publish PTR records", "1.168.192.in-addr.arpa"} {
		if !strings.Contains(zones.Body.String(), expected) {
			t.Errorf("zones step does not contain %q", expected)
		}
	}
	if strings.Contains(zones.Body.String(), `value="net-iot"`) && strings.Contains(zones.Body.String(), `name="network_id_1"`) {
		t.Error("zones step included a network the operator did not select")
	}

	mapped := url.Values{
		"wizard_step": {"zones"}, "controller_url": {"https://192.168.1.1"}, "site": {"default"},
		"auth_mode": {"api-key"}, "interval": {"2m"},
		"source_reservations": {"true"}, "source_active": {"true"}, "network": {"net-lan"},
		"network_id_0": {"net-lan"}, "network_name_0": {"Default"}, "network_subnet_0": {"192.168.1.0/24"},
		"zone_0": {"clients.example.test"}, "template_0": {"{{host}}.{{network}}.{{zone}}"},
		"ttl_0": {"300"}, "reverse_0": {"true"},
	}
	review := postIntegrations(server, "/ui/integrations/unifi/wizard", mapped)
	if review.Code != http.StatusOK {
		t.Fatalf("review step = %d %s", review.Code, review.Body.String())
	}
	for _, expected := range []string{"Enable Synchronization", "printer.default.clients.example.test", "192.168.1.10", "Zones Sable will create"} {
		if !strings.Contains(review.Body.String(), expected) {
			t.Errorf("review step does not contain %q", expected)
		}
	}
	if controller.previewedWith.ControllerURL != "https://192.168.1.1" || len(controller.previewedWith.Networks) != 1 {
		t.Fatalf("preview received %+v", controller.previewedWith)
	}

	finish := mapped
	finish.Set("wizard_step", "review")
	enabled := postIntegrations(server, "/ui/integrations/unifi/wizard", finish)
	if enabled.Code != http.StatusOK {
		t.Fatalf("finish step = %d %s", enabled.Code, enabled.Body.String())
	}
	settings := configuration.snapshot.Config.UniFi
	if !settings.Enabled || len(settings.Networks) != 1 {
		t.Fatalf("saved settings = %+v", settings)
	}
	mapping := settings.Networks[0]
	if mapping.ID != "net-lan" || mapping.Zone != "clients.example.test" || !mapping.Reverse || !mapping.Enabled {
		t.Fatalf("saved mapping = %+v", mapping)
	}
	if controller.syncs != 1 {
		t.Fatalf("finishing the wizard triggered %d syncs, want 1", controller.syncs)
	}
	if enabled.Header().Get("HX-Replace-Url") != "/integrations" {
		t.Fatalf("HX-Replace-Url = %q", enabled.Header().Get("HX-Replace-Url"))
	}
}

func TestUniFiWizardReportsRejectedCredentials(t *testing.T) {
	t.Parallel()
	controller := &testUniFiController{inventoryError: unifi.ErrUnauthorized}
	server, _ := newIntegrationsTestServer(t, controller)

	response := postIntegrations(server, "/ui/integrations/unifi/wizard", url.Values{
		"wizard_step": {"connect"}, "controller_url": {"https://192.168.1.1"}, "site": {"default"},
		"auth_mode": {"api-key"}, "api_key": {"wrong"}, "interval": {"2m"}, "source_active": {"true"},
	})

	if response.Code != http.StatusBadGateway {
		t.Fatalf("connect step = %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "rejected these credentials") {
		t.Fatalf("connect step body = %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `name="api_key"`) {
		t.Fatal("the wizard did not stay on the connection step")
	}
}

func TestUniFiWizardRequiresACredential(t *testing.T) {
	t.Parallel()
	server, _ := newIntegrationsTestServer(t, &testUniFiController{})

	response := postIntegrations(server, "/ui/integrations/unifi/wizard", url.Values{
		"wizard_step": {"connect"}, "controller_url": {"https://192.168.1.1"},
		"auth_mode": {"api-key"}, "interval": {"2m"},
	})

	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "Enter the UniFi API key") {
		t.Fatalf("connect step = %d %s", response.Code, response.Body.String())
	}
}

func TestUniFiWizardRequiresASelectedNetwork(t *testing.T) {
	t.Parallel()
	server, _ := newIntegrationsTestServer(t, &testUniFiController{inventory: testUniFiInventory()})

	response := postIntegrations(server, "/ui/integrations/unifi/wizard", url.Values{
		"wizard_step": {"networks"}, "controller_url": {"https://192.168.1.1"}, "site": {"default"},
		"auth_mode": {"api-key"}, "interval": {"2m"}, "source_active": {"true"},
	})

	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "Select at least one network") {
		t.Fatalf("networks step = %d %s", response.Code, response.Body.String())
	}
}

// Two networks sharing one zone need the network in their names, and the
// wizard must say so before writing anything.
func TestUniFiWizardRejectsCollidingZoneMapping(t *testing.T) {
	t.Parallel()
	server, configuration := newIntegrationsTestServer(t, &testUniFiController{inventory: testUniFiInventory()})

	response := postIntegrations(server, "/ui/integrations/unifi/wizard", url.Values{
		"wizard_step": {"zones"}, "controller_url": {"https://192.168.1.1"}, "site": {"default"},
		"auth_mode": {"api-key"}, "interval": {"2m"}, "source_active": {"true"},
		"network":      {"net-lan", "net-iot"},
		"network_id_0": {"net-lan"}, "network_name_0": {"Default"}, "zone_0": {"clients.example.test"},
		"template_0": {"{{host}}.{{zone}}"}, "ttl_0": {"300"},
		"network_id_1": {"net-iot"}, "network_name_1": {"IoT"}, "zone_1": {"clients.example.test"},
		"template_1": {"{{host}}.{{zone}}"}, "ttl_1": {"300"},
	})

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("zones step = %d %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "{{network}}") {
		t.Fatalf("zones step body = %s", response.Body.String())
	}
	if len(configuration.snapshot.Config.UniFi.Networks) != 0 {
		t.Fatal("a rejected mapping was persisted")
	}
}

func TestUniFiPauseAndResume(t *testing.T) {
	t.Parallel()
	controller := &testUniFiController{}
	server, configuration := newIntegrationsTestServer(t, controller)
	candidate := configuration.snapshot.Config
	candidate.UniFi.Enabled = true
	candidate.UniFi.ControllerURL = "https://192.168.1.1"
	candidate.UniFi.Networks = []config.UniFiNetwork{{
		ID: "net-lan", Name: "Default", Zone: "clients.example.test",
		HostnameTemplate: unifi.DefaultHostnameTemplate, TTL: 300, Reverse: true, Enabled: true,
	}}
	configuration.snapshot.Config = candidate

	paused := postIntegrations(server, "/ui/integrations/unifi/enabled", url.Values{"enabled": {"false"}})
	if paused.Code != http.StatusOK || configuration.snapshot.Config.UniFi.Enabled {
		t.Fatalf("pause = %d, enabled = %v", paused.Code, configuration.snapshot.Config.UniFi.Enabled)
	}
	if !strings.Contains(paused.Body.String(), "left in place") {
		t.Fatalf("pause body = %s", paused.Body.String())
	}

	resumed := postIntegrations(server, "/ui/integrations/unifi/enabled", url.Values{"enabled": {"true"}})
	if resumed.Code != http.StatusOK || !configuration.snapshot.Config.UniFi.Enabled {
		t.Fatalf("resume = %d, enabled = %v", resumed.Code, configuration.snapshot.Config.UniFi.Enabled)
	}
	if controller.syncs != 1 {
		t.Fatalf("resume triggered %d syncs, want 1", controller.syncs)
	}
}

func TestUniFiSyncNowRequiresSetup(t *testing.T) {
	t.Parallel()
	controller := &testUniFiController{}
	server, _ := newIntegrationsTestServer(t, controller)

	response := postIntegrations(server, "/ui/integrations/unifi/sync", url.Values{})

	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "Finish UniFi setup") {
		t.Fatalf("sync = %d %s", response.Code, response.Body.String())
	}
	if controller.syncs != 0 {
		t.Fatal("an unconfigured integration was asked to synchronize")
	}
}

func TestUniFiStatusPanelReportsFailure(t *testing.T) {
	t.Parallel()
	controller := &testUniFiController{status: unifi.Status{
		LastError: "controller unreachable", Hosts: 12, Added: 3,
	}}
	server, _ := newIntegrationsTestServer(t, controller)

	response := serveRequest(server, http.MethodGet, "/ui/integrations/unifi/status")

	if response.Code != http.StatusOK {
		t.Fatalf("status panel = %d", response.Code)
	}
	for _, expected := range []string{"controller unreachable", "Last synchronization failed", ">12<", ">3<"} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("status panel does not contain %q", expected)
		}
	}
}

// A record the synchronizer owns is read-only here: the next sync would revert
// an edit made from the zone editor.
func TestZoneEditorRefusesSynchronizedRecords(t *testing.T) {
	t.Parallel()
	server, configuration := newIntegrationsTestServer(t, nil)
	configuration.zoneSnapshot = zonemodel.Snapshot{Zones: []zonemodel.Zone{{
		Name: "clients.example.test", Type: "primary", DefaultTTL: 300, ZoneTransfer: "deny",
		Records: []zonemodel.Record{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.clients.example.test. hostmaster.clients.example.test. 1 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.clients.example.test."},
			{Name: "printer.default", Type: "A", TTL: 300, Value: "192.168.1.10", Source: zonemodel.SourceUniFi},
		},
	}}}

	page := serveRequest(server, http.MethodGet, "/zones/clients.example.test")
	body := page.Body.String()
	if !strings.Contains(body, "record-source-badge") || !strings.Contains(body, "Published by UniFi synchronization") {
		t.Fatal("the zone editor did not mark the record as UniFi-owned")
	}
	// The record still opens so its contents can be read; it just cannot be
	// changed from here.
	if !strings.Contains(body, "View A record") {
		t.Error("a synchronized record offered no way to open it")
	}
	if !strings.Contains(body, `<fieldset class="isotope-record-fieldset" disabled>`) {
		t.Error("the synchronized record dialog was not disabled")
	}
	if !strings.Contains(body, "Published into clients.example.test by UniFi") {
		t.Error("the dialog did not explain who owns the record")
	}
	// Exactly one dialog is read-only, and the synchronized record contributes
	// no update or delete control of its own. The editable NS record is the only
	// one that may be deleted; the SOA never offers deletion.
	if got := strings.Count(body, "record-readonly-footer"); got != 1 {
		t.Errorf("read-only footers = %d, want 1", got)
	}
	if got := strings.Count(body, "Update Record"); got != 2 {
		t.Errorf("update buttons = %d, want 2 (the SOA and NS records only)", got)
	}
	if got := strings.Count(body, "Delete Record"); got != 1 {
		t.Errorf("delete buttons = %d, want 1 (the NS record only)", got)
	}

	response := postIntegrations(server, "/ui/zones/records/delete", url.Values{
		"zone": {"clients.example.test"}, "name": {"printer.default"},
		"type": {"A"}, "value": {"192.168.1.10"}, "ttl": {"300"},
	})
	if !strings.Contains(response.Body.String(), "published by UniFi synchronization") {
		t.Fatalf("delete response = %d %s", response.Code, response.Body.String())
	}
	if len(configuration.zoneSnapshot.Zones[0].Records) != 3 {
		t.Fatal("a synchronized record was deleted from the zone editor")
	}
}

func TestUniFiControllerAbsentDegradesGracefully(t *testing.T) {
	t.Parallel()
	server, _ := newIntegrationsTestServer(t, nil)

	page := serveRequest(server, http.MethodGet, "/integrations")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "not running on this node") {
		t.Fatalf("apps page = %d %s", page.Code, page.Body.String())
	}

	response := postIntegrations(server, "/ui/integrations/unifi/wizard", url.Values{"wizard_step": {"connect"}})
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("wizard without a controller = %d", response.Code)
	}
}

// The connection step is long enough already, so what to publish is asked on the
// networks step instead.
func TestUniFiWizardAsksWhatToPublishOnTheNetworksStep(t *testing.T) {
	t.Parallel()
	server, _ := newIntegrationsTestServer(t, &testUniFiController{inventory: testUniFiInventory()})

	connect := postIntegrations(server, "/ui/integrations/unifi/wizard", url.Values{
		"wizard_step": {"connect"}, "controller_url": {"https://192.168.1.1"}, "site": {"default"},
		"auth_mode": {"api-key"}, "api_key": {"secret"},
	})

	body := connect.Body.String()
	if strings.Count(body, `name="source_reservations"`) != 1 || !strings.Contains(body, `name="sources_present"`) {
		t.Fatalf("networks step did not own the publishing choices: %s", body)
	}
	// Both sources default on for a first-time setup, so the wizard publishes
	// everything unless the operator narrows it.
	if strings.Count(body, `name="source_reservations" value="true" checked`) != 1 {
		t.Error("fixed-IP reservations were not selected by default")
	}
	if strings.Count(body, `name="source_active" value="true" checked`) != 1 {
		t.Error("connected clients were not selected by default")
	}
}

func TestUniFiWizardStepsGoBack(t *testing.T) {
	t.Parallel()
	controller := &testUniFiController{inventory: testUniFiInventory(), plan: unifi.Plan{Hosts: 1}}
	server, configuration := newIntegrationsTestServer(t, controller)

	mapped := url.Values{
		"wizard_step": {"zones"}, "controller_url": {"https://192.168.1.1"}, "site": {"default"},
		"auth_mode": {"api-key"}, "interval": {"5m"}, "sources_present": {"true"},
		"source_reservations": {"true"}, "network": {"net-lan"},
		"network_id_0": {"net-lan"}, "network_name_0": {"Default"}, "network_subnet_0": {"192.168.1.0/24"},
		"zone_0": {"clients.example.test"}, "template_0": {"{{host}}.{{network}}.{{zone}}"},
		"ttl_0": {"300"}, "reverse_0": {"true"},
	}

	// Back from the zones step returns to the network list with the same
	// selection and publishing choices still in hand.
	back := mapped
	back.Set("wizard_target", "networks")
	response := postIntegrations(server, "/ui/integrations/unifi/wizard", back)
	if response.Code != http.StatusOK {
		t.Fatalf("back to networks = %d %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `value="net-lan" checked`) {
		t.Error("back to networks lost the network selection")
	}
	if !strings.Contains(body, `value="5m"`) {
		t.Error("back to networks lost the sync interval")
	}
	if strings.Contains(body, `name="source_active" value="true" checked`) {
		t.Error("back to networks re-checked a source the operator cleared")
	}

	// Jumping back to the very first step keeps the connection details.
	toConnect := mapped
	toConnect.Set("wizard_target", "connect")
	first := postIntegrations(server, "/ui/integrations/unifi/wizard", toConnect)
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `name="api_key"`) {
		t.Fatalf("back to connect = %d %s", first.Code, first.Body.String())
	}
	if !strings.Contains(first.Body.String(), `value="https://192.168.1.1"`) {
		t.Error("back to connect lost the controller URL")
	}

	// Returning from the review step preserves the zone mapping already typed.
	review := mapped
	review.Set("wizard_step", "review")
	review.Set("wizard_target", "zones")
	zones := postIntegrations(server, "/ui/integrations/unifi/wizard", review)
	if zones.Code != http.StatusOK || !strings.Contains(zones.Body.String(), `value="clients.example.test"`) {
		t.Fatalf("back to zones = %d %s", zones.Code, zones.Body.String())
	}
	if len(configuration.snapshot.Config.UniFi.Networks) != 0 {
		t.Fatal("navigating backwards persisted configuration")
	}
}

// Going back must not be blocked by the step the operator is leaving, so the
// markers and the Back button opt out of form validation.
func TestUniFiWizardBackControlsSkipValidation(t *testing.T) {
	t.Parallel()
	server, _ := newIntegrationsTestServer(t, &testUniFiController{inventory: testUniFiInventory()})

	response := postIntegrations(server, "/ui/integrations/unifi/wizard", url.Values{
		"wizard_step": {"connect"}, "controller_url": {"https://192.168.1.1"}, "site": {"default"},
		"auth_mode": {"api-key"}, "api_key": {"secret"},
	})

	body := response.Body.String()
	if !strings.Contains(body, `name="wizard_target" value="connect" formnovalidate`) {
		t.Error("the completed step marker is not a back control")
	}
	if strings.Count(body, "formnovalidate") < 2 {
		t.Errorf("expected the step marker and the Back button to skip validation:\n%s", body)
	}
}

// With nothing to change the review step must still show what the mapping
// publishes, otherwise re-running setup looks like it found nothing.
func TestUniFiWizardReviewShowsPublishedRecordsWhenInSync(t *testing.T) {
	t.Parallel()
	controller := &testUniFiController{
		inventory: testUniFiInventory(),
		plan: unifi.Plan{
			Hosts: 1,
			Publishing: []unifi.PlanRecord{
				{Zone: "clients.example.test", Name: "printer.default", Type: "A", Value: "192.168.1.10"},
			},
		},
	}
	server, _ := newIntegrationsTestServer(t, controller)

	response := postIntegrations(server, "/ui/integrations/unifi/wizard", url.Values{
		"wizard_step": {"zones"}, "controller_url": {"https://192.168.1.1"}, "site": {"default"},
		"auth_mode": {"api-key"}, "interval": {"2m"}, "sources_present": {"true"},
		"source_active": {"true"}, "network": {"net-lan"},
		"network_id_0": {"net-lan"}, "network_name_0": {"Default"}, "network_subnet_0": {"192.168.1.0/24"},
		"zone_0": {"clients.example.test"}, "template_0": {"{{host}}.{{network}}.{{zone}}"},
		"ttl_0": {"300"}, "reverse_0": {"true"},
	})

	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("review step = %d %s", response.Code, body)
	}
	if !strings.Contains(body, "Nothing to change") {
		t.Error("review step did not say the mapping is already in sync")
	}
	if !strings.Contains(body, "Everything this mapping publishes (1)") {
		t.Errorf("review step did not list the published records:\n%s", body)
	}
	if !strings.Contains(body, "printer.default.clients.example.test") {
		t.Error("review step did not name the published record")
	}
}

// Removing the integration has to leave nothing behind: no configuration, no
// stored credentials, and none of the records it published.
func TestUniFiRemoveResetsEverything(t *testing.T) {
	t.Parallel()
	controller := &testUniFiController{credentials: unifi.Credentials{APIKey: "secret"}, configured: true}
	server, configuration := newIntegrationsTestServer(t, controller)
	candidate := configuration.snapshot.Config
	candidate.UniFi = config.UniFi{
		Enabled: true, ControllerURL: "https://192.168.1.1", Site: "default",
		Interval: config.Duration{Duration: 2 * time.Minute}, Sources: []string{"active"},
		Networks: []config.UniFiNetwork{{
			ID: "net-lan", Name: "Default", Zone: "clients.example.test",
			HostnameTemplate: unifi.DefaultHostnameTemplate, TTL: 300, Reverse: true, Enabled: true,
		}},
	}
	configuration.snapshot.Config = candidate
	configuration.zoneSnapshot = zonemodel.Snapshot{Zones: []zonemodel.Zone{{
		Name: "clients.example.test", Type: "primary", DefaultTTL: 300, ZoneTransfer: "deny",
		Records: []zonemodel.Record{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.clients.example.test. hostmaster.clients.example.test. 1 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.clients.example.test."},
			{Name: "printer.default", Type: "A", TTL: 300, Value: "192.168.1.10", Source: zonemodel.SourceUniFi},
			{Name: "nas", Type: "A", TTL: 300, Value: "192.168.1.250"},
		},
	}}}

	response := postIntegrations(server, "/ui/integrations/unifi/remove", url.Values{})

	if response.Code != http.StatusOK {
		t.Fatalf("remove = %d %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "1 published records were deleted") {
		t.Errorf("remove did not report what it deleted: %s", response.Body.String())
	}
	if settings := configuration.snapshot.Config.UniFi; settings.Enabled || settings.ControllerURL != "" || len(settings.Networks) != 0 {
		t.Fatalf("configuration survived removal: %+v", settings)
	}
	if controller.forgotten != 1 {
		t.Fatalf("credentials cleared %d times, want 1", controller.forgotten)
	}
	records := configuration.zoneSnapshot.Zones[0].Records
	for _, record := range records {
		if record.Source == zonemodel.SourceUniFi {
			t.Fatalf("a published record survived removal: %+v", record)
		}
	}
	// The zone and the hand-authored record inside it must survive.
	if len(records) != 3 {
		t.Fatalf("records after removal = %d, want the SOA, NS, and hand-authored record", len(records))
	}
	if !strings.Contains(response.Body.String(), "Set Up UniFi Sync") {
		t.Error("the card did not return to its unconfigured state")
	}
}

// A synchronization in flight must disable Sync Now, spin its icon, and show a
// progress bar, and the poll has to tighten so that state clears promptly.
func TestUniFiStatusReflectsRunningSynchronization(t *testing.T) {
	t.Parallel()
	controller := &testUniFiController{status: unifi.Status{Running: true, Hosts: 4}}
	server, configuration := newIntegrationsTestServer(t, controller)
	candidate := configuration.snapshot.Config
	candidate.UniFi = config.UniFi{
		Enabled: true, ControllerURL: "https://192.168.1.1", Site: "default",
		Interval: config.Duration{Duration: 2 * time.Minute}, Sources: []string{"active"},
		Networks: []config.UniFiNetwork{{
			ID: "net-lan", Name: "Default", Zone: "clients.example.test",
			HostnameTemplate: unifi.DefaultHostnameTemplate, TTL: 300, Reverse: true, Enabled: true,
		}},
	}
	configuration.snapshot.Config = candidate

	response := serveRequest(server, http.MethodGet, "/ui/integrations/unifi/status")

	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	for _, expected := range []string{
		`hx-trigger="every 1s"`, "cluster-sync-indeterminate", "Synchronizing…",
		"is-syncing", "disabled", `hx-swap-oob="true"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("running status does not contain %q", expected)
		}
	}

	controller.status = unifi.Status{Running: false, Hosts: 4}
	idle := serveRequest(server, http.MethodGet, "/ui/integrations/unifi/status").Body.String()
	if !strings.Contains(idle, `hx-trigger="every 10s"`) {
		t.Error("an idle integration kept the fast poll")
	}
	if strings.Contains(idle, "cluster-sync-indeterminate") || strings.Contains(idle, "Synchronizing…") {
		t.Error("an idle integration still showed the progress bar")
	}
	if !strings.Contains(idle, "Sync Now") {
		t.Error("an idle integration did not re-enable Sync Now")
	}
}

// A per-network host count only means something once a synchronization has
// reported one, so before that the column says so rather than claiming zero.
func TestUniFiMappingTableCountsHostsPerNetwork(t *testing.T) {
	t.Parallel()
	controller := &testUniFiController{status: unifi.Status{
		Hosts: 7, HostsByNetwork: map[string]int{"net-lan": 5},
	}}
	server, configuration := newIntegrationsTestServer(t, controller)
	candidate := configuration.snapshot.Config
	candidate.UniFi = config.UniFi{
		Enabled: true, ControllerURL: "https://192.168.1.1", Site: "default",
		Interval: config.Duration{Duration: 2 * time.Minute}, Sources: []string{"active"},
		Networks: []config.UniFiNetwork{
			{
				ID: "net-lan", Name: "Default", Zone: "clients.example.test",
				HostnameTemplate: unifi.DefaultHostnameTemplate, TTL: 300, Reverse: true, Enabled: true,
			},
			{
				ID: "net-iot", Name: "IoT", Zone: "iot.example.test",
				HostnameTemplate: unifi.DefaultHostnameTemplate, TTL: 300, Enabled: true,
			},
		},
	}
	configuration.snapshot.Config = candidate

	body := serveRequest(server, http.MethodGet, "/integrations").Body.String()

	if !strings.Contains(body, "<th>Hosts</th>") {
		t.Fatal("the mapping table has no host count column")
	}
	if !strings.Contains(body, "<td>5</td>") {
		t.Error("the mapped network did not report its host count")
	}
	// The controller reported nothing for this network, which after a
	// synchronization means it really holds no hosts.
	if !strings.Contains(body, "<td>0</td>") {
		t.Error("a network the last sync found empty did not report zero")
	}

	// Without a synchronization there is no count to show at all.
	controller.status = unifi.Status{}
	fresh := serveRequest(server, http.MethodGet, "/integrations").Body.String()
	if strings.Contains(fresh, "<td>0</td>") {
		t.Error("an unsynchronized network claimed it had no hosts")
	}
	if !strings.Contains(fresh, "Counted after the first synchronization") {
		t.Error("an unsynchronized network did not explain the missing count")
	}
}

// The mapping table sits outside the polled fragment, so the counts only stay
// current if the status poll swaps it in as well.
func TestUniFiStatusPollRefreshesTheMappingTable(t *testing.T) {
	t.Parallel()
	controller := &testUniFiController{status: unifi.Status{
		Hosts: 5, HostsByNetwork: map[string]int{"net-lan": 5},
	}}
	server, configuration := newIntegrationsTestServer(t, controller)
	candidate := configuration.snapshot.Config
	candidate.UniFi = config.UniFi{
		Enabled: true, ControllerURL: "https://192.168.1.1", Site: "default",
		Interval: config.Duration{Duration: 2 * time.Minute}, Sources: []string{"active"},
		Networks: []config.UniFiNetwork{{
			ID: "net-lan", Name: "Default", Zone: "clients.example.test",
			HostnameTemplate: unifi.DefaultHostnameTemplate, TTL: 300, Reverse: true, Enabled: true,
		}},
	}
	configuration.snapshot.Config = candidate

	body := serveRequest(server, http.MethodGet, "/ui/integrations/unifi/status").Body.String()

	if !strings.Contains(body, `id="unifi-mapping-table"`) {
		t.Fatal("the status poll did not carry the mapping table")
	}
	if !strings.Contains(body, "<td>5</td>") {
		t.Error("the swapped mapping table did not carry the host count")
	}
}

// The remove dialog needs a control that opens it.
func TestUniFiCardOffersRemove(t *testing.T) {
	t.Parallel()
	controller := &testUniFiController{}
	server, configuration := newIntegrationsTestServer(t, controller)
	candidate := configuration.snapshot.Config
	candidate.UniFi = config.UniFi{
		Enabled: true, ControllerURL: "https://192.168.1.1", Site: "default",
		Interval: config.Duration{Duration: 2 * time.Minute}, Sources: []string{"active"},
		Networks: []config.UniFiNetwork{{
			ID: "net-lan", Name: "Default", Zone: "clients.example.test",
			HostnameTemplate: unifi.DefaultHostnameTemplate, TTL: 300, Reverse: true, Enabled: true,
		}},
	}
	configuration.snapshot.Config = candidate

	body := serveRequest(server, http.MethodGet, "/integrations").Body.String()

	if !strings.Contains(body, `data-dialog-open="remove-unifi-dialog"`) {
		t.Error("the card has no control that opens the remove dialog")
	}
	if !strings.Contains(body, `id="remove-unifi-dialog"`) {
		t.Error("the remove dialog is missing")
	}
}

// Servers commonly run on UTC, so the sync timestamps have to follow the
// browser's clock rather than the process location.
func TestUniFiStatusRendersSyncTimeInTheBrowserZone(t *testing.T) {
	t.Parallel()
	lastSuccess := time.Date(2026, time.August, 13, 1, 7, 6, 0, time.UTC)
	controller := &testUniFiController{status: unifi.Status{Hosts: 4, LastSuccess: lastSuccess}}
	server, _ := newIntegrationsTestServer(t, controller)

	request := httptest.NewRequest(http.MethodGet, "/ui/integrations/unifi/status", nil)
	request.AddCookie(&http.Cookie{Name: timeZoneCookie, Value: "America/New_York"})
	request.AddCookie(&http.Cookie{Name: timeFormatCookie, Value: "24"})
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status panel = %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "8/12 21:07:06") {
		t.Errorf("status panel did not render the sync time as eastern time")
	}
}
