package web

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web/pages"
	"github.com/drudge/sable/internal/zone"
)

func TestCommandPaletteEntitiesRespectZoneGrantsAndIncludeIntegrations(t *testing.T) {
	t.Parallel()

	server := &Server{
		securityEnabled: true,
		zones: testZones{snapshot: zone.Snapshot{Zones: []zone.Zone{
			{ID: "zone-allowed", Name: "penree.net", Type: "primary"},
			{ID: "zone-hidden", Name: "secret.internal", Type: "secondary"},
		}}},
	}
	configuration := config.Defaults()
	configuration.UniFi.ControllerURL = "https://unifi.example.test"
	configuration.UniFi.Site = "default"
	configuration.UniFi.Networks = []config.UniFiNetwork{{ID: "network-1", Name: "Corporate LAN", Zone: "penree.net"}}
	configuration.OIDC.Enabled = true
	configuration.OIDC.DisplayName = "Vandelay SSO"
	configuration.OIDC.Issuer = "https://login.example.test"
	request := httptest.NewRequest("GET", "/", nil)
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, auth.Principal{
		Surface: auth.SurfaceWeb,
		Grants: []auth.Grant{{
			Permission: auth.PermissionZonesRead, Surface: auth.SurfaceWeb,
			ResourceType: auth.ResourceZone, ResourceID: "zone-allowed",
		}},
	}))

	entities := server.commandPaletteEntities(request, config.Snapshot{Config: configuration}, pages.DashboardView{CanZones: true, CanSettings: true, CanWriteSettings: true})
	byLabel := make(map[string]pages.CommandEntityView, len(entities))
	for _, entity := range entities {
		byLabel[entity.Label] = entity
	}
	if _, found := byLabel["secret.internal"]; found {
		t.Fatal("command palette exposed a zone outside the principal's resource grant")
	}
	if entity, found := byLabel["penree.net"]; !found || entity.Href != "/zones/penree.net" || entity.Kind != "Zone" {
		t.Fatalf("allowed zone entity = %+v, found=%v", entity, found)
	}
	if entity, found := byLabel["Search in penree.net"]; !found || entity.Route != "/zones/penree.net" || entity.Focus != "[data-record-search]" || entity.SearchPrompt != "Search records in penree.net…" {
		t.Fatalf("zone search entity = %+v, found=%v", entity, found)
	}
	if _, found := byLabel["Corporate LAN"]; found {
		t.Fatal("command palette included an individual UniFi network")
	}
	if entity, found := byLabel["Edit UniFi Setup"]; !found || entity.Href != "/integrations?setup=unifi" {
		t.Fatalf("UniFi setup entity = %+v, found=%v", entity, found)
	}
	if entity, found := byLabel["Edit SSO Setup"]; !found || entity.Href != "/integrations?setup=sso" {
		t.Fatalf("SSO setup entity = %+v, found=%v", entity, found)
	}
}
