package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/config"
)

func TestDHCPAPIImportsAnotherServersReservations(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPTestServer(t)
	reservations := func() []config.DHCPReservation { return configuration.snapshot.Config.DHCP.Scopes[0].Reservations }
	export := strings.Join([]string{
		"dhcp-host=00:11:22:33:44:01,192.0.2.10,printer",   // already reserved, the same: unchanged
		"dhcp-host=00:11:22:33:44:02,192.0.2.11,nas.lan",   // added as nas
		"dhcp-host=00:11:22:33:44:03,192.0.2.10,clash",     // address taken
		"dhcp-host=00:11:22:33:44:04,198.51.100.4,away",    // outside the subnet
		"dhcp-host=00:11:22:33:44:05,192.0.2.12,printer",   // name taken: added without it
		"dhcp-host=00:11:22:33:44:06,192.0.2.13,bad_label", // not a label: added without it
		"dhcp-host=00:11:22:33:44:07,ignore",               // not read
	}, "\n")
	type result struct {
		Format    string                   `json:"format"`
		Scope     string                   `json:"scope"`
		DryRun    bool                     `json:"dry_run"`
		Added     []config.DHCPReservation `json:"added"`
		Unchanged int                      `json:"unchanged"`
		Skipped   []dhcpImportNote         `json:"skipped"`
		Warnings  []dhcpImportNote         `json:"warnings"`
	}
	post := func(path string) (int, result) {
		response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPost, path, export)
		var body result
		if response.Code == http.StatusOK {
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("%s: %v %s", path, err, response.Body)
			}
		}
		return response.Code, body
	}

	revision := configuration.snapshot.Revision
	code, preview := post("/api/v1/dhcp/import?dry_run=true")
	if code != http.StatusOK || !preview.DryRun || preview.Scope != "lan" || len(preview.Added) != 3 || configuration.snapshot.Revision != revision {
		t.Fatalf("dry run = %d %+v; want 3 to add and nothing saved", code, preview)
	}
	code, applied := post("/api/v1/dhcp/import?scope=lan")
	want := []config.DHCPReservation{
		{MAC: "00:11:22:33:44:01", Address: "192.0.2.10", Name: "printer"},
		{MAC: "00:11:22:33:44:02", Address: "192.0.2.11", Name: "nas"},
		{MAC: "00:11:22:33:44:05", Address: "192.0.2.12"},
		{MAC: "00:11:22:33:44:06", Address: "192.0.2.13"},
	}
	if code != http.StatusOK || applied.Format != "dnsmasq" || applied.Unchanged != 1 || len(applied.Skipped) != 3 || len(applied.Warnings) != 2 {
		t.Fatalf("import = %d %+v", code, applied)
	}
	if got := reservations(); len(got) != len(want) || got[1] != want[1] || got[2] != want[2] || got[3] != want[3] {
		t.Fatalf("reservations = %+v; want %+v", got, want)
	}
	lines := []int{applied.Skipped[0].Line, applied.Skipped[1].Line, applied.Skipped[2].Line}
	if lines[0] != 7 || lines[1] != 3 || lines[2] != 4 {
		t.Fatalf("skipped lines = %v (%+v); want 7, 3, 4", lines, applied.Skipped)
	}

	// Again: everything is already there, so nothing is saved.
	revision = configuration.snapshot.Revision
	if code, again := post("/api/v1/dhcp/import?scope=lan"); code != http.StatusOK || len(again.Added) != 0 || again.Unchanged != 4 || configuration.snapshot.Revision != revision {
		t.Fatalf("second import = %d %+v; want 4 unchanged and nothing saved", code, again)
	}
	if code, _ := post("/api/v1/dhcp/import?scope=guest"); code != http.StatusNotFound {
		t.Fatalf("unknown scope = %d; want 404", code)
	}
	if response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPost, "/api/v1/dhcp/import", `{"zones":[]}`); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown export = %d %s; want 422", response.Code, response.Body)
	}
	if response := dhcpAPIRequest(t, server, "sable_pat_settings", http.MethodPost, "/api/v1/dhcp/import", export); response.Code != http.StatusForbidden {
		t.Fatalf("token without dhcp.write = %d; want 403", response.Code)
	}
}
