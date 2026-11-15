package web

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// dhcpOffController is a DHCP server that's off, as the real one reports once
// [dhcp] enabled is false.
type dhcpOffController struct{ *testDHCPController }

func (dhcpOffController) Status() DHCPStatus { return DHCPStatus{} }

// An off server's status card told the admin to set
// enabled = true in sable.toml; the page now has a Turn On button for that.
func TestReview632OffStatusPointsAtTheButton(t *testing.T) {
	server, configuration, controller := newDHCPConsoleServer(t)
	configuration.snapshot.Config.DHCP.Enabled = false
	server.SetDHCPController(dhcpOffController{controller})
	body := dhcpConsoleRequest(t, server, http.MethodGet, "/dhcp", nil).Body.String()
	if !strings.Contains(body, "Turn On") {
		t.Fatalf("an off server's page has no Turn On button")
	}
	if strings.Contains(body, "enabled = true under [dhcp]") {
		t.Errorf("next to the Turn On button, the status card still says: Turn it on with enabled = true under [dhcp]")
	}
}

// The Add dialog's element id was dhcp-scope-new, and a scope's Edit dialog
// is dhcp-scope-<id>, so a scope with the ID "new" shared the Add dialog's id:
// its Edit button opened Add Scope, which refused the ID. A scope named
// "new-notice" met scope new's notice the same way, so no id may repeat.
func TestReview632ScopeNamedNewHasItsOwnDialog(t *testing.T) {
	server, configuration, _ := newDHCPConsoleServer(t)
	for index, id := range []string{"new", "new-notice"} {
		subnet := fmt.Sprintf("203.0.%d.", 113+index)
		form := url.Values{"new": {"1"}, "id": {id}, "name": {"Lab"}, "subnet": {subnet + "0/24"},
			"range_start": {subnet + "10"}, "range_end": {subnet + "20"}}
		if response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/scopes", form); response.Code != http.StatusOK || len(configuration.snapshot.Config.DHCP.Scopes) != 2+index {
			t.Fatalf("add scope with ID %s = %d: %s", id, response.Code, response.Body.String())
		}
	}
	body := dhcpConsoleRequest(t, server, http.MethodGet, "/dhcp?tab=scopes", nil).Body.String()
	if count := strings.Count(body, `id="dhcp-scope-new"`); count != 1 {
		t.Errorf("%d elements have id dhcp-scope-new; the Add dialog and scope new's Edit dialog need their own", count)
	}
	seen := map[string]bool{}
	for _, match := range regexp.MustCompile(` id="([^"]+)"`).FindAllStringSubmatch(body, -1) {
		if seen[match[1]] {
			t.Errorf("id %q appears more than once", match[1])
		}
		seen[match[1]] = true
	}
}
