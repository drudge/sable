package pages

import (
	"strings"
	"testing"
)

func TestCommandPaletteExposesKeyboardCombobox(t *testing.T) {
	t.Parallel()

	page := renderComponent(t, AppDocument(DashboardView{}, "Dashboard", "dashboard", Empty()))
	for _, expected := range []string{
		`id="command-palette"`, `data-command-palette`, `aria-labelledby="command-palette-title"`,
		`id="command-palette-input"`, `role="combobox"`, `aria-autocomplete="list"`,
		`id="command-palette-results"`, `role="listbox"`, `data-command-item`,
		`data-command-search-scope`, `data-command-search-back`, `data-command-search-modes`,
		`data-command-footer-search-mode`, `>←</kbd><kbd>→</kbd> Search by`,
		`role="radiogroup"`, `data-command-search-modes-label="DNS record type"`,
		`aria-keyshortcuts="Meta+K Control+K"`, `data-command-shortcut`,
		`id="command-action-query"`, `data-command-focus="#query-name"`, `data-command-search-submit="#dns-query-form"`,
	} {
		if !strings.Contains(page, expected) {
			t.Errorf("command palette markup does not contain %q", expected)
		}
	}
	if triggers := strings.Count(page, `data-command-open`); triggers != 2 {
		t.Errorf("command palette triggers = %d, want desktop and mobile triggers", triggers)
	}
}

func TestCommandPaletteRendersClusterQuickActionForCurrentState(t *testing.T) {
	t.Parallel()

	uninitialized := renderComponent(t, CommandPalette(DashboardView{CommandEntities: []CommandEntityView{{
		ID: "command-action-initialize-cluster", Label: "Initialize Cluster", Description: "Create a cluster with this server as primary", Icon: "server-crash", Kind: "Action",
		Route: "/cluster", Dialog: "initialize-cluster-dialog",
	}}}))
	for _, expected := range []string{`id="command-action-initialize-cluster"`, `icon-server-crash`, `data-command-route="/cluster"`, `data-command-dialog="initialize-cluster-dialog"`} {
		if !strings.Contains(uninitialized, expected) {
			t.Errorf("uninitialized palette does not contain %q", expected)
		}
	}

	primary := renderComponent(t, CommandPalette(DashboardView{CommandEntities: []CommandEntityView{{
		ID: "command-action-add-replica", Label: "Add Replica", Description: "Create an enrollment token for a new replica", Icon: "server-plus", Kind: "Action",
		Route: "/cluster", Dialog: "enrollment-token-dialog",
	}}}))
	for _, expected := range []string{`id="command-action-add-replica"`, `icon-server-plus`, `data-command-route="/cluster"`, `data-command-dialog="enrollment-token-dialog"`} {
		if !strings.Contains(primary, expected) {
			t.Errorf("primary palette does not contain %q", expected)
		}
	}
}

func TestCommandPaletteCommandsFollowPermissionsAndReplicaState(t *testing.T) {
	t.Parallel()

	fullAccess := DashboardView{
		SecurityEnabled: true,
		CanSettings:     true, CanWriteSettings: true,
		CanAdministration: true, CanWriteUsers: true,
		CanZones: true, CanCreateZones: true,
		CanBlocking: true, CanWriteBlocking: true,
		BlockingEnabled: true, HasRemoteBlockLists: true,
		CanLogs: true, CanCluster: true,
	}
	page := renderComponent(t, CommandPalette(fullAccess))
	for _, expected := range []string{
		`id="command-page-zones"`, `id="command-page-query-logs"`,
		`id="command-action-query"`, `data-command-keywords="rdq resolve lookup dig nslookup"`,
		`id="command-action-add-zone"`, `id="command-action-import-zone"`, `data-command-dialog="import-new-zone-dialog"`, `id="command-action-block-domain"`,
		`id="command-action-search-server-logs"`, `id="command-action-search-query-logs"`, `id="command-action-search-cache"`,
		`id="command-action-search-blocked"`, `data-command-focus="[data-domain-search=domains]"`,
		`id="command-action-search-allowed"`, `data-command-focus="[data-domain-search=allowed]"`,
		`data-command-search-modes-label="Search query logs by"`, `data-command-keywords="sql dns history client response filters ip address"`,
		`data-command-search-modes-config=`, `data-command-search-submit="#dns-query-form"`,
		`data-command-focus="#cache-browser-dialog [data-cache-search]"`, `data-command-search-prompt="Search cached domains…"`,
		`data-command-search="true"`, `data-command-search-param="search"`, `data-command-search-param="name"`,
		`id="command-action-pause-blocking-5"`,
		`id="command-action-pause-blocking-15"`, `id="command-action-pause-blocking-30"`,
		`id="command-action-pause-blocking-60"`, `id="command-action-resume-blocking"`,
		`id="command-action-update-block-lists"`, `data-command-post="/ui/blocking/pause"`,
		`id="command-action-flush-cache"`, `id="command-action-create-token"`,
		`id="command-action-add-user"`, `id="command-action-add-group"`,
	} {
		if !strings.Contains(page, expected) {
			t.Errorf("full-access command palette does not contain %q", expected)
		}
	}
	searchGroup := strings.Index(page, `id="command-search-title"`)
	dnsQuery := strings.Index(page, `id="command-action-query"`)
	quickActions := strings.Index(page, `id="command-actions-title"`)
	if searchGroup < 0 || dnsQuery < searchGroup || quickActions < dnsQuery {
		t.Fatal("Run DNS Query is not rendered in Search actions")
	}
	fullAccess.ControlPlaneReadOnly = true
	replica := renderComponent(t, CommandPalette(fullAccess))
	for _, forbidden := range []string{
		`id="command-action-add-zone"`, `id="command-action-import-zone"`, `id="command-action-block-domain"`,
		`id="command-action-pause-blocking-5"`, `id="command-action-resume-blocking"`, `id="command-action-update-block-lists"`,
		`id="command-action-create-token"`, `id="command-action-add-user"`,
	} {
		if strings.Contains(replica, forbidden) {
			t.Errorf("replica command palette unexpectedly contains %q", forbidden)
		}
	}
	for _, local := range []string{`id="command-action-query"`, `id="command-action-browse-cache"`, `id="command-action-flush-cache"`} {
		if !strings.Contains(replica, local) {
			t.Errorf("replica command palette lost node-local action %q", local)
		}
	}

	restricted := renderComponent(t, CommandPalette(DashboardView{}))
	for _, forbidden := range []string{`id="command-page-zones"`, `id="command-page-settings"`, `id="command-page-administration"`} {
		if strings.Contains(restricted, forbidden) {
			t.Errorf("restricted command palette unexpectedly contains %q", forbidden)
		}
	}
}

func TestDNSClientAcceptsCommandPaletteQueryDefaults(t *testing.T) {
	t.Parallel()

	page := renderComponent(t, DNSClientContent(DNSClientPageView{QueryName: "mail.example.test", RecordType: "MX"}))
	for _, expected := range []string{`id="query-name" name="name" value="mail.example.test"`, `<option selected>MX</option>`} {
		if !strings.Contains(page, expected) {
			t.Errorf("DNS client command defaults do not contain %q", expected)
		}
	}
}

func TestCommandPaletteRendersSearchableEntities(t *testing.T) {
	t.Parallel()

	page := renderComponent(t, CommandPalette(DashboardView{CommandEntities: []CommandEntityView{
		{ID: "command-zone-penree", Label: "penree.net", Description: "Primary DNS zone", Icon: "globe", Kind: "Zone", Keywords: "dns zone primary", Href: "/zones/penree.net"},
		{ID: "command-zone-search-penree", Label: "Search in penree.net", Description: "Filter records in this zone", Icon: "search", Kind: "Search", Keywords: "dns records", Route: "/zones/penree.net", Focus: "[data-record-search]", SearchPrompt: "Search records in penree.net…"},
		{ID: "command-integration-unifi", Label: "Edit UniFi Setup", Description: "Edit controller and network mappings", Icon: "wifi-sync", Kind: "Integration", Keywords: "unifi", Href: "/integrations?setup=unifi"},
	}}))
	for _, expected := range []string{
		`id="command-zones-title"`, `>Zones</h3>`, `id="command-search-title"`, `>Search actions</h3>`,
		`id="command-integrations-title"`, `>Integrations</h3>`, `data-command-label="penree.net"`,
		`data-command-href="/zones/penree.net"`, `>Zone</span>`,
		`data-command-label="Search in penree.net"`, `data-command-route="/zones/penree.net"`,
		`data-command-focus="[data-record-search]"`, `data-command-search="true"`,
		`data-command-search-prompt="Search records in penree.net…"`, `>Search</span>`,
		`data-command-label="Edit UniFi Setup"`, `data-command-href="/integrations?setup=unifi"`, `>Integration</span>`,
	} {
		if !strings.Contains(page, expected) {
			t.Errorf("entity command palette does not contain %q", expected)
		}
	}
	if strings.Contains(page, `>Sable</h3>`) {
		t.Error("entity command palette still contains the catch-all Sable group")
	}
}
