package pages

import (
	"context"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

// The setup wizards are control-plane writes, so a replica has to show them as
// unavailable. They are opened by links rather than submitted as forms, and the
// console's read-only pass only finds a link through this marker, so without it
// a replica offers Edit Setup and then refuses the save.
func TestIntegrationSetupLaunchersAreMarkedPrimaryOnly(t *testing.T) {
	tests := []struct {
		name   string
		render func() string
		target string
	}{
		{"single sign-on, not set up", func() string { return render(t, SSOCard(SSOAppView{})) }, "setup=sso"},
		{"single sign-on, configured", func() string {
			return render(t, SSOCard(SSOAppView{Configured: true, Enabled: true, Issuer: "https://id.example.test"}))
		}, "setup=sso"},
		{"unifi, not set up", func() string { return render(t, UniFiCard(UniFiAppView{Available: true})) }, "setup=unifi"},
		{"unifi, configured", func() string {
			return render(t, UniFiCard(UniFiAppView{Available: true, Configured: true, ControllerURL: "https://unifi.example.test"}))
		}, "setup=unifi"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			launchers := openingTags(test.render(), "<a ", test.target)
			if len(launchers) == 0 {
				t.Fatalf("no launcher for %s appeared on the card", test.target)
			}
			for _, launcher := range launchers {
				if !strings.Contains(launcher, "data-replica-primary-action") {
					t.Errorf("launcher is not marked primary-only: %s", launcher)
				}
			}
		})
	}
}

// A card that is set up also offers Remove, which is a write like any other.
func TestIntegrationRemoveButtonsAreMarkedPrimaryOnly(t *testing.T) {
	for name, html := range map[string]string{
		"single sign-on": render(t, SSOCard(SSOAppView{Configured: true, Enabled: true})),
		"unifi":          render(t, UniFiCard(UniFiAppView{Available: true, Configured: true, ControllerURL: "https://unifi.example.test"})),
	} {
		buttons := openingTags(html, "<button ", "-dialog\"")
		if len(buttons) == 0 {
			t.Fatalf("%s: no remove button appeared on the card", name)
		}
		for _, button := range buttons {
			if strings.Contains(button, "remove-") && !strings.Contains(button, "data-replica-primary-action") {
				t.Errorf("%s: remove is not marked primary-only: %s", name, button)
			}
		}
	}
}

func TestDynamicDNSCardUsesSharedStatusBadges(t *testing.T) {
	tests := []struct {
		name     string
		view     DynamicDNSAppView
		expected string
	}{
		{
			name:     "not configured",
			view:     DynamicDNSAppView{Available: true},
			expected: `class="status-badge">Not set up</span>`,
		},
		{
			name:     "active",
			view:     DynamicDNSAppView{Available: true, Configured: true, Enabled: true, CredentialsConfigured: true},
			expected: `class="status-badge success">Active</span>`,
		},
		{
			name: "failed publication",
			view: DynamicDNSAppView{
				Available: true, Configured: true, Enabled: true, CredentialsConfigured: true,
				Status: DynamicDNSStatusView{LastError: "provider rejected the request"},
			},
			expected: `class="status-badge danger">Needs attention</span>`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if html := render(t, DynamicDNSCard(test.view)); !strings.Contains(html, test.expected) {
				t.Errorf("Dynamic DNS card does not use the shared status treatment %q", test.expected)
			}
		})
	}
}

func TestDynamicDNSCardShowsCopyableAddressesWithFullAddressTitles(t *testing.T) {
	t.Parallel()
	view := DynamicDNSAppView{
		Available: true, Configured: true, Enabled: true,
		Publishers: []DynamicDNSPublisherView{{
			Provider: "cloudflare",
			Zones: []DynamicDNSZoneView{{
				Zone: "example.com", Names: "home.example.com", PublishIPv4: true, PublishIPv6: true, TTL: 300,
			}},
		}},
		Status: DynamicDNSStatusView{
			LastPublished: "Sep 5, 2026 1:12 PM",
			IPv4:          "203.0.113.42",
			IPv6:          "2001:db8:1234:5678:90ab:cdef:1234:5678",
		},
	}
	html := render(t, DynamicDNSCard(view))
	for _, expected := range []string{
		`class="nav-icon icon-cloud-sync"`,
		`<path d="m17 18-1.535 1.605`,
		"Last published",
		"Sep 5, 2026 1:12 PM",
		`title="203.0.113.42"`,
		`title="2001:db8:1234:5678:90ab:cdef:1234:5678"`,
		`aria-label="IPv6: 2001:db8:1234:5678:90ab:cdef:1234:5678"`,
		`id="dynamic-dns-ipv4"`,
		`data-copy-target="dynamic-dns-ipv4"`,
		`aria-label="Copy IPv4 address"`,
		`id="dynamic-dns-ipv6"`,
		`data-copy-target="dynamic-dns-ipv6"`,
		`aria-label="Copy IPv6 address"`,
	} {
		if !strings.Contains(html, expected) {
			t.Errorf("Dynamic DNS card does not contain %q", expected)
		}
	}
	if strings.Contains(html, `<span class="integration-fact-label">Interval</span>`) {
		t.Error("Dynamic DNS card still presents the polling interval as a status fact")
	}
	if published, ipv6 := strings.Index(html, "Last published"), strings.Index(html, ">IPv6<"); published < ipv6 {
		t.Error("Last published is not the final Dynamic DNS status fact")
	}

	view.Status.LastPublished = ""
	if html := render(t, DynamicDNSCard(view)); !strings.Contains(html, `<span class="integration-fact-value">Never</span>`) {
		t.Error("Dynamic DNS card does not use the Never fallback before its first publication")
	}

	view.Status.IPv4 = ""
	view.Status.IPv6 = ""
	if html := render(t, DynamicDNSCard(view)); strings.Contains(html, `data-copy-target="dynamic-dns-ip`) {
		t.Error("Dynamic DNS card offers to copy an address that has not been discovered")
	}
}

func TestDynamicDNSPublisherEditorUsesCollapsibleStatusSummary(t *testing.T) {
	t.Parallel()
	configured := DynamicDNSPublisherView{
		Provider: "cloudflare", CredentialsConfigured: true,
		Zones: []DynamicDNSZoneView{{Zone: "example.com", Names: "home.example.com\nvpn.example.com", PublishIPv4: true, TTL: 300}},
	}
	html := render(t, DynamicDNSPublisherEditor(configured, "0", false))
	details := openingTags(html, "<details ", "dynamic-dns-publisher")
	if len(details) != 1 || strings.Contains(details[0], " open") {
		t.Fatalf("configured publisher should render collapsed: %v", details)
	}
	for _, expected := range []string{"<summary>", `class="status-badge success">Configured</span>`, ">Cloudflare</strong>", "1 zone · 2 hosts"} {
		if !strings.Contains(html, expected) {
			t.Errorf("configured publisher summary does not contain %q", expected)
		}
	}
	zones := openingTags(html, "<details ", "dynamic-dns-zone")
	if len(zones) < 1 || strings.Contains(zones[0], " open") {
		t.Fatalf("configured zone should render collapsed: %v", zones)
	}
	if !strings.Contains(html, ">example.com</strong>") || !strings.Contains(html, "2 hosts · A") || strings.Contains(html, ">Zone 1</strong>") {
		t.Error("configured zone summary is missing its identifying details")
	}
	if !strings.Contains(html, `type="hidden" name="publisher_0_provider" value="cloudflare"`) || strings.Contains(html, `<span>Provider</span><select`) {
		t.Error("configured publisher should carry its fixed provider without rendering a provider picker")
	}

	unconfigured := DynamicDNSPublisherView{Provider: "route53", Zones: []DynamicDNSZoneView{{PublishIPv4: true}}}
	html = render(t, DynamicDNSPublisherEditor(unconfigured, "0", false))
	details = openingTags(html, "<details ", "dynamic-dns-publisher")
	if len(details) != 1 || !strings.Contains(details[0], " open") {
		t.Fatalf("unconfigured publisher should render expanded: %v", details)
	}
	if !strings.Contains(html, `class="status-badge">Needs credentials</span>`) {
		t.Error("unconfigured publisher summary is missing its credential badge")
	}
	if !strings.Contains(html, ">Amazon Route 53</strong>") {
		t.Error("unconfigured publisher summary does not retain the provider chosen before insertion")
	}
	zones = openingTags(html, "<details ", "dynamic-dns-zone")
	if len(zones) < 1 || !strings.Contains(zones[0], " open") {
		t.Fatalf("unconfigured zone should render expanded: %v", zones)
	}
	if !strings.Contains(html, ">New zone</strong>") {
		t.Error("empty zone summary is missing its descriptive fallback")
	}
}

func TestDynamicDNSSetupUsesProviderMenuAndGlobalPublishingSettings(t *testing.T) {
	t.Parallel()
	html := render(t, DynamicDNSSetupDialog(DynamicDNSAppView{Interval: "5m", TTL: 600}))
	for _, expected := range []string{
		`class="nav-icon icon-globe"`,
		`data-dynamic-dns-add-provider-menu`,
		`data-dynamic-dns-add-publisher data-provider="cloudflare"`,
		`data-dynamic-dns-add-publisher data-provider="route53"`,
		`name="interval" value="5m"`,
		`name="ttl" value="600"`,
		`data-dynamic-dns-publishers-empty`,
	} {
		if !strings.Contains(html, expected) {
			t.Errorf("dynamic DNS setup does not contain %q", expected)
		}
	}
	if strings.Contains(html, `<span>Provider</span><select`) || strings.Contains(html, `_zone___ZONE___ttl`) {
		t.Error("dynamic DNS setup still renders per-publisher provider or per-zone TTL controls")
	}
}

func TestDynamicDNSStatusPollingDoesNotReloadAfterEverySwap(t *testing.T) {
	t.Parallel()
	for _, running := range []bool{false, true} {
		trigger := dynamicDNSStatusPoll(running)
		if strings.Contains(trigger, "load") {
			t.Errorf("dynamic DNS status trigger %q reloads immediately after replacing itself", trigger)
		}
	}
}

func TestDynamicDNSStatusPanelDisclosesProviderDetails(t *testing.T) {
	t.Parallel()
	html := render(t, DynamicDNSStatusPanel(DynamicDNSAppView{Status: DynamicDNSStatusView{
		LastError:       "Cloudflare rejected the request: Invalid request headers (code 6003).",
		LastErrorDetail: "{\n  \"code\": 6003\n}",
	}}))
	for _, expected := range []string{
		"Last publish failed",
		"Cloudflare rejected the request",
		"View provider details",
		`<pre>{`,
		`&#34;code&#34;: 6003`,
	} {
		if !strings.Contains(html, expected) {
			t.Errorf("Dynamic DNS status panel does not contain %q", expected)
		}
	}
}

func TestDynamicDNSAddressPlaceholdersAreDashes(t *testing.T) {
	t.Parallel()
	view := DynamicDNSAppView{Publishers: []DynamicDNSPublisherView{{
		Zones: []DynamicDNSZoneView{{PublishIPv4: true, PublishIPv6: true}},
	}}}
	if got := dynamicDNSIPv4(view); got != "—" {
		t.Errorf("empty IPv4 label = %q, want em dash", got)
	}
	if got := dynamicDNSIPv6(view); got != "—" {
		t.Errorf("empty IPv6 label = %q, want em dash", got)
	}
}

func render(t *testing.T, component templ.Component) string {
	t.Helper()
	var out strings.Builder
	if err := component.Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// openingTags returns the opening tags of the given kind that mention needle.
func openingTags(html, kind, needle string) []string {
	var tags []string
	for _, fragment := range strings.Split(html, kind)[1:] {
		if tag, _, found := strings.Cut(fragment, ">"); found && strings.Contains(tag, needle) {
			tags = append(tags, tag)
		}
	}
	return tags
}
