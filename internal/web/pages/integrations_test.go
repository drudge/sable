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
			expected: `class="status-badge">Not configured</span>`,
		},
		{
			name:     "active",
			view:     DynamicDNSAppView{Available: true, Configured: true, Enabled: true, CredentialsConfigured: true},
			expected: `class="status-badge success">Active</span>`,
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
