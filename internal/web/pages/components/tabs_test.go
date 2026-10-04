package components

import (
	"strings"
	"testing"
)

func TestTabsRendersTablist(t *testing.T) {
	t.Parallel()

	got := renderWithChildren(t, Tabs(TabsProps{
		Label:    "Settings sections",
		Class:    "settings-tab-list",
		TabClass: "settings-tab",
		Active:   "web",
		Tabs: []Tab{
			{Value: "general", Label: "General"},
			{Value: "web", Label: "Web", Count: "3", CountID: "web-count"},
		},
	}), "")
	for _, want := range []string{
		`<div class="isotope-tab-list settings-tab-list" role="tablist" aria-label="Settings sections">`,
		`<button class="isotope-tab settings-tab" type="button" role="tab" data-isotope-tab="general" data-tab-title="General" aria-selected="false" tabindex="-1"><span>General</span> </button>`,
		`<button class="isotope-tab settings-tab active" type="button" role="tab" data-isotope-tab="web" data-tab-title="Web" aria-selected="true" tabindex="0"><span>Web</span> <span class="tab-count" id="web-count">3</span></button>`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Tabs() missing %s\ngot %s", want, got)
		}
	}
}

func TestTabsRendersNavLinks(t *testing.T) {
	t.Parallel()

	got := renderWithChildren(t, Tabs(TabsProps{
		Label:  "Profile sections",
		Active: "account",
		Nav:    true,
		Tabs: []Tab{
			{Value: "account", Label: "Account", Href: "/profile"},
			{Value: "tokens", Label: "API Tokens", Href: "/profile?tab=tokens", Count: "0"},
		},
	}), "")
	for _, want := range []string{
		`<nav class="isotope-tab-list" aria-label="Profile sections">`,
		`<a class="isotope-tab active" href="/profile" aria-current="page"><span>Account</span> </a>`,
		`<a class="isotope-tab" href="/profile?tab=tokens" aria-current="false"><span>API Tokens</span> <span class="tab-count">0</span></a>`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Tabs() missing %s\ngot %s", want, got)
		}
	}
	if strings.Contains(got, `role="tab"`) {
		t.Errorf("nav tabs should be plain links, got %s", got)
	}
}
