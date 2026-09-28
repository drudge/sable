package pages

import (
	"strings"
	"testing"
)

// The everyday DNS pages lead the sidebar under no heading. System lists the
// server's own pages in a fixed order, which the command palette follows too.
func TestSidebarListsSystemPagesUnderItsOnlyHeading(t *testing.T) {
	t.Parallel()

	page := renderComponent(t, AppDocument(DashboardView{CanSettings: true, CanAdministration: true, CanCluster: true, CanLogs: true}, "Dashboard", "dashboard", Empty()))
	start := strings.Index(page, `id="primary-navigation"`)
	if start < 0 {
		t.Fatal("application shell has no primary navigation")
	}
	nav, _, _ := strings.Cut(page[start:], "</nav>")
	if headings := strings.Count(nav, `class="nav-label"`); headings != 1 {
		t.Errorf("sidebar has %d group headings, want only System", headings)
	}
	assertInOrder(t, "sidebar", nav, `href="/dns-client"`, `href="/logs"`, `<div class="nav-label">System</div>`, `href="/administration"`, `href="/cluster"`, `href="/integrations"`, `href="/settings"`, `href="/about"`)
	assertInOrder(t, "command palette", page, `id="command-page-query-logs"`, `id="command-page-administration"`, `id="command-page-cluster"`, `id="command-page-integrations"`, `id="command-page-settings"`, `id="command-page-about"`)
}

func assertInOrder(t *testing.T, name, markup string, markers ...string) {
	t.Helper()
	last := -1
	for _, marker := range markers {
		at := strings.Index(markup, marker)
		if at < 0 {
			t.Errorf("%s does not contain %q", name, marker)
			continue
		}
		if at < last {
			t.Errorf("%s lists %q out of order", name, marker)
		}
		last = at
	}
}
