package components

import (
	"testing"

	"github.com/a-h/templ"
)

func TestPageHeaderRendersTitleDescriptionAndActions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		props PageHeaderProps
		want  string
	}{
		{
			name:  "title and description",
			props: PageHeaderProps{Title: "Cluster", Description: "Synchronize Sable"},
			want:  `<header class="page-header"><div class="page-heading"><h1>Cluster</h1><p>Synchronize Sable</p></div></header>`,
		},
		{
			name:  "title only",
			props: PageHeaderProps{Title: "Zones"},
			want:  `<header class="page-header"><div class="page-heading"><h1>Zones</h1></div></header>`,
		},
		{
			name: "actions, class, and attributes",
			props: PageHeaderProps{
				Title:   "Logs",
				Actions: templ.Raw(`<a href="/settings">Settings</a>`),
				Class:   "insights-heading",
				Attrs:   templ.Attributes{"data-hook": "1"},
			},
			want: `<header class="page-header insights-heading" data-hook="1"><div class="page-heading"><h1>Logs</h1></div><a href="/settings">Settings</a></header>`,
		},
	}
	for _, test := range tests {
		if got := renderWithChildren(t, PageHeader(test.props), ""); got != test.want {
			t.Errorf("%s:\ngot  %s\nwant %s", test.name, got, test.want)
		}
	}
}
