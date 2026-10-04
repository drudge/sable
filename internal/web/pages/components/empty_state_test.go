package components

import (
	"testing"

	"github.com/a-h/templ"
)

func TestEmptyStateRendersParts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		props    EmptyStateProps
		children string
		want     string
	}{
		{
			name:  "icon, title, and description",
			props: EmptyStateProps{Icon: "key", Title: "No keys yet", Description: "Add one to start.", Class: "tsig-empty"},
			want:  `<div class="empty-state tsig-empty">` + iconHTML(t, "key") + `<h3>No keys yet</h3><p>Add one to start.</p></div>`,
		},
		{
			name:  "boxed icon",
			props: EmptyStateProps{Icon: "key", IconBox: true, Title: "No tokens yet"},
			want:  `<div class="empty-state"><span class="empty-state-icon">` + iconHTML(t, "key") + `</span> <h3>No tokens yet</h3></div>`,
		},
		{
			name:     "attributes and actions",
			props:    EmptyStateProps{Title: "No devices match", Class: "insight-section-empty", Attrs: templ.Attributes{"hidden": true, "data-list-filter-empty": true}},
			children: `<button>Clear Filters</button>`,
			want:     `<div class="empty-state insight-section-empty" data-list-filter-empty hidden><h3>No devices match</h3><button>Clear Filters</button></div>`,
		},
		{
			name:  "description only",
			props: EmptyStateProps{Description: "No blocked domains yet."},
			want:  `<div class="empty-state"><p>No blocked domains yet.</p></div>`,
		},
	}
	for _, test := range tests {
		if got := renderWithChildren(t, EmptyState(test.props), test.children); got != test.want {
			t.Errorf("%s:\ngot  %s\nwant %s", test.name, got, test.want)
		}
	}
}

func iconHTML(t *testing.T, name string) string {
	t.Helper()
	return renderWithChildren(t, Icon(name), "")
}
