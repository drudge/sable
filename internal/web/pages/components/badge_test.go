package components

import (
	"testing"

	"github.com/a-h/templ"
)

func TestBadgeRendersTones(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		props    BadgeProps
		children string
		want     string
	}{
		{
			name:  "neutral",
			props: BadgeProps{Label: "Not set up"},
			want:  `<span class="status-badge">Not set up</span>`,
		},
		{
			name:  "success with a tooltip",
			props: BadgeProps{Label: "On", Tone: BadgeSuccess, Title: "Alerts are on"},
			want:  `<span class="status-badge success" title="Alerts are on">On</span>`,
		},
		{
			name:  "warning with a class",
			props: BadgeProps{Label: "Paused", Tone: BadgeWarning, Class: "sso-badge"},
			want:  `<span class="status-badge warning sso-badge">Paused</span>`,
		},
		{
			name:  "current",
			props: BadgeProps{Label: "This node", Tone: BadgeCurrent},
			want:  `<span class="current-badge">This node</span>`,
		},
		{
			name:  "count with a data hook",
			props: BadgeProps{Label: "3 apps", Tone: BadgeCount, Attrs: templ.Attributes{"data-list-count": "3"}},
			want:  `<span class="count-badge" data-list-count="3">3 apps</span>`,
		},
		{
			name:     "icon and children",
			props:    BadgeProps{Icon: "clock", Class: "cluster-updated-badge"},
			children: `<span>Updated now</span>`,
			want:     `<span class="status-badge cluster-updated-badge">` + iconHTML(t, "clock") + `<span>Updated now</span></span>`,
		},
	}
	for _, test := range tests {
		if got := renderWithChildren(t, Badge(test.props), test.children); got != test.want {
			t.Errorf("%s:\ngot  %s\nwant %s", test.name, got, test.want)
		}
	}
}
