package components

import (
	"strings"
	"testing"

	"github.com/a-h/templ"
)

func TestMenuRendersTriggerAndPanel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		props MenuProps
		want  string
	}{
		{
			name:  "outline compact trigger with a label",
			props: MenuProps{Label: "Hide Finding", Variant: ButtonOutline, Compact: true, Class: "insight-hide-menu", TriggerAttrs: templ.Attributes{"data-replica-primary-action": true}},
			want:  `<details class="insight-hide-menu" data-menu><summary class="button outline compact" data-replica-primary-action><span>Hide Finding</span></summary><div>items</div></details>`,
		},
		{
			name:  "caret and menu attributes",
			props: MenuProps{Label: "Add Provider", Variant: ButtonOutline, Caret: true, Class: "provider-menu", Attrs: templ.Attributes{"data-hook": true}},
			want:  `<details class="provider-menu" data-menu data-hook><summary class="button outline"><span>Add Provider</span><span class="styled-select-chevron" aria-hidden="true"></span></summary><div>items</div></details>`,
		},
		{
			name:  "icon button trigger",
			props: MenuProps{IconButton: true, TriggerClass: "zone-more-button", Class: "zone-action-menu", TriggerAttrs: templ.Attributes{"aria-label": "Actions for example.com"}},
			want:  `<details class="zone-action-menu" data-menu><summary class="icon-button zone-more-button" aria-label="Actions for example.com"></summary><div>items</div></details>`,
		},
	}
	for _, test := range tests {
		if got := renderWithChildren(t, Menu(test.props), "<div>items</div>"); got != test.want {
			t.Errorf("%s:\ngot  %s\nwant %s", test.name, got, test.want)
		}
	}
}

func TestMenuDrawsIconsAroundTheLabel(t *testing.T) {
	t.Parallel()

	got := renderWithChildren(t, Menu(MenuProps{Label: "Import", Icon: "upload", TrailingIcon: "chevron-down", Class: "import-menu"}), "")
	upload := strings.Index(got, "icon-upload")
	label := strings.Index(got, "<span>Import</span>")
	chevron := strings.Index(got, "icon-chevron-down")
	if upload < 0 || label < 0 || chevron < 0 || !(upload < label && label < chevron) {
		t.Errorf("want upload icon, label, then chevron in order; got %s", got)
	}
	if !strings.HasPrefix(got, `<details class="import-menu" data-menu><summary class="button">`) {
		t.Errorf("unexpected trigger: %s", got)
	}
}
