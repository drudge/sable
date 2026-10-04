package components

import (
	"context"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

func TestButtonRendersClassesAndElement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		props ButtonProps
		want  string
	}{
		{
			name:  "primary",
			props: ButtonProps{Label: "Save Settings", Type: "submit"},
			want:  `<button class="button" type="submit"><span>Save Settings</span></button>`,
		},
		{
			name:  "outline compact disabled",
			props: ButtonProps{Label: "Restore", Variant: ButtonOutline, Compact: true, Disabled: true, Class: "extra", Attrs: templ.Attributes{"data-hook": true}},
			want:  `<button class="button outline compact extra" type="button" disabled data-hook><span>Restore</span></button>`,
		},
		{
			name:  "destructive",
			props: ButtonProps{Label: "Delete", Destructive: true},
			want:  `<button class="button destructive" type="button"><span>Delete</span></button>`,
		},
		{
			name:  "link",
			props: ButtonProps{Label: "Download", Href: "/file", Attrs: templ.Attributes{"download": "a.bin"}},
			want:  `<a class="button" href="/file" download="a.bin"><span>Download</span></a>`,
		},
	}
	for _, test := range tests {
		var b strings.Builder
		if err := Button(test.props).Render(context.Background(), &b); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if got := b.String(); got != test.want {
			t.Errorf("%s:\n got %s\nwant %s", test.name, got, test.want)
		}
	}
}

func TestButtonDrawsIconBeforeLabel(t *testing.T) {
	t.Parallel()

	var b strings.Builder
	if err := Button(ButtonProps{Label: "Add Key", Icon: "plus"}).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	if !strings.Contains(got, `</svg><span>Add Key</span></button>`) || !strings.HasPrefix(got, `<button class="button" type="button"><svg`) {
		t.Errorf("icon did not render before the label: %s", got)
	}
}
