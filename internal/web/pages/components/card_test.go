package components

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

func renderWithChildren(t *testing.T, c templ.Component, children string) string {
	t.Helper()
	var b strings.Builder
	ctx := templ.WithChildren(context.Background(), templ.ComponentFunc(func(_ context.Context, w io.Writer) error {
		_, err := io.WriteString(w, children)
		return err
	}))
	if err := c.Render(ctx, &b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestCardRendersElementAndAttributes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		props CardProps
		want  string
	}{
		{
			name:  "section",
			props: CardProps{Class: "about-card"},
			want:  `<section class="card about-card"><p>body</p></section>`,
		},
		{
			name:  "id and attributes",
			props: CardProps{ID: "watches", Class: "settings-source-card", Attrs: templ.Attributes{"data-settings-card": true}},
			want:  `<section class="card settings-source-card" id="watches" data-settings-card><p>body</p></section>`,
		},
		{
			name:  "article",
			props: CardProps{Article: true},
			want:  `<article class="card"><p>body</p></article>`,
		},
	}
	for _, test := range tests {
		if got := renderWithChildren(t, Card(test.props), "<p>body</p>"); got != test.want {
			t.Errorf("%s:\n got %s\nwant %s", test.name, got, test.want)
		}
	}
}

func TestCardHeaderRendersTitleDescriptionAndActions(t *testing.T) {
	t.Parallel()

	got := renderWithChildren(t, CardHeader(CardHeaderProps{Title: "Node Sync Status", Description: "By node"}), `<span class="status-badge">Live</span>`)
	want := `<header><div><h2>Node Sync Status</h2><p>By node</p></div><span class="status-badge">Live</span></header>`
	if got != want {
		t.Errorf("plain header:\n got %s\nwant %s", got, want)
	}

	got = renderWithChildren(t, CardHeader(CardHeaderProps{Icon: "key", Title: "TSIG Keys", TitleID: "tsig-title", TitleClass: "about-card-title", Class: "extra"}), "")
	if !strings.HasPrefix(got, `<header class="extra"><div><h2 id="tsig-title" class="about-card-title"><svg`) || !strings.HasSuffix(got, `</svg><span>TSIG Keys</span></h2></div></header>`) {
		t.Errorf("icon header: %s", got)
	}
}
