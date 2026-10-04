package components

import (
	"testing"

	"github.com/a-h/templ"
)

func TestFactListRendersRows(t *testing.T) {
	t.Parallel()

	got := renderWithChildren(t, FactList(FactListProps{Class: "query-detail-grid"}), `<div><dt>Role</dt><dd>Primary</dd></div>`)
	if want := `<dl class="query-detail-grid"><div><dt>Role</dt><dd>Primary</dd></div></dl>`; got != want {
		t.Errorf("FactList:\ngot  %s\nwant %s", got, want)
	}
}

func TestFactRendersParts(t *testing.T) {
	t.Parallel()

	copyButton := renderWithChildren(t, FactCopyButton("node-id", "Copy node ID"), "")
	tests := []struct {
		name     string
		props    FactProps
		children string
		want     string
	}{
		{
			name:  "plain",
			props: FactProps{Label: "Role", Value: "Primary"},
			want:  `<div><dt>Role</dt><dd>Primary</dd></div>`,
		},
		{
			name:  "wide tile with a value hook",
			props: FactProps{Label: "Timestamp", Value: "—", Wide: true, ValueAttrs: templ.Attributes{"data-query-detail-value": "time"}},
			want:  `<div class="fact-wide"><dt>Timestamp</dt><dd data-query-detail-value="time">—</dd></div>`,
		},
		{
			name:  "full tile wins over wide",
			props: FactProps{Label: "Maker", Value: "Raspberry Pi", Wide: true, Full: true},
			want:  `<div class="fact-full"><dt>Maker</dt><dd>Raspberry Pi</dd></div>`,
		},
		{
			name:     "copyable value with a note",
			props:    FactProps{Label: "Node ID", Value: "abc", Full: true, CopyID: "node-id", CopyLabel: "Copy node ID"},
			children: `<small>Note</small>`,
			want:     `<div class="fact-full fact-copyable"><dt>Node ID</dt><dd><code id="node-id">abc</code>` + copyButton + `<small>Note</small></dd></div>`,
		},
		{
			name:     "markup value and classes",
			props:    FactProps{Label: "Commit", Class: "build-row", ValueClass: "build-commit"},
			children: `<code>abc</code>`,
			want:     `<div class="build-row"><dt>Commit</dt><dd class="build-commit"><code>abc</code></dd></div>`,
		},
	}
	for _, test := range tests {
		if got := renderWithChildren(t, Fact(test.props), test.children); got != test.want {
			t.Errorf("%s:\ngot  %s\nwant %s", test.name, got, test.want)
		}
	}
}
