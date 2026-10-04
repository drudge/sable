package components

import (
	"testing"

	"github.com/a-h/templ"
)

func TestDataTableRendersHeadingsAndRows(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		props DataTableProps
		want  string
	}{
		{
			name:  "plain columns",
			props: DataTableProps{Caption: "Users", Columns: []DataTableColumn{{Label: "Username"}, {Label: "Groups"}}},
			want: `<div class="admin-desktop-table"><table class="isotope-table"><caption class="sr-only">Users</caption>` +
				`<thead><tr><th scope="col">Username</th><th scope="col">Groups</th></tr></thead>` +
				`<tbody><tr><td>row</td></tr></tbody></table></div>`,
		},
		{
			name: "classes, hidden label, and wrapper attributes",
			props: DataTableProps{
				Caption: "Devices",
				Class:   "insight-entity-table",
				Columns: []DataTableColumn{{Label: "Queries", Class: "right-cell"}, {Label: "Details", Hidden: true}},
				Attrs:   templ.Attributes{"data-list-results": true},
			},
			want: `<div class="admin-desktop-table" data-list-results><table class="isotope-table insight-entity-table"><caption class="sr-only">Devices</caption>` +
				`<thead><tr><th scope="col" class="right-cell">Queries</th><th scope="col"><span class="sr-only">Details</span></th></tr></thead>` +
				`<tbody><tr><td>row</td></tr></tbody></table></div>`,
		},
	}
	for _, test := range tests {
		if got := renderWithChildren(t, DataTable(test.props), `<tr><td>row</td></tr>`); got != test.want {
			t.Errorf("%s:\ngot  %s\nwant %s", test.name, got, test.want)
		}
	}
}
