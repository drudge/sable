package pages

import (
	"strings"
	"testing"
)

func TestZoneHistoryDialogLazyLoadsRevisionDiffs(t *testing.T) {
	t.Parallel()
	markup := renderComponent(t, ZoneHistoryDialog(ZoneView{
		Name: "example.test",
		History: []ZoneRevisionView{
			{Number: 3, Kind: "updated", KindLabel: "Updated", OccurredAt: "Aug 28, 2026 14:00 EDT", Current: true},
			{Number: 2, Kind: "created", KindLabel: "Created", OccurredAt: "Aug 28, 2026 13:00 EDT"},
		},
	}, "zone-history-dialog"))
	for _, expected := range []string{
		"Change Center", "Revision 3", "Current", `hx-trigger="toggle once"`,
		`/ui/zones/history/diff?zone=example.test&amp;revision=2`, `id="zone-history-dialog-revision-3"`,
	} {
		if !strings.Contains(markup, expected) {
			t.Errorf("history dialog does not contain %q: %s", expected, markup)
		}
	}
}

func TestZoneHistoryLivesInListActionMenu(t *testing.T) {
	t.Parallel()
	markup := renderComponent(t, ZoneListView(ZonesPageView{Zones: []ZoneView{
		{Name: "one.test", History: []ZoneRevisionView{{Number: 1, Current: true}}},
		{Name: "two.test", History: []ZoneRevisionView{{Number: 1, Current: true}}},
	}}))
	for _, expected := range []string{
		`data-dialog-open="zone-history-0"`, `id="zone-history-0"`, `id="zone-history-0-revision-1"`,
		`data-dialog-open="zone-history-1"`, `id="zone-history-1"`, `id="zone-history-1-revision-1"`,
	} {
		if !strings.Contains(markup, expected) {
			t.Errorf("zones list does not contain %q: %s", expected, markup)
		}
	}
}

func TestZoneHistoryLivesInDetailActionMenu(t *testing.T) {
	t.Parallel()
	markup := renderComponent(t, ZoneActionMenu(ZoneView{
		Name:    "example.test",
		History: []ZoneRevisionView{{Number: 1, Current: true}},
	}, "detail-menu", "zone-history-dialog", "settings-dialog", "dnssec-dialog", "clone-dialog", "delete-dialog"))
	for _, expected := range []string{`data-dialog-open="zone-history-dialog"`, `icon-clock`, ">History<"} {
		if !strings.Contains(markup, expected) {
			t.Errorf("zone action menu does not contain %q: %s", expected, markup)
		}
	}
}

func TestZoneRevisionDiffOffersReversibleRestore(t *testing.T) {
	t.Parallel()
	markup := renderComponent(t, ZoneRevisionDiff(ZoneRevisionDiffView{
		ZoneName: "example.test", Revision: 2, Summary: "1 added · 1 changed", CanRollback: true,
		Changes: []ZoneRevisionChangeView{
			{Kind: "added", Label: "A www → 192.0.2.10", After: "TTL 300s"},
			{Kind: "changed", Label: "Default TTL", Before: "300s", After: "600s"},
		},
	}))
	for _, expected := range []string{
		"1 added · 1 changed", "A www → 192.0.2.10", "Before", "600s",
		`hx-post="/ui/zones/rollback"`, `name="revision" value="2"`, `icon-rotate-ccw`, "save the restored state as a new revision",
	} {
		if !strings.Contains(markup, expected) {
			t.Errorf("revision diff does not contain %q: %s", expected, markup)
		}
	}
	if restore, changes := strings.Index(markup, `hx-post="/ui/zones/rollback"`), strings.Index(markup, `class="zone-history-changes"`); restore < 0 || changes < 0 || restore > changes {
		t.Errorf("restore action should appear before the revision changes: %s", markup)
	}
}
