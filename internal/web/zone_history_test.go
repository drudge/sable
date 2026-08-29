package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/web/pages"
	zonemodel "github.com/drudge/sable/internal/zone"
)

type zoneHistoryListStore struct {
	snapshot  zonemodel.Snapshot
	histories map[string][]zonemodel.Revision
	listed    []string
}

func (store *zoneHistoryListStore) Current() zonemodel.Snapshot {
	return store.snapshot
}

func (store *zoneHistoryListStore) ListZoneRevisions(_ context.Context, name string, _ int) ([]zonemodel.Revision, error) {
	store.listed = append(store.listed, name)
	return store.histories[name], nil
}

func (*zoneHistoryListStore) ZoneRevision(context.Context, string, uint64) (zonemodel.Revision, error) {
	return zonemodel.Revision{}, zonemodel.ErrRevisionNotFound
}

func (*zoneHistoryListStore) PreviousZoneRevision(context.Context, string, uint64) (zonemodel.Revision, error) {
	return zonemodel.Revision{}, zonemodel.ErrRevisionNotFound
}

func TestZonesListLoadsHistoryForEveryZoneMenu(t *testing.T) {
	t.Parallel()
	store := &zoneHistoryListStore{
		snapshot: zonemodel.Snapshot{Zones: []zonemodel.Zone{
			{ID: "zone-one", Name: "one.test", Type: "primary", Revision: 2},
			{ID: "zone-two", Name: "two.test", Type: "primary", Revision: 1},
		}},
		histories: map[string][]zonemodel.Revision{
			"one.test": {{ZoneName: "one.test", Number: 2, ChangeKind: "updated", CreatedAt: time.Now()}},
			"two.test": {{ZoneName: "two.test", Number: 1, ChangeKind: "created", CreatedAt: time.Now()}},
		},
	}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		testConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}},
		store,
		"sqlite",
		testQueryLog{},
		testQueryLog{},
		func(context.Context) error { return nil },
		nil,
		false,
		false,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}

	response := serveRequest(server, http.MethodGet, "/zones")
	if response.Code != http.StatusOK {
		t.Fatalf("zones page status = %d", response.Code)
	}
	markup := response.Body.String()
	for _, expected := range []string{
		`data-dialog-open="zone-history-0"`, `id="zone-history-0"`,
		`data-dialog-open="zone-history-1"`, `id="zone-history-1"`,
	} {
		if !strings.Contains(markup, expected) {
			t.Errorf("zones page does not contain %q", expected)
		}
	}
	if strings.Join(store.listed, ",") != "one.test,two.test" {
		t.Fatalf("history loaded for %q, want both listed zones", store.listed)
	}
}

func TestDiffZoneRevisionReportsSettingsAndRecordChanges(t *testing.T) {
	t.Parallel()
	previous := zonemodel.Zone{
		DefaultTTL: 300,
		Records: []zonemodel.Record{
			{Name: "www", Type: "A", Value: "192.0.2.10", TTL: 300},
			{Name: "mail", Type: "CNAME", Value: "old.example.test.", TTL: 300},
			{Name: "old", Type: "TXT", Value: `"retired"`, TTL: 300},
		},
	}
	current := zonemodel.Zone{
		DefaultTTL: 600,
		Records: []zonemodel.Record{
			{Name: "www", Type: "A", Value: "192.0.2.10", TTL: 600},
			{Name: "mail", Type: "CNAME", Value: "new.example.test.", TTL: 300},
			{Name: "api", Type: "AAAA", Value: "2001:db8::10", TTL: 300},
		},
	}

	changes, hidden, summary := diffZoneRevision(zonemodel.Revision{ChangeKind: "updated", Zone: current}, previous)
	if hidden != 0 || summary != "1 added · 1 removed · 3 changed" {
		t.Fatalf("diff summary = %q, hidden=%d, changes=%+v", summary, hidden, changes)
	}
	for _, expected := range []string{"Default TTL", "A www → 192.0.2.10", "CNAME mail", "AAAA api → 2001:db8::10", `TXT old → "retired"`} {
		if !containsZoneChange(changes, expected) {
			t.Errorf("diff does not contain %q: %+v", expected, changes)
		}
	}
}

func TestRestoreZoneRevisionPreservesIdentityAndAdvancesSOA(t *testing.T) {
	t.Parallel()
	current := zonemodel.Zone{
		ID: "zone-current", Name: "example.test", Revision: 3, DefaultTTL: 300,
		Records: []zonemodel.Record{{Name: "@", Type: "SOA", Value: "ns1.example.test. hostmaster.example.test. 2026082805 3600 600 1209600 300", TTL: 300}},
	}
	target := zonemodel.Revision{
		Number: 1, ChangeKind: "created",
		Zone: zonemodel.Zone{
			ID: "zone-current", Name: "example.test", Revision: 1, DefaultTTL: 900,
			Records: []zonemodel.Record{{Name: "@", Type: "SOA", Value: "ns1.example.test. hostmaster.example.test. 2026082701 3600 600 1209600 300", TTL: 900}},
		},
	}
	zones := []zonemodel.Zone{current}
	if err := restoreZoneRevision(&zones, "example.test", target, time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if zones[0].ID != "zone-current" || zones[0].Name != "example.test" || zones[0].Revision != 3 || zones[0].DefaultTTL != 900 {
		t.Fatalf("restored zone identity/settings = %+v", zones[0])
	}
	if serial := zoneRecordSOASerial(zones[0].Records[0].Value); serial != 2026082806 {
		t.Fatalf("restored SOA serial = %d, want 2026082806", serial)
	}
}

func TestRestoreZoneRevisionRejectsEarlierZoneIdentity(t *testing.T) {
	t.Parallel()
	zones := []zonemodel.Zone{{ID: "new-zone", Name: "example.test", Revision: 5}}
	err := restoreZoneRevision(&zones, "example.test", zonemodel.Revision{
		Number: 2, ChangeKind: "updated", Zone: zonemodel.Zone{ID: "deleted-zone", Name: "example.test"},
	}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "earlier zone") {
		t.Fatalf("restore error = %v", err)
	}
	if zones[0].ID != "new-zone" || zones[0].Revision != 5 {
		t.Fatalf("rejected restore changed zone: %+v", zones[0])
	}
}

func containsZoneChange(changes []pages.ZoneRevisionChangeView, label string) bool {
	for _, change := range changes {
		if change.Label == label {
			return true
		}
	}
	return false
}
