package web

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/auth"
	zonemodel "github.com/drudge/sable/internal/zone"
)

type authorizedHistoryStore struct {
	zoneHistoryListStore
	target, previous zonemodel.Revision
}

func (store *authorizedHistoryStore) ZoneRevision(context.Context, string, uint64) (zonemodel.Revision, error) {
	return store.target, nil
}

func (store *authorizedHistoryStore) PreviousZoneRevision(context.Context, string, uint64) (zonemodel.Revision, error) {
	return store.previous, nil
}

func TestZoneHistoryAuthorizesBothSnapshotIdentities(t *testing.T) {
	for _, test := range []struct {
		name, targetID, previousID, grantID string
		status                              int
		disclosed                           bool
	}{
		{"recreated zone", "old-zone", "old-zone", "new-zone", 403, false},
		{"legacy zone", "", "", "new-zone", 403, false},
		{"prior identity", "new-zone", "old-zone", "new-zone", 200, false},
		{"legacy prior identity", "new-zone", "", "new-zone", 200, false},
		{"current identity", "new-zone", "new-zone", "new-zone", 200, true},
		{"global reader", "old-zone", "old-zone", auth.ResourceAll, 200, true},
		{"global legacy reader", "", "", auth.ResourceAll, 200, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &authorizedHistoryStore{
				zoneHistoryListStore: zoneHistoryListStore{snapshot: zonemodel.Snapshot{Zones: []zonemodel.Zone{{ID: "new-zone", Name: "example.test", Revision: 4}}}},
				target:               zonemodel.Revision{Number: 2, ChangeKind: "updated", Zone: zonemodel.Zone{ID: test.targetID}},
				previous: zonemodel.Revision{Number: 1, Zone: zonemodel.Zone{ID: test.previousID, Records: []zonemodel.Record{
					{Name: "private", Type: "TXT", Value: "previous-owner-data", TTL: 300},
				}}},
			}
			server := &Server{securityEnabled: true, zones: store}
			request := httptest.NewRequest("GET", "/ui/zones/history/diff?zone=example.test&revision=2", nil)
			request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, auth.Principal{
				Surface: auth.SurfaceWeb, Grants: []auth.Grant{{Permission: auth.PermissionZonesRead, Surface: auth.SurfaceWeb, ResourceType: auth.ResourceZone, ResourceID: test.grantID}},
			}))
			response := httptest.NewRecorder()
			server.zoneRevisionDiff(response, request)
			if response.Code != test.status || strings.Contains(response.Body.String(), "previous-owner-data") != test.disclosed {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestZoneHistoryFiltersMetadataForScopedReaders(t *testing.T) {
	server := &Server{securityEnabled: true}
	revisions := []zonemodel.Revision{{ZoneID: "new-zone", Number: 3}, {ZoneID: "old-zone", Number: 2}, {Number: 1}}
	for _, grant := range []string{"new-zone", auth.ResourceAll} {
		request := httptest.NewRequest("GET", "/zones", nil)
		request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, auth.Principal{
			Surface: auth.SurfaceWeb, Grants: []auth.Grant{{Permission: auth.PermissionZonesRead, Surface: auth.SurfaceWeb, ResourceType: auth.ResourceZone, ResourceID: grant}},
		}))
		filtered := server.readableZoneRevisions(request, revisions)
		want := 1
		if grant == auth.ResourceAll {
			want = len(revisions)
		}
		if len(filtered) != want || filtered[0].Number != 3 {
			t.Fatalf("grant=%s revisions=%+v", grant, filtered)
		}
	}
}
