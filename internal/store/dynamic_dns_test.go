package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/drudge/sable/internal/dynamicdns"
)

func TestDynamicDNSStatePersistsAcrossOpen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sable.db")
	opened, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	want := dynamicdns.PersistentState{
		IPv4:          "8.8.8.8",
		IPv6:          "2001:4860:4860::8888",
		LastSuccess:   time.Date(2026, time.September, 5, 18, 4, 0, 0, time.UTC),
		LastPublished: time.Date(2026, time.September, 5, 18, 3, 0, 0, time.UTC),
		PreviousIPv4:  "8.8.4.4",
		PreviousIPv6:  "2001:4860:4860::8844",
		IPv4ChangedAt: time.Date(2026, time.September, 5, 18, 3, 0, 0, time.UTC),
		IPv6ChangedAt: time.Date(2026, time.September, 4, 7, 30, 0, 0, time.UTC),
	}
	if err := opened.SaveDynamicDNSState(ctx, want); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.LoadDynamicDNSState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("LoadDynamicDNSState() = %+v, want %+v", got, want)
	}
}

// An upgrade must keep reading the row an older release wrote, which has no
// address history.
func TestDynamicDNSStateLoadsEveryShapeItWasSavedIn(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		saved string
		want  dynamicdns.PersistentState
	}{
		{
			name:  "an older release without address history",
			saved: `{"ipv4":"8.8.8.8","ipv6":"2001:4860:4860::8888","last_success":"2026-09-05T18:04:00Z","last_published":"0001-01-01T00:00:00Z"}`,
			want: dynamicdns.PersistentState{
				IPv4: "8.8.8.8", IPv6: "2001:4860:4860::8888",
				LastSuccess: time.Date(2026, time.September, 5, 18, 4, 0, 0, time.UTC),
			},
		},
		{
			name: "this release with a changed IPv4 address",
			saved: `{"ipv4":"8.8.8.8","last_success":"2026-09-05T18:04:00Z","last_published":"2026-09-05T18:04:00Z",` +
				`"previous_ipv4":"8.8.4.4","ipv4_changed_at":"2026-09-05T18:04:00Z"}`,
			want: dynamicdns.PersistentState{
				IPv4: "8.8.8.8", PreviousIPv4: "8.8.4.4",
				LastSuccess:   time.Date(2026, time.September, 5, 18, 4, 0, 0, time.UTC),
				LastPublished: time.Date(2026, time.September, 5, 18, 4, 0, 0, time.UTC),
				IPv4ChangedAt: time.Date(2026, time.September, 5, 18, 4, 0, 0, time.UTC),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			opened, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "sable.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			if _, err := opened.database.ExecContext(ctx,
				"INSERT INTO sable_metadata (key, value) VALUES ("+opened.placeholders(2)+")",
				dynamicDNSStateMetadataKey, test.saved,
			); err != nil {
				t.Fatal(err)
			}
			got, err := opened.LoadDynamicDNSState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("LoadDynamicDNSState() = %+v, want %+v", got, test.want)
			}
		})
	}
}
