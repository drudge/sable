package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestZoneRefreshesPersistAcrossOpen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sable.db")
	opened, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := opened.LoadZoneRefreshes(ctx)
	if err != nil || len(empty) != 0 {
		opened.Close()
		t.Fatalf("fresh refreshes = %v, %v", empty, err)
	}
	want := map[string]ZoneRefresh{
		"secondary.test": {Serial: 7, RefreshedAt: time.Date(2026, time.November, 7, 9, 0, 0, 0, time.UTC)},
	}
	if err := opened.SaveZoneRefreshes(ctx, want); err != nil {
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
	got, err := reopened.LoadZoneRefreshes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["secondary.test"].Serial != 7 || !got["secondary.test"].RefreshedAt.Equal(want["secondary.test"].RefreshedAt) {
		t.Fatalf("refreshes = %+v, want %+v", got, want)
	}
}
