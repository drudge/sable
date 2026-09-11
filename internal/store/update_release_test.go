package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/drudge/sable/internal/update"
)

func TestUpdateReleaseSurvivesDatabaseReopen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sable.db")
	database, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if empty, err := database.LoadUpdateRelease(ctx); err != nil || empty != (update.ReleaseInfo{}) {
		t.Fatalf("initial cache = %+v, %v", empty, err)
	}
	want := update.ReleaseInfo{Repository: "drudge/sable", APIBaseURL: "https://api.github.com", Version: "1.0.2", URL: "https://github.com/drudge/sable/releases/tag/v1.0.2", Notes: "### Improvements\n\n- Reliable updates.", CheckedAt: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)}
	if err := database.SaveUpdateRelease(ctx, want); err != nil {
		t.Fatal(err)
	}
	want.Notes += "\n- Release notes survive restarts."
	if err := database.SaveUpdateRelease(ctx, want); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.LoadUpdateRelease(ctx)
	if err != nil || got != want {
		t.Fatalf("restored release = %+v, %v; want %+v", got, err, want)
	}
}
