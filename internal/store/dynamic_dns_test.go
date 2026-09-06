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
