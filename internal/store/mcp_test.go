package store

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestMCPUseRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	opened, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	if use, err := opened.LoadMCPUse(ctx); err != nil || !use.At.IsZero() {
		t.Fatalf("fresh use = %+v, %v", use, err)
	}
	first := MCPUse{At: time.Date(2026, 9, 27, 9, 14, 0, 0, time.UTC), Username: "nick", Client: "claude-code", Tool: "set_records"}
	second := MCPUse{At: first.At.Add(time.Minute), Username: "nick", Client: "codex", Tool: "lookup",
		Calls: []MCPCallCount{{Start: first.At, Calls: 2}}}
	for _, use := range []MCPUse{first, second} {
		if err := opened.SaveMCPUse(ctx, use); err != nil {
			t.Fatal(err)
		}
	}
	if use, err := opened.LoadMCPUse(ctx); err != nil || !reflect.DeepEqual(use, second) {
		t.Fatalf("loaded use = %+v, %v, want %+v", use, err, second)
	}
}

func TestMCPUseCountsCallsByQuarterHour(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 9, 27, 9, 0, 0, 0, time.UTC)
	var use MCPUse
	use.RecordCall(start.Add(-49*time.Hour), "nick", "codex", "lookup")
	use.RecordCall(start.Add(-2*time.Hour), "nick", "codex", "lookup")
	use.RecordCall(start.Add(time.Minute), "nick", "claude-code", "list_zones")
	use.RecordCall(start.Add(14*time.Minute), "nick", "claude-code", "set_records")
	use.RecordCall(start.Add(20*time.Minute), "deploy", "cursor", "add_record")

	if use.Tool != "add_record" || use.Username != "deploy" || !use.At.Equal(start.Add(20*time.Minute)) {
		t.Fatalf("last call = %+v", use)
	}
	// The call from 49 hours ago is past the two-day window and was dropped.
	if len(use.Calls) != 3 || use.Calls[1].Calls != 2 {
		t.Fatalf("buckets = %+v", use.Calls)
	}
	if got := use.CallsSince(start.Add(-3 * time.Hour)); got != 4 {
		t.Fatalf("calls in last 3 hours = %d, want 4", got)
	}
	if got := use.CallsSince(start.Add(15 * time.Minute)); got != 1 {
		t.Fatalf("calls since 9:15 = %d, want 1", got)
	}
}
