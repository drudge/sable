//go:build !faultinject

package faultinject

import (
	"testing"
	"time"
)

func TestDefaultBuildHasNoFaults(t *testing.T) {
	t.Setenv(ControlEnv, "/nonexistent/faults.json")
	if Enabled {
		t.Fatal("Enabled = true in a build without the faultinject tag")
	}
	before := time.Now()
	now := Now()
	if now.Before(before) || now.Sub(before) > time.Second {
		t.Fatalf("Now() = %v, want close to %v", now, before)
	}
	if err := CheckWrite("write"); err != nil {
		t.Fatalf("CheckWrite() = %v, want nil", err)
	}
	if name := SQLDriver("sqlite"); name != "sqlite" {
		t.Fatalf("SQLDriver(sqlite) = %q, want sqlite", name)
	}
}

func TestDefaultBuildHooksDoNotAllocate(t *testing.T) {
	allocations := testing.AllocsPerRun(100, func() {
		_ = Now()
		_ = CheckWrite("write")
	})
	if allocations != 0 {
		t.Fatalf("hooks allocate %v times per call, want 0", allocations)
	}
}
