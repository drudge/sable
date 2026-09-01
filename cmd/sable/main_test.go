package main

import (
	"testing"
	"time"
)

func TestDurationFlagSupportsFixedUnits(t *testing.T) {
	t.Parallel()

	value := durationFlag(3 * time.Second)
	if err := value.Set("2w3d"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if want := durationFlag(17 * 24 * time.Hour); value != want {
		t.Fatalf("duration flag = %s, want %s", value.String(), want.String())
	}
}
