package zone

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDurationJSONSupportsFixedUnits(t *testing.T) {
	t.Parallel()

	var duration Duration
	if err := json.Unmarshal([]byte(`"1mo2d"`), &duration); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if want := 32 * 24 * time.Hour; duration.Duration != want {
		t.Fatalf("Duration = %s, want %s", duration.Duration, want)
	}
	encoded, err := json.Marshal(duration)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if string(encoded) != `"1mo2d"` {
		t.Fatalf("Marshal() = %s, want friendly fixed units", encoded)
	}
}
