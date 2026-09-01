package durationfmt

import (
	"testing"
	"time"
)

func TestParseSupportsFixedAndStandardUnits(t *testing.T) {
	t.Parallel()

	tests := map[string]time.Duration{
		"30d":            30 * Day,
		"2w3d":           17 * Day,
		"1mo":            Month,
		"1y6mo2w3d4h30m": Year + 6*Month + 17*Day + 4*time.Hour + 30*time.Minute,
		"1.5d":           36 * time.Hour,
		"-2d12h":         -(2*Day + 12*time.Hour),
		"750ms":          750 * time.Millisecond,
		" 24h ":          Day,
	}
	for value, want := range tests {
		value, want := value, want
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			got, err := Parse(value)
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", value, err)
			}
			if got != want {
				t.Fatalf("Parse(%q) = %s, want %s", value, got, want)
			}
		})
	}
}

func TestParseRejectsInvalidAndOverflowingDurations(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "d", "1month", "1d-2h", "1e3d", "999y"} {
		if parsed, err := Parse(value); err == nil {
			t.Fatalf("Parse(%q) = %s, want error", value, parsed)
		}
	}
}

func TestFormatUsesFriendlyFixedUnits(t *testing.T) {
	t.Parallel()

	tests := map[time.Duration]string{
		0:         "0s",
		30 * Day:  "1mo",
		400 * Day: "1y1mo5d",
		Year + 6*Month + 2*Week + 3*Day + 4*time.Hour: "1y6mo2w3d4h0m0s",
		-36 * time.Hour:        "-1d12h0m0s",
		750 * time.Millisecond: "750ms",
	}
	for value, want := range tests {
		if got := Format(value); got != want {
			t.Fatalf("Format(%s) = %q, want %q", value, got, want)
		}
	}
}

func TestFormatRoundTrips(t *testing.T) {
	t.Parallel()

	for _, value := range []time.Duration{
		time.Nanosecond,
		36 * time.Hour,
		400*Day + 45*time.Minute,
		-time.Duration(1<<63 - 1),
	} {
		formatted := Format(value)
		parsed, err := Parse(formatted)
		if err != nil {
			t.Fatalf("Parse(Format(%s)) error = %v", value, err)
		}
		if parsed != value {
			t.Fatalf("Parse(Format(%s)) = %s from %q", value, parsed, formatted)
		}
	}
}
