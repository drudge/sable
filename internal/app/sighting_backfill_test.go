package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestBackfillClientSightingsReportsWhatHappened(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		filled bool
		err    error
		want   string
	}{
		{"filled", true, nil, "filled device history"},
		{"nothing to fill", false, nil, ""},
		{"failed", false, errors.New("disk full"), "disk full"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			backfillClientSightings(context.Background(), func(context.Context) (bool, error) { return test.filled, test.err }, logger)
			if test.want == "" && logs.Len() != 0 || test.want != "" && !strings.Contains(logs.String(), test.want) {
				t.Fatalf("logs = %q, want %q", logs.String(), test.want)
			}
		})
	}
}
