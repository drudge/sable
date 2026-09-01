package serverlog

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLevelHandlerAppliesRuntimeLevelChanges(t *testing.T) {
	var output bytes.Buffer
	var level slog.LevelVar
	level.Set(slog.LevelInfo)
	downstream := slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(NewLevelHandler(downstream, &level))

	logger.Debug("hidden debug")
	logger.Info("visible info")
	level.Set(slog.LevelDebug)
	logger.Debug("visible debug")

	logged := output.String()
	if strings.Contains(logged, "hidden debug") {
		t.Fatalf("output includes debug entry below the active level: %s", logged)
	}
	for _, message := range []string{"visible info", "visible debug"} {
		if !strings.Contains(logged, message) {
			t.Fatalf("output does not include %q after level update: %s", message, logged)
		}
	}
}
