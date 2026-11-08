package updatefeed

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// BuildOptions describes one labeled Sable build.
type BuildOptions struct {
	Output  string    // path of the binary to write
	Release string    // version.Release, like 1.0.2
	Commit  string    // version.Commit
	Tags    string    // comma-separated build tags
	Log     io.Writer // receives the go build output
}

// Build builds cmd/sable as options describe, from anywhere in the module.
func Build(ctx context.Context, options BuildOptions) error {
	if err := os.MkdirAll(filepath.Dir(options.Output), 0o755); err != nil {
		return err
	}
	flags := "-s -w -X github.com/drudge/sable/internal/version.Release=" + options.Release +
		" -X github.com/drudge/sable/internal/version.Commit=" + options.Commit +
		" -X github.com/drudge/sable/internal/version.BuiltAt=" + time.Now().UTC().Format(time.RFC3339)
	command := exec.CommandContext(ctx, "go", "build", "-tags", options.Tags, "-trimpath", "-ldflags", flags, "-o", options.Output, "github.com/drudge/sable/cmd/sable")
	command.Stdout, command.Stderr = options.Log, options.Log
	if err := command.Run(); err != nil {
		return fmt.Errorf("build %s: %w", options.Release, err)
	}
	return nil
}
