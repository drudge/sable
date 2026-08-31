package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/drudge/sable/internal/update"
	"github.com/drudge/sable/internal/version"
	"golang.org/x/mod/semver"
)

const (
	containerWebUpdatesEnvironment = "SABLE_WEB_UPDATES"
	containerUpdateBinaryPath      = "/data/.sable/bin/sable"
	containerVersionTimeout        = 3 * time.Second
	maximumVersionOutputBytes      = 1024
)

// containerCommand is the image's immutable entrypoint. Web updates are
// opt-in: when enabled, the release installer stages a newer executable in the
// data volume. On the next container restart this launcher selects that build
// only when it is newer than the one shipped in the image.
func containerCommand(arguments []string) error {
	enabled, err := containerWebUpdatesEnabled(os.Getenv(containerWebUpdatesEnvironment))
	if err != nil {
		return err
	}
	if !enabled {
		return run(arguments)
	}
	if err := os.MkdirAll(filepath.Dir(containerUpdateBinaryPath), 0o700); err != nil {
		return fmt.Errorf("prepare the container web-update directory: %w", err)
	}
	if err := os.Setenv(update.BinaryPathEnvironment, containerUpdateBinaryPath); err != nil {
		return fmt.Errorf("configure the container update path: %w", err)
	}
	candidateRelease, err := executableRelease(containerUpdateBinaryPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// The image build handles the first run. A console update creates the
		// persistent executable before requesting a controlled restart.
	case err != nil:
		fmt.Fprintf(os.Stderr, "sable: ignoring the staged container executable: %v\n", err)
	case preferMutableRelease(version.Current().Release, candidateRelease):
		return execContainerBinary(containerUpdateBinaryPath, arguments, os.Environ())
	}
	return run(arguments)
}

func containerWebUpdatesEnabled(value string) (bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, nil
	}
	enabled, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", containerWebUpdatesEnvironment)
	}
	return enabled, nil
}

func executableRelease(path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), containerVersionTimeout)
	defer cancel()
	output := cappedBuffer{limit: maximumVersionOutputBytes}
	command := exec.CommandContext(ctx, path, "version", "--short")
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("inspect %s: %w", path, err)
	}
	release := strings.TrimSpace(output.String())
	if comparableRelease(release) == "" {
		return "", fmt.Errorf("inspect %s: invalid release %q", path, release)
	}
	return release, nil
}

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (buffer *cappedBuffer) Write(contents []byte) (int, error) {
	written := len(contents)
	remaining := max(0, buffer.limit-buffer.Len())
	if remaining > 0 {
		_, _ = buffer.Buffer.Write(contents[:min(len(contents), remaining)])
	}
	return written, nil
}

func preferMutableRelease(imageRelease, mutableRelease string) bool {
	image := comparableRelease(imageRelease)
	mutable := comparableRelease(mutableRelease)
	return mutable != "" && (image == "" || semver.Compare(mutable, image) > 0)
}

func comparableRelease(release string) string {
	release = strings.TrimSpace(release)
	if release == "" {
		return ""
	}
	if !strings.HasPrefix(release, "v") {
		release = "v" + release
	}
	if !semver.IsValid(release) {
		return ""
	}
	return release
}
