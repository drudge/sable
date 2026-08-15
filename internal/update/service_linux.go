//go:build linux

package update

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/drudge/sable/internal/install"
)

// restartService restarts the installed Sable service so that the replacement
// executable takes effect. It reports whether the service was restarted and
// whether a Sable service is installed at all.
func restartService(ctx context.Context, output io.Writer) (bool, bool, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, false, nil
	}
	if _, err := os.Stat(install.ServiceUnitPath); err != nil {
		return false, false, nil
	}
	if err := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", install.ServiceName).Run(); err != nil {
		return false, true, nil
	}
	fmt.Fprintf(output, "Restarting %s...\n", install.ServiceName)
	command := exec.CommandContext(ctx, "systemctl", "restart", install.ServiceName)
	command.Stdout = output
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return false, true, fmt.Errorf("restart Sable service: %w", err)
	}
	return true, true, nil
}
