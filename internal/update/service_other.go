//go:build !linux

package update

import (
	"context"
	"io"
)

// restartService is a no-op on platforms where Sable does not manage a service.
func restartService(context.Context, io.Writer) (bool, bool, error) {
	return false, false, nil
}

// ServiceManaged reports whether an installed Sable service starts the server
// again after it exits. Sable only installs a service on Linux.
func ServiceManaged() bool { return false }
