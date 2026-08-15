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
