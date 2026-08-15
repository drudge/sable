//go:build !linux

package install

import (
	"context"
	"errors"
)

func SystemService(context.Context, Options) (Result, error) {
	return Result{}, errors.New("system service installation is supported only on Linux")
}
