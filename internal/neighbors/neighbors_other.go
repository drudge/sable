//go:build !linux && !darwin

package neighbors

func read() ([]Entry, error) { return nil, ErrUnsupported }
