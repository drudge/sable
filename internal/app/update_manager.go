//go:build !updatedemo

package app

import "github.com/drudge/sable/internal/update"

func newUpdateManager(options update.Options) *update.Manager {
	return update.NewManager(options)
}
