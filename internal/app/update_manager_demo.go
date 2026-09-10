//go:build updatedemo

package app

import (
	"net/url"
	"os"

	"github.com/drudge/sable/internal/update"
)

// Only explicitly tagged demo builds accept the disposable loopback release
// feed. Normal binaries always use the published GitHub releases.
func newUpdateManager(options update.Options) *update.Manager {
	options.APIBaseURL = "http://127.0.0.1:1"
	endpoint := os.Getenv("SABLE_DEMO_RELEASE_API")
	if parsed, err := url.Parse(endpoint); err == nil && parsed.Scheme == "http" && parsed.Hostname() == "127.0.0.1" && parsed.Port() != "" {
		options.APIBaseURL = endpoint
	}
	return update.NewManager(options)
}
