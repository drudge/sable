package main

import (
	"path/filepath"
	"time"

	"github.com/drudge/sable/internal/updatefeed"
)

const updateDemoNotes = `## Update demonstration

These are local demonstration builds of the current source, labeled 1.0.1 and 1.0.2. They are not the published GitHub binaries.

### What's new
- Check for updates automatically after sign-in, with an option to turn checks off.
- Read release notes directly in the console and follow version links to GitHub.
- Update replicas one at a time, verify synchronization, and restart the primary last.

### Try it
Open **Cluster**, choose **Update all**, and watch the rollout. The terminal probes DNS throughout the update.

This feed uses curated release notes; merge commits and raw commit lists are excluded.
`

// startUpdateDemoFeed offers target as the demo's next release. A short
// download delay makes each installation visible in the console.
func startUpdateDemoFeed(workspace, target string) (*updatefeed.Feed, error) {
	return updatefeed.Start(updatefeed.Release{
		Version: updateDemoTarget, Binary: target, Directory: filepath.Join(workspace, "build"),
		Notes: updateDemoNotes, DownloadDelay: 3 * time.Second,
	})
}
