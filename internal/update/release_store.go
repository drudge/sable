package update

import (
	"context"
	"time"

	"golang.org/x/mod/semver"
)

// ReleaseStore keeps the last successful release lookup local to this node.
type ReleaseStore interface {
	LoadUpdateRelease(context.Context) (ReleaseInfo, error)
	SaveUpdateRelease(context.Context, ReleaseInfo) error
}

// ReleaseInfo contains display metadata only. Installation progress, restart
// requests, reservations, and errors must never be restored from this cache.
type ReleaseInfo struct {
	Repository        string    `json:"repository"`
	APIBaseURL        string    `json:"api_base_url"`
	Version           string    `json:"version"`
	URL               string    `json:"url"`
	Notes             string    `json:"notes"`
	PreRelease        bool      `json:"pre_release"`
	IncludePreRelease bool      `json:"include_pre_release"`
	CheckedAt         time.Time `json:"checked_at"`
}

func (manager *Manager) restoreRelease() {
	if manager.options.ReleaseStore == nil || manager.status.Development {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release, err := manager.options.ReleaseStore.LoadUpdateRelease(ctx)
	if err != nil {
		manager.options.Logger.Warn("restore update release notes", "error", err)
		return
	}
	if release.Repository != manager.options.Repository || release.APIBaseURL != manager.options.APIBaseURL ||
		release.IncludePreRelease != manager.options.PreRelease || release.CheckedAt.IsZero() || !semver.IsValid(normalizeTag(release.Version)) {
		return
	}
	status := &manager.status
	status.LatestVersion, status.ReleaseURL, status.ReleaseNotes = release.Version, release.URL, release.Notes
	status.PreRelease, status.CheckedAt = release.PreRelease, release.CheckedAt
	status.Available = isNewer(release.Version, status.CurrentVersion)
	if status.Available {
		status.Blocked = blockedReason(Installable(manager.options.BinaryPath))
	}
}

func (manager *Manager) saveRelease() {
	if manager.options.ReleaseStore == nil {
		return
	}
	status := manager.status
	release := ReleaseInfo{
		Repository: manager.options.Repository, APIBaseURL: manager.options.APIBaseURL,
		Version: status.LatestVersion, URL: status.ReleaseURL, Notes: status.ReleaseNotes,
		PreRelease: status.PreRelease, IncludePreRelease: status.IncludePreRelease, CheckedAt: status.CheckedAt,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := manager.options.ReleaseStore.SaveUpdateRelease(ctx, release); err != nil {
		// A cache failure must not turn a successful binary replacement into a
		// failed installation or prevent its controlled restart.
		manager.options.Logger.Warn("save update release notes", "error", err)
	}
}
