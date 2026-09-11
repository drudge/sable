package pages

import (
	"github.com/drudge/sable/internal/version"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

func releaseURL(release string) string {
	if (version.Info{Release: release}).Development() {
		return ""
	}
	return "https://github.com/drudge/sable/releases/tag/" + formatReleaseVersion(release)
}

func formatReleaseVersion(release string) string {
	tag := "v" + strings.TrimPrefix(release, "v")
	if semver.IsValid(tag) {
		return tag
	}
	return release
}

func formatBuildDateTime(value string, display TimeDisplay) (string, string) {
	builtAt, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value, ""
	}
	return display.In(builtAt).Format("Jan 2, 2006"), FormatClock(builtAt, display, false)
}
