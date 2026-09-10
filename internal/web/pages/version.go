package pages

import (
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

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
