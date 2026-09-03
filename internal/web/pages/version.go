package pages

import (
	"strings"

	"golang.org/x/mod/semver"
)

func formatReleaseVersion(release string) string {
	tag := "v" + strings.TrimPrefix(release, "v")
	if semver.IsValid(tag) {
		return tag
	}
	return release
}
