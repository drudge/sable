package version

import (
	"runtime"
	"strings"

	"golang.org/x/mod/semver"
)

var (
	Release = "dev"
	Commit  = "unknown"
	BuiltAt = "unknown"
)

type Info struct {
	Release string `json:"release"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"built_at"`
	Go      string `json:"go"`
}

func Current() Info {
	return Info{Release: Release, Commit: Commit, BuiltAt: BuiltAt, Go: runtime.Version()}
}

// Development identifies unversioned builds and development or snapshot versions.
// Published alpha, beta, and release-candidate versions remain eligible for updates.
func (info Info) Development() bool {
	release := canonical(info.Release)
	if !semver.IsValid(release) {
		return true
	}
	for _, identifier := range strings.FieldsFunc(semver.Prerelease(release), func(r rune) bool { return r == '.' || r == '-' }) {
		switch strings.ToLower(identifier) {
		case "dev", "snapshot":
			return true
		}
	}
	return false
}

// Older reports whether release is an earlier published version than
// reference. Development and unversioned builds can't be ordered, so neither
// side counts as older when one of them is one.
func Older(release, reference string) bool {
	if (Info{Release: release}).Development() || (Info{Release: reference}).Development() {
		return false
	}
	return semver.Compare(canonical(release), canonical(reference)) < 0
}

func canonical(release string) string {
	return "v" + strings.TrimPrefix(strings.TrimSpace(release), "v")
}
