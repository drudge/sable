package version

import "testing"

func TestDevelopmentBuildIdentification(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		release string
		want    bool
	}{
		{"", true}, {"dev", true}, {"unknown", true}, {"dev-snapshot", true},
		{"1.0.0-dev", true}, {"v1.0.0-dev.7+abc123", true},
		{"1.0.0-snapshot", true}, {"1.0.0-rc.1-snapshot", true},
		{"1.0.0", false}, {" v1.0.0 ", false}, {"1.0.1+abc123", false},
		{"1.0.0-alpha.1", false}, {"1.0.0-beta.1", false}, {"1.0.0-rc.11", false},
	} {
		t.Run(test.release, func(t *testing.T) {
			if got := (Info{Release: test.release}).Development(); got != test.want {
				t.Fatalf("Development(%q) = %t, want %t", test.release, got, test.want)
			}
		})
	}
}
