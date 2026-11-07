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

func TestOlderOrdersPublishedReleasesOnly(t *testing.T) {
	for _, test := range []struct {
		release, reference string
		older              bool
	}{
		{"1.7.2", "1.8.0", true},
		{"v1.8.0-beta.5", "1.8.0-beta.6", true},
		{"1.8.0-beta.6", "1.8.0", true},
		{"1.8.0", "1.8.0", false},
		{"1.9.0", "1.8.0", false},
		{"dev", "1.8.0", false},
		{"", "1.8.0", false},
		{"1.7.0", "dev", false},
		{"1.7.0-dev.1", "1.8.0", false},
	} {
		if got := Older(test.release, test.reference); got != test.older {
			t.Errorf("Older(%q, %q) = %v, want %v", test.release, test.reference, got, test.older)
		}
	}
}
