package pages

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestAboutVersionLabels(t *testing.T) {
	t.Parallel()
	for _, release := range []struct{ raw, label string }{
		{"dev", "dev"}, {"unknown", "unknown"}, {"1.0.0", "v1.0.0"},
		{"1.0.0-rc.11", "v1.0.0-rc.11"}, {"v1.0.0", "v1.0.0"},
	} {
		t.Run(release.raw, func(t *testing.T) {
			var body bytes.Buffer
			if err := AboutContent(AboutPageView{Console: DashboardView{Version: release.raw}}).Render(context.Background(), &body); err != nil {
				t.Fatal(err)
			}
			for _, expected := range []string{"Sable " + release.label + "</span>", "<strong>" + release.label + "</strong>"} {
				if !strings.Contains(body.String(), expected) {
					t.Errorf("about version is missing %q", expected)
				}
			}
		})
	}
}

func TestUpdatePanelChecksOnceAfterServerRestart(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		view      UpdateView
		automatic bool
	}{
		{"unchecked", UpdateView{Supported: true, CanCheck: true, IncludePreRelease: true}, true},
		{"checked", UpdateView{Supported: true, CanCheck: true, Checked: true, UpToDate: true}, false},
		{"failed", UpdateView{Supported: true, CanCheck: true, Checked: true, Error: "offline"}, false},
		{"busy", UpdateView{Supported: true, CanCheck: true, Busy: true}, false},
		{"installed", UpdateView{Supported: true, CanCheck: true, Installed: true}, false},
		{"unavailable", UpdateView{CanCheck: true}, false},
		{"not permitted", UpdateView{Supported: true}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var body bytes.Buffer
			if err := UpdatePanel(test.view).Render(context.Background(), &body); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(body.String(), `hx-trigger="submit, change, load"`); got != test.automatic {
				t.Errorf("automatic check = %t, want %t", got, test.automatic)
			}
			if test.automatic && !strings.Contains(body.String(), `value="true" checked`) {
				t.Error("automatic check lost the saved prerelease choice")
			}
		})
	}
}

func TestAvailableUpdateKeepsReleaseChecksAndChannelOptions(t *testing.T) {
	t.Parallel()
	var body bytes.Buffer
	view := UpdateView{Supported: true, CanCheck: true, CanApply: true, Available: true, Checked: true, LatestVersion: "1.0.0"}
	if err := UpdatePanel(view).Render(context.Background(), &body); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`hx-post="/ui/updates/install"`, `hx-post="/ui/updates/check"`, "Include pre-releases", "This node only", "Checking…", "data-update-check"} {
		if !strings.Contains(body.String(), expected) {
			t.Errorf("available update is missing %q", expected)
		}
	}
}
