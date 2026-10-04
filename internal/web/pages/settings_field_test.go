package pages

import (
	"regexp"
	"strings"
	"testing"
)

func TestSettingsHelpTextDescribesItsControl(t *testing.T) {
	t.Parallel()

	markup := renderComponent(t, SettingsContent(SettingsPageView{
		ResolverTimeout: "3s",
		Backup: SettingsBackupView{
			Available:      true,
			LocalAvailable: true,
			CanCreate:      true,
		},
	}))

	helps := regexp.MustCompile(`<small id="([a-z0-9-]+-help)">`).FindAllStringSubmatch(markup, -1)
	if len(helps) < 40 {
		t.Fatalf("Settings rendered %d linked help texts, want at least 40", len(helps))
	}
	seen := map[string]bool{}
	for _, help := range helps {
		id := help[1]
		if seen[id] {
			t.Errorf("help id %q appears twice", id)
		}
		seen[id] = true
		if strings.Count(markup, `aria-describedby="`+id+`"`) != 1 {
			t.Errorf("no single control is described by %q", id)
		}
	}

	if !strings.Contains(markup, `<small id="settings-resolver-timeout-help">End-to-end deadline, such as <code>3s</code>.</small>`) {
		t.Error("Resolution Timeout help did not set its example as code")
	}
}
