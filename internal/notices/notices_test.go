package notices

import (
	"strings"
	"testing"
)

func TestNoticesCoverTheConsoleGoAndCompiledModules(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"htmx", "Inter", "Lucide", "Simple Icons", "Go", "github.com/miekg/dns", "golang.org/x/net", "modernc.org/sqlite"} {
		if _, found := Named(name); !found {
			t.Errorf("no notice for %s", name)
		}
	}
	if _, found := Named("github.com/drudge/sable"); found {
		t.Error("Sable lists itself as third-party software")
	}
	seen := map[string]bool{}
	console := true
	for _, notice := range All() {
		if seen[notice.Name] {
			t.Errorf("%s is listed twice", notice.Name)
		}
		seen[notice.Name] = true
		if notice.License == "" || notice.URL == "" || len(notice.Files) == 0 {
			t.Errorf("%s is missing its license, link, or files", notice.Name)
		}
		for _, file := range notice.Files {
			if file.Name == "" || strings.TrimSpace(file.Text) == "" {
				t.Errorf("%s has an empty license file %q", notice.Name, file.Name)
			}
		}
		if notice.Console && !console {
			t.Errorf("%s is listed after the server's software", notice.Name)
		}
		console = notice.Console
	}
}

func TestGoNoticeLeadsWithItsLicense(t *testing.T) {
	t.Parallel()

	notice, found := Named("Go")
	if !found {
		t.Fatal("no notice for Go")
	}
	if notice.Files[0].Name != "LICENSE" || !strings.Contains(notice.Files[0].Text, "The Go Authors") {
		t.Errorf("Go's first file = %q, want its license", notice.Files[0].Name)
	}
}

// Dependabot updates modules every week. Without versions, an update touches
// notices.json only when a license text changes or a module comes or goes.
func TestNoticesLeaveOutVersions(t *testing.T) {
	t.Parallel()

	if strings.Contains(string(data), `"version":`) {
		t.Error("notices.json records versions, so every dependency update needs it regenerated")
	}
}

func TestAllReturnsACopy(t *testing.T) {
	t.Parallel()

	first := All()
	first[0].Name = "changed"
	if All()[0].Name == "changed" {
		t.Fatal("All shares its slice with callers")
	}
}
