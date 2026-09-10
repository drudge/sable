package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/blocking"
)

func TestRetiredHageziSubscriptionKeepsItsCacheAndAcceptsBothFormats(t *testing.T) {
	t.Parallel()

	const retiredURL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt"
	for _, format := range []string{"", "auto", "hosts"} {
		for _, cachePath := range []string{"", "lists/existing.txt"} {
			t.Run(format+"/"+cachePath, func(t *testing.T) {
				t.Parallel()

				loaded, err := Decode(strings.NewReader(fmt.Sprintf(`
[[blocking.lists]]
name = "My Hagezi subscription"
url = %q
path = %q
format = %q
`, retiredURL, cachePath, format)))
				if err != nil {
					t.Fatal(err)
				}
				list := loaded.Blocking.Lists[0]
				wantPath := cachePath
				if wantPath == "" {
					wantPath = blocking.CachePath(retiredURL)
				}
				if list.URL != blocking.HageziProURL || list.Path != wantPath || list.Format != "auto" || list.Name != "My Hagezi subscription" {
					t.Fatalf("migrated subscription = %+v", list)
				}
				root := t.TempDir()
				path := filepath.Join(root, list.Path)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				for _, contents := range []string{"0.0.0.0 ads.example\n", "[Adblock Plus]\n! Title: HaGeZi's Multi PRO\n||ads.example^\n"} {
					if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
						t.Fatal(err)
					}
					compiled, err := blocking.Compile(root, nil, []blocking.Source{{Name: list.Name, Path: list.Path, Format: blocking.Format(list.Format)}})
					if err != nil || !slices.Equal(compiled.Domains, []string{"ads.example"}) {
						t.Fatalf("Compile(%q) = %+v, %v", contents, compiled, err)
					}
				}
				loaded.normalize()
				if loaded.Blocking.Lists[0] != list {
					t.Fatalf("normalizing again changed the migrated subscription: %+v", loaded.Blocking.Lists[0])
				}
			})
		}
	}
}

func TestHageziMigrationLeavesCustomSourcesAlone(t *testing.T) {
	t.Parallel()

	configuration := Defaults()
	list := BlockList{Name: "Hagezi Pro", URL: "https://example.com/my-hosts.txt", Path: "lists/custom.txt", Format: "hosts"}
	configuration.Blocking.Lists = []BlockList{list}
	configuration.normalize()
	if configuration.Blocking.Lists[0] != list {
		t.Fatalf("custom source changed: %+v", configuration.Blocking.Lists[0])
	}
}
