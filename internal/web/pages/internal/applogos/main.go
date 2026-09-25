// Command applogos writes the brand marks of the apps Sable recognizes from
// the Simple Icons package, which is released under CC0, into the table the
// console draws app icons from. An app whose brand is not in Simple Icons is
// left out and shows its category's icon instead.
//
//	curl -sSL https://registry.npmjs.org/simple-icons/-/simple-icons-16.32.0.tgz | tar -xz
//	go run ./internal/web/pages/internal/applogos -icons package -out internal/web/pages/app_logos.go
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/drudge/sable/internal/insights/services"
)

// slugs names the Simple Icons mark of each app whose slug is not its ID
// without dashes. An empty slug means Simple Icons has no mark for the app,
// only one for another brand of the same name.
var slugs = map[string]string{
	"apple-updates":   "apple",
	"battle-net":      "battledotnet",
	"chromecast":      "googlecast",
	"gemini":          "googlegemini",
	"go-modules":      "go",
	"google-search":   "google",
	"hp-printing":     "hp",
	"lg-webos":        "lg",
	"nytimes":         "newyorktimes",
	"python-packages": "pypi",
	"roomba":          "irobot",
	"tp-link-kasa":    "kasasmart",
	"unifi":           "ubiquiti",
	// Simple Icons' Max is Cycling '74's music software, not the streaming
	// service.
	"max": "",
}

// retiredMark is a brand mark Simple Icons has since dropped, kept as the
// last release that carried it drew it, under the same CC0 terms.
type retiredMark struct {
	Release string
	Hex     string
	Path    string
}

// retired are the marks of apps whose brand left Simple Icons, keyed by app.
var retired = map[string]retiredMark{
	// OpenAI's mark, which ChatGPT carries, left in Simple Icons 16.
	"chatgpt": {Release: "15.22.0", Hex: "412991", Path: "M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .071 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813zm1.0976-2.3654l2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.4997-2.6067-1.4997Z"},
	// Xbox's mark left in Simple Icons 12.5.
	"xbox": {Release: "12.4.0", Hex: "107C10", Path: "M4.102 21.033C6.211 22.881 8.977 24 12 24c3.026 0 5.789-1.119 7.902-2.967 1.877-1.912-4.316-8.709-7.902-11.417-3.582 2.708-9.779 9.505-7.898 11.417zm11.16-14.406c2.5 2.961 7.484 10.313 6.076 12.912C23.002 17.48 24 14.861 24 12.004c0-3.34-1.365-6.362-3.57-8.536 0 0-.027-.022-.082-.042-.063-.022-.152-.045-.281-.045-.592 0-1.985.434-4.805 3.246zM3.654 3.426c-.057.02-.082.041-.086.042C1.365 5.642 0 8.664 0 12.004c0 2.854.998 5.473 2.661 7.533-1.401-2.605 3.579-9.951 6.08-12.91-2.82-2.813-4.216-3.245-4.806-3.245-.131 0-.223.021-.281.046v-.002zM12 3.551S9.055 1.828 6.755 1.746c-.903-.033-1.454.295-1.521.339C7.379.646 9.659 0 11.984 0H12c2.334 0 4.605.646 6.766 2.085-.068-.046-.615-.372-1.52-.339C14.946 1.828 12 3.545 12 3.545v.006z"},
}

// darkMarks are the brands that show a black mark on their own color, though
// the color is not light enough for the rule below to call for one.
var darkMarks = map[string]bool{"android": true, "homebrew": true, "kagi": true, "plex": true, "spotify": true, "synology": true}

type icon struct {
	Title string `json:"title"`
	Slug  string `json:"slug"`
	Hex   string `json:"hex"`
}

var markPath = regexp.MustCompile(`<path d="([^"]+)"`)

func main() {
	directory := flag.String("icons", "package", "unpacked simple-icons npm package")
	output := flag.String("out", "app_logos.go", "Go file to write")
	flag.Parse()
	if err := generate(*directory, *output); err != nil {
		log.Fatal(err)
	}
}

func generate(directory, output string) error {
	manifest, err := os.ReadFile(filepath.Join(directory, "package.json"))
	if err != nil {
		return err
	}
	var release struct{ Version string }
	if err := json.Unmarshal(manifest, &release); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(directory, "data", "simple-icons.json"))
	if err != nil {
		return err
	}
	var icons []icon
	if err := json.Unmarshal(data, &icons); err != nil {
		return err
	}
	bySlug := make(map[string]icon, len(icons))
	for _, entry := range icons {
		bySlug[entry.Slug] = entry
	}

	var table bytes.Buffer
	fmt.Fprintf(&table, "// Code generated by go run ./internal/web/pages/internal/applogos; DO NOT EDIT.\n\n")
	fmt.Fprintf(&table, "package pages\n\n")
	fmt.Fprintf(&table, "// appLogos are the brand marks of the apps Sable recognizes, keyed by app, from\n")
	fmt.Fprintf(&table, "// Simple Icons %s (CC0): each mark's path on a 24-unit square, its brand's\n", release.Version)
	fmt.Fprintf(&table, "// color, and the ink that reads best on that color.\n")
	fmt.Fprintf(&table, "var appLogos = map[string]appLogo{\n")
	var missing []string
	for _, service := range services.All() {
		slug, mapped := slugs[service.ID]
		if !mapped {
			slug = strings.ReplaceAll(service.ID, "-", "")
		}
		entry, found := bySlug[slug]
		if old, kept := retired[service.ID]; kept && !found {
			ink, err := inkOn(old.Hex)
			if err != nil {
				return fmt.Errorf("%s: %w", service.ID, err)
			}
			fmt.Fprintf(&table, "\t%q: {Path: %q, Color: %q, Ink: %q}, // Simple Icons %s, the last release with this mark\n",
				service.ID, old.Path, "#"+old.Hex, ink, old.Release)
			continue
		}
		if slug == "" || !found {
			missing = append(missing, service.ID)
			continue
		}
		mark, err := os.ReadFile(filepath.Join(directory, "icons", slug+".svg"))
		if err != nil {
			return err
		}
		path := markPath.FindSubmatch(mark)
		if path == nil {
			return fmt.Errorf("%s: no path in %s.svg", service.ID, slug)
		}
		ink, err := inkOn(entry.Hex)
		if err != nil {
			return fmt.Errorf("%s: %w", service.ID, err)
		}
		if darkMarks[slug] {
			ink = "#000"
		}
		fmt.Fprintf(&table, "\t%q: {Path: %q, Color: %q, Ink: %q},\n", service.ID, path[1], "#"+entry.Hex, ink)
	}
	fmt.Fprintf(&table, "}\n")
	source, err := format.Source(table.Bytes())
	if err != nil {
		return err
	}
	if err := os.WriteFile(output, source, 0o644); err != nil {
		return err
	}
	log.Printf("%d apps have no mark and show their category: %s", len(missing), strings.Join(missing, " "))
	return nil
}

// inkOn picks the ink for a mark on a brand color. Brands draw their marks in
// white on their color unless it is very light, even where black would
// contrast a little more, as on YouTube's red or Reddit's orange, so white
// wins until the color is light enough that white would wash out.
func inkOn(hex string) (string, error) {
	value, err := strconv.ParseUint(hex, 16, 32)
	if err != nil || len(hex) != 6 {
		return "", fmt.Errorf("color %q", hex)
	}
	channel := func(shift uint) float64 {
		level := float64(value>>shift&0xff) / 255
		if level <= 0.04045 {
			return level / 12.92
		}
		return math.Pow((level+0.055)/1.055, 2.4)
	}
	if 0.2126*channel(16)+0.7152*channel(8)+0.0722*channel(0) <= 0.55 {
		return "#fff", nil
	}
	return "#000", nil
}
