package blocking

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCompileCombinesInlineHostsAndAdblockDomains(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	writeList(t, directory, "hosts.txt", `
# hosts format
0.0.0.0 ads.example telemetry.example
127.0.0.1 duplicate.example # inline comment
`)
	writeList(t, directory, "filters.txt", `
! Adblock syntax
||tracker.example^
@@||allowed.example^
example##.cosmetic
||duplicate.example^$important
`)
	result, err := Compile(directory, []string{"Inline.Example."}, []Source{
		{Name: "hosts", Path: "hosts.txt", Format: FormatAuto},
		{Name: "filters", Path: "filters.txt", Format: FormatAdblock},
	})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	want := []string{"ads.example", "duplicate.example", "inline.example", "telemetry.example", "tracker.example"}
	if !slices.Equal(result.Domains, want) {
		t.Fatalf("Domains = %v, want %v", result.Domains, want)
	}
	if len(result.Sources) != 2 || result.Sources[0].Accepted != 3 || result.Sources[1].Accepted != 2 {
		t.Fatalf("Sources = %+v, want compiler statistics", result.Sources)
	}
}

func BenchmarkCompileDomainList(b *testing.B) {
	const domainCount = 10_000
	directory := b.TempDir()
	var contents strings.Builder
	for index := range domainCount {
		fmt.Fprintf(&contents, "host-%d.example\n", index)
	}
	path := filepath.Join(directory, "domains.txt")
	if err := os.WriteFile(path, []byte(contents.String()), 0o600); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(contents.Len()))
	b.ResetTimer()
	for b.Loop() {
		if _, err := Compile(directory, nil, []Source{{
			Name: "benchmark", Path: path, Format: FormatDomains,
		}}); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCompileRejectsMissingSource(t *testing.T) {
	t.Parallel()

	_, err := Compile(t.TempDir(), nil, []Source{{Name: "missing", Path: "missing.txt", Format: FormatAuto}})
	if err == nil {
		t.Fatal("Compile() error = nil, want missing source error")
	}
}

func TestNormalizeDomainConvertsInternationalNameToASCII(t *testing.T) {
	t.Parallel()

	domain, valid := normalizeDomain("BÜCHER.example")
	if !valid || domain != "xn--bcher-kva.example" {
		t.Fatalf("normalizeDomain() = %q, %v", domain, valid)
	}
}

func writeList(t *testing.T, directory, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func TestCompileRecordsEverySourceOfEachDomain(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	writeList(t, directory, "alpha.txt", "shared.example\nalpha-only.example\nshared.example\n")
	writeList(t, directory, "beta.txt", "0.0.0.0 shared.example\n0.0.0.0 custom.example\n")
	result, err := Compile(directory, []string{"custom.example"}, []Source{
		{Name: "Alpha", Path: "alpha.txt", Format: FormatAuto},
		{Name: "Beta", Path: "beta.txt", Format: FormatAuto},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Owners) != len(result.Domains) {
		t.Fatalf("owners = %d, domains = %d", len(result.Owners), len(result.Domains))
	}
	want := map[string][]string{
		"alpha-only.example": {"Alpha"},
		"custom.example":     {CustomSourceName, "Beta"},
		"shared.example":     {"Alpha", "Beta"},
	}
	for index, domain := range result.Domains {
		if got := result.OwnerSets[result.Owners[index]]; !slices.Equal(got, want[domain]) {
			t.Errorf("sources of %s = %v, want %v", domain, got, want[domain])
		}
	}
	// Owner sets are shared, not rebuilt per domain.
	if len(result.OwnerSets) > 5 {
		t.Fatalf("owner sets = %v, want the few distinct combinations only", result.OwnerSets)
	}
}

// Adblock rules are applied only when they name a whole host. Cutting a rule
// with a path or a modifier down to its host blocks far more than the rule
// does: EasyList's ||google.com/adsense/search/ads.js blocked google.com.
func TestParseLineAcceptsOnlyHostAdblockRules(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, line string
		kind       lineKind
		names      []string
	}{
		{"host", "||ads.example^", lineBlock, []string{"ads.example"}},
		{"host with end anchor", "||ads.example^|", lineBlock, []string{"ads.example"}},
		{"important", "||ads.example^$important", lineImportant, []string{"ads.example"}},
		{"important with end anchor", "||ads.example^|$important", lineImportant, []string{"ads.example"}},
		{"exception", "@@||cdn.example^", lineException, []string{"cdn.example"}},
		{"exception with end anchor", "@@||cdn.example^|", lineException, []string{"cdn.example"}},
		{"important exception", "@@||cdn.example^$important", lineException, []string{"cdn.example"}},
		{"path", "||google.com/adsense/search/ads.js", lineUnsupported, nil},
		{"path after separator", "||google.com^/ads/", lineUnsupported, nil},
		{"no separator", "||deloton.com$important", lineUnsupported, nil},
		{"bare host", "||ads.example", lineUnsupported, nil},
		{"wildcard label", "||ads.*.example^", lineUnsupported, nil},
		{"wildcard prefix", "||*.ads.example^", lineUnsupported, nil},
		{"regex", `/^ad[0-9]+\.example\.com$/`, lineUnsupported, nil},
		{"third-party", "||ads.example^$third-party", lineUnsupported, nil},
		{"important with another modifier", "||ads.example^$important,third-party", lineUnsupported, nil},
		{"badfilter", "||pl.ua^$badfilter", lineUnsupported, nil},
		{"denyallow", "||ads.example^$denyallow=cdn.example", lineUnsupported, nil},
		{"dnstype", "||ads.example^$dnstype=AAAA", lineUnsupported, nil},
		{"exception with a path", "@@||google.com/recaptcha/", lineUnsupported, nil},
		{"exception with a modifier", "@@||cdn.example^$third-party", lineUnsupported, nil},
		{"hostname anchor", "@@|cdn.taboola.com^|", lineUnsupported, nil},
		{"URL pattern", "-ad-banner.$image", lineUnsupported, nil},
		{"query string", ".aspx?adid=", lineUnsupported, nil},
		{"address", "||192.0.2.1^", lineUnsupported, nil},
		{"element hiding", "example.com##.ad-banner", lineUnsupported, nil},
		{"element hiding exception", "example.com#@#.ad-banner", lineUnsupported, nil},
		{"extended CSS", "example.com#?#div:has(> .ad)", lineUnsupported, nil},
		{"scriptlet", "example.com#%#//scriptlet('abort-on-property-read', 'ads')", lineUnsupported, nil},
		{"header", "[Adblock Plus 2.0]", lineSkipped, nil},
		{"comment", "! Title: EasyList", lineSkipped, nil},
		{"plain domain", "tracker.example", lineBlock, []string{"tracker.example"}},
	} {
		for _, format := range []Format{FormatAuto, FormatAdblock} {
			kind, names := parseLine(test.line, format)
			if kind != test.kind || !slices.Equal(names, test.names) {
				t.Errorf("%s (%s): parseLine(%q) = %v, %q; want %v, %q", test.name, format, test.line, kind, names, test.kind, test.names)
			}
		}
	}
	// A generic element hiding rule reads as a comment in a hosts or domain
	// list, so only an adblock list counts it.
	if kind, _ := parseLine("##.ad-banner", FormatAdblock); kind != lineUnsupported {
		t.Errorf("generic element hiding in an adblock list = %v, want unsupported", kind)
	}
	if kind, _ := parseLine("## Section", FormatAuto); kind != lineSkipped {
		t.Errorf("a ## comment in an automatic list = %v, want skipped", kind)
	}
}

// Hosts and domain lines read as before, including a hosts line whose
// trailing comment starts with ##.
func TestParseLineKeepsHostsAndDomainLines(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		line   string
		format Format
		names  []string
	}{
		{"0.0.0.0 ads.example ## from the 2024 import", FormatAuto, []string{"ads.example"}},
		{"0.0.0.0 ads.example telemetry.example", FormatAuto, []string{"ads.example", "telemetry.example"}},
		{"*.ads.example", FormatAuto, []string{"*.ads.example"}},
		{"ads.example # inline", FormatDomains, []string{"ads.example"}},
		{"127.0.0.1 ads.example", FormatHosts, []string{"ads.example"}},
	} {
		if kind, names := parseLine(test.line, test.format); kind != lineBlock || !slices.Equal(names, test.names) {
			t.Errorf("parseLine(%q, %s) = %v, %q; want block %q", test.line, test.format, kind, names, test.names)
		}
	}
}

func TestReadSourceCountsExceptionsAndUnsupportedRules(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	writeList(t, directory, "filters.txt", `[Adblock Plus 2.0]
! Title: test
||ads.example^
||google.com/adsense/search/ads.js
||pl.ua^$badfilter
@@||cdn.example^
example.com##.ad-banner
||bad_name^
`)
	var blocked []string
	stats, err := ReadSource(directory, Source{Name: "filters", Path: "filters.txt", Format: FormatAuto}, func(domain string) {
		blocked = append(blocked, domain)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(blocked, []string{"ads.example"}) {
		t.Fatalf("blocked = %v, want only ads.example", blocked)
	}
	if stats.Lines != 8 || stats.Accepted != 1 || stats.Exceptions != 1 || stats.Unsupported != 3 || stats.Invalid != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestCompileCollectsExceptionsAndFirmBlocks(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	writeList(t, directory, "adguard.txt", "||ads.example^\n@@||cdn.example^\n@@||ads.example^\n")
	writeList(t, directory, "easylist.txt", "||cdn.example^\n||pixel.example^$important\n@@||ads.example^|\n")
	result, err := Compile(directory, []string{"mine.example"}, []Source{
		{Name: "AdGuard DNS Filter", Path: "adguard.txt", Format: FormatAuto},
		{Name: "EasyList", Path: "easylist.txt", Format: FormatAdblock},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ads.example", "cdn.example", "mine.example", "pixel.example"}; !slices.Equal(result.Domains, want) {
		t.Fatalf("Domains = %v, want %v", result.Domains, want)
	}
	if want := []string{"ads.example", "cdn.example"}; !slices.Equal(result.Exceptions, want) {
		t.Fatalf("Exceptions = %v, want %v", result.Exceptions, want)
	}
	owners := map[string][]string{}
	for index, domain := range result.Exceptions {
		owners[domain] = result.OwnerSets[result.ExceptionOwners[index]]
	}
	if got := owners["ads.example"]; !slices.Equal(got, []string{"AdGuard DNS Filter", "EasyList"}) {
		t.Fatalf("ads.example exception owners = %v", got)
	}
	if got := owners["cdn.example"]; !slices.Equal(got, []string{"AdGuard DNS Filter"}) {
		t.Fatalf("cdn.example exception owners = %v", got)
	}
	if want := []string{"mine.example", "pixel.example"}; !slices.Equal(result.Important, want) {
		t.Fatalf("Important = %v, want %v", result.Important, want)
	}
	if result.Sources[0].Exceptions != 2 || result.Sources[1].Exceptions != 1 || result.Sources[1].Accepted != 2 {
		t.Fatalf("Sources = %+v", result.Sources)
	}
}

// A list of exceptions alone, like the 179 in AdGuard DNS Filter, costs
// little: benchmark a large list with a share of them.
func BenchmarkCompileAdblockList(b *testing.B) {
	const ruleCount = 200_000
	directory := b.TempDir()
	var contents strings.Builder
	for index := range ruleCount {
		switch index % 100 {
		case 0:
			fmt.Fprintf(&contents, "@@||host-%d.example^\n", index)
		case 1:
			fmt.Fprintf(&contents, "||host-%d.example/ads.js$script\n", index)
		default:
			fmt.Fprintf(&contents, "||host-%d.example^\n", index)
		}
	}
	path := filepath.Join(directory, "filters.txt")
	if err := os.WriteFile(path, []byte(contents.String()), 0o600); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(contents.Len()))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := Compile(directory, nil, []Source{{Name: "benchmark", Path: path, Format: FormatAuto}}); err != nil {
			b.Fatal(err)
		}
	}
}
