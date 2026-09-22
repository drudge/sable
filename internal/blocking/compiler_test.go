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
