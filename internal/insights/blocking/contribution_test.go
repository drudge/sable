package blocking

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	blockcompiler "github.com/drudge/sable/internal/blocking"
)

func writeList(t *testing.T, directory, name string, lines ...string) List {
	t.Helper()
	path := filepath.Join(directory, name+".txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return List{Name: name, Path: name + ".txt", Format: "auto"}
}

func contributionByName(t *testing.T, result Contribution, name string) ListContribution {
	t.Helper()
	for _, list := range result.Lists {
		if list.Name == name {
			return list
		}
	}
	t.Fatalf("no contribution for %s in %+v", name, result.Lists)
	return ListContribution{}
}

func TestAnalyzeMeasuresUniqueAndOverlappingCoverage(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	lists := []List{
		writeList(t, directory, "alpha", "one.example", "two.example", "three.example", "four.example"),
		writeList(t, directory, "beta", "two.example", "three.example", "five.example"),
		writeList(t, directory, "gamma", "three.example", "six.example"),
	}

	result, err := Analyze(context.Background(), directory, lists, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if result.Analyzed != 3 || result.Domains != 6 {
		t.Fatalf("analyzed %d lists with %d distinct domains, want 3 and 6", result.Analyzed, result.Domains)
	}
	alpha := contributionByName(t, result, "alpha")
	if alpha.Domains != 4 || alpha.Unique != 2 || alpha.Covered != 2 {
		t.Fatalf("alpha = %+v, want 4 domains, 2 unique, 2 covered", alpha)
	}
	if alpha.LargestOverlap != (Overlap{Name: "beta", Domains: 2}) {
		t.Fatalf("alpha largest overlap = %+v, want beta covering 2", alpha.LargestOverlap)
	}
	beta := contributionByName(t, result, "beta")
	if beta.Unique != 1 || beta.Covered != 2 {
		t.Fatalf("beta = %+v, want 1 unique and 2 covered", beta)
	}
	gamma := contributionByName(t, result, "gamma")
	if gamma.Unique != 1 || gamma.Covered != 1 {
		t.Fatalf("gamma = %+v", gamma)
	}
	// A domain two lists share is unique to neither, so the unique counts add
	// up to the domains exactly one list provides.
	if result.Unique != 4 {
		t.Fatalf("unique across lists = %d, want 4", result.Unique)
	}
}

func TestAnalyzeCountsADomainOnceHoweverOftenAListRepeatsIt(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	lists := []List{
		writeList(t, directory, "repeats", "ads.example", "ADS.example.", "0.0.0.0 ads.example", "||ads.example^", "*.ads.example", "solo.example"),
		writeList(t, directory, "other", "ads.example", "ads.example"),
		writeList(t, directory, "third", "ads.example"),
	}
	result, err := Analyze(context.Background(), directory, lists, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	repeats := contributionByName(t, result, "repeats")
	if repeats.Domains != 2 || repeats.Unique != 1 || repeats.Covered != 1 {
		t.Fatalf("repeats = %+v, want 2 distinct domains with 1 unique", repeats)
	}
	other := contributionByName(t, result, "other")
	if other.Domains != 1 || other.Unique != 0 || other.Covered != 1 {
		t.Fatalf("other = %+v, want its only domain covered", other)
	}
}

// Blocking a domain blocks its subdomains, so a list's subdomain entry adds
// nothing when another list already blocks the parent. The reverse is not
// true: a subdomain entry elsewhere does not cover the parent.
func TestAnalyzeTreatsParentDomainsAsCoverage(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	lists := []List{
		writeList(t, directory, "broad", "tracker.example"),
		writeList(t, directory, "narrow", "cdn.tracker.example", "eu.cdn.tracker.example", "unrelated.example"),
	}
	result, err := Analyze(context.Background(), directory, lists, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	narrow := contributionByName(t, result, "narrow")
	if narrow.Unique != 1 || narrow.Covered != 2 || narrow.LargestOverlap.Name != "broad" {
		t.Fatalf("narrow = %+v, want its two subdomains covered by broad", narrow)
	}
	broad := contributionByName(t, result, "broad")
	if broad.Unique != 1 || broad.Covered != 0 {
		t.Fatalf("broad = %+v, want its parent domain unique", broad)
	}
}

// The comparison has to see a list exactly as the compiled policy does, so it
// reads through the compiler's own parser and normalization. Every format
// quirk here must produce the compiler's domain set.
func TestAnalyzeNormalizesDomainsExactlyLikeTheCompiler(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	list := writeList(t, directory, "mixed",
		"\ufeff# comment",
		"! adblock comment",
		"0.0.0.0 Hosts.Example tracker.hosts.example # trailing",
		"||adblock.example^$third-party",
		"@@||exception.example^",
		"example.com##.banner",
		"*.wild.example",
		"bücher.example",
		"plain.example.",
		"not a domain!",
		"",
	)
	compiled, err := blockcompiler.Compile(directory, nil, []blockcompiler.Source{{Name: list.Name, Path: list.Path, Format: blockcompiler.FormatAuto}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Analyze(context.Background(), directory, []List{list}, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	mixed := contributionByName(t, result, "mixed")
	if mixed.Domains != len(compiled.Domains) {
		t.Fatalf("analysis saw %d domains, compiler %d (%v)", mixed.Domains, len(compiled.Domains), compiled.Domains)
	}
	// A single list has nothing to be compared with, so everything is unique.
	if mixed.Unique != mixed.Domains {
		t.Fatalf("single list = %+v, want every domain unique", mixed)
	}
}

func TestAnalyzeReportsUnreadableListsWithoutFailing(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	lists := []List{
		writeList(t, directory, "present", "one.example", "two.example"),
		{Name: "missing", Path: "never-downloaded.txt", Format: "auto"},
		writeList(t, directory, "empty"),
	}
	result, err := Analyze(context.Background(), directory, lists, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	missing := contributionByName(t, result, "missing")
	if missing.Available || missing.Problem != "No cached copy has been downloaded yet" {
		t.Fatalf("missing = %+v", missing)
	}
	present := contributionByName(t, result, "present")
	if !present.Available || present.Unique != 2 {
		t.Fatalf("present = %+v, want both domains unique despite the missing list", present)
	}
	empty := contributionByName(t, result, "empty")
	if !empty.Available || empty.Domains != 0 || empty.UniqueShare() != 0 {
		t.Fatalf("empty = %+v", empty)
	}
	if result.Analyzed != 2 {
		t.Fatalf("analyzed = %d, want 2", result.Analyzed)
	}
}

func TestAnalyzeStopsComparingPastTheListLimit(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	lists := make([]List, 0, MaximumAnalyzedLists+2)
	for index := range MaximumAnalyzedLists + 2 {
		lists = append(lists, writeList(t, directory, "list-"+strings.Repeat("x", index), "shared.example"))
	}
	result, err := Analyze(context.Background(), directory, lists, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if result.Analyzed != MaximumAnalyzedLists || result.Skipped != 2 {
		t.Fatalf("analyzed %d, skipped %d", result.Analyzed, result.Skipped)
	}
	if last := result.Lists[len(result.Lists)-1]; !last.Skipped || last.Available {
		t.Fatalf("last list = %+v, want it skipped", last)
	}
}

func TestAnalyzerReusesTheComparisonUntilAListChanges(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	lists := []List{
		writeList(t, directory, "alpha", "one.example", "two.example"),
		writeList(t, directory, "beta", "two.example"),
	}
	var calls atomic.Int32
	analyzer := &ContributionCache{now: func() time.Time { calls.Add(1); return time.Unix(int64(calls.Load()), 0) }}

	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := analyzer.Contribution(context.Background(), directory, lists); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	first, err := analyzer.Contribution(context.Background(), directory, lists)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("analysis ran %d times for unchanged lists, want 1", calls.Load())
	}

	// An update rewrites the cached file, which must invalidate the result. The
	// last comparison answers until the new one is ready.
	future := time.Now().Add(time.Hour)
	updated := writeList(t, directory, "beta", "two.example", "three.example")
	if err := os.Chtimes(filepath.Join(directory, updated.Path), future, future); err != nil {
		t.Fatal(err)
	}
	stale, err := analyzer.Contribution(context.Background(), directory, lists)
	if err != nil {
		t.Fatal(err)
	}
	if !stale.AnalyzedAt.Equal(first.AnalyzedAt) {
		t.Fatalf("waited for a new comparison when only a list file changed")
	}
	var second Contribution
	for deadline := time.Now().Add(5 * time.Second); second.AnalyzedAt.IsZero() || second.AnalyzedAt.Equal(first.AnalyzedAt); {
		if time.Now().After(deadline) {
			t.Fatal("the new comparison never replaced the last one")
		}
		time.Sleep(5 * time.Millisecond)
		if second, err = analyzer.Contribution(context.Background(), directory, lists); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("analysis runs = %d after a list changed, want 2", calls.Load())
	}
	if beta := contributionByName(t, second, "beta"); beta.Domains != 2 || beta.Unique != 1 {
		t.Fatalf("beta after update = %+v", beta)
	}

	// A different set of lists is a different question, so it waits.
	added := append(lists, writeList(t, directory, "gamma", "four.example"))
	third, err := analyzer.Contribution(context.Background(), directory, added)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || len(third.Lists) != 3 {
		t.Fatalf("analysis runs = %d with %d lists after one was added, want 3 and 3", calls.Load(), len(third.Lists))
	}
}
