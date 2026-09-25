// Package blocking explains what Sable's blocking policy is doing: how much
// each block list contributes that no other list already covers, which names
// were blocked and later allowed, and which list updates are failing.
//
// Everything here reads data Sable already keeps, entirely outside the DNS
// request path. List contents come from the cached source files through the
// same reader the policy compiler uses, and query activity comes from the
// persisted query log.
package blocking

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"io/fs"
	"math/bits"
	"slices"
	"strings"
	"time"

	blockcompiler "github.com/drudge/sable/internal/blocking"
)

// MaximumAnalyzedLists is how many lists one analysis compares. Coverage is
// tracked as one bit per list, and no realistic deployment subscribes to more.
const MaximumAnalyzedLists = 64

// List is one configured block-list source.
type List struct {
	Name   string
	Path   string
	URL    string
	Format string
}

// Overlap names the other list that covers the most of one list's domains.
type Overlap struct {
	Name    string
	Domains int
}

// ListContribution is what one list adds to the compiled policy.
type ListContribution struct {
	Name string
	URL  string
	// Available is false when the cached file could not be read. Such a list
	// is left out of every other list's comparison.
	Available bool
	// Skipped is true for a list beyond MaximumAnalyzedLists.
	Skipped bool
	Problem string
	// Domains is the number of distinct normalized domains in the list.
	Domains int
	// Unique is how many of those domains no other analyzed list covers,
	// either with the same name or with a parent domain, which blocks the
	// name too because blocking rules match subdomains.
	Unique int
	// Covered is how many of the list's domains another list also covers.
	Covered int
	// LargestOverlap is the single other list covering the most of this list.
	LargestOverlap Overlap
}

// UniqueShare reports Unique as a fraction of Domains.
func (list ListContribution) UniqueShare() float64 {
	if list.Domains == 0 {
		return 0
	}
	return float64(list.Unique) / float64(list.Domains)
}

// Contribution compares every configured list with the others.
type Contribution struct {
	Lists []ListContribution
	// Analyzed is how many lists could be read and compared.
	Analyzed int
	// Domains is the number of distinct domains across the analyzed lists.
	Domains int
	// Unique is how many of those domains exactly one list covers. A domain
	// two lists both contain is unique to neither, so this is the sum of every
	// list's Unique count.
	Unique int
	// Skipped is how many lists exceeded MaximumAnalyzedLists.
	Skipped    int
	AnalyzedAt time.Time
}

// Analyze reads each list's cached file and measures how much of it the other
// lists already cover. It runs in two streaming passes over the files and
// never holds the domain names themselves: each list is reduced to a sorted
// set of 64-bit name hashes, and the union of those sets records which lists
// contain each name. The second pass checks every domain and its parents
// against that union, so the work is linear in the size of the lists rather
// than quadratic in their number.
//
// A hash collision could only make two different names look identical. With
// 64-bit hashes and a few million names that probability is around one in a
// million million, far below anything the rounded percentages could show.
func Analyze(ctx context.Context, baseDirectory string, lists []List, now time.Time) (Contribution, error) {
	result := Contribution{Lists: make([]ListContribution, len(lists)), AnalyzedAt: now}
	seed := maphash.MakeSeed()
	hash := func(name string) uint64 { return maphash.String(seed, name) }

	// Pass one: each list becomes a sorted, de-duplicated set of name hashes.
	hashes := make([][]uint64, len(lists))
	analyzed := make([]int, 0, min(len(lists), MaximumAnalyzedLists))
	for index, list := range lists {
		result.Lists[index] = ListContribution{Name: list.Name, URL: list.URL}
		if err := ctx.Err(); err != nil {
			return Contribution{}, err
		}
		if len(analyzed) == MaximumAnalyzedLists {
			result.Lists[index].Problem = fmt.Sprintf("Only the first %d block lists are compared", MaximumAnalyzedLists)
			result.Lists[index].Skipped = true
			result.Skipped++
			continue
		}
		set := make([]uint64, 0, 1024)
		_, err := blockcompiler.ReadSource(baseDirectory, source(list), func(domain string) {
			set = append(set, hash(domain))
		})
		if err != nil {
			result.Lists[index].Problem = readProblem(err)
			continue
		}
		slices.Sort(set)
		set = slices.Compact(set)
		hashes[index] = set
		result.Lists[index].Available = true
		result.Lists[index].Domains = len(set)
		analyzed = append(analyzed, index)
	}
	result.Analyzed = len(analyzed)

	// The union records, for every distinct name, which lists contain it.
	membership := unionMembership(hashes, analyzed)
	result.Domains = len(membership)
	lookup := func(name string) uint64 {
		target := hash(name)
		position, found := slices.BinarySearchFunc(membership, target, func(entry listMembership, target uint64) int {
			switch {
			case entry.hash < target:
				return -1
			case entry.hash > target:
				return 1
			default:
				return 0
			}
		})
		if !found {
			return 0
		}
		return membership[position].lists
	}

	// Pass two: a domain is covered by another list when that list contains
	// the domain or any of its parents.
	for bit, index := range analyzed {
		if err := ctx.Err(); err != nil {
			return Contribution{}, err
		}
		own := uint64(1) << bit
		set := hashes[index]
		visited := make([]bool, len(set))
		overlaps := make([]int, len(analyzed))
		unique := 0
		_, err := blockcompiler.ReadSource(baseDirectory, source(lists[index]), func(domain string) {
			position, found := slices.BinarySearch(set, hash(domain))
			if !found || visited[position] {
				return
			}
			visited[position] = true
			covering := lookup(domain)
			for parent := domain; ; {
				_, rest, cut := strings.Cut(parent, ".")
				if !cut || rest == "" {
					break
				}
				covering |= lookup(rest)
				parent = rest
			}
			covering &^= own
			if covering == 0 {
				unique++
				return
			}
			for covering != 0 {
				other := bits.TrailingZeros64(covering)
				overlaps[other]++
				covering &^= uint64(1) << other
			}
		})
		contribution := &result.Lists[index]
		if err != nil {
			// The file changed or vanished between passes. Report it rather
			// than publish numbers from two different copies of the list.
			contribution.Available = false
			contribution.Problem = readProblem(err)
			contribution.Domains = 0
			result.Analyzed--
			continue
		}
		contribution.Unique = unique
		contribution.Covered = contribution.Domains - unique
		result.Unique += unique
		for other, count := range overlaps {
			if count > contribution.LargestOverlap.Domains {
				contribution.LargestOverlap = Overlap{Name: lists[analyzed[other]].Name, Domains: count}
			}
		}
	}
	return result, nil
}

type listMembership struct {
	hash  uint64
	lists uint64
}

// unionMembership merges the per-list hash sets into one sorted set whose
// entries carry a bit for every list containing the name. Bits are assigned
// in the order the lists were analyzed.
func unionMembership(hashes [][]uint64, analyzed []int) []listMembership {
	total := 0
	for _, index := range analyzed {
		total += len(hashes[index])
	}
	all := make([]listMembership, 0, total)
	for bit, index := range analyzed {
		for _, value := range hashes[index] {
			all = append(all, listMembership{hash: value, lists: uint64(1) << bit})
		}
	}
	slices.SortFunc(all, func(left, right listMembership) int {
		switch {
		case left.hash < right.hash:
			return -1
		case left.hash > right.hash:
			return 1
		default:
			return 0
		}
	})
	merged := all[:0]
	for _, entry := range all {
		if last := len(merged) - 1; last >= 0 && merged[last].hash == entry.hash {
			merged[last].lists |= entry.lists
			continue
		}
		merged = append(merged, entry)
	}
	return merged
}

func source(list List) blockcompiler.Source {
	format := blockcompiler.Format(list.Format)
	if format == "" {
		format = blockcompiler.FormatAuto
	}
	return blockcompiler.Source{Name: list.Name, Path: list.Path, Format: format}
}

func readProblem(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "No cached copy has been downloaded yet"
	}
	return "The cached copy could not be read"
}
