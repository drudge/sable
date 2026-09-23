package blocking

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/drudge/sable/internal/dnsname"
)

const maximumBlockListLineBytes = 1 << 20

type Format string

const (
	FormatAuto    Format = "auto"
	FormatDomains Format = "domains"
	FormatHosts   Format = "hosts"
	FormatAdblock Format = "adblock"
)

type Source struct {
	Name   string
	Path   string
	Format Format
}

type SourceStats struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Lines    int    `json:"lines"`
	Accepted int    `json:"accepted"`
	Invalid  int    `json:"invalid"`
}

// CustomSourceName labels the domains an operator blocked by hand rather than
// through a block list.
const CustomSourceName = "Custom blocked domains"

type Result struct {
	Domains []string `json:"domains"`
	// Owners runs parallel to Domains and indexes OwnerSets, naming every
	// source that contributed each domain. Sets are shared, so a million
	// domains drawn from three lists hold a handful of small slices.
	Owners    []uint32      `json:"-"`
	OwnerSets [][]string    `json:"-"`
	Sources   []SourceStats `json:"sources"`
}

// ownerSets interns the combinations of sources that contribute a domain. Set
// zero is empty. Sources are applied in compile order, so a set only ever grows
// by appending the source currently being read.
type ownerSets struct {
	sets        [][]string
	transitions map[ownerTransition]uint32
}

type ownerTransition struct {
	from   uint32
	source string
}

func newOwnerSets() *ownerSets {
	return &ownerSets{sets: [][]string{nil}, transitions: make(map[ownerTransition]uint32)}
}

func (owners *ownerSets) add(current uint32, source string) uint32 {
	set := owners.sets[current]
	if len(set) > 0 && set[len(set)-1] == source {
		return current
	}
	key := ownerTransition{from: current, source: source}
	if next, found := owners.transitions[key]; found {
		return next
	}
	next := uint32(len(owners.sets))
	owners.sets = append(owners.sets, append(append(make([]string, 0, len(set)+1), set...), source))
	owners.transitions[key] = next
	return next
}

func Compile(baseDirectory string, inlineDomains []string, sources []Source) (Result, error) {
	owners := newOwnerSets()
	domains := make(map[string]uint32, len(inlineDomains))
	for _, domain := range inlineDomains {
		normalized, valid := normalizeDomain(domain)
		if !valid {
			return Result{}, fmt.Errorf("invalid inline blocked domain %q", domain)
		}
		domains[normalized] = owners.add(domains[normalized], CustomSourceName)
	}
	result := Result{Sources: make([]SourceStats, 0, len(sources))}
	for _, source := range sources {
		if err := ValidateFormat(string(source.Format)); err != nil {
			return Result{}, fmt.Errorf("block list %q: %w", source.Name, err)
		}
		stats, err := ReadSource(baseDirectory, source, func(domain string) {
			domains[domain] = owners.add(domains[domain], source.Name)
		})
		if err != nil {
			return Result{}, err
		}
		result.Sources = append(result.Sources, stats)
	}
	result.Domains = make([]string, 0, len(domains))
	for domain := range domains {
		result.Domains = append(result.Domains, domain)
	}
	slices.Sort(result.Domains)
	result.Owners = make([]uint32, len(result.Domains))
	for index, domain := range result.Domains {
		result.Owners[index] = domains[domain]
	}
	result.OwnerSets = owners.sets
	return result, nil
}

// SourcePath resolves a configured block-list path the way the compiler opens
// it, so a caller inspecting the cached file looks at the same file.
func SourcePath(baseDirectory, path string) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDirectory, path)
	}
	return filepath.Clean(path)
}

// ReadSource streams every domain one block list contributes, normalized
// exactly as the compiled policy stores it. The compiler and anything that
// analyzes a list's contents share this reader so their notion of a list's
// domains cannot drift apart. A domain can be visited more than once when the
// list repeats it.
func ReadSource(baseDirectory string, source Source, visit func(string)) (SourceStats, error) {
	path := SourcePath(baseDirectory, source.Path)
	file, err := os.Open(path)
	if err != nil {
		return SourceStats{}, fmt.Errorf("open block list %q: %w", source.Name, err)
	}
	defer file.Close()

	stats := SourceStats{Name: source.Name, Path: path}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maximumBlockListLineBytes)
	for scanner.Scan() {
		stats.Lines++
		parsed, recognized := parseLine(scanner.Text(), source.Format)
		if !recognized {
			continue
		}
		if len(parsed) == 0 {
			stats.Invalid++
			continue
		}
		accepted := 0
		for _, candidate := range parsed {
			domain, valid := normalizeDomain(candidate)
			if !valid {
				stats.Invalid++
				continue
			}
			visit(domain)
			accepted++
		}
		stats.Accepted += accepted
	}
	if err := scanner.Err(); err != nil {
		return SourceStats{}, fmt.Errorf("read block list %q: %w", source.Name, err)
	}
	return stats, nil
}

func parseLine(line string, format Format) ([]string, bool) {
	line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return nil, false
	}
	switch format {
	case FormatAuto:
		return parseAutomaticLine(line)
	case FormatDomains:
		return parseDomainLine(line)
	case FormatHosts:
		return parseHostsLine(line)
	case FormatAdblock:
		return parseAdblockLine(line)
	default:
		return nil, false
	}
}

func parseAutomaticLine(line string) ([]string, bool) {
	if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@") || strings.Contains(line, "##") {
		return parseAdblockLine(line)
	}
	fields := strings.Fields(stripInlineComment(line))
	if len(fields) > 1 && net.ParseIP(fields[0]) != nil {
		return fields[1:], true
	}
	return parseDomainLine(line)
}

func parseDomainLine(line string) ([]string, bool) {
	fields := strings.Fields(stripInlineComment(line))
	if len(fields) == 0 {
		return nil, false
	}
	return fields[:1], true
}

func parseHostsLine(line string) ([]string, bool) {
	fields := strings.Fields(stripInlineComment(line))
	if len(fields) < 2 || net.ParseIP(fields[0]) == nil {
		return nil, true
	}
	return fields[1:], true
}

func parseAdblockLine(line string) ([]string, bool) {
	if strings.HasPrefix(line, "@@") || strings.Contains(line, "##") || strings.Contains(line, "#@#") {
		return nil, false
	}
	if !strings.HasPrefix(line, "||") {
		return parseDomainLine(line)
	}
	candidate := strings.TrimPrefix(line, "||")
	if end := strings.IndexAny(candidate, "^$|/"); end >= 0 {
		candidate = candidate[:end]
	}
	return []string{candidate}, true
}

func stripInlineComment(line string) string {
	if index := strings.IndexByte(line, '#'); index >= 0 {
		return line[:index]
	}
	return line
}

func normalizeDomain(domain string) (string, bool) {
	domain = strings.TrimPrefix(strings.TrimSpace(domain), "*.")
	normalized, err := dnsname.Normalize(domain)
	return normalized, err == nil
}

func ValidateFormat(format string) error {
	switch Format(format) {
	case FormatAuto, FormatDomains, FormatHosts, FormatAdblock:
		return nil
	default:
		return errors.New("format must be auto, domains, hosts, or adblock")
	}
}

func ValidateURL(value string) error {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" {
		return errors.New("must be a valid absolute URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("must use HTTP or HTTPS")
	}
	return nil
}

func CachePath(value string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return filepath.Join("data", "blocklists", fmt.Sprintf("%x.txt", digest[:12]))
}
