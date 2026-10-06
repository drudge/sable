package blocking

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
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
	// Exceptions counts the list's @@ rules, which unblock a host on every
	// list.
	Exceptions int `json:"exceptions,omitempty"`
	// Unsupported counts adblock rules a DNS server can't apply: paths,
	// wildcards, regular expressions, modifiers other than $important, and
	// cosmetic rules.
	Unsupported int `json:"unsupported,omitempty"`
}

// RuleKind says what a host rule from a block list does.
type RuleKind uint8

const (
	RuleBlock RuleKind = iota
	// RuleImportantBlock is an adblock ||host^$important rule, which an
	// exception from another list doesn't lift.
	RuleImportantBlock
	// RuleException is an adblock @@||host^ rule, which unblocks the host and
	// its subdomains on every list.
	RuleException
)

// CustomSourceName labels the domains an operator blocked by hand rather than
// through a block list.
const CustomSourceName = "Custom blocked domains"

type Result struct {
	Domains []string `json:"domains"`
	// Owners runs parallel to Domains and indexes OwnerSets, naming every
	// source that contributed each domain. Sets are shared, so a million
	// domains drawn from three lists hold a handful of small slices.
	Owners    []uint32   `json:"-"`
	OwnerSets [][]string `json:"-"`
	// Exceptions are the hosts that @@ rules unblock, with their subdomains,
	// whichever list blocks them. ExceptionOwners runs parallel and indexes
	// OwnerSets, naming the lists that carry each exception.
	Exceptions      []string `json:"-"`
	ExceptionOwners []uint32 `json:"-"`
	// Important lists the blocks an exception doesn't lift: $important rules,
	// and the operator's own blocked domains, which win over any list.
	Important []string      `json:"-"`
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
	var important map[string]struct{}
	if len(inlineDomains) > 0 {
		important = make(map[string]struct{}, len(inlineDomains))
		for domain := range domains {
			important[domain] = struct{}{}
		}
	}
	result := Result{Sources: make([]SourceStats, 0, len(sources))}
	var exceptions map[string]uint32
	for _, source := range sources {
		if err := ValidateFormat(string(source.Format)); err != nil {
			return Result{}, fmt.Errorf("block list %q: %w", source.Name, err)
		}
		stats, err := ReadSourceRules(baseDirectory, source, func(domain string, kind RuleKind) {
			switch kind {
			case RuleException:
				if exceptions == nil {
					exceptions = make(map[string]uint32)
				}
				exceptions[domain] = owners.add(exceptions[domain], source.Name)
				return
			case RuleImportantBlock:
				if important == nil {
					important = make(map[string]struct{})
				}
				important[domain] = struct{}{}
			}
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
	if len(exceptions) > 0 {
		result.Exceptions = slices.Sorted(maps.Keys(exceptions))
		result.ExceptionOwners = make([]uint32, len(result.Exceptions))
		for index, domain := range result.Exceptions {
			result.ExceptionOwners[index] = exceptions[domain]
		}
	}
	if len(important) > 0 {
		result.Important = slices.Sorted(maps.Keys(important))
	}
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

// ReadSource streams every domain one block list blocks, normalized exactly
// as the compiled policy stores it. The compiler and anything that analyzes a
// list's contents share this reader so their notion of a list's domains cannot
// drift apart. A domain can be visited more than once when the list repeats
// it. Exceptions are counted but not visited.
func ReadSource(baseDirectory string, source Source, visit func(string)) (SourceStats, error) {
	return ReadSourceRules(baseDirectory, source, func(domain string, kind RuleKind) {
		if kind != RuleException {
			visit(domain)
		}
	})
}

// ReadSourceRules streams every host rule one block list contributes, blocks
// and exceptions alike, normalized as ReadSource normalizes them.
func ReadSourceRules(baseDirectory string, source Source, visit func(string, RuleKind)) (SourceStats, error) {
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
		kind, parsed := parseLine(scanner.Text(), source.Format)
		switch kind {
		case lineSkipped:
			continue
		case lineUnsupported:
			stats.Unsupported++
			continue
		}
		if len(parsed) == 0 {
			stats.Invalid++
			continue
		}
		rule := RuleBlock
		switch kind {
		case lineImportant:
			rule = RuleImportantBlock
		case lineException:
			rule = RuleException
		}
		for _, candidate := range parsed {
			domain, valid := normalizeDomain(candidate)
			if !valid {
				stats.Invalid++
				continue
			}
			visit(domain, rule)
			if rule == RuleException {
				stats.Exceptions++
			} else {
				stats.Accepted++
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return SourceStats{}, fmt.Errorf("read block list %q: %w", source.Name, err)
	}
	return stats, nil
}

// lineKind says what one line of a block list holds.
type lineKind uint8

const (
	// lineSkipped is blank, a comment, or a list header.
	lineSkipped lineKind = iota
	lineBlock
	lineImportant
	lineException
	// lineUnsupported is an adblock rule DNS can't apply.
	lineUnsupported
)

// parseLine returns the names a line blocks or unblocks. A recognized line
// without names is invalid.
func parseLine(line string, format Format) (lineKind, []string) {
	line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
	// Elsewhere a leading # starts a comment, but an adblock list has none.
	if format == FormatAdblock && strings.HasPrefix(line, "#") && isCosmeticRule(line) {
		return lineUnsupported, nil
	}
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return lineSkipped, nil
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
		return lineSkipped, nil
	}
}

func parseAutomaticLine(line string) (lineKind, []string) {
	if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@") {
		return parseAdblockLine(line)
	}
	// Hosts lines come first, so a trailing "## comment" stays a comment.
	fields := strings.Fields(stripInlineComment(line))
	if len(fields) > 1 && net.ParseIP(fields[0]) != nil {
		return lineBlock, fields[1:]
	}
	if isAdblockHeader(line) {
		return lineSkipped, nil
	}
	if isCosmeticRule(line) || hasAdblockSyntax(line) {
		return lineUnsupported, nil
	}
	return parseDomainLine(line)
}

func parseDomainLine(line string) (lineKind, []string) {
	fields := strings.Fields(stripInlineComment(line))
	if len(fields) == 0 {
		return lineSkipped, nil
	}
	return lineBlock, fields[:1]
}

func parseHostsLine(line string) (lineKind, []string) {
	fields := strings.Fields(stripInlineComment(line))
	if len(fields) < 2 || net.ParseIP(fields[0]) == nil {
		return lineBlock, nil
	}
	return lineBlock, fields[1:]
}

// parseAdblockLine accepts the host-only rules a DNS server can enforce:
// ||host^, optionally followed by | or the $important modifier, and the same
// shapes after @@ as exceptions. Anything with a path, a wildcard, a regular
// expression, or another modifier is skipped as unsupported, as AdGuard Home,
// Technitium, and Pi-hole skip it. Cutting such a rule down to its host would
// block far more than the rule does: ||google.com/adsense/search/ads.js would
// block google.com, and ||pl.ua^$badfilter, which cancels a rule, would block
// a public suffix.
func parseAdblockLine(line string) (lineKind, []string) {
	if isCosmeticRule(line) {
		return lineUnsupported, nil
	}
	if isAdblockHeader(line) {
		return lineSkipped, nil
	}
	kind := lineBlock
	rule := line
	if after, exception := strings.CutPrefix(rule, "@@"); exception {
		kind, rule = lineException, after
	}
	host, anchored := strings.CutPrefix(rule, "||")
	if !anchored {
		if kind == lineException || hasAdblockSyntax(rule) {
			return lineUnsupported, nil
		}
		// A bare name blocks that name, as a domain list does.
		return parseDomainLine(line)
	}
	host, modifiers, separated := strings.Cut(host, "^")
	// ||192.0.2.1^ filters answers by address, which a name list can't do.
	if !separated || strings.ContainsAny(host, "*/|$^:?=&") || isAddress(host) {
		return lineUnsupported, nil
	}
	modifiers = strings.TrimPrefix(modifiers, "|")
	switch {
	case modifiers == "":
	case strings.EqualFold(modifiers, "$important"):
		if kind == lineBlock {
			kind = lineImportant
		}
	default:
		return lineUnsupported, nil
	}
	return kind, []string{host}
}

// isAddress reports an IPv4 address, or anything else made of digits and
// dots; no top-level domain is numeric, so none of those is a host name. The
// caller has already ruled out the colons of IPv6.
func isAddress(host string) bool {
	return host != "" && strings.Trim(host, "0123456789.") == ""
}

// isCosmeticRule reports element hiding, CSS, scriptlet, and HTML filtering
// rules and their exceptions, which act on pages rather than names.
func isCosmeticRule(line string) bool {
	for index := strings.IndexByte(line, '#'); index >= 0 && index < len(line)-1; {
		rest := line[index+1:]
		rest = strings.TrimPrefix(rest, "@")
		rest = strings.TrimLeft(rest, "?$%")
		if strings.HasPrefix(rest, "#") {
			return true
		}
		next := strings.IndexByte(line[index+1:], '#')
		if next < 0 {
			return false
		}
		index += next + 1
	}
	return false
}

// isAdblockHeader reports a filter list's version line, such as
// [Adblock Plus 2.0].
func isAdblockHeader(line string) bool {
	return strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]")
}

// hasAdblockSyntax reports a line no domain or hosts entry could be: a
// regular expression, an anchored URL, a separator, a modifier, or a query
// string.
func hasAdblockSyntax(line string) bool {
	return strings.HasPrefix(line, "/") || strings.ContainsAny(line, "|^$?&=")
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
