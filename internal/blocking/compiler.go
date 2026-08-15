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

type Result struct {
	Domains []string      `json:"domains"`
	Sources []SourceStats `json:"sources"`
}

func Compile(baseDirectory string, inlineDomains []string, sources []Source) (Result, error) {
	domains := make(map[string]struct{}, len(inlineDomains))
	for _, domain := range inlineDomains {
		normalized, valid := normalizeDomain(domain)
		if !valid {
			return Result{}, fmt.Errorf("invalid inline blocked domain %q", domain)
		}
		domains[normalized] = struct{}{}
	}
	result := Result{Sources: make([]SourceStats, 0, len(sources))}
	for _, source := range sources {
		if err := ValidateFormat(string(source.Format)); err != nil {
			return Result{}, fmt.Errorf("block list %q: %w", source.Name, err)
		}
		stats, err := compileSource(baseDirectory, source, domains)
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
	return result, nil
}

func compileSource(baseDirectory string, source Source, domains map[string]struct{}) (SourceStats, error) {
	path := source.Path
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDirectory, path)
	}
	path = filepath.Clean(path)
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
			domains[domain] = struct{}{}
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
