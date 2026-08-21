package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"

	blockcompiler "github.com/drudge/sable/internal/blocking"
)

// Sable downloads a subscription the first time it starts unless the cache file
// is already there. Writing the cache ourselves lets the demo show real
// subscription URLs at their real sizes on a machine with no internet access,
// and keeps a run from depending on somebody else's uptime.
func writeBlockListCaches(directory string) error {
	for _, source := range blockListSources {
		path := filepath.Join(directory, blockcompiler.CachePath(source.URL))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("create block list cache directory: %w", err)
		}
		if err := writeBlockListCache(path, source); err != nil {
			return err
		}
	}
	return nil
}

func writeBlockListCache(path string, source blockListSource) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create block list cache %s: %w", source.Name, err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	switch source.Format {
	case "hosts":
		fmt.Fprintf(writer, "# %s\n", source.Name)
	case "adblock":
		fmt.Fprintf(writer, "! %s\n", source.Name)
	default:
		fmt.Fprintf(writer, "# %s\n", source.Name)
	}
	for _, domain := range syntheticDomains(source) {
		switch source.Format {
		case "hosts":
			fmt.Fprintf(writer, "0.0.0.0 %s\n", domain)
		case "adblock":
			fmt.Fprintf(writer, "||%s^\n", domain)
		default:
			fmt.Fprintln(writer, domain)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("write block list cache %s: %w", source.Name, err)
	}
	return nil
}

var (
	blockListPrefixes = []string{
		"ad", "ads", "track", "pixel", "beacon", "metric", "stat", "click", "serve",
		"banner", "promo", "tag", "sync", "bid", "rtb", "cdn", "edge", "imp", "conv",
		"event", "collect", "adserv", "adnet", "offer", "retarget",
	}
	blockListBrands = []string{
		"adzone", "clickly", "trackr", "pixelnet", "admetric", "bidhub", "tagsync",
		"promoly", "beaconly", "adnexo", "statly", "impressly", "servly", "convrt",
		"retargo", "adloop", "pixly", "metricly", "clicksafe", "adrelay",
	}
	blockListSuffixes = []string{
		"com", "net", "io", "co", "info", "biz", "org", "cloud", "link", "site",
		"xyz", "online", "digital", "media",
	}
)

// syntheticDomains invents a deterministic set of advertising and tracking names
// so each list has a believable size. The seed is derived from the URL, so the
// same list produces the same file on every run.
func syntheticDomains(source blockListSource) []string {
	random := rand.New(rand.NewSource(int64(len(source.URL)) * 7919))
	unique := make(map[string]struct{}, source.Count)
	for len(unique) < source.Count {
		prefix := blockListPrefixes[random.Intn(len(blockListPrefixes))]
		brand := blockListBrands[random.Intn(len(blockListBrands))]
		suffix := blockListSuffixes[random.Intn(len(blockListSuffixes))]
		var domain string
		switch random.Intn(4) {
		case 0:
			domain = fmt.Sprintf("%s%d.%s.%s", prefix, random.Intn(999)+1, brand, suffix)
		case 1:
			domain = fmt.Sprintf("%s-%s%d.%s", prefix, brand, random.Intn(99)+1, suffix)
		case 2:
			domain = fmt.Sprintf("%s%d.%s", brand, random.Intn(9900)+100, suffix)
		default:
			domain = fmt.Sprintf("%s.%s-%d.%s", prefix, brand, random.Intn(499)+1, suffix)
		}
		unique[domain] = struct{}{}
	}
	domains := make([]string, 0, len(unique))
	for domain := range unique {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
}
