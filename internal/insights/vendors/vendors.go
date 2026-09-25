// Package vendors names the company that made a network interface from the
// first three bytes of its hardware address, using the IEEE registry embedded
// in the binary. Nothing is looked up online. A randomized, locally
// administered address belongs to no company, so it has no vendor.
package vendors

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

// registry is the IEEE MA-L table: "prefix<TAB>organization" per line, sorted.
// Regenerate it with ./internal/generate.
//
//go:embed oui.txt.gz
var registry []byte

var (
	loadOnce sync.Once
	prefixes []uint32
	names    []string
)

func load() {
	reader, err := gzip.NewReader(bytes.NewReader(registry))
	if err != nil {
		return
	}
	defer reader.Close()
	interned := make(map[string]string)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		prefix, name, found := strings.Cut(scanner.Text(), "\t")
		value, err := strconv.ParseUint(prefix, 16, 32)
		if !found || err != nil {
			continue
		}
		if existing, seen := interned[name]; seen {
			name = existing
		} else {
			interned[name] = name
		}
		prefixes = append(prefixes, uint32(value))
		names = append(names, name)
	}
}

// Lookup names the maker of a hardware address, in the short form people
// know, such as "Apple" or "Raspberry Pi".
func Lookup(mac string) (string, bool) {
	address, err := net.ParseMAC(mac)
	if err != nil || len(address) < 3 || address[0]&0x02 != 0 {
		return "", false
	}
	loadOnce.Do(load)
	key := uint32(address[0])<<16 | uint32(address[1])<<8 | uint32(address[2])
	index, found := slices.BinarySearch(prefixes, key)
	if !found {
		return "", false
	}
	// The registry's own blocks are subdivided among many companies, so they
	// name no maker.
	brand := Brand(names[index])
	return brand, brand != ""
}

// brands maps the start of a registered organization name to the brand
// people call it. The registry spells many companies in capitals or by a
// subsidiary's name. A prefix ending in "$" must match the whole name.
var brands = []struct{ prefix, brand string }{
	{"amazon", "Amazon"}, {"amcrest", "Amcrest"}, {"zebra technologies", "Zebra"}, {"wyze", "Wyze"}, {"apple", "Apple"}, {"arcadyan", "Arcadyan"}, {"arlo", "Arlo"}, {"asustek", "ASUS"},
	{"belkin", "Belkin"}, {"brother", "Brother"}, {"canon", "Canon"}, {"chamberlain", "Chamberlain"},
	{"cisco", "Cisco"}, {"dell", "Dell"}, {"ecobee", "ecobee"}, {"eero", "eero"}, {"epson", "Epson"},
	{"seiko epson", "Epson"}, {"espressif", "Espressif"}, {"garmin", "Garmin"}, {"google", "Google"},
	{"nest labs", "Google Nest"}, {"hewlett packard enterprise", "HPE"}, {"hewlett packard", "HP"}, {"hp inc", "HP"},
	{"huawei", "Huawei"}, {"intel", "Intel"}, {"irobot", "iRobot"}, {"lenovo", "Lenovo"},
	{"lg electronics", "LG"}, {"lg innotek", "LG"}, {"liteon", "Lite-On"}, {"microsoft", "Microsoft"},
	{"motorola", "Motorola"}, {"murata", "Murata"}, {"netgear", "Netgear"}, {"nintendo", "Nintendo"},
	{"oneplus", "OnePlus"}, {"guangdong oppo", "OPPO"}, {"philips lighting", "Philips Hue"}, {"signify", "Philips Hue"},
	{"raspberry pi", "Raspberry Pi"}, {"realtek", "Realtek"}, {"ring$", "Ring"}, {"roku", "Roku"},
	{"samsung", "Samsung"}, {"sonos", "Sonos"}, {"sony interactive", "Sony PlayStation"}, {"sony", "Sony"},
	{"synology", "Synology"}, {"qnap", "QNAP"}, {"tp-link", "TP-Link"}, {"tp link", "TP-Link"},
	{"tuya", "Tuya"}, {"ubiquiti", "Ubiquiti"}, {"vizio", "Vizio"},
	{"xiaomi", "Xiaomi"}, {"zte", "ZTE"}, {"texas instruments", "Texas Instruments"},
	{"silicon laboratories", "Silicon Labs"}, {"azurewave", "AzureWave"}, {"hon hai", "Foxconn"},
	{"universal global scientific", "USI"}, {"cloud network technology", "Foxconn"},
	{"ieee registration authority", ""},
}

// Brand shortens a registered organization name to its brand.
func Brand(organization string) string {
	lower := strings.ToLower(organization)
	for _, entry := range brands {
		if whole, exact := strings.CutSuffix(entry.prefix, "$"); exact {
			if lower == whole {
				return entry.brand
			}
			continue
		}
		// The prefix must end at a word boundary, so "SonoSite" is not Sonos.
		if rest, found := strings.CutPrefix(lower, entry.prefix); found && (rest == "" || !unicode.IsLetter(rune(rest[0]))) {
			return entry.brand
		}
	}
	return organization
}
