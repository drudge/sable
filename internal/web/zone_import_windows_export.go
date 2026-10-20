package web

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Windows DNS Server exports (dnscmd /zoneexport, Export-DnsServerZone) put an
// aging timestamp such as [AGE:3794565] in front of dynamically registered
// records and can hold WINS and WINS-R records, which no other server reads.
var (
	windowsAgingField  = regexp.MustCompile(`^\[AGE:\d+\]$`)
	windowsExportName  = regexp.MustCompile(`(?mi)^;\s*Database file \S+ for (\S+) zone\.`)
	windowsRecordTypes = map[string]bool{"WINS": true, "WINSR": true, "WINS-R": true}
)

// cleanWindowsZoneExport removes aging timestamps, drops WINS and WINS-R
// records, and gives records without a TTL the zone's default, returning the
// cleaned text and the owners of the records it dropped.
func cleanWindowsZoneExport(contents string) (string, []string) {
	cleaned, skipped := stripWindowsRecords(contents)
	return withWindowsDefaultTTL(cleaned), skipped
}

func stripWindowsRecords(contents string) (string, []string) {
	var cleaned strings.Builder
	skipped := make([]string, 0, 2)
	skippingRecord := false
	for _, line := range strings.SplitAfter(contents, "\n") {
		recordText, _, _ := strings.Cut(line, ";")
		if skippingRecord {
			// A WINS record's server list can run across lines in parentheses.
			skippingRecord = !strings.Contains(recordText, ")")
			cleaned.WriteString(lineEnding(line))
			continue
		}
		fields := strings.Fields(recordText)
		line = stripWindowsAging(line, fields)
		hasOwner := recordText != "" && !strings.ContainsAny(recordText[:1], " \t")
		if windowsOnlyRecord(fields, hasOwner) {
			if hasOwner {
				skipped = append(skipped, strings.TrimSuffix(fields[0], "."))
			}
			skippingRecord = strings.Contains(recordText, "(") && !strings.Contains(recordText, ")")
			cleaned.WriteString(lineEnding(line))
			continue
		}
		cleaned.WriteString(line)
	}
	return cleaned.String(), skipped
}

// stripWindowsAging removes an [AGE:n] field from a record's preamble.
func stripWindowsAging(line string, fields []string) string {
	for index := 0; index < len(fields) && index <= 3; index++ {
		if windowsAgingField.MatchString(fields[index]) {
			return strings.Replace(line, fields[index], "", 1)
		}
	}
	return line
}

// windowsOnlyRecord reports whether a record is WINS or WINS-R: its type
// follows the owner, when there is one, and only TTL, class and aging fields.
func windowsOnlyRecord(fields []string, hasOwner bool) bool {
	first := 0
	if hasOwner {
		first = 1
	}
	if len(fields) == 0 || strings.HasPrefix(fields[0], "$") {
		return false
	}
	for index := first; index < len(fields) && index <= first+3; index++ {
		if windowsRecordTypes[strings.ToUpper(fields[index])] {
			return true
		}
		if !windowsAgingField.MatchString(fields[index]) && !zoneRecordPreamble(fields[index:index+1]) {
			return false
		}
	}
	return false
}

func lineEnding(line string) string {
	if strings.HasSuffix(line, "\n") {
		return "\n"
	}
	return ""
}

// windowsZoneExportName reads the zone name from the header comment Windows
// writes at the top of an export, since its records use @ without $ORIGIN.
func windowsZoneExportName(contents string) string {
	match := windowsExportName.FindStringSubmatch(contents)
	if match == nil {
		return ""
	}
	return match[1]
}

// prepareZoneImportText applies the import's Windows cleanup when asked for.
func prepareZoneImportText(request *http.Request, zoneText string) (string, []string) {
	if request.FormValue("windows_export") != "true" {
		return zoneText, nil
	}
	return cleanWindowsZoneExport(zoneText)
}

// withWindowsDefaultTTL adds a $TTL of the SOA minimum. Windows gives a record
// without a TTL the zone's default, but a zone file without $TTL gives it the
// TTL of the record before it. The directive shares the export's opening
// comment line when there is one, so parse errors keep their line numbers.
func withWindowsDefaultTTL(contents string) string {
	if strings.Contains(strings.ToUpper(contents), "$TTL") {
		return contents
	}
	parser := dns.NewZoneParser(strings.NewReader(contents), ".", "zone import")
	parser.SetIncludeAllowed(false)
	for record, ok := parser.Next(); ok; record, ok = parser.Next() {
		if soa, isSOA := record.(*dns.SOA); isSOA {
			directive := "$TTL " + strconv.FormatUint(uint64(soa.Minttl), 10)
			if strings.HasPrefix(contents, ";") {
				return directive + " " + contents
			}
			return directive + "\n" + contents
		}
	}
	return contents
}
