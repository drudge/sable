package dhcpimport

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// review635Scope is what Technitium 15.6.2 answered /api/dhcp/scopes/get with
// in the review, cut to its reserved leases.
const review635Scope = `{"response":{"name":"LAN","startingAddress":"192.0.2.100","endingAddress":"192.0.2.199","subnetMask":"255.255.255.0","reservedLeases":[{"hostName":"Server.home.arpa","hardwareAddress":"02-00-00-00-06-03","address":"192.0.2.43","comments":"rack, top shelf"},{"hostName":null,"hardwareAddress":"02-00-00-00-06-04","address":"192.0.2.44","comments":null}]},"server":"38575756986b","status":"ok"}`

// Technitium mostly runs on Windows, where an export is saved with a byte
// order mark: UTF-8 with one from many editors, UTF-16 from Windows
// PowerShell 5's ">" and Out-File. Either has to read as the export it is,
// not come back as "found no reservations in the dnsmasq export".
func TestReview635ExportsSavedOnWindowsRead(t *testing.T) {
	t.Parallel()
	units := utf16.Encode([]rune(review635Scope))
	wide := []byte{0xff, 0xfe}
	for _, unit := range units {
		wide = binary.LittleEndian.AppendUint16(wide, unit)
	}
	cases := map[string][]byte{
		"UTF-8 with a byte order mark": append([]byte{0xef, 0xbb, 0xbf}, review635Scope...),
		"UTF-16 little endian":         wide,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result, err := Parse(data)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if result.Format != FormatTechnitium || len(result.Entries) != 2 || result.Entries[0].Name != "server" || result.Entries[1].Address != "192.0.2.44" {
				t.Errorf("format %s, entries %+v, problems %+v", result.Format, result.Entries, result.Problems)
			}
		})
	}
}
