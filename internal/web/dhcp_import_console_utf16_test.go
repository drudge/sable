package web

import (
	"encoding/binary"
	"net/http"
	"os"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/net/html"
)

// A browser sends a preview's hidden fields back as it parsed them: text, in
// the page's UTF-8. So an export uploaded as UTF-16 (what Windows PowerShell
// 5's ">" writes, and the importer reads) has to survive that trip, or
// Preview offers an import that Import then refuses.
func TestDHCPConsoleImportAppliesAUTF16UploadItPreviewed(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPConsoleServer(t)
	export, err := os.ReadFile("../dhcpimport/testdata/technitium-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	// The fixture's addresses, moved into the test server's scope.
	upload := []byte{0xff, 0xfe}
	for _, unit := range utf16.Encode([]rune(strings.ReplaceAll(string(export), "10.0.7.", "192.0.2."))) {
		upload = binary.LittleEndian.AppendUint16(upload, unit)
	}
	before := len(configuration.snapshot.Config.DHCP.Scopes[0].Reservations)

	response := dhcpImportConsoleRequest(t, server, map[string]string{"scope": "lan"}, string(upload))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `name="step" value="apply"`) {
		t.Fatalf("preview of the UTF-16 upload = %d: %s", response.Code, response.Body)
	}
	document, err := html.Parse(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{"step": "apply"}
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "input" {
			attrs := map[string]string{}
			for _, attr := range node.Attr {
				attrs[attr.Key] = attr.Val
			}
			if attrs["type"] == "hidden" {
				fields[attrs["name"]] = attrs["value"]
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)

	response = dhcpImportConsoleRequest(t, server, fields, "")
	added := len(configuration.snapshot.Config.DHCP.Scopes[0].Reservations) - before
	if response.Code != http.StatusOK || added != 2 {
		said := html.UnescapeString(stripTags(response.Body.String()))
		t.Fatalf("Import of what the preview sent back = %d, added %d of 2: %.200s", response.Code, added, said)
	}
}

func stripTags(body string) string {
	var out strings.Builder
	depth := 0
	for _, r := range body {
		switch {
		case r == '<':
			depth++
		case r == '>' && depth > 0:
			depth--
		case depth == 0:
			out.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(out.String()), " ")
}
