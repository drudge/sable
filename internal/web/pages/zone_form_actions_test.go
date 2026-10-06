package pages

import (
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// htmx sends a form with hx-post to that address whichever button submits it,
// so a button meant for another endpoint needs its own hx-post. Without one,
// Delete Record saved the record as an update.
func TestZoneDialogButtonsPostToTheirOwnEndpoints(t *testing.T) {
	t.Parallel()

	zone := ZoneView{Name: "example.test", Type: "primary", DNSSEC: true, DNSSECKeys: []DNSSECKeyView{
		{Role: "KSK", State: "ready", KeyTag: 12345, DS: "example.test. IN DS 12345 15 2 ABCDEF"},
		{Role: "ZSK", State: "active", KeyTag: 23456},
	}}
	record := ZoneRecordView{Name: "www", Type: "A", Value: "192.0.2.10", TTL: 300}
	page := renderComponent(t, EditZoneRecordDialog(zone, record, "record-dialog")) +
		renderComponent(t, ZoneSigningDNSSECDialog(zone, "dnssec-dialog"))
	document, err := html.Parse(strings.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	attribute := func(node *html.Node, name string) (string, bool) {
		for _, candidate := range node.Attr {
			if candidate.Key == name {
				return candidate.Val, true
			}
		}
		return "", false
	}
	found := map[string]bool{}
	var walk func(node *html.Node, formPost string)
	walk = func(node *html.Node, formPost string) {
		if node.Type == html.ElementNode && node.Data == "form" {
			formPost, _ = attribute(node, "hx-post")
		}
		if action, ok := attribute(node, "formaction"); ok && node.Type == html.ElementNode && formPost != "" && action != formPost {
			found[action] = true
			if post, _ := attribute(node, "hx-post"); post != action {
				t.Errorf("button for %s posts to %q, so htmx sends it to the form's %s", action, post, formPost)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child, formPost)
		}
	}
	walk(document, "")
	for _, action := range []string{"/ui/zones/records/delete", "/ui/zones/dnssec/confirm-ds", "/ui/zones/dnssec/rollover"} {
		if !found[action] {
			t.Errorf("no button for %s rendered", action)
		}
	}
	if !strings.Contains(page, `hx-confirm="Delete the A record for “www.example.test”?`) {
		t.Error("Delete Record does not ask before deleting")
	}
}
