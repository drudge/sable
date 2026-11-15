package dhcpimport

import "testing"

// Sable's UniFi sync names a client by the alias the operator typed in the
// controller, then by the host name the client sent, through
// unifi.SanitizeLabel (internal/unifi/client.go, stations and reservations):
// "Office AP" is office-ap in DNS today. An import that drops the alias
// renames, or unnames, every such device the day DHCP moves to Sable.
func TestReview635UniFiImportNamesClientsLikeTheUniFiSync(t *testing.T) {
	t.Parallel()
	export := `{"meta":{"rc":"ok"},"data":[
 {"mac":"aa:bb:cc:dd:ee:51","name":"Office AP","hostname":"uap-office","use_fixedip":true,"fixed_ip":"192.0.2.51","note":"closet"},
 {"mac":"aa:bb:cc:dd:ee:53","name":"Classic Laddie","use_fixedip":true,"fixed_ip":"192.0.2.53","network_id":null},
 {"mac":"aa:bb:cc:dd:ee:54","hostname":"homeautomation","use_fixedip":true,"fixed_ip":"192.0.2.54"},
 {"mac":"aa:bb:cc:dd:ee:55","name":"printer","use_fixedip":true,"fixed_ip":"192.0.2.55"}
]}`
	result, err := Parse([]byte(export))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"office-ap", "classic-laddie", "homeautomation", "printer"}
	if result.Format != FormatUniFi || len(result.Entries) != len(want) {
		t.Fatalf("format %s, entries %+v", result.Format, result.Entries)
	}
	for i, name := range want {
		if result.Entries[i].Name != name {
			t.Errorf("%s (%s) is named %q, want %q", result.Entries[i].MAC, result.Entries[i].Address, result.Entries[i].Name, name)
		}
	}
}
