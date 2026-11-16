package web

import "testing"

// The console's DHCP notices name fields as the dialogs do, never by their
// place in the settings file.
func TestDHCPProblemTextNamesFields(t *testing.T) {
	t.Parallel()
	for message, want := range map[string]string{
		"dhcp.scopes[1] needs at least one range or reservation":                                                  "The scope needs at least one range or reservation",
		"dhcp.scopes[0].router is inside ranges[0]":                                                               "The router is inside a range",
		"dhcp.scopes[2].subnet overlaps scopes[0]":                                                                "The subnet overlaps another scope",
		"dhcp.scopes[0].reservations[3].address is the router":                                                    "The reservation's address is the router",
		"dhcp.scopes[0].reservations[1].mac duplicates reservations[0]":                                           "The reservation's MAC address duplicates another reservation",
		"dhcp.scopes[0].dns[1] must be an IPv4 address":                                                           "The DNS servers must be an IPv4 address",
		"dhcp.scopes[0].ranges[0] starts after it ends":                                                           "The range starts after it ends",
		"dhcp.scopes[1].reservations[0].name nas.home.arpa is already reserved by dhcp.scopes[0].reservations[2]": "The reservation's name nas.home.arpa is already reserved by another reservation",
		"dhcp.scopes[0].lease must be between 2m0s and 8760h0m0s":                                                 "The lease time must be between 2m0s and 8760h0m0s",
		"mac must be a hardware address, like 00:11:22:33:44:55":                                                  "The MAC address must be a hardware address, like 00:11:22:33:44:55",
		"address must be an IPv4 address":                                                                         "The address must be an IPv4 address",
		"dhcp.scopes[0].router is inside ranges[0]\ndhcp.scopes[0].id is required":                                "The router is inside a range\nThe ID is required",
		"192.0.2.9 is already reserved for 00:11:22:33:44:55":                                                     "192.0.2.9 is already reserved for 00:11:22:33:44:55",
	} {
		if got := dhcpProblemText(message); got != want {
			t.Errorf("dhcpProblemText(%q)\n got %q\nwant %q", message, got, want)
		}
	}
}
