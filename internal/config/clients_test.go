package config

import (
	"slices"
	"strings"
	"testing"
)

func TestClientsValidateAndNormalize(t *testing.T) {
	t.Parallel()
	configuration := Defaults()
	configuration.Clients = []Client{
		{Name: " Kids iPad ", MAC: "DA-A1-19-00-00-01"},
		{Name: "Guest Wi-Fi", Address: "10.20.40.77/24"},
		{Name: "Printer", Address: "::ffff:10.20.10.9"},
	}
	configuration.normalize()
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
	byName := map[string]Client{}
	for _, client := range configuration.Clients {
		byName[client.Name] = client
	}
	if byName["Kids iPad"].MAC != "da:a1:19:00:00:01" || byName["Guest Wi-Fi"].Address != "10.20.40.0/24" || byName["Printer"].Address != "10.20.10.9" {
		t.Fatalf("normalized clients = %+v", configuration.Clients)
	}

	for _, test := range []struct {
		client Client
		want   string
	}{
		{Client{MAC: "da:a1:19:00:00:01"}, "name or clients[0].type is required"},
		{Client{MAC: "da:a1:19:00:00:01", Type: "toaster"}, "type must be one of"},
		{Client{Name: "Both", MAC: "da:a1:19:00:00:01", Address: "10.0.0.1"}, "not both"},
		{Client{Name: "Neither"}, "must set mac or address"},
		{Client{Name: "Bad", MAC: "nope"}, "hardware address"},
		{Client{Name: "Bad", Address: "example.com"}, "IP address or CIDR"},
		{Client{Name: strings.Repeat("x", 65), Address: "10.0.0.1"}, "at most 64"},
	} {
		invalid := Defaults()
		invalid.Clients = []Client{test.client}
		if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("Validate(%+v) = %v, want %q", test.client, err, test.want)
		}
	}
	duplicate := Defaults()
	duplicate.Clients = []Client{{Name: "One", Address: "10.0.0.1"}, {Name: "Two", Address: "10.0.0.1"}}
	if err := duplicate.Validate(); err == nil || !strings.Contains(err.Error(), "same device") {
		t.Fatalf("duplicate Validate() = %v", err)
	}
}

func TestSetClientNameReplacesAndRemoves(t *testing.T) {
	t.Parallel()
	clients := []Client{{Name: "Old", MAC: "da:a1:19:00:00:01"}, {Name: "Printer", Address: "10.0.0.9"}}
	updated, err := SetClientName(clients, Client{Name: "Kids iPad", MAC: "DA:A1:19:00:00:01"})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 2 || updated[1].Name != "Kids iPad" || clients[0].Name != "Old" {
		t.Fatalf("renamed = %+v (original %+v)", updated, clients)
	}
	removed, err := SetClientName(updated, Client{Address: "10.0.0.9"})
	if err != nil || len(removed) != 1 || removed[0].Name != "Kids iPad" {
		t.Fatalf("removed = %+v, %v", removed, err)
	}
	if _, err := SetClientName(nil, Client{Name: "Nowhere"}); err == nil {
		t.Fatal("a name with no device identifier was accepted")
	}
}

// A name or type set by hardware address takes over what Sable kept on the
// device's addresses before it knew the hardware, so removing it later leaves
// nothing behind. Other addresses and networks keep theirs.
func TestHardwareAddressTakesOverItsAddresses(t *testing.T) {
	t.Parallel()
	clients := []Client{
		{Name: "Old Name", Address: "10.0.0.5"},
		{Name: "Laptop v6", Address: "fd00::5", Type: "computer"},
		{Name: "Printer", Address: "10.0.0.9", Type: "printer"},
		{Name: "Guest Wi-Fi", Address: "10.20.40.0/24", Type: "phone"},
	}
	addresses := []string{"10.0.0.5", "fd00::5", "10.20.40.0/24"}
	renamed, err := SetClientName(clients, Client{Name: "Work Laptop", MAC: "3c:22:fb:01:02:03"}, addresses...)
	if err != nil {
		t.Fatal(err)
	}
	want := []Client{
		{Name: "Printer", Address: "10.0.0.9", Type: "printer"},
		{Name: "Guest Wi-Fi", Address: "10.20.40.0/24", Type: "phone"},
		{Address: "fd00::5", Type: "computer"},
		{Name: "Work Laptop", MAC: "3c:22:fb:01:02:03"},
	}
	if !slices.Equal(renamed, want) {
		t.Fatalf("renamed = %+v, want %+v", renamed, want)
	}
	typed, err := SetClientType(renamed, Client{MAC: "3c:22:fb:01:02:03"}, addresses...)
	if err != nil || len(typed) != 3 || slices.ContainsFunc(typed, func(client Client) bool { return client.Address == "fd00::5" }) {
		t.Fatalf("returning the type to Sable left %+v, %v", typed, err)
	}
	removed, err := SetClientName(typed, Client{MAC: "3c:22:fb:01:02:03"}, addresses...)
	if err != nil || !slices.Equal(removed, want[:2]) {
		t.Fatalf("removed = %+v, %v", removed, err)
	}
	// A device known only by its address has nothing to take over.
	if byAddress, err := SetClientName(clients, Client{Name: "NAS", Address: "10.0.0.9"}, addresses...); err != nil || byAddress[0].Name != "Old Name" {
		t.Fatalf("naming by address = %+v, %v", byAddress, err)
	}
}

func TestSetClientTypeKeepsTheName(t *testing.T) {
	t.Parallel()
	clients := []Client{{Name: "Front door", MAC: "da:a1:19:00:00:01"}}
	typed, err := SetClientType(clients, Client{MAC: "DA:A1:19:00:00:01", Type: "doorbell"})
	if err != nil || len(typed) != 1 || typed[0].Name != "Front door" || typed[0].Type != "doorbell" {
		t.Fatalf("typed = %+v, %v", typed, err)
	}
	// Removing the name keeps the entry for its type.
	unnamed, err := SetClientName(typed, Client{MAC: "da:a1:19:00:00:01"})
	if err != nil || len(unnamed) != 1 || unnamed[0].Name != "" || unnamed[0].Type != "doorbell" {
		t.Fatalf("unnamed = %+v, %v", unnamed, err)
	}
	// Clearing the type too leaves nothing to remember.
	cleared, err := SetClientType(unnamed, Client{MAC: "da:a1:19:00:00:01"})
	if err != nil || len(cleared) != 0 {
		t.Fatalf("cleared = %+v, %v", cleared, err)
	}
	if _, err := SetClientType(nil, Client{Address: "10.0.0.9", Type: "toaster"}); err == nil {
		t.Fatal("an unknown type was accepted")
	}
}
