package config

import (
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
		{Client{MAC: "da:a1:19:00:00:01"}, "name is required"},
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
