package vendors

import "testing"

func TestLookupNamesTheMakerByBrand(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ mac, want string }{
		{"b8:27:eb:33:0c:c6", "Raspberry Pi"},
		{"3C-22-FB-01-02-03", "Apple"},
		{"18:b4:30:aa:bb:cc", "Google Nest"},
		{"a4:cf:12:00:00:01", "Espressif"},
	} {
		if got, found := Lookup(test.mac); !found || got != test.want {
			t.Errorf("Lookup(%q) = %q, %t; want %q", test.mac, got, found, test.want)
		}
	}
	for _, mac := range []string{"da:a1:19:00:00:01", "not a mac", "00:00:00"} {
		if got, found := Lookup(mac); found {
			t.Errorf("Lookup(%q) = %q, want no maker for a private or invalid address", mac, got)
		}
	}
}

func TestBrandMatchesWholeWords(t *testing.T) {
	t.Parallel()
	for organization, want := range map[string]string{
		"SONOS":                 "Sonos",
		"SonoSite":              "SonoSite",
		"Intel Corporate":       "Intel",
		"Intellicheck Mobilisa": "Intellicheck Mobilisa",
		"Hewlett Packard":       "HP",
		"Ring":                  "Ring",
		"RING ACCESS":           "RING ACCESS",
	} {
		if got := Brand(organization); got != want {
			t.Errorf("Brand(%q) = %q, want %q", organization, got, want)
		}
	}
}
