package services

import "testing"

func TestCatalogOwnsEachDomainOnce(t *testing.T) {
	t.Parallel()
	owners := make(map[string]string)
	ids := make(map[string]bool)
	for _, entry := range catalog {
		if ids[entry.service.ID] {
			t.Errorf("service ID %q is listed twice", entry.service.ID)
		}
		ids[entry.service.ID] = true
		if entry.service.Name == "" || entry.service.Category == "" || len(entry.suffixes) == 0 {
			t.Errorf("service %q is incomplete", entry.service.ID)
		}
		for _, suffix := range entry.suffixes {
			if owner, found := owners[suffix]; found {
				t.Errorf("%s is owned by both %s and %s", suffix, owner, entry.service.ID)
			}
			owners[suffix] = entry.service.ID
		}
	}
}

func TestLookupPrefersTheMostSpecificOwner(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, want string }{
		{"rr3---sn-p5qlsndk.googlevideo.com.", "youtube"},
		{"i.ytimg.com", "youtube"},
		{"tv.youtube.com", "youtube-tv"},
		{"gateway.discord.gg", "discord"},
		{"Mesu.Apple.com", "apple-updates"},
		{"gsp-ssl.apple.com", "apple"},
		{"api.netflix.com", "netflix"},
		{"ws.ring.com", "ring"},
		{"www.google.com", "google-search"},
		{"mail.google.com", "gmail"},
	} {
		service, found := Lookup(test.name)
		if !found || service.ID != test.want {
			t.Errorf("Lookup(%q) = %q, %t; want %q", test.name, service.ID, found, test.want)
		}
	}
	for _, name := range []string{"d3abc.cloudfront.net", "fonts.googleapis.com", "example.com", "", "com"} {
		if service, found := Lookup(name); found {
			t.Errorf("Lookup(%q) = %q, want no owner for shared or unknown names", name, service.ID)
		}
	}
}

func TestGroupSumsDomainsIntoServices(t *testing.T) {
	t.Parallel()
	usages := Group([]Domain{
		{Name: "i.ytimg.com", Queries: 30},
		{Name: "discord.com", Queries: 12},
		{Name: "rr1.googlevideo.com", Queries: 70},
		{Name: "example.net", Queries: 500},
		{Name: "gateway.discord.gg", Queries: 20},
	})
	if len(usages) != 2 {
		t.Fatalf("usages = %+v", usages)
	}
	if usages[0].Service.Name != "YouTube" || usages[0].Queries != 100 || usages[0].Domains[0].Name != "rr1.googlevideo.com" {
		t.Errorf("first usage = %+v", usages[0])
	}
	if usages[1].Service.Name != "Discord" || usages[1].Queries != 32 || len(usages[1].Domains) != 2 {
		t.Errorf("second usage = %+v", usages[1])
	}
}
