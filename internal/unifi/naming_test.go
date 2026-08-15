package unifi

import "testing"

func TestSanitizeLabel(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "lowercases", input: "MacBook-Pro", want: "macbook-pro"},
		{name: "strips apostrophes without splitting", input: "Nick's iPhone", want: "nicks-iphone"},
		{name: "strips curly apostrophes", input: "Nick’s iPad", want: "nicks-ipad"},
		{name: "replaces underscores and spaces", input: "living_room tv", want: "living-room-tv"},
		{name: "drops unsafe runes", input: "Office (Printer)!", want: "office-printer"},
		{name: "collapses repeated dashes", input: "a---b", want: "a-b"},
		{name: "trims leading and trailing dashes", input: "-edge-", want: "edge"},
		{name: "splits dotted names", input: "host.local", want: "host-local"},
		{name: "returns empty when nothing usable remains", input: "!!!", want: ""},
		{name: "keeps digits", input: "Camera 02", want: "camera-02"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := SanitizeLabel(testCase.input); got != testCase.want {
				t.Fatalf("SanitizeLabel(%q) = %q, want %q", testCase.input, got, testCase.want)
			}
		})
	}
}

func TestSanitizeLabelTruncatesToOneLabel(t *testing.T) {
	long := ""
	for range 80 {
		long += "a"
	}
	got := SanitizeLabel(long)
	if len(got) != 63 {
		t.Fatalf("SanitizeLabel truncated to %d characters, want 63", len(got))
	}
}

func TestParseTemplate(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "defaults when empty", input: "  ", want: DefaultHostnameTemplate},
		{name: "accepts flat template", input: "{{host}}.{{zone}}", want: "{{host}}.{{zone}}"},
		{name: "normalizes internal spacing", input: "{{ host }}.{{ zone }}", want: "{{host}}.{{zone}}"},
		{name: "rejects unknown placeholder", input: "{{mac}}.{{zone}}", wantErr: true},
		{name: "rejects missing host", input: "{{network}}.{{zone}}", wantErr: true},
		{name: "rejects missing zone suffix", input: "{{host}}.{{network}}", wantErr: true},
		{name: "rejects literal text", input: "{{host}}.static.{{zone}}", wantErr: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			template, err := ParseTemplate(testCase.input)
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("ParseTemplate(%q) succeeded, want error", testCase.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTemplate(%q): %v", testCase.input, err)
			}
			if template.String() != testCase.want {
				t.Fatalf("ParseTemplate(%q) = %q, want %q", testCase.input, template.String(), testCase.want)
			}
		})
	}
}

func TestTemplateRender(t *testing.T) {
	cases := []struct {
		name     string
		template string
		host     string
		network  string
		zone     string
		want     string
		wantErr  bool
	}{
		{
			name: "default layout", template: DefaultHostnameTemplate,
			host: "Nick's iPhone", network: "IoT", zone: "clients.example.net",
			want: "nicks-iphone.iot.clients.example.net",
		},
		{
			name: "flat layout", template: "{{host}}.{{zone}}",
			host: "printer", network: "IoT", zone: "example.net",
			want: "printer.example.net",
		},
		{
			name: "collapses an unusable network label", template: DefaultHostnameTemplate,
			host: "printer", network: "!!!", zone: "example.net",
			want: "printer.example.net",
		},
		{
			name: "rejects an unusable host", template: DefaultHostnameTemplate,
			host: "***", network: "IoT", zone: "example.net", wantErr: true,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			template, err := ParseTemplate(testCase.template)
			if err != nil {
				t.Fatalf("ParseTemplate: %v", err)
			}
			got, err := template.Render(testCase.host, testCase.network, testCase.zone)
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("Render succeeded with %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			if got != testCase.want {
				t.Fatalf("Render = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestRelativeOwner(t *testing.T) {
	cases := []struct {
		fqdn string
		zone string
		want string
	}{
		{fqdn: "printer.iot.example.net", zone: "example.net", want: "printer.iot"},
		{fqdn: "example.net", zone: "example.net", want: "@"},
		{fqdn: "printer.example.net.", zone: "example.net", want: "printer"},
		{fqdn: "printer.elsewhere.test", zone: "example.net", want: "printer.elsewhere.test"},
	}
	for _, testCase := range cases {
		if got := RelativeOwner(testCase.fqdn, testCase.zone); got != testCase.want {
			t.Fatalf("RelativeOwner(%q, %q) = %q, want %q", testCase.fqdn, testCase.zone, got, testCase.want)
		}
	}
}

func TestTemplateUsesNetwork(t *testing.T) {
	withNetwork, err := ParseTemplate(DefaultHostnameTemplate)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	flat, err := ParseTemplate("{{host}}.{{zone}}")
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if !withNetwork.UsesNetwork() || flat.UsesNetwork() {
		t.Fatal("UsesNetwork did not distinguish network-scoped templates")
	}
}
