package dnsname

import "testing"

func TestNormalizeConvertsCaseDotsAndIDNA(t *testing.T) {
	t.Parallel()

	name, err := Normalize(" BÜCHER.Example. ")
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if name != "xn--bcher-kva.example" {
		t.Fatalf("Normalize() = %q", name)
	}
}

func TestNormalizeRejectsIPAddressAndMalformedName(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"192.0.2.1", "bad..example", ""} {
		if _, err := Normalize(input); err == nil {
			t.Errorf("Normalize(%q) error = nil", input)
		}
	}
}

func TestNormalizeOwnerAcceptsServiceAndWildcardLabels(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]string{
		"_HTTPS._TCP.Example.": "_https._tcp.example",
		"*.BÜCHER.Example.":    "*.xn--bcher-kva.example",
	} {
		got, err := NormalizeOwner(input)
		if err != nil || got != want {
			t.Errorf("NormalizeOwner(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"_sip..example", "_sí p.example", ""} {
		if _, err := NormalizeOwner(input); err == nil {
			t.Errorf("NormalizeOwner(%q) error = nil", input)
		}
	}
}
