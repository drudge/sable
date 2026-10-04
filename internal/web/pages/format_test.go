package pages

import "testing"

func TestFormatNumberGroupsThousands(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		value int64
		want  string
	}{
		{0, "0"}, {999, "999"}, {1_000, "1,000"}, {1_234_567, "1,234,567"}, {-1_234_567, "-1,234,567"}, {-123, "-123"},
	} {
		if got := formatNumber(test.value); got != test.want {
			t.Errorf("formatNumber(%d) = %q, want %q", test.value, got, test.want)
		}
	}
	if got := formatNumber(uint64(12_345)); got != "12,345" {
		t.Errorf("formatNumber(uint64) = %q", got)
	}
}

func TestFormatByteSizeUsesBinaryUnits(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		size int64
		want string
	}{
		{0, "0 bytes"}, {1, "1 byte"}, {512, "512 bytes"}, {4096, "4.0 KiB"}, {3 << 19, "1.5 MiB"}, {5 << 30, "5.0 GiB"},
	} {
		if got := FormatByteSize(test.size); got != test.want {
			t.Errorf("FormatByteSize(%d) = %q, want %q", test.size, got, test.want)
		}
	}
}

func TestPluralPicksTheWordForTheCount(t *testing.T) {
	t.Parallel()

	if got := plural(1, "domain", "domains"); got != "domain" {
		t.Errorf("plural(1) = %q", got)
	}
	if got := plural(0, "domain", "domains"); got != "domains" {
		t.Errorf("plural(0) = %q", got)
	}
}
