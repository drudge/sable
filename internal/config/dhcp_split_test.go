package config

import (
	"slices"
	"testing"
)

func TestSplitDHCPRange(t *testing.T) {
	t.Parallel()
	got, err := SplitDHCPRange("192.0.2.100", "192.0.2.200", []string{"a", "b", "c"})
	want := []DHCPRange{{Start: "192.0.2.100", End: "192.0.2.133", Node: "a"},
		{Start: "192.0.2.134", End: "192.0.2.167", Node: "b"}, {Start: "192.0.2.168", End: "192.0.2.200", Node: "c"}}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("101 addresses over three nodes = %v, %v; want %v", got, err, want)
	}
	if got, err := SplitDHCPRange("192.0.2.100", "192.0.2.199", nil); err != nil || len(got) != 1 || got[0].Node != "" {
		t.Fatalf("no nodes = %v, %v; want the range unpinned", got, err)
	}
	for _, bad := range [][2]string{{"192.0.2.100", "192.0.2.100"}, {"192.0.2.9", "192.0.2.1"}, {"nope", "192.0.2.1"}, {"2001:db8::1", "2001:db8::9"}} {
		if got, err := SplitDHCPRange(bad[0], bad[1], []string{"a", "b"}); err == nil {
			t.Errorf("SplitDHCPRange(%s, %s) = %v; want an error", bad[0], bad[1], got)
		}
	}
}
