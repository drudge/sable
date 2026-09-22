package pages

import "testing"

func TestInsightCausesReadAsOneSentence(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		causes []string
		want   string
	}{
		{[]string{"Switched off or unplugged"}, "switched off or unplugged."},
		{[]string{"A software update", "DNS moved elsewhere"}, "a software update or DNS moved elsewhere."},
		{[]string{"Switched off or unplugged", "Moved to another network", "Set to use a different DNS server"},
			"switched off or unplugged, moved to another network, or set to use a different DNS server."},
	} {
		if got := insightCauses(test.causes); got != test.want {
			t.Errorf("insightCauses(%q) = %q, want %q", test.causes, got, test.want)
		}
	}
}
