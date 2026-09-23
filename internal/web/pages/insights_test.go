package pages

import (
	"strings"
	"testing"
)

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

func TestInsightEvidenceShowsWhereTheNameCameFromBesideIt(t *testing.T) {
	t.Parallel()
	finding := InsightFindingView{ID: "insight-finding-1", Title: "New device on the network", Subject: "front-door-doorbell", SubjectSource: "UniFi"}
	markup := renderComponent(t, InsightEvidence(finding, InsightsOverviewView{}))
	if !strings.Contains(markup, `<span class="sr-only">Name from </span>UniFi</span>`) {
		t.Errorf("drawer header is missing the name source badge:\n%s", markup)
	}
	if strings.Contains(markup, "<dt>Name from</dt>") {
		t.Error("the name source is still a fact card")
	}
}

func TestInsightDeviceDrawerShowsWhereTheNameCameFromBesideIt(t *testing.T) {
	t.Parallel()
	view := InsightDeviceDrawerView{Device: InsightDeviceView{Key: "mac:b8:27:eb:33:0c:c6", Label: "front-door-doorbell", NameSource: "UniFi"}}
	for _, canName := range []bool{false, true} {
		view.CanName = canName
		markup := renderComponent(t, InsightDeviceDrawer(view))
		if !strings.Contains(markup, `<span class="sr-only">Name from </span>UniFi</span>`) {
			t.Errorf("CanName=%v: drawer header is missing the name source badge", canName)
		}
		if count := strings.Count(markup, ">UniFi</span>"); count != 1 {
			t.Errorf("CanName=%v: name source shown %d times, want once", canName, count)
		}
		if got := strings.Contains(markup, `title="Rename device"`); got != canName {
			t.Errorf("CanName=%v: rename button shown = %v", canName, got)
		}
	}
}
