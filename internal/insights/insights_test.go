package insights

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fixedAnalyzer struct {
	findings []Finding
	err      error
}

func (analyzer fixedAnalyzer) Analyze(context.Context, Window) ([]Finding, error) {
	return analyzer.findings, analyzer.err
}

func TestCollectOrdersFindingsAndGivesThemStableIDs(t *testing.T) {
	t.Parallel()
	window := Window{Start: time.Unix(0, 0), End: time.Unix(3600, 0)}
	broken := fixedAnalyzer{err: errors.New("store unavailable")}
	var failures []error
	findings := Collect(context.Background(), window, []Analyzer{
		fixedAnalyzer{findings: []Finding{
			{Kind: "blocking.unique-coverage", Tone: TonePositive, Subject: Subject{Label: "OISD Big", BlockList: "OISD Big"}},
			{Kind: "blocking.low-unique-coverage", Tone: ToneNotice, Subject: Subject{Label: "AdGuard", BlockList: "AdGuard"}},
		}},
		broken,
		fixedAnalyzer{findings: []Finding{
			{Kind: "devices.went-quiet", Tone: ToneAttention, Subject: Subject{Label: "dock-camera-02", Device: "mac:b8:27:eb:33:0c:c3"}},
		}},
	}, func(_ Analyzer, err error) { failures = append(failures, err) })

	if len(failures) != 1 || len(findings) != 3 {
		t.Fatalf("findings = %+v, failures = %v", findings, failures)
	}
	if findings[0].Kind != "devices.went-quiet" || findings[1].Tone != ToneNotice || findings[2].Tone != TonePositive {
		t.Fatalf("order = %s, %s, %s", findings[0].Kind, findings[1].Kind, findings[2].Kind)
	}
	if findings[0].ID != "devices.went-quiet/device:mac:b8:27:eb:33:0c:c3" || !findings[0].ObservedAt.Equal(window.End) {
		t.Fatalf("finding identity = %q at %s", findings[0].ID, findings[0].ObservedAt)
	}
	// The same situation analyzed again, even under a new display name, keeps
	// its identity because the ID follows the durable reference.
	renamed := Subject{Label: "Loading Dock Camera", Device: "mac:b8:27:eb:33:0c:c3"}
	if NewID("devices.went-quiet", renamed) != findings[0].ID {
		t.Fatal("a renamed device produced a different finding ID")
	}
	if NewID("blocking.low-unique-coverage", Subject{Label: "x", Domain: "ads.example"}) != "blocking.low-unique-coverage/domain:ads.example" {
		t.Fatal("a domain subject did not key by domain")
	}
}

func TestSummarizeNamesWhatStandsOut(t *testing.T) {
	t.Parallel()
	findings := []Finding{
		{Headline: "dock-camera-02 went quiet"},
		{Headline: ""},
		{Headline: "front-door-doorbell joined the network"},
		{Headline: "george-laptop started using Discord"},
		{Headline: "file-server woke up at 3 AM"},
	}
	if got := Summarize(findings); got != "dock-camera-02 went quiet, front-door-doorbell joined the network, and george-laptop started using Discord. 1 more thing below." {
		t.Errorf("Summarize = %q", got)
	}
	if got := Summarize(findings[:1]); got != "dock-camera-02 went quiet." {
		t.Errorf("Summarize one = %q", got)
	}
	if got := Summarize(nil); got != "All quiet. Nothing on your network changed in a way that needs a look." {
		t.Errorf("Summarize none = %q", got)
	}
}
