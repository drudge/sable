package devices

import (
	"testing"
	"time"

	"github.com/drudge/sable/internal/insights"
)

func TestChangesReportAppsADeviceStartedUsing(t *testing.T) {
	t.Parallel()
	day := 24 * time.Hour
	windowStart := testNow.Add(-7 * day)
	laptop := Device{Key: "mac:3c:22:fb:01:02:03", MAC: "3c:22:fb:01:02:03", Name: "george-laptop", Queries: 5_000, NewDomains: 6, FirstSeen: testNow.Add(-40 * day)}
	tv := Device{Key: "ip:10.0.0.8", Queries: 900, NewDomains: 2, FirstSeen: testNow.Add(-40 * day)}
	truncated := Device{Key: "ip:10.0.0.9", Queries: 900, NewDomains: 2, FirstSeen: testNow.Add(-40 * day)}
	histories := map[string][]insights.DomainEvidence{
		laptop.Key: {
			{Name: "gateway.discord.gg", FirstSeen: testNow.Add(-3 * time.Hour)},
			{Name: "discord.com", FirstSeen: testNow.Add(-2 * time.Hour)},
			{Name: "store.steampowered.com", FirstSeen: testNow.Add(-2 * day)},
			// YouTube was already in use before the period.
			{Name: "i.ytimg.com", FirstSeen: testNow.Add(-time.Hour)},
			{Name: "www.youtube.com", FirstSeen: testNow.Add(-30 * day)},
			// Operating system traffic never counts as a new app.
			{Name: "mesu.apple.com", FirstSeen: testNow.Add(-time.Hour)},
		},
		tv.Key:        {{Name: "api.example.net", FirstSeen: testNow.Add(-time.Hour)}},
		truncated.Key: {{Name: "netflix.com", FirstSeen: testNow.Add(-time.Hour)}},
	}
	findings := Changes(ChangesInput{
		Now: testNow, WindowStart: windowStart, SeenSince: testNow.Add(-60 * day),
		Devices: []Device{laptop, tv, truncated},
		DomainHistory: func(device Device) ([]insights.DomainEvidence, bool) {
			return histories[device.Key], device.Key != truncated.Key
		},
	})
	if len(findings) != 1 || findings[0].Kind != KindNewApp {
		t.Fatalf("findings = %+v", findings)
	}
	finding := findings[0]
	if finding.Title != "Started using new apps" || finding.Summary != "Started using Discord and Steam during the selected period." {
		t.Fatalf("finding = %q / %q", finding.Title, finding.Summary)
	}
	if finding.Reasons[0].Text != "First Discord lookup 3 hours ago:" || finding.Reasons[0].Code != "gateway.discord.gg" {
		t.Fatalf("first reason = %+v", finding.Reasons[0])
	}
	if len(finding.Domains) != 3 || finding.Domains[0].Name != "store.steampowered.com" {
		t.Fatalf("domains = %+v", finding.Domains)
	}
	if finding.Subject.Device != laptop.Key {
		t.Fatalf("subject = %+v", finding.Subject)
	}
}

func TestJoinListsReadAsSentences(t *testing.T) {
	t.Parallel()
	if got := insights.JoinAnd([]string{"Discord", "Steam", "Zoom"}); got != "Discord, Steam, and Zoom" {
		t.Errorf("JoinAnd = %q", got)
	}
	if got := insights.JoinOr([]string{"Discord", "Steam"}); got != "Discord or Steam" {
		t.Errorf("JoinOr = %q", got)
	}
}
