package devices

import (
	"fmt"
	"strings"
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

// A device that starts using a tunnel is worth a look, and the tunnel is named
// first even among more apps than a finding lists. It is never crowded out by
// devices that started using ordinary apps more recently.
func TestChangesRaiseRemoteAccessADeviceStartedUsing(t *testing.T) {
	t.Parallel()
	day := 24 * time.Hour
	windowStart := testNow.Add(-7 * day)
	server := Device{Key: "mac:bc:24:11:91:d5:a4", MAC: "bc:24:11:91:d5:a4", Name: "dokploy", Queries: 80_000, NewDomains: 5, FirstSeen: testNow.Add(-40 * day)}
	histories := map[string][]insights.DomainEvidence{
		server.Key: {
			{Name: "discord.com", FirstSeen: testNow.Add(-time.Hour)},
			{Name: "www.netflix.com", FirstSeen: testNow.Add(-2 * time.Hour)},
			{Name: "store.steampowered.com", FirstSeen: testNow.Add(-3 * time.Hour)},
			{Name: "www.reddit.com", FirstSeen: testNow.Add(-4 * time.Hour)},
			{Name: "region1.v2.argotunnel.com", FirstSeen: testNow.Add(-5 * day)},
		},
	}
	devices := []Device{server}
	for index := range 4 {
		busy := Device{Key: fmt.Sprintf("ip:10.0.7.%d", 50+index), Queries: 1_000, NewDomains: 1, FirstSeen: testNow.Add(-40 * day)}
		devices = append(devices, busy)
		histories[busy.Key] = []insights.DomainEvidence{{Name: "discord.com", FirstSeen: testNow.Add(-time.Minute)}}
	}
	findings := Changes(ChangesInput{
		Now: testNow, WindowStart: windowStart, SeenSince: testNow.Add(-60 * day), Devices: devices,
		DomainHistory: func(device Device) ([]insights.DomainEvidence, bool) { return histories[device.Key], true },
	})
	var tunnel *insights.Finding
	for index := range findings {
		if findings[index].Subject.Device == server.Key {
			tunnel = &findings[index]
		}
	}
	if tunnel == nil {
		t.Fatalf("the tunnel was crowded out: %+v", findings)
	}
	if tunnel.Tone != insights.ToneAttention || tunnel.Reasons[0].Text != "Cloudflare Tunnel can let someone reach this network from outside" ||
		!strings.HasPrefix(tunnel.Headline, "dokploy started using Cloudflare Tunnel, ") {
		t.Fatalf("tunnel finding = %+v", tunnel)
	}
}
