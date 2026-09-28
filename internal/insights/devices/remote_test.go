package devices

import (
	"slices"
	"testing"
	"time"

	"github.com/drudge/sable/internal/insights"
)

// A device that uses remote access is reported whether or not it used it
// before, once for each tool, so marking one tool normal leaves another
// showing. Its other addresses count, and a device with none is left alone.
func TestChangesReportRemoteAccessNewOrNot(t *testing.T) {
	t.Parallel()
	day := 24 * time.Hour
	server := Device{
		Key: "mac:bc:24:11:91:d5:a4", MAC: "bc:24:11:91:d5:a4", Name: "dokploy", Queries: 80_000, FirstSeen: testNow.Add(-40 * day),
		Addresses: []Address{{Address: "10.0.7.88"}, {Address: "2603:7083:af01:1500:be24:11ff:fe91:d5a4"}},
	}
	laptop := Device{Key: "ip:10.0.7.80", Name: "Mac", Queries: 5_000, FirstSeen: testNow.Add(-40 * day), Addresses: []Address{{Address: "10.0.7.80"}}}
	findings := Changes(ChangesInput{
		Now: testNow, WindowStart: testNow.Add(-7 * day), SeenSince: testNow.Add(-60 * day),
		Devices: []Device{server, laptop},
		RemoteAccess: map[string][]string{
			"10.0.7.88": {"region1.v2.argotunnel.com", "region2.v2.argotunnel.com"},
			"2603:7083:af01:1500:be24:11ff:fe91:d5a4": {"router4.teamviewer.com", "region1.v2.argotunnel.com"},
			// Not a remote access name, whatever the caller handed over.
			"10.0.7.80": {"www.netflix.com"},
		},
	})
	remote := make([]insights.Finding, 0)
	for _, finding := range findings {
		if finding.Kind == KindRemoteAccess {
			remote = append(remote, finding)
		}
	}
	if len(remote) != 2 {
		t.Fatalf("remote access findings = %+v", remote)
	}
	tunnel, viewer := remote[0], remote[1]
	if tunnel.ID != "devices.remote-access/device:mac:bc:24:11:91:d5:a4/cloudflare-tunnel" ||
		viewer.ID != "devices.remote-access/device:mac:bc:24:11:91:d5:a4/teamviewer" {
		t.Fatalf("IDs = %q, %q", tunnel.ID, viewer.ID)
	}
	if tunnel.Tone != insights.ToneAttention || tunnel.Headline != "dokploy uses Cloudflare Tunnel" ||
		tunnel.Reasons[0].Text != "Cloudflare Tunnel can let someone reach this network from outside" {
		t.Fatalf("tunnel = %+v", tunnel)
	}
	looked := make([]string, 0)
	for _, reason := range tunnel.Reasons {
		if reason.Text == "Looked up" {
			looked = append(looked, reason.Code)
		}
	}
	if !slices.Equal(looked, []string{"region1.v2.argotunnel.com", "region2.v2.argotunnel.com"}) {
		t.Fatalf("looked up = %v", looked)
	}
	// Remote access is never also reported as a new app.
	for _, finding := range findings {
		if finding.Kind == KindNewApp {
			t.Fatalf("remote access also reported as a new app: %+v", finding)
		}
	}
}

func TestRemoteAccessOffIsNotLookedFor(t *testing.T) {
	t.Parallel()
	device := Device{Key: "ip:10.0.7.88", Addresses: []Address{{Address: "10.0.7.88"}}, FirstSeen: testNow.Add(-40 * 24 * time.Hour)}
	findings := Changes(ChangesInput{
		Now: testNow, WindowStart: testNow.Add(-7 * 24 * time.Hour), Devices: []Device{device},
		RemoteAccess: map[string][]string{"10.0.7.88": {"connect.ngrok-agent.com"}},
		Off:          map[string]bool{KindRemoteAccess: true},
	})
	if len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
}
