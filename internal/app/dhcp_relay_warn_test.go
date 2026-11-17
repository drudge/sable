package app

import (
	"bytes"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/dhcp"
)

// A relay pointed at Sable for a network with no scope is a setup mistake
// the operator can't see from the client, so it is a warning, once an hour
// per relay, naming the relay's address and any link selection hint it sent
// (#673). The remembered relays are bounded.
func TestDHCPServerWarnsOnceAboutARelayWithNoScope(t *testing.T) {
	var logs bytes.Buffer
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	server := &dhcpServer{now: func() time.Time { return now }, logger: slog.New(slog.NewTextHandler(&logs, nil))}
	request := dhcpTestPacket(dhcp.Discover, dhcp.Option{Code: 82, Data: []byte{1, 2, 0, 7, 5, 4, 10, 0, 30, 0}})
	request.GIAddr = netip.MustParseAddr("192.168.99.1")

	server.warnRelayNoScope(request)
	line := logs.String()
	for _, want := range []string{"level=WARN", "relay_address=192.168.99.1", "client_subnet_hint=10.0.30.0", "RFC 3527"} {
		if !strings.Contains(line, want) {
			t.Fatalf("warning %q doesn't say %q", line, want)
		}
	}
	now = now.Add(30 * time.Minute)
	server.warnRelayNoScope(request)
	if count := strings.Count(logs.String(), "level=WARN"); count != 1 {
		t.Fatalf("%d warnings within the hour; want 1", count)
	}
	now = now.Add(31 * time.Minute)
	server.warnRelayNoScope(request)
	if count := strings.Count(logs.String(), "level=WARN"); count != 2 {
		t.Fatalf("%d warnings after the hour; want 2", count)
	}

	for host := range dhcpRelayWarnLimit * 3 {
		forged := request
		forged.GIAddr = netip.AddrFrom4([4]byte{172, 16, byte(host >> 8), byte(host)})
		server.warnRelayNoScope(forged)
		if len(server.relayWarned) > dhcpRelayWarnLimit {
			t.Fatalf("%d relays remembered; want at most %d", len(server.relayWarned), dhcpRelayWarnLimit)
		}
	}
}
