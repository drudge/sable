package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/localnet"
)

type fixedAttachedNetworks []localnet.Network

func (networks fixedAttachedNetworks) Networks() []localnet.Network { return networks }

func (networks fixedAttachedNetworks) Prefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(networks))
	for _, network := range networks {
		prefixes = append(prefixes, network.Prefix)
	}
	return prefixes
}

func attachedNetworksTestServer(t *testing.T, resolver func(*config.Resolver)) *Server {
	t.Helper()
	defaults := config.Defaults()
	if resolver != nil {
		resolver(&defaults.Resolver)
	}
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: defaults, Revision: 1}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration, configuration.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	server.SetAttachedNetworks(fixedAttachedNetworks{
		{Prefix: netip.MustParsePrefix("2001:db8:1234:1500::/64"), Interface: "eth0"},
		{Prefix: netip.MustParsePrefix("2001:db8:1234:1600::/64"), Node: "ns1"},
	})
	return server
}

// Settings → Recursion lists each network private access covers, with the
// interface it's on or the node that shared it.
func TestRecursionSettingsListTheAttachedNetworks(t *testing.T) {
	t.Parallel()
	server := attachedNetworksTestServer(t, nil)
	request := httptest.NewRequest(http.MethodGet, "/settings?tab=recursion", nil)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	body := response.Body.String()
	for _, want := range []string{
		`<div class="read-only-field attached-networks"><span>This Network</span>`,
		`<li><code>2001:db8:1234:1500::/64</code><small>eth0</small></li>`,
		`<li><code>2001:db8:1234:1600::/64</code><small>from ns1</small></li>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("settings page is missing %q", want)
		}
	}
}

// Insights checks addresses against the policy in force: private access
// covers the attached networks, and a listed-clients policy doesn't.
func TestRecursionAllowsCountsAttachedNetworksOnlyForPrivateAccess(t *testing.T) {
	t.Parallel()
	device := "2001:db8:1234:1600::a"
	if !attachedNetworksTestServer(t, nil).recursionAllows()(device) {
		t.Fatal("private access refused a device on an attached network")
	}
	acl := attachedNetworksTestServer(t, func(resolver *config.Resolver) {
		resolver.Recursion, resolver.RecursionClients = "acl", []string{"10.0.0.0/8"}
	})
	if acl.recursionAllows()(device) {
		t.Fatal("a listed-clients policy admitted an attached network it doesn't list")
	}
	if !acl.onAttachedNetwork()(device) || acl.onAttachedNetwork()("2001:db8:9::1") {
		t.Fatal("onAttachedNetwork misjudged an address")
	}
}
