package clustertest

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/dnsclient"
)

const (
	// Timeout bounds how long a test waits for a node condition.
	Timeout = 15 * time.Second
	// PollingInterval is the pause between condition checks.
	PollingInterval = 100 * time.Millisecond

	// shutdownTimeout is the graceful shutdown limit configured on test nodes.
	shutdownTimeout = 5 * time.Second
	// certificateLife is how long generated test certificates stay valid.
	certificateLife = 24 * time.Hour
)

// WaitForClusterState polls the cluster state until ready returns true.
func WaitForClusterState(t *testing.T, node *Node, client *http.Client, httpsAddress string, ready func(cluster.State) bool) cluster.State {
	t.Helper()
	var state cluster.State
	WaitForConditionWithDetails(t, node, func() bool {
		state = FetchClusterState(t, client, httpsAddress)
		return ready(state)
	}, func() any {
		return state
	})
	return state
}

// WaitForBlockedDNSResponse waits until the node answers domain with the blocked-by-Sable TXT report.
func WaitForBlockedDNSResponse(t *testing.T, node *Node, dnsAddress, domain string) {
	t.Helper()
	WaitForCondition(t, node, func() bool {
		result, err := dnsclient.Query(context.Background(), dnsclient.Request{
			Server: dnsAddress, Name: domain, Type: "TXT", Transport: "udp", Timeout: time.Second,
		})
		if err != nil || result.Response.Rcode != dns.RcodeSuccess || len(result.Response.Answer) != 1 {
			return false
		}
		report, ok := result.Response.Answer[0].(*dns.TXT)
		return ok && len(report.Txt) == 1 && report.Txt[0] == "blocked by Sable"
	})
}

// WaitForCondition polls condition until it is true, failing if the node stops or Timeout passes.
func WaitForCondition(t *testing.T, node *Node, condition func() bool) {
	t.Helper()
	WaitForConditionWithDetails(t, node, condition, nil)
}

// WaitForConditionWithDetails is WaitForCondition with details reported on timeout.
func WaitForConditionWithDetails(t *testing.T, node *Node, condition func() bool, details func() any) {
	t.Helper()
	deadline := time.Now().Add(Timeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-node.done:
			t.Fatalf("Sable integration node stopped early: %v\n%s", err, node.logs.String())
		default:
		}
		if condition() {
			return
		}
		time.Sleep(PollingInterval)
	}
	if details != nil {
		t.Fatalf("timed out waiting for Sable integration node; last observed state: %#v\n%s", details(), node.logs.String())
	}
	t.Fatalf("timed out waiting for Sable integration node\n%s", node.logs.String())
}
