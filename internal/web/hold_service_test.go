package web

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/querylog"
)

// holdTestQueries ties addresses to hardware, as Insights does.
type holdTestQueries struct {
	*mcpTestQueries
	tracking bool
}

func (queries holdTestQueries) ClientTracking() bool { return queries.tracking }

func (queries holdTestQueries) ClientIdentities(context.Context, time.Time) ([]querylog.ClientIdentity, error) {
	return []querylog.ClientIdentity{
		{Address: "10.0.0.7", MAC: "DA:A1:19:00:00:01"},
		{Address: "10.0.0.7", MAC: "da:a1:19:00:00:02"}, // an older lease
	}, nil
}

func TestMCPBlockDevice(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	queries := holdTestQueries{mcpTestQueries: server.queries.(*mcpTestQueries), tracking: true}
	server.queries = queries
	configuration.snapshot.Config.MCP.Tools = append(configuration.snapshot.Config.MCP.Tools, "block_device", "unblock_device")
	configuration.snapshot.Config.Clients = []config.Client{{Name: "Leo's Switch", Address: "10.0.0.20"}}
	const token = "sable_pat_blocking"
	call := func(tool string, arguments map[string]any) (map[string]any, string) {
		t.Helper()
		return callMCPToolForTest(t, server, token, tool, arguments)
	}
	holds := func() []config.Hold { return configuration.snapshot.Config.Blocking.Holds }

	// An address Sable ties to hardware holds the device, wherever it goes.
	result, failure := call("block_device", map[string]any{"device": "::ffff:10.0.0.7", "minutes": 30})
	if failure != "" || result["device"] != "da:a1:19:00:00:01" || result["until"] == nil ||
		len(holds()) != 1 || holds()[0].MAC != "da:a1:19:00:00:01" || time.Until(holds()[0].Until) > 30*time.Minute {
		t.Fatalf("block by address = %v %q, holds %+v", result, failure, holds())
	}
	// Blocking again replaces the hold.
	if result, failure = call("block_device", map[string]any{"device": "da:a1:19:00:00:01", "until": "2099-01-01T07:00:00-05:00"}); failure != "" ||
		len(holds()) != 1 || holds()[0].Until.Year() != 2099 {
		t.Fatalf("extend = %v %q, holds %+v", result, failure, holds())
	}
	if result, failure = call("block_device", map[string]any{"device": "leo's switch"}); failure != "" || result["until"] != nil ||
		!strings.Contains(result["message"].(string), "until it is turned off") || len(holds()) != 2 {
		t.Fatalf("block by name = %v %q, holds %+v", result, failure, holds())
	}
	if result, failure = call("unblock_device", map[string]any{"device": "10.0.0.20"}); failure != "" || result["changed"] != true || len(holds()) != 1 {
		t.Fatalf("unblock = %v %q, holds %+v", result, failure, holds())
	}
	revision := configuration.snapshot.Revision
	if result, failure = call("unblock_device", map[string]any{"device": "10.0.0.20"}); failure != "" || result["changed"] != false ||
		configuration.snapshot.Revision != revision {
		t.Fatalf("repeated unblock = %v %q", result, failure)
	}

	for _, test := range []struct {
		arguments map[string]any
		want      string
	}{
		{map[string]any{"device": "10.0.0.8", "minutes": 30, "until": "2099-01-01T07:00:00Z"}, "not both"},
		{map[string]any{"device": "10.0.0.8", "minutes": maximumHoldMinutes + 1}, "minutes must be between"},
		{map[string]any{"device": "10.0.0.8", "until": "tonight"}, "RFC 3339"},
		{map[string]any{"device": "10.0.0.8", "until": "2001-01-01T07:00:00Z"}, "must end in the future"},
		{map[string]any{"device": "Emma's iPad"}, "device name Sable knows"},
	} {
		if _, failure := call("block_device", test.arguments); !strings.Contains(failure, test.want) {
			t.Errorf("block_device(%v) failure = %q, want %q", test.arguments, failure, test.want)
		}
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_reader", "block_device", map[string]any{"device": "10.0.0.8"}); !strings.Contains(failure, "blocking.write") {
		t.Fatalf("reader block = %q", failure)
	}

	// With Insights off, Sable can't follow hardware, so it holds the address.
	queries.tracking = false
	server.queries = queries
	if result, failure = call("block_device", map[string]any{"device": "10.0.0.7"}); failure != "" || result["device"] != "10.0.0.7" {
		t.Fatalf("block with Insights off = %v %q", result, failure)
	}
	if _, failure = call("block_device", map[string]any{"device": "da:a1:19:00:00:03"}); !strings.Contains(failure, "Insights off") {
		t.Fatalf("block by hardware with Insights off = %q", failure)
	}
}
