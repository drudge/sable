package app

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/querylog"
)

func TestDeviceAddressesFollowEachAddressToItsNewestDevice(t *testing.T) {
	t.Parallel()
	ruleSets := ruleSetsByMAC([]config.Client{
		{Name: "Emma's iPad", MAC: "DA:A1:19:00:00:01", RuleSet: "Kids"},
		{Name: "Work laptop", MAC: "da:a1:19:00:00:02", RuleSet: "Work"},
		{Name: "Printer", MAC: "da:a1:19:00:00:03"},
		{Name: "Guests", Address: "10.0.40.0/24", RuleSet: "Work"},
	})
	if len(ruleSets) != 2 || ruleSets["da:a1:19:00:00:01"] != "Kids" {
		t.Fatalf("ruleSetsByMAC() = %v", ruleSets)
	}
	// Newest first, as the store returns them.
	addresses := deviceAddresses(ruleSets, []querylog.ClientIdentity{
		{Address: "10.0.0.5", MAC: "da:a1:19:00:00:03"}, // the printer has it now
		{Address: "fd00::a1", MAC: "da:a1:19:00:00:01"}, // an IPv6 privacy address
		{Address: "10.0.0.7", MAC: "DA:A1:19:00:00:01"}, // the iPad
		{Address: "10.0.0.5", MAC: "da:a1:19:00:00:02"}, // the laptop had it before
		{Address: "::ffff:10.0.0.9", MAC: "da:a1:19:00:00:02"},
		{Address: "not-an-address", MAC: "da:a1:19:00:00:02"},
	})
	want := dnsserver.DeviceAddresses{
		netip.MustParseAddr("fd00::a1"): "Kids",
		netip.MustParseAddr("10.0.0.7"): "Kids",
		netip.MustParseAddr("10.0.0.9"): "Work",
	}
	if len(addresses) != len(want) {
		t.Fatalf("deviceAddresses() = %v, want %v", addresses, want)
	}
	for address, ruleSet := range want {
		if addresses[address] != ruleSet {
			t.Fatalf("deviceAddresses()[%s] = %q, want %q", address, addresses[address], ruleSet)
		}
	}
}

func TestDeviceRuleSetsRebuildOnIdentitiesAndConfiguration(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tracking := true
	reads := make(chan time.Time, 10)
	applied := make(chan dnsserver.DeviceAddresses, 10)
	table := newDeviceRuleSets(
		func(_ context.Context, since time.Time) ([]querylog.ClientIdentity, error) {
			reads <- since
			return []querylog.ClientIdentity{{Address: "10.0.0.7", MAC: "da:a1:19:00:00:01"}}, nil
		},
		func() bool { return tracking },
		func(addresses dnsserver.DeviceAddresses) { applied <- addresses },
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	next := func() dnsserver.DeviceAddresses {
		t.Helper()
		select {
		case addresses := <-applied:
			return addresses
		case <-time.After(5 * time.Second):
			t.Fatal("the table was not rebuilt")
			return nil
		}
	}

	// No device in a rule set by hardware address: nothing to read.
	table.SetClients([]config.Client{{Name: "Switch", Address: "192.0.2.20", RuleSet: "Kids"}})
	go table.Run(ctx)
	if addresses := next(); addresses != nil || len(reads) != 0 {
		t.Fatalf("table without MAC devices = %v after %d reads", addresses, len(reads))
	}

	table.SetClients([]config.Client{{Name: "Emma's iPad", MAC: "da:a1:19:00:00:01", RuleSet: "Kids"}})
	if addresses := next(); addresses[netip.MustParseAddr("10.0.0.7")] != "Kids" {
		t.Fatalf("table = %v, want the iPad in Kids", addresses)
	}
	if since := <-reads; time.Since(since) < 24*time.Hour {
		t.Fatalf("identities read since %s, want the Insights lookback", since)
	}

	recorded := 0
	record := table.Record(func(context.Context, []querylog.ClientIdentity) error { recorded++; return nil })
	if err := record(ctx, nil); err != nil || recorded != 1 {
		t.Fatalf("Record() = %v after %d calls", err, recorded)
	}
	if addresses := next(); len(addresses) != 1 {
		t.Fatalf("table after new identities = %v", addresses)
	}

	// With Insights off, only configured addresses apply.
	tracking = false
	table.Refresh()
	if addresses := next(); addresses != nil {
		t.Fatalf("table with Insights off = %v, want none", addresses)
	}
}
