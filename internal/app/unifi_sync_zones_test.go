package app

import (
	"slices"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/zone"
)

// forwarderZone builds a Forwarder zone that sends every name it does not
// answer itself to an upstream, the way one sits in front of a live domain.
func forwarderZone(t *testing.T, name string, records ...zone.Record) zone.Zone {
	t.Helper()
	current, err := zone.NewPrimary(name, 300, "", "", syncTestTime)
	if err != nil {
		t.Fatalf("NewPrimary: %v", err)
	}
	current.Type = "forwarder"
	current.Records = append(current.Records, zone.Record{Name: "@", Type: "FWD", TTL: 300, Value: "udp 0 192.0.2.53:53"})
	current.Records = append(current.Records, records...)
	return current
}

func hasRecord(target zone.Zone, name, recordType string) bool {
	return slices.ContainsFunc(target.Records, func(record zone.Record) bool {
		return record.Name == name && record.Type == recordType
	})
}

// A Forwarder zone answers its own records and forwards the rest, so it can
// hold synchronized hosts in front of the domain it forwards.
func TestUniFiSyncPublishesIntoForwarderZone(t *testing.T) {
	editor := &stubZoneEditor{zones: []zone.Zone{forwarderZone(t, "clients.example.net")}}
	syncer := newTestSyncer(t, testSettings(mapping("net-lan", "Default", "clients.example.net")), editor, &stubReader{inventory: testInventory()})

	syncer.runOnce(t.Context())

	if status := syncer.Status(); status.LastError != "" || len(status.Skipped) != 0 {
		t.Fatalf("sync reported error %q, skipped %v", status.LastError, status.Skipped)
	}
	forward := editor.zone(t, "clients.example.net")
	if forward.Type != "forwarder" {
		t.Fatalf("zone type = %q, want it left a forwarder", forward.Type)
	}
	if got := recordValue(t, forward, "printer.default", "A"); got != "192.168.1.10" {
		t.Fatalf("printer A = %q", got)
	}
	if !hasRecord(forward, "@", "FWD") {
		t.Fatalf("the zone's forwarding was lost: %+v", forward.Records)
	}
	if got := recordValue(t, editor.zone(t, "1.168.192.in-addr.arpa"), "10", "PTR"); got != "printer.default.clients.example.net." {
		t.Fatalf("printer PTR = %q", got)
	}
	if err := zone.ValidateAll(editor.Current().Zones, nil); err != nil {
		t.Fatalf("synchronized zones failed validation: %v", err)
	}
}

// A PTR whose name has no address fails the forward-confirmed check RFC 1912
// §2.1 asks for, so a host the forward zone cannot take gets no PTR either.
func TestUniFiSyncSkipsPTRWhenForwardZoneRefuses(t *testing.T) {
	editor := &stubZoneEditor{zones: []zone.Zone{{
		Name: "clients.example.net", Type: "secondary", DefaultTTL: 300,
		PrimaryServers: []string{"192.0.2.1:53"}, PrimaryProtocol: "tcp",
	}}}
	syncer := newTestSyncer(t, testSettings(mapping("net-lan", "Default", "clients.example.net")), editor, &stubReader{inventory: testInventory()})

	plan, err := syncer.Preview(t.Context(), syncer.configuration.Current().Config.UniFi)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if skipped := strings.Join(plan.Skipped, "\n"); !strings.Contains(skipped, "secondary zone") {
		t.Fatalf("preview did not explain the refused zone: %q", skipped)
	}
	syncer.runOnce(t.Context())

	for _, current := range editor.Current().Zones {
		for _, record := range current.Records {
			if record.Source == zone.SourceUniFi {
				t.Fatalf("published %+v in %s although its forward zone refused the host", record, current.Name)
			}
		}
		if current.Name == "1.168.192.in-addr.arpa" {
			t.Fatalf("created reverse zone %s with nothing to publish", current.Name)
		}
	}
	if skipped := strings.Join(syncer.Status().Skipped, "\n"); !strings.Contains(skipped, "secondary zone") {
		t.Fatalf("status did not explain the refused zone: %q", skipped)
	}
}

// A name the operator answers with a record of their own stays theirs: beside
// a CNAME an address breaks RFC 1034 §3.6.2, and beside their address or
// forwarding it would quietly change the answer.
func TestUniFiSyncLeavesHandAuthoredNamesAlone(t *testing.T) {
	inventory := testInventory()
	inventory.Hosts[1].NetworkID = "net-lan"
	inventory.Hosts[1].Address = inventory.Hosts[0].Address.Next()
	editor := &stubZoneEditor{zones: []zone.Zone{forwarderZone(t, "clients.example.net",
		zone.Record{Name: "printer.default", Type: "CNAME", TTL: 300, Value: "print-server.example.net."},
	)}}
	syncer := newTestSyncer(t, testSettings(mapping("net-lan", "Default", "clients.example.net")), editor, &stubReader{inventory: inventory})

	syncer.runOnce(t.Context())

	forward := editor.zone(t, "clients.example.net")
	if hasRecord(forward, "printer.default", "A") {
		t.Fatalf("an A record was published beside the operator's CNAME: %+v", forward.Records)
	}
	if got := recordValue(t, forward, "printer.default", "CNAME"); got != "print-server.example.net." {
		t.Fatalf("hand-authored CNAME = %q, want it untouched", got)
	}
	if got := recordValue(t, forward, "laptop.default", "A"); got != "192.168.1.11" {
		t.Fatalf("laptop A = %q", got)
	}
	reverse := editor.zone(t, "1.168.192.in-addr.arpa")
	if hasRecord(reverse, "10", "PTR") {
		t.Fatalf("a PTR was published for the skipped printer: %+v", reverse.Records)
	}
	if !hasRecord(reverse, "11", "PTR") {
		t.Fatalf("the laptop lost its PTR: %+v", reverse.Records)
	}
	skipped := strings.Join(syncer.Status().Skipped, "\n")
	if !strings.Contains(skipped, "printer.default.clients.example.net already has a hand-authored CNAME record") {
		t.Fatalf("status did not explain the claimed name: %q", skipped)
	}
	if err := zone.ValidateAll(editor.Current().Zones, nil); err != nil {
		t.Fatalf("synchronized zones failed validation: %v", err)
	}
}

// A record the sync published earlier gives way once the operator adds their
// own address at the same name.
func TestUniFiSyncYieldsWhenOperatorClaimsName(t *testing.T) {
	editor := &stubZoneEditor{}
	syncer := newTestSyncer(t, testSettings(mapping("net-lan", "Default", "clients.example.net")), editor, &stubReader{inventory: testInventory()})
	syncer.runOnce(t.Context())

	if err := editor.UpdateZones(t.Context(), func(zones *[]zone.Zone) error {
		index := slices.IndexFunc(*zones, func(candidate zone.Zone) bool { return candidate.Name == "clients.example.net" })
		(*zones)[index].Records = append((*zones)[index].Records, zone.Record{Name: "printer.default", Type: "A", Value: "192.168.1.250", TTL: 300})
		return nil
	}); err != nil {
		t.Fatalf("add manual record: %v", err)
	}
	syncer.runOnce(t.Context())

	forward := editor.zone(t, "clients.example.net")
	for _, record := range forward.Records {
		if record.Name == "printer.default" && record.Source == zone.SourceUniFi {
			t.Fatalf("synchronized record kept beside the operator's own: %+v", forward.Records)
		}
	}
	if got := recordValue(t, forward, "printer.default", "A"); got != "192.168.1.250" {
		t.Fatalf("operator's A = %q", got)
	}
}
