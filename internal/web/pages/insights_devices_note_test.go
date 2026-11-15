package pages

import (
	"strings"
	"testing"
)

// The note under the Devices table lists where a device's name comes from,
// in order. A lease's name now sits between UniFi's and a local host's, and
// the DHCP badge in the rows above it needs the note to say so.
func TestInsightDevicesNoteListsTheDHCPLease(t *testing.T) {
	t.Parallel()
	device := InsightDeviceView{Key: "mac:3c:22:fb:01:02:03", Label: "georges-macbook", NameSource: "DHCP"}
	markup := renderComponent(t, InsightDevices(InsightsOverviewView{Devices: []InsightDeviceView{device}}))
	start := strings.Index(markup, "Sable names each device from")
	if start < 0 {
		t.Fatalf("no naming note under the Devices table:\n%s", markup)
	}
	note, _, _ := strings.Cut(markup[start:], ".")
	if !strings.Contains(note, "DHCP") {
		t.Errorf("the note leaves DHCP out of the naming order: %q", note)
	}
}
