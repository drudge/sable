package neighbors

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestUsableSkipsAddressesThatCannotIdentifyADevice(t *testing.T) {
	t.Parallel()
	device := net.HardwareAddr{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03}
	for _, test := range []struct {
		address string
		mac     net.HardwareAddr
		want    bool
	}{
		{"192.168.1.20", device, true},
		{"fd00::20", device, true},
		{"192.168.1.20", net.HardwareAddr{0, 0, 0, 0, 0, 0}, false},
		{"192.168.1.20", net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, false},
		{"192.168.1.20", net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}, false},
		{"224.0.0.251", device, false},
		{"127.0.0.1", device, false},
		{"192.168.1.20", net.HardwareAddr{0x01}, false},
	} {
		if got := usable(netip.MustParseAddr(test.address), test.mac); got != test.want {
			t.Errorf("usable(%s, %s) = %t, want %t", test.address, test.mac, got, test.want)
		}
	}
}

func TestPrivateMACRecognizesLocallyAdministeredAddresses(t *testing.T) {
	t.Parallel()
	if !PrivateMAC(net.HardwareAddr{0xda, 0xa1, 0x19, 0x00, 0x00, 0x01}) {
		t.Fatal("a randomized phone address was not recognized as private")
	}
	if PrivateMAC(net.HardwareAddr{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03}) {
		t.Fatal("a vendor address was reported as private")
	}
}

func TestReadReturnsEntriesOrReportsUnsupported(t *testing.T) {
	entries, err := Read()
	if errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !usable(entry.Address, entry.MAC) {
			t.Errorf("Read returned unusable entry %+v", entry)
		}
	}
	t.Logf("%d neighbors", len(entries))
}

func netlinkNeighbor(state uint16, address []byte, mac []byte) []byte {
	attribute := func(kind uint16, value []byte) []byte {
		length := 4 + len(value)
		buffer := make([]byte, (length+3)&^3)
		binary.NativeEndian.PutUint16(buffer[0:2], uint16(length))
		binary.NativeEndian.PutUint16(buffer[2:4], kind)
		copy(buffer[4:], value)
		return buffer
	}
	body := make([]byte, ndMessageLength)
	binary.NativeEndian.PutUint16(body[8:10], state)
	body = append(body, attribute(ndaDestination, address)...)
	body = append(body, attribute(ndaLinkAddress, mac)...)
	message := make([]byte, netlinkHeaderLength, netlinkHeaderLength+len(body))
	binary.NativeEndian.PutUint32(message[0:4], uint32(netlinkHeaderLength+len(body)))
	binary.NativeEndian.PutUint16(message[4:6], netlinkNewNeighbor)
	return append(message, body...)
}

func TestParseNeighborMessagesDecodesALinuxDump(t *testing.T) {
	t.Parallel()
	laptop := []byte{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03}
	phone := []byte{0xda, 0xa1, 0x19, 0x00, 0x00, 0x01}
	dump := append(netlinkNeighbor(0x02, []byte{192, 168, 1, 20}, laptop),
		netlinkNeighbor(0x04, netip.MustParseAddr("fd00::20").AsSlice(), phone)...)
	dump = append(dump, netlinkNeighbor(nudFailed, []byte{192, 168, 1, 99}, laptop)...)
	dump = append(dump, netlinkNeighbor(0x02, []byte{192, 168, 1, 1}, []byte{0, 0, 0, 0, 0, 0})...)
	// A done message and trailing garbage end the dump without a panic.
	done := make([]byte, netlinkHeaderLength)
	binary.NativeEndian.PutUint32(done[0:4], netlinkHeaderLength)
	binary.NativeEndian.PutUint16(done[4:6], 3)
	dump = append(append(dump, done...), 0xde, 0xad)

	entries := parseNeighborMessages(dump)
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want the reachable and stale neighbors", entries)
	}
	if entries[0].Address != netip.MustParseAddr("192.168.1.20") || entries[0].MAC.String() != "3c:22:fb:01:02:03" {
		t.Fatalf("first entry = %+v", entries[0])
	}
	if entries[1].Address != netip.MustParseAddr("fd00::20") || !PrivateMAC(entries[1].MAC) {
		t.Fatalf("second entry = %+v", entries[1])
	}
	if got := parseNeighborMessages([]byte{1, 2, 3}); len(got) != 0 {
		t.Fatalf("truncated dump = %+v", got)
	}
}
