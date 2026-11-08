package clustertest

import (
	"net"
	"strconv"
	"testing"
)

func TestAllocatedPortsAreUniqueAndBelowTheEphemeralRange(t *testing.T) {
	seen := map[string]bool{}
	for range 500 {
		address := AllocateTCPAddress(t)
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatal(err)
		}
		number, _ := strconv.Atoi(port)
		if number < lowestListenPort || number > highestListenPort {
			t.Fatalf("port %d is outside %d-%d", number, lowestListenPort, highestListenPort)
		}
		if seen[address] {
			t.Fatalf("%s handed out twice", address)
		}
		seen[address] = true
	}
}
