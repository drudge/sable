package dhcp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

// Whose lease is it? exchange.owns decides (D23): a reserved client owns the
// active leases bound to its MAC, whatever identifier a row is keyed by.
// These check the paths that ask.

// A reserved host that still holds its pre-reservation lease (keyed by its
// RFC 4361 identifier) shuts down and sends DHCPRELEASE. systemd-networkd
// does this by default. The lease is its own (D16), so it must end.
func TestReview618ReservedClientCanReleaseItsCarriedOverLease(t *testing.T) {
	engine, held, _ := reserveAndReload(t, "")
	release := clientPacket(Release, testMAC, reservingClientID, ourServerID())
	release.CIAddr = held
	now := testNow.Add(10 * time.Minute)
	answer := engine.Handle(now, release, testLink)
	if len(answer.Save) != 1 || answer.Save[0].Address != held || answer.Save[0].State != LeaseReleased {
		t.Errorf("RELEASE of %s by the MAC it is reserved for: drop %q, saved %+v; want the lease released and saved", held, answer.Drop, answer.Save)
	}
	if active := activeFor(engine, testMAC.String()); len(active) != 0 {
		t.Errorf("after RELEASE the engine still has active leases for %s: %v", testMAC, active)
	}
}

// The same host finds its address in use (it ARPs after INIT-REBOOT) and
// declines it. The address must leave the pool for the hold time.
func TestReview618ReservedClientCanDeclineItsCarriedOverLease(t *testing.T) {
	engine, held, _ := reserveAndReload(t, "")
	decline := clientPacket(Decline, testMAC, reservingClientID, ourServerID(), addrOption(optionRequestedIP, held.String()))
	now := testNow.Add(10 * time.Minute)
	answer := engine.Handle(now, decline, testLink)
	if len(answer.Save) != 1 || answer.Save[0].Address != held || answer.Save[0].State != LeaseDeclined {
		t.Errorf("DECLINE of %s by the MAC it is reserved for: drop %q, saved %+v; want the address declined and saved", held, answer.Drop, answer.Save)
	}
	if active := activeFor(engine, testMAC.String()); len(active) != 0 {
		t.Errorf("after DECLINE the engine still has active leases for %s: %v", testMAC, active)
	}
}

// PXE firmware and the OS each took a lease under their own identifier
// (F11's host), then the MAC is reserved at a third address. Moving to the
// reservation must end both old leases, in memory and in Save (D19).
func TestReview618ReservedClientMovingReleasesEveryOldLease(t *testing.T) {
	pxe := Option{Code: optionClientID, Data: []byte{0, 0x44, 0x45, 0x4c, 0x4c, 0x31}}
	before := newTestEngine(t, nil)
	first := bind(t, before, testMAC, pxe)
	second := bind(t, before, testMAC, reservingClientID)
	if first == second {
		t.Fatalf("setup: both identifiers bound %s", first)
	}
	engine := newTestEngine(t, func(settings *config.DHCPScope) {
		settings.Reservations = append(settings.Reservations,
			config.DHCPReservation{MAC: testMAC.String(), Address: "10.0.7.21", Name: "host"})
	})
	engine.Load(before.Leases())
	now := testNow.Add(30 * time.Minute)
	offered, answer := offerThenRequest(t, engine, now, testMAC, reservingClientID)
	if offered != netip.MustParseAddr("10.0.7.21") || answer.Reply == nil || answer.Reply.MessageType() != Ack {
		t.Fatalf("offered %s, answer %+v drop %q; want 10.0.7.21 ACKed", offered, answer.Reply, answer.Drop)
	}
	released := map[netip.Addr]bool{}
	for _, lease := range answer.Save {
		if lease.State == LeaseReleased {
			released[lease.Address] = true
		}
	}
	if !released[first] || !released[second] {
		t.Errorf("Save released %v; want both %s and %s", released, first, second)
	}
	if active := activeFor(engine, testMAC.String()); len(active) != 1 || active[0] != offered {
		t.Errorf("active leases for %s = %v, want only %s", testMAC, active, offered)
	}
}

// Whose lease is it? exchange.owns answers that (D23), and a path that
// compares ClientKey itself forgets the reserved-by-MAC half, as release
// did (F15). This keeps the comparison in the three functions that need it.
func TestReview618OwnershipGoesThroughOwns(t *testing.T) {
	allowed := map[string]bool{"owns": true, "remember": true, "releaseOthers": true}
	files := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(files, entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil || allowed[function.Name.Name] {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				comparison, isBinary := node.(*ast.BinaryExpr)
				if !isBinary || (comparison.Op != token.EQL && comparison.Op != token.NEQ) {
					return true
				}
				for _, side := range []ast.Expr{comparison.X, comparison.Y} {
					if selector, isSelector := side.(*ast.SelectorExpr); isSelector && selector.Sel.Name == "ClientKey" {
						t.Errorf("%s: %s compares ClientKey itself; ask exchange.owns", files.Position(comparison.Pos()), function.Name.Name)
					}
				}
				return true
			})
		}
	}
}
