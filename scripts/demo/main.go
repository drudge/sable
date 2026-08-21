// Command demo builds a complete, disposable Sable deployment filled with
// invented Vandelay Industries data and photographs its console.
//
// Nothing here touches a real network or a real database. A mock UniFi
// controller serves the fixture, the block list caches are generated offline at
// the sizes the real subscriptions have, and the traffic history is written
// straight into a throwaway SQLite file. Every number in the resulting
// screenshots is produced by Sable itself from that fixture.
//
//	go run ./scripts/demo -out docs/assets/screenshots   # capture and exit
//	go run ./scripts/demo -keep                          # leave it running
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/drudge/sable/internal/config"
)

// The controller URL the screenshots show. Sable synchronizes against the mock
// controller on loopback and the configuration is rewritten to this address
// afterwards, so the published image names Vandelay's gateway instead of a port
// on the machine that took the picture. The synchronizer only wakes on its own
// interval, so the rewrite cannot disturb a completed synchronization.
const presentedControllerURL = "https://10.20.10.1"

// unifiSyncInterval is long enough that a capture always lands between two
// synchronizations, and short enough to read as a live integration.
const unifiSyncInterval = 15 * time.Minute

// demoUniFiAPIKey is a fixture: the mock controller accepts anything, and the
// vault it lands in is deleted on the next run.
const demoUniFiAPIKey = "vandelay-demo-controller-key"

func main() {
	root := flag.String("root", filepath.Join("_work", "demo"), "working directory for the demo deployment")
	binary := flag.String("binary", filepath.Join("bin", "sable"), "Sable binary to run")
	output := flag.String("out", "", "directory to write screenshots into (empty skips capture)")
	keep := flag.Bool("keep", false, "leave the deployment running after capture")
	basePort := flag.Int("base-port", 5391, "first console port; each node takes the next one")
	flag.Parse()

	if err := run(*root, *binary, *output, *basePort, *keep); err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}

func run(root, binary, output string, basePort int, keep bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if _, err := os.Stat(binary); err != nil {
		return fmt.Errorf("%s is missing; run `mage build` first", binary)
	}
	fmt.Println("Resetting", root)
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("clear demo workspace: %w", err)
	}

	controller, err := startMockController("127.0.0.1:0")
	if err != nil {
		return err
	}
	defer controller.Close()
	fmt.Println("Mock UniFi controller on", controller.URL())

	nodes, err := buildNodes(ctx, root, controller.URL(), basePort)
	if err != nil {
		return err
	}
	primary := nodes[0]

	// Every node needs the caches, not just the primary: a replica adopts the
	// primary's subscriptions along with the rest of its configuration and
	// would otherwise try to download them.
	fmt.Println("Generating block list caches")
	for _, member := range nodes {
		if err := writeBlockListCaches(member.Directory); err != nil {
			return err
		}
	}
	fmt.Println("Seeding query history")
	if err := seedTraffic(ctx, primary.Configuration.Database.DSN); err != nil {
		return err
	}

	defer stopNodes(nodes)
	for _, member := range nodes {
		fmt.Println("Starting", member.Name, "at", member.ConsoleURL())
		if err := member.Start(ctx, binary); err != nil {
			return err
		}
	}

	operator := newConsole(primary.ConsoleURL())
	fmt.Println("Creating the operator account")
	if err := operator.CreateOperator(operatorUsername, operatorPassword, operatorName, operatorEmail); err != nil {
		return err
	}
	fmt.Println("Storing the UniFi controller credentials")
	if err := operator.StoreUniFiCredentials(controller.URL(), demoUniFiAPIKey); err != nil {
		return err
	}
	if err := formCluster(operator, nodes); err != nil {
		return err
	}
	fmt.Println("Waiting for the replicas to catch up")
	if err := waitForClusterSync(ctx, operator, len(nodes)); err != nil {
		return err
	}
	fmt.Println("Waiting for the first UniFi synchronization")
	if err := waitForUniFiSync(ctx, operator); err != nil {
		return err
	}
	if err := presentControllerURL(primary); err != nil {
		return err
	}

	if output != "" {
		fmt.Println("Capturing screenshots")
		if err := captureShots(ctx, operator, output); err != nil {
			return err
		}
	}
	if keep {
		return waitForShutdown(ctx, nodes)
	}
	return nil
}

// buildNodes lays out the primary and its replicas. Only the primary carries
// the demo's data, because everything else replicates from it.
func buildNodes(ctx context.Context, root, controllerURL string, basePort int) ([]*node, error) {
	nodes := make([]*node, 0, len(clusterNodes))
	for index, member := range clusterNodes {
		ports := nodePorts{
			http:  fmt.Sprintf("127.0.0.1:%d", basePort+index),
			https: fmt.Sprintf("127.0.0.1:%d", basePort+100+index),
			dns:   fmt.Sprintf("127.0.0.1:%d", 8555+index),
		}
		built, err := newNode(ctx, root, member.Name, ports, func(configuration *config.Config) {
			// Only the primary is photographed, so only it carries the fixture
			// and the sign-in the screenshots show.
			configuration.Security.Enabled = index == 0
			if index == 0 {
				applyPrimaryFixture(configuration, controllerURL)
			}
		})
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, built)
	}
	return nodes, nil
}

func stopNodes(nodes []*node) {
	for index := len(nodes) - 1; index >= 0; index-- {
		nodes[index].Stop()
	}
}

// formCluster initializes the primary and enrolls every replica against it.
func formCluster(operator *console, nodes []*node) error {
	fmt.Println("Initializing the cluster on", nodes[0].Name)
	if err := operator.InitializeCluster(clusterDomain, clusterNodes[0].Addresses); err != nil {
		return err
	}
	for index := 1; index < len(nodes); index++ {
		token, err := operator.EnrollmentToken("15m")
		if err != nil {
			return err
		}
		fmt.Println("Enrolling", nodes[index].Name)
		replica := newConsole(nodes[index].ConsoleURL())
		if err := replica.JoinCluster(nodes[0].ClusterURL(), token, clusterNodes[index].Addresses); err != nil {
			return err
		}
	}
	return nil
}

// waitForClusterSync blocks until every node reports itself online and at the
// primary's generation. Replicas reconcile once a second, so this is a short
// wait that keeps a capture from photographing a cluster mid-enrollment.
func waitForClusterSync(ctx context.Context, operator *console, nodes int) error {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		page, err := operator.get("/cluster")
		if err == nil && strings.Count(page, ">In sync<") >= nodes && strings.Count(page, ">Online<") >= nodes {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("the cluster did not finish synchronizing in time")
}

// waitForUniFiSync blocks until the integrations page reports a completed
// synchronization, so the capture never photographs a half-finished one.
func waitForUniFiSync(ctx context.Context, operator *console) error {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		page, err := operator.get("/integrations")
		if err == nil && strings.Contains(page, "Last synchronized") {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("the UniFi synchronizer did not finish in time")
}

// presentControllerURL rewrites the finished deployment to name Vandelay's own
// gateway. Sable reloads the file, and the next synchronization is a quarter of
// an hour away, so the console keeps reporting the run that already succeeded.
func presentControllerURL(primary *node) error {
	primary.Configuration.UniFi.ControllerURL = presentedControllerURL
	if err := primary.writeConfiguration(); err != nil {
		return err
	}
	time.Sleep(3 * time.Second)
	return nil
}

func waitForShutdown(ctx context.Context, nodes []*node) error {
	fmt.Println()
	fmt.Println("Vandelay Industries is up. Sign in with", operatorUsername, "/", operatorPassword)
	for _, member := range nodes {
		fmt.Println("  ", member.Name, member.ConsoleURL())
	}
	fmt.Println("Press Ctrl-C to shut it down.")
	<-ctx.Done()
	fmt.Println("\nShutting down")
	return nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
