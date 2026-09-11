package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
)

// Both binaries contain the current source. These labels exercise a stable
// release upgrade without publishing or downloading an actual GitHub release.
const (
	updateDemoCurrent      = "1.0.1"
	updateDemoTarget       = "1.0.2"
	updateDemoZone         = "demo.vandelay.test."
	updateDemoRestartDelay = 2 * time.Second
)

func runUpdateDemo(root string, basePort int, smoke bool) error {
	if runtime.GOOS == "windows" {
		return errors.New("the update demo supervisor requires macOS or Linux")
	}
	if err := checkUpdateDemoPorts(basePort); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	workspace, err := os.MkdirTemp(root, "run-")
	if err != nil {
		return err
	}
	fmt.Println("Disposable update demo:", workspace)
	fmt.Printf("Building current source twice, labeled %s and %s (local demonstration releases).\n", updateDemoCurrent, updateDemoTarget)
	current, err := buildUpdateDemoBinary(ctx, workspace, updateDemoCurrent)
	if err != nil {
		return err
	}
	target, err := buildUpdateDemoBinary(ctx, workspace, updateDemoTarget)
	if err != nil {
		return err
	}
	feed, err := startUpdateDemoFeed(workspace, target)
	if err != nil {
		return err
	}
	defer feed.Close()
	fmt.Println("Local release feed:", feed.URL)
	nodes, err := buildUpdateDemoNodes(ctx, workspace, basePort)
	if err != nil {
		return err
	}
	supervisor := &updateDemoSupervisor{}
	defer supervisor.stop()
	for _, member := range nodes {
		if err := supervisor.start(ctx, member, current, feed.URL); err != nil {
			return err
		}
	}
	operator := newConsole(nodes[0].ConsoleURL())
	if err := operator.CreateOperator(operatorUsername, operatorPassword, operatorName, operatorEmail); err != nil {
		return err
	}
	if _, err := operator.post("/ui/zones/add", url.Values{"name": {strings.TrimSuffix(updateDemoZone, ".")}, "type": {"primary"}}); err != nil {
		return err
	}
	if err := formCluster(operator, nodes); err != nil {
		return err
	}
	if err := waitForClusterSync(ctx, operator, len(nodes)); err != nil {
		return err
	}
	probe := &updateDemoProbe{}
	probeCtx, stopProbe := context.WithCancel(ctx)
	defer stopProbe()
	go probe.run(probeCtx, nodes)
	if smoke {
		return smokeUpdateDemo(ctx, operator, nodes, supervisor, probe)
	}
	fmt.Printf("\nOpen %s and sign in:\n  Username: %s\n  Password: %s\n", nodes[0].ConsoleURL(), operatorUsername, operatorPassword)
	fmt.Println("Choose Release notes in the update notification to open the notes dialog. Install update updates this node; Cluster > Update all runs a rolling cluster upgrade.")
	fmt.Println("Watch replica restarts, followed by the primary. Reload the primary console after its restart.")
	fmt.Println("DNS availability and restart order appear below. Ctrl-C stops all demo nodes; run again for a fresh demo.")
	for _, member := range nodes {
		fmt.Printf("  %s: %s (DNS %s)\n", member.Name, member.ConsoleURL(), member.Ports.dns)
	}
	<-ctx.Done()
	return nil
}

func checkUpdateDemoPorts(basePort int) error {
	if basePort < 1024 || basePort+200+len(clusterNodes)-1 > 65535 {
		return errors.New("choose an unprivileged base port with room for the HTTP, HTTPS, and DNS listeners")
	}
	for index := range clusterNodes {
		for _, offset := range []int{0, 100, 200} {
			address := fmt.Sprintf("127.0.0.1:%d", basePort+offset+index)
			listener, err := net.Listen("tcp", address)
			if err != nil {
				return fmt.Errorf("demo port %s is unavailable; choose another -base-port: %w", address, err)
			}
			listener.Close()
			if offset == 200 {
				packet, err := net.ListenPacket("udp", address)
				if err != nil {
					return fmt.Errorf("demo DNS port %s is unavailable: %w", address, err)
				}
				packet.Close()
			}
		}
	}
	return nil
}

func buildUpdateDemoBinary(ctx context.Context, workspace, release string) (string, error) {
	binary := filepath.Join(workspace, "build", release, "sable")
	if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
		return "", err
	}
	flags := "-s -w -X github.com/drudge/sable/internal/version.Release=" + release +
		" -X github.com/drudge/sable/internal/version.Commit=local-update-demo" +
		" -X github.com/drudge/sable/internal/version.BuiltAt=" + time.Now().UTC().Format(time.RFC3339)
	command := exec.CommandContext(ctx, "go", "build", "-tags", "updatedemo", "-trimpath", "-ldflags", flags, "-o", binary, "./cmd/sable")
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("build demo %s: %w", release, err)
	}
	return binary, nil
}

func buildUpdateDemoNodes(ctx context.Context, workspace string, basePort int) ([]*node, error) {
	nodes := make([]*node, 0, len(clusterNodes))
	for index, fixture := range clusterNodes {
		member, err := newNode(ctx, workspace, fixture.Name, nodePorts{
			http:  fmt.Sprintf("127.0.0.1:%d", basePort+index),
			https: fmt.Sprintf("127.0.0.1:%d", basePort+100+index),
			dns:   fmt.Sprintf("127.0.0.1:%d", basePort+200+index),
		}, func(configuration *config.Config) {
			configuration.Security.Enabled = index == 0
			configuration.Updates.RestartManaged = true
			configuration.Updates.CheckOnLogin = true
			configuration.Blocking.Enabled = false
		})
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, member)
	}
	return nodes, nil
}

// Each process owns a separate binary. Exit 75 is the same controlled restart
// used by Sable's installed service; the next launch runs the replaced file.
type updateDemoSupervisor struct {
	mu       sync.Mutex
	restarts []string
	cancels  []context.CancelFunc
	wg       sync.WaitGroup
}

func (supervisor *updateDemoSupervisor) start(ctx context.Context, member *node, current, feedURL string) error {
	binary := filepath.Join(member.Directory, "bin", "sable")
	if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
		return err
	}
	contents, err := os.ReadFile(current)
	if err != nil {
		return err
	}
	if err := os.WriteFile(binary, contents, 0o755); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(member.Directory, "sable.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	nodeCtx, cancel := context.WithCancel(ctx)
	supervisor.cancels = append(supervisor.cancels, cancel)
	supervisor.wg.Add(1)
	go func() {
		defer supervisor.wg.Done()
		defer logFile.Close()
		for nodeCtx.Err() == nil {
			command := exec.CommandContext(nodeCtx, binary, "serve", "--config", member.configurationPath)
			command.Env = append(os.Environ(), "SABLE_DEMO_RELEASE_API="+feedURL, "SABLE_UPDATE_BINARY_PATH="+binary, "SABLE_GITHUB_TOKEN=", "GITHUB_TOKEN=")
			command.Stdout, command.Stderr = logFile, logFile
			command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
			command.WaitDelay = 20 * time.Second
			err := command.Run()
			if nodeCtx.Err() != nil {
				return
			}
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 75 {
				fmt.Printf("%s stopped unexpectedly: %v (see %s/sable.log)\n", member.Name, err, member.Directory)
				return
			}
			supervisor.mu.Lock()
			supervisor.restarts = append(supervisor.restarts, member.Name)
			supervisor.mu.Unlock()
			fmt.Println("Controlled restart:", member.Name)
			select {
			case <-nodeCtx.Done():
				return
			case <-time.After(updateDemoRestartDelay):
			}
		}
	}()
	fmt.Println("Starting", member.Name, "at", member.ConsoleURL())
	return member.waitForConsole(ctx)
}

func (supervisor *updateDemoSupervisor) stop() {
	for _, cancel := range supervisor.cancels {
		cancel()
	}
	supervisor.wg.Wait()
}

type updateDemoProbe struct {
	mu      sync.Mutex
	samples int
	outages int
}

func (probe *updateDemoProbe) run(ctx context.Context, nodes []*node) {
	previous := -1
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		available := 0
		for _, member := range nodes {
			query := new(dns.Msg).SetQuestion(updateDemoZone, dns.TypeNS)
			client := &dns.Client{Timeout: 300 * time.Millisecond}
			answer, _, err := client.ExchangeContext(ctx, query, member.Ports.dns)
			if err == nil && answer.Rcode == dns.RcodeSuccess && len(answer.Answer) > 0 {
				available++
			}
		}
		if ctx.Err() != nil {
			return
		}
		probe.mu.Lock()
		probe.samples++
		if available == 0 {
			probe.outages++
		}
		probe.mu.Unlock()
		if previous != available {
			fmt.Printf("DNS probe: %d/%d nodes answering %s\n", available, len(nodes), updateDemoZone)
			previous = available
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func smokeUpdateDemo(ctx context.Context, operator *console, nodes []*node, supervisor *updateDemoSupervisor, probe *updateDemoProbe) error {
	if _, err := operator.post("/ui/updates/automatic-check", nil); err != nil {
		return err
	}
	if _, err := operator.post("/ui/updates/cluster", url.Values{"version": {updateDemoTarget}}); err != nil {
		return err
	}
	fmt.Println("Smoke check: rolling update started")
	deadline := time.NewTimer(3 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	statePath := filepath.Join(nodes[0].Configuration.Cluster.DataDirectory, "update-rollout.json")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("update demo rollout timed out")
		case <-ticker.C:
		}
		contents, err := os.ReadFile(statePath)
		if err != nil {
			continue
		}
		var status cluster.RolloutStatus
		if err := json.Unmarshal(contents, &status); err != nil {
			return err
		}
		if status.Phase == "failed" {
			return fmt.Errorf("rollout failed: %s", status.Error)
		}
		if status.Phase != "complete" {
			continue
		}
		if err := waitForClusterSync(ctx, operator, len(nodes)); err != nil {
			return err
		}
		supervisor.mu.Lock()
		restarts := append([]string(nil), supervisor.restarts...)
		supervisor.mu.Unlock()
		if len(restarts) != len(nodes) || restarts[len(restarts)-1] != nodes[0].Name {
			return fmt.Errorf("unexpected restart order: %v", restarts)
		}
		for _, member := range status.Nodes {
			if member.Phase != "complete" {
				return fmt.Errorf("%s did not finish: %s", member.Name, member.Phase)
			}
		}
		probe.mu.Lock()
		samples, outages := probe.samples, probe.outages
		probe.mu.Unlock()
		if samples == 0 || outages != 0 {
			return fmt.Errorf("DNS probe: %d samples, %d outages", samples, outages)
		}
		fmt.Printf("PASS: all nodes updated to %s and synchronized; restart order %v; %d DNS samples with no all-node outage.\n", updateDemoTarget, restarts, samples)
		return nil
	}
}
