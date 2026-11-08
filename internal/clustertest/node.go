package clustertest

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/drudge/sable/internal/app"
	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/config"
)

// Node is a running Sable node, in-process or a child binary.
type Node struct {
	cancel context.CancelFunc
	done   chan error
	logs   *synchronizedBuffer
	stop   sync.Once

	mu       sync.Mutex
	process  *os.Process // the child process running now
	stopping bool        // set once the node is told to stop
}

// restartExitCode is Sable's controlled restart: the installed service starts
// the process again, which then runs the binary an update put in place.
const restartExitCode = 75

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer strings.Builder
}

func (buffer *synchronizedBuffer) Write(contents []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(contents)
}

func (buffer *synchronizedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

// NodeConfiguration returns the default configuration for a test node on the given ports.
func NodeConfiguration(directory string, ports Ports, nodeName string, certificate certificates.GeneratedCertificate) config.Config {
	configuration := config.Defaults()
	configuration.Server.HTTPListen = ports.HTTP
	configuration.Server.HTTPSListen = ports.HTTPS
	configuration.Server.DNSListen = []string{ports.DNS}
	configuration.Server.ShutdownTimeout = config.Duration{Duration: shutdownTimeout}
	configuration.Database.DSN = filepath.Join(directory, "data", "sable.db")
	configuration.Resolver.DNSSECValidation = false
	configuration.Resolver.DNSSECTrustAnchorUpdates = false
	configuration.QueryLog.Enabled = false
	configuration.EncryptedDNS.CertificateFile = certificate.CertificateFile
	configuration.EncryptedDNS.PrivateKeyFile = certificate.PrivateKeyFile
	configuration.Security.Enabled = false
	configuration.Cluster.NodeName = nodeName
	configuration.Cluster.AdvertiseURL = "https://" + ports.HTTPS
	configuration.Cluster.TrustAnchorFile = certificate.CAFile
	configuration.Reload.Watch = false
	return configuration
}

// WriteConfiguration writes the configuration to sable.toml in directory and returns its path.
func WriteConfiguration(t *testing.T, directory string, configuration config.Config) string {
	t.Helper()
	contents, err := toml.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "sable.toml")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// StartNode starts a node and waits until its health endpoint answers. It
// runs the binary named by SABLE_INTEGRATION_BINARY when that is set, and
// runs the node in-process otherwise.
func StartNode(t *testing.T, configurationPath string, client *http.Client, httpsAddress string) *Node {
	t.Helper()
	if binaryPath := strings.TrimSpace(os.Getenv("SABLE_INTEGRATION_BINARY")); binaryPath != "" {
		return StartBinaryNode(t, binaryPath, nil, configurationPath, client, httpsAddress)
	}
	node := &Node{done: make(chan error, 1), logs: &synchronizedBuffer{}}
	ctx, cancel := context.WithCancel(context.Background())
	node.cancel = cancel
	go func() {
		node.done <- app.Run(ctx, configurationPath, Logger(node.logs))
	}()
	waitStarted(t, node, client, httpsAddress)
	return node
}

// StartBinaryNode runs binaryPath as a child process with environment added
// to the test's own, and waits until its health endpoint answers.
func StartBinaryNode(t *testing.T, binaryPath string, environment []string, configurationPath string, client *http.Client, httpsAddress string) *Node {
	t.Helper()
	node := &Node{done: make(chan error, 1), logs: &synchronizedBuffer{}}
	node.cancel = node.interrupt
	command, err := node.launch(binaryPath, environment, configurationPath)
	if err != nil {
		t.Fatalf("start Sable integration binary: %v", err)
	}
	go func() { node.done <- command.Wait() }()
	waitStarted(t, node, client, httpsAddress)
	return node
}

// StartSupervisedBinaryNode runs binaryPath like StartBinaryNode and, like
// Sable's installed service, starts it again each time it exits with code
// 75, so a node can install an update and restart into it. restarted, if
// set, is called after each restart.
func StartSupervisedBinaryNode(t *testing.T, binaryPath string, environment []string, configurationPath string, client *http.Client, httpsAddress string, restarted func()) *Node {
	t.Helper()
	node := &Node{done: make(chan error, 1), logs: &synchronizedBuffer{}}
	node.cancel = node.interrupt
	command, err := node.launch(binaryPath, environment, configurationPath)
	if err != nil {
		t.Fatalf("start Sable integration binary: %v", err)
	}
	go func() {
		node.done <- node.supervise(command, func() (*exec.Cmd, error) {
			return node.launch(binaryPath, environment, configurationPath)
		}, restarted)
	}()
	waitStarted(t, node, client, httpsAddress)
	return node
}

// launch starts one child process unless the node is stopping, in which case
// it returns a nil command.
func (node *Node) launch(binaryPath string, environment []string, configurationPath string) (*exec.Cmd, error) {
	node.mu.Lock()
	defer node.mu.Unlock()
	if node.stopping {
		return nil, nil
	}
	command := exec.Command(binaryPath, "serve", "--config", configurationPath)
	command.Env = append(os.Environ(), environment...)
	command.Stdout = node.logs
	command.Stderr = node.logs
	if err := command.Start(); err != nil {
		return nil, err
	}
	node.process = command.Process
	return command, nil
}

// supervise waits on command and relaunches it after each controlled
// restart, returning how the last process ended.
func (node *Node) supervise(command *exec.Cmd, relaunch func() (*exec.Cmd, error), restarted func()) error {
	for {
		err := command.Wait()
		var exited *exec.ExitError
		if !errors.As(err, &exited) || exited.ExitCode() != restartExitCode {
			return err
		}
		next, err := relaunch()
		if err != nil || next == nil {
			return err
		}
		command = next
		if restarted != nil {
			restarted()
		}
	}
}

// interrupt tells the running child process to shut down and keeps a
// supervised node from starting another.
func (node *Node) interrupt() {
	node.mu.Lock()
	defer node.mu.Unlock()
	node.stopping = true
	_ = node.process.Signal(os.Interrupt)
}

func (node *Node) currentProcess() *os.Process {
	node.mu.Lock()
	defer node.mu.Unlock()
	return node.process
}

func waitStarted(t *testing.T, node *Node, client *http.Client, httpsAddress string) {
	t.Helper()
	t.Cleanup(func() { StopNode(t, node) })
	WaitForCondition(t, node, func() bool {
		response, err := client.Get("https://" + httpsAddress + "/api/v1/health")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK
	})
}

// KillNode ends a child-process node with SIGKILL, so it gets no chance to
// shut down cleanly, and waits for the process to exit.
func KillNode(t *testing.T, node *Node) {
	t.Helper()
	if node.currentProcess() == nil {
		t.Fatal("only a child-process node can be killed")
	}
	node.stop.Do(func() {
		node.mu.Lock()
		node.stopping = true
		process := node.process
		node.mu.Unlock()
		if err := process.Kill(); err != nil {
			t.Errorf("kill Sable integration node: %v", err)
		}
		select {
		case <-node.done:
		case <-time.After(Timeout):
			t.Errorf("killed Sable integration node did not exit\n%s", node.logs.String())
		}
	})
}

// StopNode stops the node once and reports a failed shutdown.
func StopNode(t *testing.T, node *Node) {
	t.Helper()
	node.stop.Do(func() {
		node.cancel()
		select {
		case err := <-node.done:
			if err != nil {
				t.Errorf("stop Sable integration node: %v\n%s", err, node.logs.String())
			}
		case <-time.After(Timeout):
			t.Errorf("Sable integration node did not stop\n%s", node.logs.String())
		}
	})
}

// Logger returns a debug-level text logger writing to writer.
func Logger(writer io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
