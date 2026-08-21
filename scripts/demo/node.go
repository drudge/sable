package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/config"
)

// nodePorts are the listeners one demo Sable server binds.
type nodePorts struct {
	http  string
	https string
	dns   string
}

// node is one Sable server in the demo deployment, together with the paths and
// process needed to start, reconfigure, and stop it.
type node struct {
	Name          string
	Directory     string
	Configuration config.Config
	Ports         nodePorts
	TrustAnchor   string

	configurationPath string
	command           *exec.Cmd
	logFile           *os.File
}

// newNode lays out a node's working directory, generates the TLS material its
// cluster membership needs, and writes its configuration.
func newNode(ctx context.Context, root, name string, ports nodePorts, customize func(*config.Config)) (*node, error) {
	directory := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(directory, "data"), 0o755); err != nil {
		return nil, fmt.Errorf("create %s workspace: %w", name, err)
	}
	certificate, err := certificates.New(nil, discardLogger(), directory).GenerateClusterPKI(ctx,
		certificates.ClusterPKIOptions{
			NodeName:         name,
			Names:            []string{"127.0.0.1"},
			StorageDirectory: filepath.Join("data", "cluster", "pki"),
			ValidFor:         365 * 24 * time.Hour,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("generate %s cluster certificate: %w", name, err)
	}

	configuration := config.Defaults()
	configuration.Server.HTTPListen = ports.http
	configuration.Server.HTTPSListen = ports.https
	configuration.Server.DNSListen = []string{ports.dns}
	configuration.Database.DSN = filepath.Join(directory, "data", "sable.db")
	configuration.Resolver.DNSSECTrustAnchorUpdates = false
	configuration.EncryptedDNS.CertificateFile = certificate.CertificateFile
	configuration.EncryptedDNS.PrivateKeyFile = certificate.PrivateKeyFile
	configuration.Security.SecretKeyFile = filepath.Join(directory, "data", "sable.key")
	configuration.Cluster.DataDirectory = filepath.Join(directory, "data", "cluster")
	configuration.Cluster.NodeName = name
	configuration.Cluster.AdvertiseURL = "https://" + ports.https
	configuration.Cluster.TrustAnchorFile = certificate.CAFile
	configuration.Reload.Watch = true
	if customize != nil {
		customize(&configuration)
	}

	created := &node{
		Name: name, Directory: directory, Configuration: configuration, Ports: ports,
		TrustAnchor:       filepath.Join(directory, certificate.CAFile),
		configurationPath: filepath.Join(directory, "sable.toml"),
	}
	return created, created.writeConfiguration()
}

// writeConfiguration persists the node's configuration. Sable watches the file,
// so this doubles as the way the demo changes a running node.
func (n *node) writeConfiguration() error {
	contents, err := toml.Marshal(n.Configuration)
	if err != nil {
		return fmt.Errorf("encode %s configuration: %w", n.Name, err)
	}
	if err := os.WriteFile(n.configurationPath, contents, 0o600); err != nil {
		return fmt.Errorf("write %s configuration: %w", n.Name, err)
	}
	return nil
}

// ConsoleURL is the plain-HTTP console address the demo drives and photographs.
func (n *node) ConsoleURL() string { return "http://" + n.Ports.http }

// ClusterURL is the HTTPS address other nodes reach this one on.
func (n *node) ClusterURL() string { return "https://" + n.Ports.https }

// Start launches the node and waits for its console to answer.
func (n *node) Start(ctx context.Context, binary string) error {
	logPath := filepath.Join(n.Directory, "sable.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("create %s log: %w", n.Name, err)
	}
	command := exec.Command(binary, "serve", "--config", n.configurationPath)
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("start %s: %w", n.Name, err)
	}
	n.command, n.logFile = command, logFile
	if err := n.waitForConsole(ctx); err != nil {
		n.Stop()
		return fmt.Errorf("%s did not come up (see %s): %w", n.Name, logPath, err)
	}
	return nil
}

func (n *node) waitForConsole(ctx context.Context) error {
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		response, err := client.Get(n.ConsoleURL() + "/api/v1/health")
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode < 500 {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("timed out waiting for the console")
}

// Stop ends the node and waits for it to exit.
func (n *node) Stop() {
	if n.command == nil || n.command.Process == nil {
		return
	}
	_ = n.command.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() {
		_ = n.command.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = n.command.Process.Kill()
		<-done
	}
	if n.logFile != nil {
		n.logFile.Close()
	}
	n.command, n.logFile = nil, nil
}
