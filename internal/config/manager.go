package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pelletier/go-toml/v2"
)

type Snapshot struct {
	Config   Config
	Revision uint64
	LoadedAt time.Time
}

func (manager *Manager) UpdateBlocking(ctx context.Context, mutate func(*Blocking) error) error {
	return manager.Update(ctx, func(candidate *Config) error {
		return mutate(&candidate.Blocking)
	})
}

func (manager *Manager) Update(ctx context.Context, mutate func(*Config) error) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	active := manager.current.Load()
	candidate := cloneConfig(active.Config)
	if err := mutate(&candidate); err != nil {
		return err
	}
	candidate.normalize()
	if err := candidate.Validate(); err != nil {
		return err
	}
	encoded, err := toml.Marshal(candidate)
	if err != nil {
		return fmt.Errorf("encode TOML: %w", err)
	}
	original, err := os.ReadFile(manager.path)
	if err != nil {
		return fmt.Errorf("read current configuration: %w", err)
	}
	info, err := os.Stat(manager.path)
	if err != nil {
		return fmt.Errorf("stat current configuration: %w", err)
	}
	if err := replaceConfigurationFile(manager.path, encoded, info.Mode().Perm()); err != nil {
		return err
	}
	if err := manager.apply(ctx, active.Config, candidate); err != nil {
		rollbackErr := replaceConfigurationFile(manager.path, original, info.Mode().Perm())
		if rollbackErr != nil {
			return fmt.Errorf("apply configuration: %w (restore configuration: %v)", err, rollbackErr)
		}
		return fmt.Errorf("apply configuration: %w", err)
	}
	revision := manager.revision.Add(1)
	manager.current.Store(&Snapshot{Config: candidate, Revision: revision, LoadedAt: time.Now()})
	return nil
}

func cloneConfig(source Config) Config {
	cloned := source
	cloned.Server.DNSListen = append([]string(nil), source.Server.DNSListen...)
	cloned.Resolver.Forwarders = append([]string(nil), source.Resolver.Forwarders...)
	cloned.Resolver.RootHints = append([]string(nil), source.Resolver.RootHints...)
	cloned.Resolver.DNSSECTrustAnchors = append([]string(nil), source.Resolver.DNSSECTrustAnchors...)
	cloned.Resolver.DNSSECNegativeTrustAnchors = append([]string(nil), source.Resolver.DNSSECNegativeTrustAnchors...)
	cloned.Resolver.Routes = make([]ForwardRoute, len(source.Resolver.Routes))
	for index, route := range source.Resolver.Routes {
		cloned.Resolver.Routes[index] = route
		cloned.Resolver.Routes[index].Forwarders = append([]string(nil), route.Forwarders...)
	}
	cloned.Resolver.Hosts = make([]HostOverride, len(source.Resolver.Hosts))
	for index, host := range source.Resolver.Hosts {
		cloned.Resolver.Hosts[index] = host
		cloned.Resolver.Hosts[index].Addresses = append([]string(nil), host.Addresses...)
	}
	cloned.TSIGKeys = append([]TSIGKey(nil), source.TSIGKeys...)
	cloned.Blocking.Domains = append([]string(nil), source.Blocking.Domains...)
	cloned.Blocking.AllowedDomains = append([]string(nil), source.Blocking.AllowedDomains...)
	cloned.Blocking.Lists = append([]BlockList(nil), source.Blocking.Lists...)
	cloned.Blocking.CustomAddresses = append([]string(nil), source.Blocking.CustomAddresses...)
	cloned.Blocking.BypassClients = append([]string(nil), source.Blocking.BypassClients...)
	cloned.EncryptedDNS.DoTListen = append([]string(nil), source.EncryptedDNS.DoTListen...)
	cloned.EncryptedDNS.DoHListen = append([]string(nil), source.EncryptedDNS.DoHListen...)
	cloned.EncryptedDNS.ACME.Domains = append([]string(nil), source.EncryptedDNS.ACME.Domains...)
	return cloned
}

func replaceConfigurationFile(path string, contents []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".sable-configuration-*.toml")
	if err != nil {
		return fmt.Errorf("create temporary configuration: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return fmt.Errorf("set temporary configuration permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary configuration: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary configuration: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary configuration: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace configuration: %w", err)
	}
	return nil
}

type ApplyFunc func(context.Context, Config, Config) error

type Manager struct {
	path     string
	apply    ApplyFunc
	current  atomic.Pointer[Snapshot]
	revision atomic.Uint64
	mu       sync.Mutex
}

func NewManager(path string, initial Config, apply ApplyFunc) *Manager {
	manager := &Manager{path: path, apply: apply}
	manager.revision.Store(1)
	manager.current.Store(&Snapshot{Config: initial, Revision: 1, LoadedAt: time.Now()})
	return manager
}

func (manager *Manager) Current() Snapshot {
	return *manager.current.Load()
}

func (manager *Manager) BaseDirectory() string { return filepath.Dir(manager.path) }

func (manager *Manager) Reload(ctx context.Context) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	candidate, err := Load(manager.path)
	if err != nil {
		return err
	}
	active := manager.current.Load()
	if err := manager.apply(ctx, active.Config, candidate); err != nil {
		return fmt.Errorf("apply configuration: %w", err)
	}
	revision := manager.revision.Add(1)
	manager.current.Store(&Snapshot{Config: candidate, Revision: revision, LoadedAt: time.Now()})
	return nil
}
