package dynamicdns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsprovider"
)

const (
	workerTick       = 5 * time.Second
	discoveryTimeout = 15 * time.Second
	maximumReplySize = 128
	minimumRetry     = 30 * time.Second
	maximumRetry     = 30 * time.Minute
)

var nonPublicAddressRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

type configurationReader interface {
	Current() config.Snapshot
}

type credentialStore interface {
	Get(context.Context, string) (dnsprovider.Credentials, bool)
	Put(context.Context, string, dnsprovider.Credentials) error
}

type provider interface {
	EnsureRecord(context.Context, dnsprovider.Record) (bool, error)
}

// Status is the latest public-address discovery and publication state.
type Status struct {
	Enabled               bool
	Running               bool
	CredentialsConfigured bool
	Provider              string
	IPv4                  string
	IPv6                  string
	Records               int
	Changed               int
	Unchanged             int
	LastAttempt           time.Time
	LastSuccess           time.Time
	LastPublished         time.Time
	NextAttempt           time.Time
	Duration              time.Duration
	LastError             string
}

// Manager discovers this node's public addresses and reconciles configured
// external A and AAAA RRsets on the writable cluster node.
type Manager struct {
	configuration configurationReader
	credentials   credentialStore
	writable      func() bool
	logger        *slog.Logger
	now           func() time.Time
	discover      func(context.Context, string, string) (netip.Addr, error)
	newProvider   func(string, dnsprovider.Credentials) (provider, error)

	wake chan struct{}

	mu               sync.Mutex
	status           Status
	consecutiveFails int
}

func New(
	configuration configurationReader,
	credentials *dnsprovider.Store,
	writable func() bool,
	logger *slog.Logger,
) *Manager {
	return &Manager{
		configuration: configuration,
		credentials:   credentials,
		writable:      writable,
		logger:        logger,
		now:           time.Now,
		discover:      discoverAddress,
		newProvider: func(name string, credentials dnsprovider.Credentials) (provider, error) {
			return dnsprovider.New(name, credentials)
		},
		wake: make(chan struct{}, 1),
	}
}

func (manager *Manager) Status(ctx context.Context) Status {
	settings := manager.configuration.Current().Config.DynamicDNS
	manager.mu.Lock()
	status := manager.status
	manager.mu.Unlock()
	status.Enabled = settings.Runnable()
	status.Provider = settings.Provider
	status.Records = dynamicRecordCount(settings.Records)
	if manager.credentials != nil && settings.Provider != "" {
		_, status.CredentialsConfigured = manager.credentials.Get(ctx, settings.Provider)
	}
	return status
}

func (manager *Manager) PutCredentials(ctx context.Context, provider string, credentials dnsprovider.Credentials) error {
	if manager.credentials == nil {
		return errors.New("external DNS credential store is unavailable")
	}
	return manager.credentials.Put(ctx, provider, credentials)
}

func (manager *Manager) StoredCredentials(ctx context.Context, provider string) (dnsprovider.Credentials, bool) {
	if manager.credentials == nil {
		return dnsprovider.Credentials{}, false
	}
	return manager.credentials.Get(ctx, provider)
}

// SyncNow queues an immediate reconciliation. Repeated requests coalesce while
// a run is active or already queued.
func (manager *Manager) SyncNow() {
	if !manager.configuration.Current().Config.DynamicDNS.Runnable() {
		return
	}
	manager.mu.Lock()
	if manager.status.Running {
		manager.mu.Unlock()
		return
	}
	manager.status.Running = true
	manager.mu.Unlock()
	select {
	case manager.wake <- struct{}{}:
	default:
	}
}

func (manager *Manager) Run(ctx context.Context) {
	if manager.due() {
		manager.runOnce(ctx)
	}
	ticker := time.NewTicker(workerTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if manager.due() {
				manager.runOnce(ctx)
			}
		case <-manager.wake:
			manager.runOnce(ctx)
		}
	}
}

func (manager *Manager) due() bool {
	if !manager.configuration.Current().Config.DynamicDNS.Runnable() {
		return false
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return !manager.status.Running && (manager.status.NextAttempt.IsZero() || !manager.now().Before(manager.status.NextAttempt))
}

func (manager *Manager) runOnce(ctx context.Context) {
	settings := manager.configuration.Current().Config.DynamicDNS
	if !settings.Runnable() || (manager.writable != nil && !manager.writable()) {
		manager.mu.Lock()
		manager.status.Running = false
		manager.mu.Unlock()
		return
	}
	started := manager.now()
	manager.beginAttempt(started)
	result, err := manager.reconcile(ctx, settings)
	manager.finishAttempt(started, settings.Interval.Duration, result, err)
	if err != nil {
		manager.logger.Warn("dynamic DNS publication failed", "provider", settings.Provider, "error", err)
		return
	}
	if result.changed > 0 {
		manager.logger.Info("dynamic DNS records published",
			"provider", settings.Provider, "changed", result.changed,
			"unchanged", result.unchanged, "ipv4", result.ipv4, "ipv6", result.ipv6)
	}
}

type reconcileResult struct {
	ipv4      string
	ipv6      string
	changed   int
	unchanged int
}

func (manager *Manager) reconcile(ctx context.Context, settings config.DynamicDNS) (reconcileResult, error) {
	if manager.credentials == nil {
		return reconcileResult{}, errors.New("external DNS credential store is unavailable")
	}
	credentials, found := manager.credentials.Get(ctx, settings.Provider)
	if !found {
		return reconcileResult{}, fmt.Errorf("%s DNS credentials are not configured", settings.Provider)
	}
	publisher, err := manager.newProvider(settings.Provider, credentials)
	if err != nil {
		return reconcileResult{}, err
	}
	result, addresses, err := manager.discoverAddresses(ctx, settings)
	if err != nil {
		return reconcileResult{}, err
	}
	for _, configured := range settings.Records {
		for _, recordType := range recordTypes(configured) {
			address := addresses[recordType]
			changed, ensureErr := publisher.EnsureRecord(ctx, dnsprovider.Record{
				Zone: configured.Zone, Name: configured.Name, Type: recordType,
				Value: address.String(), TTL: configured.TTL,
			})
			if ensureErr != nil {
				return result, fmt.Errorf("publish %s %s: %w", configured.Name, recordType, ensureErr)
			}
			if changed {
				result.changed++
			} else {
				result.unchanged++
			}
		}
	}
	return result, nil
}

func (manager *Manager) discoverAddresses(ctx context.Context, settings config.DynamicDNS) (reconcileResult, map[string]netip.Addr, error) {
	needed := neededRecordTypes(settings.Records)
	addresses := make(map[string]netip.Addr, len(needed))
	result := reconcileResult{}
	for _, recordType := range []string{dnsprovider.TypeA, dnsprovider.TypeAAAA} {
		if !needed[recordType] {
			continue
		}
		endpoint := settings.IPv4URL
		if recordType == dnsprovider.TypeAAAA {
			endpoint = settings.IPv6URL
		}
		address, err := manager.discover(ctx, endpoint, recordType)
		if err != nil {
			return reconcileResult{}, nil, fmt.Errorf("discover public %s address: %w", recordType, err)
		}
		addresses[recordType] = address
		if recordType == dnsprovider.TypeA {
			result.ipv4 = address.String()
		} else {
			result.ipv6 = address.String()
		}
	}
	return result, addresses, nil
}

func discoverAddress(ctx context.Context, endpoint, recordType string) (netip.Addr, error) {
	network := "tcp4"
	if recordType == dnsprovider.TypeAAAA {
		network = "tcp6"
	}
	dialer := &net.Dialer{Timeout: discoveryTimeout}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   discoveryTimeout,
		CheckRedirect: func(request *http.Request, previous []*http.Request) error {
			if request.URL.Scheme != "https" || request.URL.User != nil {
				return errors.New("address service redirected to an unsafe URL")
			}
			if len(previous) >= 3 {
				return errors.New("address service redirected too many times")
			}
			return nil
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	request.Header.Set("Accept", "text/plain")
	request.Header.Set("User-Agent", "Sable dynamic DNS")
	response, err := client.Do(request)
	if err != nil {
		return netip.Addr{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return netip.Addr{}, fmt.Errorf("address service returned %s", response.Status)
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, maximumReplySize+1))
	if err != nil {
		return netip.Addr{}, err
	}
	if len(contents) > maximumReplySize {
		return netip.Addr{}, errors.New("address service reply is too large")
	}
	address, err := netip.ParseAddr(strings.TrimSpace(string(contents)))
	if err != nil {
		return netip.Addr{}, errors.New("address service did not return an IP address")
	}
	if err := validatePublicAddress(address, recordType); err != nil {
		return netip.Addr{}, err
	}
	return address, nil
}

func validatePublicAddress(address netip.Addr, recordType string) error {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
		return errors.New("address service returned a non-public address")
	}
	for _, reserved := range nonPublicAddressRanges {
		if reserved.Contains(address) {
			return errors.New("address service returned a non-public address")
		}
	}
	if recordType == dnsprovider.TypeA && !address.Is4() {
		return errors.New("IPv4 address service returned a non-IPv4 address")
	}
	if recordType == dnsprovider.TypeAAAA && (!address.Is6() || address.Is4In6()) {
		return errors.New("IPv6 address service returned a non-IPv6 address")
	}
	return nil
}

func (manager *Manager) beginAttempt(started time.Time) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.status.Running = true
	manager.status.LastAttempt = started
	manager.status.LastError = ""
}

func (manager *Manager) finishAttempt(started time.Time, interval time.Duration, result reconcileResult, err error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	finished := manager.now()
	manager.status.Running = false
	manager.status.Duration = finished.Sub(started)
	if result.ipv4 != "" {
		manager.status.IPv4 = result.ipv4
	}
	if result.ipv6 != "" {
		manager.status.IPv6 = result.ipv6
	}
	manager.status.Changed = result.changed
	manager.status.Unchanged = result.unchanged
	if result.changed > 0 {
		manager.status.LastPublished = finished
	}
	if err == nil {
		manager.consecutiveFails = 0
		manager.status.LastSuccess = finished
		manager.status.LastError = ""
		manager.status.NextAttempt = started.Add(interval)
		return
	}
	manager.consecutiveFails++
	manager.status.LastError = err.Error()
	manager.status.NextAttempt = started.Add(retryDelay(manager.consecutiveFails, interval))
}

func retryDelay(failures int, interval time.Duration) time.Duration {
	delay := minimumRetry
	for attempt := 1; attempt < failures && delay < maximumRetry; attempt++ {
		delay *= 2
	}
	if delay > maximumRetry {
		delay = maximumRetry
	}
	if interval > 0 && delay > interval {
		delay = interval
	}
	return delay
}

func neededRecordTypes(records []config.DynamicDNSRecord) map[string]bool {
	needed := make(map[string]bool, 2)
	for _, record := range records {
		if record.IPv4 {
			needed[dnsprovider.TypeA] = true
		}
		if record.IPv6 {
			needed[dnsprovider.TypeAAAA] = true
		}
	}
	return needed
}

func recordTypes(record config.DynamicDNSRecord) []string {
	types := make([]string, 0, 2)
	if record.IPv4 {
		types = append(types, dnsprovider.TypeA)
	}
	if record.IPv6 {
		types = append(types, dnsprovider.TypeAAAA)
	}
	return types
}

func dynamicRecordCount(records []config.DynamicDNSRecord) int {
	count := 0
	for _, record := range records {
		count += len(recordTypes(record))
	}
	return count
}
