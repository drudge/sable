package alerts

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/drudge/sable/internal/config"
)

const (
	// tickInterval is how often the dispatcher asks its sources for news.
	// Sources that are slow to ask, such as Insights, keep their own answer
	// for longer.
	tickInterval = time.Minute
	// startDelay lets startup settle before the first round.
	startDelay = time.Minute
	// forgetAfter is how long an alert must be gone before it can alert again,
	// so one that flickers does not alert every few minutes.
	forgetAfter = 6 * time.Hour
	// refreshEvery is how often an alert that is still news has its record
	// renewed, so forgetAfter counts from when it stopped being news.
	refreshEvery = time.Hour
	// repeatLog is how long an unchanged send error stays out of the log once
	// it has been written there.
	repeatLog = time.Hour
)

// ErrNoDestination is why there was nothing to send a test to.
var ErrNoDestination = errors.New("that alert destination no longer exists")

// SentStore remembers which alerts each destination was sent, keyed by the
// destination's ID.
type SentStore interface {
	AlertsSent(ctx context.Context, target string) (map[string]time.Time, bool, error)
	MarkAlertsSent(ctx context.Context, target string, ids []string, at time.Time) error
	ForgetAlertsSent(ctx context.Context, target string, ids []string) error
}

// Status is how sending to one destination has gone since this server started.
type Status struct {
	LastSent      time.Time
	LastSentTitle string
	LastError     string
	LastErrorAt   time.Time
	loggedAt      time.Time
}

// Failing reports whether the latest send failed.
func (status Status) Failing() bool {
	return status.LastError != "" && !status.LastErrorAt.Before(status.LastSent)
}

// Receipt is what a destination said about one alert.
type Receipt struct {
	// ID is the ID ntfy or Pushover gave the message, if it gave one.
	ID string
	// Browsers counts the browsers a push reached.
	Browsers int
}

// Dispatcher sends alerts from its sources to the configured destinations.
type Dispatcher struct {
	// Config returns the configuration alerts are sent by.
	Config   func() config.Config
	Secrets  *SecretStore
	Sent     SentStore
	Browsers *Browsers
	Client   *http.Client
	// Icon is the image browsers show beside a pushed alert.
	Icon   string
	Logger *slog.Logger

	mu      sync.Mutex
	sources []Source
	status  map[string]Status
}

// Add gives the dispatcher more sources.
func (dispatcher *Dispatcher) Add(sources ...Source) {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	for _, source := range sources {
		if source != nil {
			dispatcher.sources = append(dispatcher.sources, source)
		}
	}
}

// Run sends alerts until ctx ends. leading reports whether this node leads the
// cluster; a node alone leads.
func (dispatcher *Dispatcher) Run(ctx context.Context, leading func() bool) {
	timer := time.NewTimer(startDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		// A failed round is recorded per destination and logged there.
		_ = dispatcher.Tick(ctx, time.Now(), leading == nil || leading())
		timer.Reset(tickInterval)
	}
}

// Tick runs one round: it asks the sources this node runs what is news, and
// sends each destination what it has not been sent. One destination failing
// does not keep the rest from hearing.
func (dispatcher *Dispatcher) Tick(ctx context.Context, now time.Time, leading bool) error {
	destinations := dispatcher.Destinations(ctx)
	if len(destinations) == 0 {
		return nil
	}
	placements := []Placement{OnReplicas}
	if leading {
		placements = []Placement{OnLead, OnEachNode}
	}
	current, complete := dispatcher.collect(ctx, now, placements...)
	configuration := dispatcher.configuration()
	var failures []error
	for _, destination := range destinations {
		if err := dispatcher.send(ctx, configuration.Alerts, destination, current, complete, now); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", destination.Label(), err))
		}
	}
	return errors.Join(failures...)
}

// Local collects what the sources placed on each node see in this node, for
// a replica to hand to the lead, which sends them.
func (dispatcher *Dispatcher) Local(ctx context.Context, now time.Time) ([]Alert, error) {
	alerts, complete := dispatcher.collect(ctx, now, OnEachNode)
	if !complete {
		return alerts, errors.New("some alert sources could not be read")
	}
	return alerts, nil
}

// collect asks the sources placed where this node runs them for what is news,
// oldest first. complete is false when a source failed, whose alerts then must
// not be forgotten this round.
func (dispatcher *Dispatcher) collect(ctx context.Context, now time.Time, placements ...Placement) ([]Alert, bool) {
	dispatcher.mu.Lock()
	sources := slices.Clone(dispatcher.sources)
	dispatcher.mu.Unlock()
	complete := true
	seen := make(map[string]bool)
	current := make([]Alert, 0)
	for _, source := range sources {
		if !slices.Contains(placements, placementOf(source)) {
			continue
		}
		alerts, err := source.Alerts(ctx, now)
		if err != nil {
			complete = false
			if ctx.Err() == nil {
				dispatcher.logger().Warn("read alert source", "source", fmt.Sprintf("%T", source), "error", err)
			}
			continue
		}
		for _, alert := range alerts {
			if alert.ID == "" || seen[alert.ID] {
				continue
			}
			seen[alert.ID] = true
			current = append(current, alert)
		}
	}
	slices.SortStableFunc(current, func(left, right Alert) int {
		return cmp.Or(left.ObservedAt.Compare(right.ObservedAt), cmp.Compare(left.ID, right.ID))
	})
	return current, complete
}

// send tells one destination what it has not been told. A destination it has
// never told anything first takes stock quietly, so adding one never floods it
// with old news. While alerts are paused, or a group is switched off for it,
// alerts still count as seen, so turning them back on never sends what
// happened meanwhile.
func (dispatcher *Dispatcher) send(ctx context.Context, alerts config.Alerts, destination config.AlertDestination, current []Alert, complete bool, now time.Time) error {
	sent, known, err := dispatcher.Sent.AlertsSent(ctx, destination.ID)
	if err != nil {
		dispatcher.fail(destination, err, now)
		return err
	}
	if !known {
		return dispatcher.Sent.MarkAlertsSent(ctx, destination.ID, idsOf(current), now)
	}
	stillNews := make(map[string]bool, len(current))
	var refresh []string
	for _, alert := range current {
		stillNews[alert.ID] = true
		if at, found := sent[alert.ID]; found {
			if now.Sub(at) >= refreshEvery {
				refresh = append(refresh, alert.ID)
			}
			continue
		}
		if !alerts.Paused && alerts.Send.Allows(alert.Group, alert.Problem) && destination.Gets(alert.Group) {
			if _, err := dispatcher.Deliver(ctx, destination, alert); err != nil && !errors.Is(err, ErrNoBrowsers) {
				dispatcher.fail(destination, err, now)
				// Leave the rest for the next round: whatever stopped this
				// one most likely stops them too.
				return err
			}
			dispatcher.succeed(destination, alert, now)
		}
		if err := dispatcher.Sent.MarkAlertsSent(ctx, destination.ID, []string{alert.ID}, now); err != nil {
			return err
		}
	}
	if len(refresh) > 0 {
		if err := dispatcher.Sent.MarkAlertsSent(ctx, destination.ID, refresh, now); err != nil {
			return err
		}
	}
	if !complete {
		return nil
	}
	gone := make([]string, 0)
	for id, at := range sent {
		if !stillNews[id] && now.Sub(at) >= forgetAfter {
			gone = append(gone, id)
		}
	}
	return dispatcher.Sent.ForgetAlertsSent(ctx, destination.ID, gone)
}

// Deliver sends one alert to one destination whose secrets are filled in.
func (dispatcher *Dispatcher) Deliver(ctx context.Context, destination config.AlertDestination, alert Alert) (Receipt, error) {
	links := dispatcher.Links()
	built, err := Build(destination, alert, links)
	if err != nil {
		return Receipt{}, err
	}
	if destination.Format == config.AlertFormatBrowser {
		count, err := dispatcher.Browsers.Push(ctx, links.Base, built.Body, alert.Problem)
		return Receipt{Browsers: count}, err
	}
	if err := destination.ValidateSecrets(); err != nil {
		return Receipt{}, err
	}
	id, err := Post(ctx, dispatcher.Client, destination, built)
	return Receipt{ID: id}, err
}

// Test sends a sample alert to a saved destination, even while alerts are
// paused, and returns the destination it went to.
func (dispatcher *Dispatcher) Test(ctx context.Context, id string, now time.Time) (config.AlertDestination, Receipt, error) {
	for _, destination := range dispatcher.Destinations(ctx) {
		if destination.ID != id {
			continue
		}
		receipt, err := dispatcher.Deliver(ctx, destination, Sample(now))
		if err != nil && !errors.Is(err, ErrNoBrowsers) {
			dispatcher.fail(destination, err, now)
		} else if err == nil {
			dispatcher.succeed(destination, Sample(now), now)
		}
		return destination, receipt, err
	}
	return config.AlertDestination{}, Receipt{}, ErrNoDestination
}

// Destinations returns the configured destinations with their secrets filled
// in from the vault.
func (dispatcher *Dispatcher) Destinations(ctx context.Context) []config.AlertDestination {
	destinations := dispatcher.configuration().Alerts.Destinations
	if dispatcher.Secrets == nil {
		return slices.Clone(destinations)
	}
	return dispatcher.Secrets.Hydrate(ctx, destinations)
}

// Status reports how sending has gone for each destination, by ID, since this
// server started.
func (dispatcher *Dispatcher) Status() map[string]Status {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	status := make(map[string]Status, len(dispatcher.status))
	for id, entry := range dispatcher.status {
		status[id] = entry
	}
	return status
}

// Links returns how alerts point back at the console.
func (dispatcher *Dispatcher) Links() Links {
	return Links{Base: dispatcher.configuration().AdvertisedBaseURL(), Icon: dispatcher.Icon}
}

func (dispatcher *Dispatcher) configuration() config.Config {
	if dispatcher.Config == nil {
		return config.Defaults()
	}
	return dispatcher.Config()
}

func (dispatcher *Dispatcher) logger() *slog.Logger {
	if dispatcher.Logger == nil {
		return slog.Default()
	}
	return dispatcher.Logger
}

func (dispatcher *Dispatcher) succeed(destination config.AlertDestination, alert Alert, now time.Time) {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if dispatcher.status == nil {
		dispatcher.status = make(map[string]Status)
	}
	status := dispatcher.status[destination.ID]
	status.LastSent, status.LastSentTitle = now, alert.NotificationTitle()
	dispatcher.status[destination.ID] = status
}

// fail records a failed send, and logs it unless the same error was logged
// within the hour.
func (dispatcher *Dispatcher) fail(destination config.AlertDestination, err error, now time.Time) {
	dispatcher.mu.Lock()
	if dispatcher.status == nil {
		dispatcher.status = make(map[string]Status)
	}
	status := dispatcher.status[destination.ID]
	log := status.LastError != err.Error() || now.Sub(status.loggedAt) >= repeatLog
	status.LastError, status.LastErrorAt = err.Error(), now
	if log {
		status.loggedAt = now
	}
	dispatcher.status[destination.ID] = status
	dispatcher.mu.Unlock()
	if log {
		dispatcher.logger().Warn("send alert", "destination", destination.Label(), "error", err)
	}
}

func idsOf(alerts []Alert) []string {
	ids := make([]string, 0, len(alerts))
	for _, alert := range alerts {
		ids = append(ids, alert.ID)
	}
	return ids
}
