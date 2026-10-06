package web

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/web/pages"
)

const (
	// alertWatchIDBytes is how much randomness names a new watch.
	alertWatchIDBytes = 8
	// alertWatchDomainsShown is how many domains a watch's row names before
	// it counts them instead.
	alertWatchDomainsShown = 2
	// alertWatchDevicesShown is how many devices a watch's row names before
	// it counts the rest.
	alertWatchDevicesShown = 2
)

// errAlertWatchGone is why a change found no watch to change.
var errAlertWatchGone = errors.New("that watch no longer exists")

// alertWatchQuietChoices are the quiet times the dialog offers, in order.
var alertWatchQuietChoices = []time.Duration{15 * time.Minute, time.Hour, 6 * time.Hour, 24 * time.Hour}

// SetWatchStatus tells the console when each domain watch last alerted, by
// watch ID, as this node knows it.
func (server *Server) SetWatchStatus(lastAlert func() map[string]time.Time) {
	server.watchLastAlert = lastAlert
}

// alertWatchDevices is what the console knows about the devices watches can
// pick: Insights' devices by key, in the order the picker lists them.
type alertWatchDevices struct {
	list   []devices.Device
	byKey  map[string]devices.Device
	loaded bool
}

// label names a watch's device: the device's name for an Insights key, or
// the address or network as written.
func (known alertWatchDevices) label(entry string) string {
	if device, found := known.byKey[entry]; found {
		return devices.Label(device)
	}
	return strings.TrimPrefix(strings.TrimPrefix(entry, "ip:"), "mac:")
}

// watchDevices reads the devices Insights knows, for an operator who may see
// them. Without that, or without Insights data, watches pick devices by
// address and network only.
func (server *Server) watchDevices(ctx context.Context, console pages.DashboardView) alertWatchDevices {
	known := alertWatchDevices{byKey: make(map[string]devices.Device)}
	// With Insights off Sable keeps no devices, so watches pick by address
	// and network alone.
	if !console.CanLogs || !server.insightsEnabled() {
		return known
	}
	reader, ok := server.queries.(deviceInsightReader)
	if !ok {
		return known
	}
	report, err := server.insightDevices(ctx, reader, insightsWindow("", time.Now()))
	if err != nil {
		server.logger.Warn("read devices for domain watches", "error", err)
		return known
	}
	known.loaded = true
	for _, device := range report.devices {
		if device.Server != "" {
			continue
		}
		known.list = append(known.list, device)
		known.byKey[device.Key] = device
	}
	slices.SortStableFunc(known.list, func(left, right devices.Device) int {
		return cmp.Compare(strings.ToLower(devices.Label(left)), strings.ToLower(devices.Label(right)))
	})
	return known
}

// alertWatchViews lists the watches as the Watches card shows them.
func (server *Server) alertWatchViews(watches []config.AlertWatch, known alertWatchDevices, now time.Time) []pages.AlertWatchView {
	var last map[string]time.Time
	if server.watchLastAlert != nil {
		last = server.watchLastAlert()
	}
	views := make([]pages.AlertWatchView, 0, len(watches))
	for _, watch := range watches {
		view := pages.AlertWatchView{
			ID: watch.ID, Label: watch.Label(), Domains: alertWatchDomainSummary(watch.Domains),
			Devices: alertWatchDeviceSummary(watch.Devices, known), Result: alertWatchResultLabel(watch.Result),
			Enabled: watch.Enabled, LastAlert: "Never triggered",
		}
		if at := last[watch.ID]; !at.IsZero() {
			view.LastAlert = "Last triggered " + strings.ToLower(clusterRelativeTime(at, now))
		}
		views = append(views, view)
	}
	return views
}

// alertWatchDomainSummary names a few domains, or counts many.
func alertWatchDomainSummary(domains []string) string {
	if len(domains) <= alertWatchDomainsShown {
		return strings.Join(domains, ", ")
	}
	return fmt.Sprintf("%d domains", len(domains))
}

// alertWatchDeviceSummary names the devices a watch covers.
func alertWatchDeviceSummary(entries []string, known alertWatchDevices) string {
	if len(entries) == 0 {
		return "Any device"
	}
	names := make([]string, 0, alertWatchDevicesShown)
	for _, entry := range entries[:min(len(entries), alertWatchDevicesShown)] {
		names = append(names, known.label(entry))
	}
	summary := strings.Join(names, ", ")
	if extra := len(entries) - len(names); extra > 0 {
		summary += fmt.Sprintf(", and %d more", extra)
	}
	return summary
}

// alertWatchResultLabel says which lookups a watch alerts on.
func alertWatchResultLabel(result string) string {
	switch result {
	case config.AlertWatchAllowed:
		return "Only when allowed"
	case config.AlertWatchBlocked:
		return "Only when blocked"
	default:
		return "Allowed or blocked"
	}
}

// alertWatchFormView lays out the Add or Edit Watch dialog.
func alertWatchFormView(watch config.AlertWatch, known alertWatchDevices, canPick bool) pages.AlertWatchFormView {
	form := pages.AlertWatchFormView{
		ID: watch.ID, Name: watch.Name, Domains: strings.Join(watch.Domains, "\n"),
		AnyDevice: len(watch.Devices) == 0, Result: cmp.Or(watch.Result, config.AlertWatchAny),
		Quiet: alertWatchQuietValue(cmp.Or(watch.Quiet.Duration, config.DefaultAlertWatchQuiet)), CanPickDevices: canPick && known.loaded,
	}
	offered := false
	for _, quiet := range alertWatchQuietChoices {
		value := alertWatchQuietValue(quiet)
		form.QuietChoices = append(form.QuietChoices, pages.AlertWatchChoice{Value: value, Label: alertWatchQuietLabel(quiet)})
		offered = offered || value == form.Quiet
	}
	// A quiet time written by hand stays a choice, so saving keeps it.
	if !offered {
		form.QuietChoices = append(form.QuietChoices, pages.AlertWatchChoice{Value: form.Quiet, Label: form.Quiet})
	}
	var addresses []string
	picked := make(map[string]bool)
	for _, entry := range watch.Devices {
		if _, found := known.byKey[entry]; found && form.CanPickDevices {
			picked[entry] = true
			continue
		}
		// A device key Insights no longer lists stays picked under its key,
		// so saving never drops it unseen.
		if form.CanPickDevices && (strings.HasPrefix(entry, "mac:") || strings.HasPrefix(entry, "ip:")) {
			form.Devices = append(form.Devices, pages.AlertWatchDeviceChoice{Key: entry, Label: known.label(entry), Detail: "Not seen lately", Picked: true})
			continue
		}
		addresses = append(addresses, entry)
	}
	form.Addresses = strings.Join(addresses, "\n")
	if form.CanPickDevices {
		for _, device := range known.list {
			form.Devices = append(form.Devices, pages.AlertWatchDeviceChoice{
				Key: device.Key, Label: devices.Label(device), Detail: alertWatchDeviceDetail(device), Picked: picked[device.Key],
			})
		}
	}
	return form
}

// alertWatchDeviceDetail tells apart devices with the same name.
func alertWatchDeviceDetail(device devices.Device) string {
	addresses := device.ClientAddresses()
	switch {
	case len(addresses) == 1:
		return addresses[0]
	case len(addresses) > 1:
		return fmt.Sprintf("%s and %d more", addresses[0], len(addresses)-1)
	default:
		return device.MAC
	}
}

// alertWatchQuietValue writes a quiet time the way people type one, such as
// 15m or 6h.
func alertWatchQuietValue(quiet time.Duration) string {
	switch {
	case quiet%time.Hour == 0:
		return fmt.Sprintf("%dh", int(quiet/time.Hour))
	case quiet%time.Minute == 0:
		return fmt.Sprintf("%dm", int(quiet/time.Minute))
	default:
		return quiet.String()
	}
}

func alertWatchQuietLabel(quiet time.Duration) string {
	switch {
	case quiet < time.Hour:
		return fmt.Sprintf("%d minutes", int(quiet/time.Minute))
	case quiet == time.Hour:
		return "1 hour"
	default:
		return fmt.Sprintf("%d hours", int(quiet/time.Hour))
	}
}

// alertWatchFormPanel loads the Add or Edit Watch form into its dialog. A
// new watch can start from a domain and a device, as Query Logs and the
// device drawer link to it: device is an Insights key, client an address the
// console ties to one.
func (server *Server) alertWatchFormPanel(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	query := request.URL.Query()
	watch := config.AlertWatch{Enabled: true}
	if id := query.Get("id"); id != "" {
		watches := server.config.Current().Config.Alerts.Watches
		index := slices.IndexFunc(watches, hasAlertWatchID(id))
		if index < 0 {
			writer.Header().Set("HX-Retarget", "#alerts-panel")
			writer.Header().Set("HX-Reswap", "outerHTML")
			server.renderAlertsPanel(writer, request, console, http.StatusNotFound, "", alertSentence(errAlertWatchGone))
			return
		}
		watch = watches[index]
	} else {
		if domain := strings.TrimSpace(query.Get("domain")); domain != "" {
			watch.Domains = []string{domain}
		}
		device := strings.TrimSpace(query.Get("device"))
		if device == "" && query.Get("client") != "" {
			device = server.watchDeviceForClient(request.Context(), console, query.Get("client"))
		}
		if device != "" {
			watch.Devices = []string{device}
		}
		watch.Normalize()
		watch.ID = ""
	}
	known := server.watchDevices(request.Context(), console)
	writeFragmentStatus(writer, http.StatusOK)
	form := alertWatchFormView(watch, known, console.CanLogs)
	form.InsightsOff = !server.insightsEnabled()
	server.render(writer, request, pages.AlertWatchForm(form))
}

// watchDeviceForClient names the device behind a client address the way
// Insights keys it, or returns the bare address for an operator who cannot
// see devices.
func (server *Server) watchDeviceForClient(ctx context.Context, console pages.DashboardView, client string) string {
	client = strings.TrimSpace(client)
	reader, ok := server.queries.(deviceInsightReader)
	if !console.CanLogs || !ok || !server.insightsEnabled() {
		return client
	}
	identities, err := reader.ClientIdentities(ctx, time.Now().Add(-devices.Lookback))
	if err != nil {
		server.logger.Warn("read client identities for a domain watch", "error", err)
		return client
	}
	return devices.NewGivenNames(identities, server.config.Current().Config.Clients).Key(client)
}

// draftAlertWatch reads the dialog's form into a watch, without checking it.
func draftAlertWatch(form url.Values) config.AlertWatch {
	watch := config.AlertWatch{
		ID: strings.TrimSpace(form.Get("id")), Name: form.Get("name"), Result: form.Get("result"), Enabled: true,
		Domains: strings.FieldsFunc(form.Get("domains"), alertWatchListSeparator),
	}
	// A quiet time that cannot be read is left out, and Normalize gives the
	// default.
	_ = watch.Quiet.UnmarshalText([]byte(strings.TrimSpace(form.Get("quiet"))))
	if form.Get("any_device") != "true" {
		watch.Devices = append(watch.Devices, form["device"]...)
		watch.Devices = append(watch.Devices, strings.FieldsFunc(form.Get("addresses"), alertWatchListSeparator)...)
	}
	watch.Normalize()
	return watch
}

// alertWatchListSeparator splits a list typed one per line, or with commas
// or spaces between.
func alertWatchListSeparator(character rune) bool {
	return character == '\n' || character == '\r' || character == ',' || character == ' ' || character == '\t'
}

// alertWatchProblem says why a watch cannot be saved, in words for the
// dialog, or nothing when it can.
func alertWatchProblem(watch config.AlertWatch, form url.Values) string {
	switch {
	case utf8.RuneCountInString(watch.Name) > config.MaximumAlertWatchName:
		return fmt.Sprintf("Keep the name to %d characters.", config.MaximumAlertWatchName)
	case len(watch.Domains) == 0:
		return "Enter at least one domain."
	case len(watch.Domains) > config.MaximumAlertWatchDomains:
		return fmt.Sprintf("A watch can have up to %d domains.", config.MaximumAlertWatchDomains)
	case form.Get("any_device") != "true" && len(watch.Devices) == 0:
		return "Pick at least one device, or choose Any Device."
	case len(watch.Devices) > config.MaximumAlertWatchDevices:
		return fmt.Sprintf("A watch can have up to %d devices.", config.MaximumAlertWatchDevices)
	}
	if err := config.ValidateAlertWatch(watch); err != nil {
		message := err.Error()
		switch {
		case strings.Contains(message, ".domains:"):
			return "Enter domain names such as discord.com, one per line. " + strings.TrimSpace(message[strings.Index(message, ".domains:")+len(".domains:"):])
		case strings.Contains(message, ".devices:"):
			return "Enter addresses such as 10.0.7.20, or networks such as 10.0.7.0/24. " + strings.TrimSpace(message[strings.Index(message, ".devices:")+len(".devices:"):])
		case strings.Contains(message, ".quiet"):
			return "Choose how long a device stays quiet after an alert."
		case strings.Contains(message, ".result"):
			return "Choose when the watch alerts."
		}
		return alertValidationSentence(err)
	}
	return ""
}

// saveAlertWatch adds a watch or changes one.
func (server *Server) saveAlertWatch(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	if err := request.ParseForm(); err != nil {
		server.renderAlertWatchProblem(writer, request, http.StatusBadRequest, "Sable could not read the form.")
		return
	}
	editor, editable := server.config.(settingsEditor)
	if !editable || server.alerts == nil {
		server.renderAlertWatchProblem(writer, request, http.StatusNotImplemented, alertSentence(errAlertsUnavailable))
		return
	}
	watch := draftAlertWatch(request.PostForm)
	// Tidying gives a watch without an ID one, so the form says whether it
	// changes a saved watch.
	existing := strings.TrimSpace(request.PostForm.Get("id")) != ""
	watches := server.config.Current().Config.Alerts.Watches
	if existing {
		index := slices.IndexFunc(watches, hasAlertWatchID(watch.ID))
		if index < 0 {
			server.renderAlertWatchProblem(writer, request, http.StatusNotFound, alertSentence(errAlertWatchGone))
			return
		}
		watch.Enabled = watches[index].Enabled
	} else {
		watch.ID = newAlertWatchID(watches)
		if len(watches) >= config.MaximumAlertWatches {
			server.renderAlertWatchProblem(writer, request, http.StatusUnprocessableEntity,
				fmt.Sprintf("Sable keeps up to %d watches. Remove one to add another.", config.MaximumAlertWatches))
			return
		}
	}
	if problem := alertWatchProblem(watch, request.PostForm); problem != "" {
		server.renderAlertWatchProblem(writer, request, http.StatusUnprocessableEntity, problem)
		return
	}
	err := editor.Update(request.Context(), func(candidate *config.Config) error {
		watches := slices.Clone(candidate.Alerts.Watches)
		index := slices.IndexFunc(watches, hasAlertWatchID(watch.ID))
		switch {
		case existing && index < 0:
			return errAlertWatchGone
		case !existing && index >= 0:
			return errors.New("another watch was added at the same moment; save again")
		case existing:
			watches[index] = watch
		default:
			watches = append(watches, watch)
		}
		candidate.Alerts.Watches = watches
		return nil
	})
	if err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, errAlertWatchGone) {
			status = http.StatusNotFound
		}
		server.renderAlertWatchProblem(writer, request, status, alertSentence(err))
		return
	}
	server.recordControlPlaneAudit(request, "alerts", fmt.Sprintf("%s domain watch %s", ifThenString(existing, "changed", "added"), watch.Label()))
	message := ifThenString(existing, "Saved ", "Added ") + watch.Label() + "."
	if snapshot := server.config.Current().Config; !snapshot.QueryLog.Enabled {
		message += " Turn on the query log for it to see lookups."
	} else if !snapshot.Alerts.Send.Watches {
		message += " Domain Watches is off in Alert Types."
	}
	server.renderAlertsPanel(writer, request, console, http.StatusOK, message, "")
}

// removeAlertWatch deletes a watch.
func (server *Server) removeAlertWatch(writer http.ResponseWriter, request *http.Request) {
	server.changeAlertWatch(writer, request, func(watches []config.AlertWatch, index int) ([]config.AlertWatch, string) {
		label := watches[index].Label()
		return slices.Delete(watches, index, index+1), "Removed " + label + "."
	})
}

// setAlertWatchEnabled switches a watch on or off from its row.
func (server *Server) setAlertWatchEnabled(writer http.ResponseWriter, request *http.Request) {
	server.changeAlertWatch(writer, request, func(watches []config.AlertWatch, index int) ([]config.AlertWatch, string) {
		watches[index].Enabled = request.FormValue("enabled") == "true"
		return watches, ifThenString(watches[index].Enabled, "Turned on ", "Turned off ") + watches[index].Label() + "."
	})
}

// changeAlertWatch applies a change to one saved watch, named by the form's
// id, and shows the panel with what it says.
func (server *Server) changeAlertWatch(writer http.ResponseWriter, request *http.Request, change func([]config.AlertWatch, int) ([]config.AlertWatch, string)) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	if err := request.ParseForm(); err != nil {
		server.renderAlertsPanel(writer, request, console, http.StatusBadRequest, "", "Sable could not read the form.")
		return
	}
	editor, editable := server.config.(settingsEditor)
	if !editable || server.alerts == nil {
		server.renderAlertsPanel(writer, request, console, http.StatusNotImplemented, "", alertSentence(errAlertsUnavailable))
		return
	}
	id := strings.TrimSpace(request.FormValue("id"))
	var message string
	err := editor.Update(request.Context(), func(candidate *config.Config) error {
		watches := slices.Clone(candidate.Alerts.Watches)
		index := slices.IndexFunc(watches, hasAlertWatchID(id))
		if index < 0 {
			return errAlertWatchGone
		}
		watches, message = change(watches, index)
		if len(watches) == 0 {
			watches = nil
		}
		candidate.Alerts.Watches = watches
		return nil
	})
	switch {
	case errors.Is(err, errAlertWatchGone):
		server.renderAlertsPanel(writer, request, console, http.StatusNotFound, "", "That watch was already removed.")
		return
	case err != nil:
		server.renderAlertsPanel(writer, request, console, http.StatusUnprocessableEntity, "", alertSentence(err))
		return
	}
	server.recordControlPlaneAudit(request, "alerts", strings.TrimSuffix(strings.ToLower(message[:1])+message[1:], ".")+" (domain watch)")
	server.renderAlertsPanel(writer, request, console, http.StatusOK, message, "")
}

// renderAlertWatchProblem shows why the dialog could not save, inside it,
// leaving what was typed alone.
func (server *Server) renderAlertWatchProblem(writer http.ResponseWriter, request *http.Request, status int, problem string) {
	writer.Header().Set("HX-Retarget", "#alert-watch-notice")
	writer.Header().Set("HX-Reswap", "innerHTML")
	writeFragmentStatus(writer, status)
	server.render(writer, request, pages.ToastSticky(problem, "error"))
}

// newAlertWatchID names a new watch with sixteen random hex characters that
// no other watch has.
func newAlertWatchID(watches []config.AlertWatch) string {
	for {
		random := make([]byte, alertWatchIDBytes)
		_, _ = rand.Read(random)
		id := hex.EncodeToString(random)
		if !slices.ContainsFunc(watches, hasAlertWatchID(id)) {
			return id
		}
	}
}

func hasAlertWatchID(id string) func(config.AlertWatch) bool {
	return func(watch config.AlertWatch) bool { return watch.ID == id }
}

// alertWatchOpenURL is the form a Settings page opened from a Watch link
// loads into the Add Watch dialog, or nothing.
func alertWatchOpenURL(query url.Values) string {
	domain := strings.TrimSpace(query.Get("watch_domain"))
	if domain == "" {
		return ""
	}
	values := url.Values{}
	values.Set("domain", domain)
	if device := strings.TrimSpace(query.Get("watch_device")); device != "" {
		values.Set("device", device)
	} else if client := strings.TrimSpace(query.Get("watch_client")); client != "" {
		values.Set("client", client)
	}
	return "/ui/settings/alerts/watches/form?" + values.Encode()
}
