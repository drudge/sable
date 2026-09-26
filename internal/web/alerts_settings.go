package web

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web/pages"
	"github.com/drudge/sable/internal/webpush"
)

const (
	// alertDestinationIDBytes is how much randomness names a new destination:
	// sixteen hex characters, which stay its name however it is renamed.
	alertDestinationIDBytes = 8
	// alertDestinationNameLimit keeps a name short enough to read in the list.
	alertDestinationNameLimit = 64
	// maximumAlertSignInsAfter and maximumAlertSignInsWithin bound the failed
	// sign-in limit the way sable.toml does: at most 1000 failures, counted
	// within at most a day.
	maximumAlertSignInsAfter  = 1000
	maximumAlertSignInsWithin = 24 * 60
)

var (
	// errAlertDestinationGone is why a change found no destination to change.
	errAlertDestinationGone = errors.New("that destination no longer exists")
	// errAlertBrowsersTaken is why a second destination cannot push to browsers.
	errAlertBrowsersTaken = errors.New("another destination already sends to your browsers")
	// errNoAlertDestinations is why there is nothing to pause.
	errNoAlertDestinations = errors.New("add a destination first")
	// errAlertsUnavailable is why a server that runs the console without
	// alerts cannot change them.
	errAlertsUnavailable = errors.New("alerts cannot be changed on this server")
)

// pushSubscriptionForm is what a browser posts when it subscribes: its
// PushSubscription as JSON.
type pushSubscriptionForm struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256DH string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
}

// alertDestinationDraft is a destination as the dialog posted it, merged with
// what is saved: a secret field left blank keeps the saved secret.
type alertDestinationDraft struct {
	destination config.AlertDestination
	// existing is set when the draft changes a saved destination.
	existing bool
	// keptHeaders marks each header whose value came from what was saved,
	// which a preview must not show.
	keptHeaders []bool
	// noGroups is set when the dialog asked for only some groups but picked
	// none.
	noGroups bool
}

// alertsView lays out Settings > Alerts for one operator: whether alerts go
// out, where they go and how sending there has gone, which groups are on, and
// the browsers that turned alerts on. Secrets leave only cut short.
func (server *Server) alertsView(ctx context.Context, console pages.DashboardView) pages.AlertsView {
	configuration := server.config.Current().Config.Alerts
	view := pages.AlertsView{
		Available: server.alerts != nil,
		CanEdit:   console.CanWriteSettings,
		Groups: pages.AlertGroupsView{
			Insights: configuration.Send.Insights, Cluster: configuration.Send.Cluster, Updates: configuration.Send.Updates,
			Integrations: configuration.Send.Integrations, Backups: configuration.Send.Backups, Server: configuration.Send.Server,
			SignIns: configuration.Send.SignIns, SignInsAfter: configuration.SignIns.After,
			SignInsWithin: alertSignInMinutes(configuration.SignIns.Within.Duration),
		},
	}
	if !view.Available {
		return view
	}
	subscriptions, push := server.alertBrowserSubscriptions(ctx)
	view.Push = push
	for _, subscription := range subscriptions {
		view.Browsers = append(view.Browsers, pages.AlertBrowserView{
			ID: subscription.ID(), Label: alertBrowserName(subscription), Added: alertBrowserAdded(subscription, console.TimeDisplay),
		})
	}
	statuses := server.alerts.Status()
	destinations := server.alertSecrets.Hydrate(ctx, configuration.Destinations)
	for _, destination := range destinations {
		view.Destinations = append(view.Destinations, alertDestinationView(destination, statuses[destination.ID], len(subscriptions), push, console.TimeDisplay))
		view.BrowserDestination = view.BrowserDestination || destination.Format == config.AlertFormatBrowser
	}
	view.State = alertsState(configuration, destinations, len(subscriptions), push)
	if view.CanEdit {
		view.NewDestination = alertDestinationFormView(configuration, config.AlertDestination{}, push)
	}
	return view
}

// alertsState says whether alerts go out: paused when an operator paused them,
// on when some destination can send, and off otherwise.
func alertsState(configuration config.Alerts, destinations []config.AlertDestination, browsers int, push bool) pages.AlertsState {
	if len(destinations) == 0 {
		return pages.AlertsOff
	}
	if configuration.Paused {
		return pages.AlertsPaused
	}
	for _, destination := range destinations {
		if alertDestinationProblem(destination, browsers, push) == "" {
			return pages.AlertsOn
		}
	}
	return pages.AlertsOff
}

// alertDestinationProblem says why a destination whose secrets are filled in
// cannot send yet, or nothing when it can.
func alertDestinationProblem(destination config.AlertDestination, browsers int, push bool) string {
	switch {
	case destination.Format == config.AlertFormatBrowser && !push:
		return "Browser alerts are not available on this server."
	case destination.Format == config.AlertFormatBrowser && browsers == 0:
		return "No browser has turned alerts on yet."
	case destination.Format == config.AlertFormatBrowser:
		return ""
	case destination.Format == config.AlertFormatPushover && destination.ValidateSecrets() != nil:
		return "No application token or user key is saved."
	case destination.ValidateSecrets() != nil:
		return "No URL is saved."
	default:
		return ""
	}
}

// alertDestinationView is one destination as the list shows it, with its
// address cut short and how sending there has gone since Sable started.
func alertDestinationView(destination config.AlertDestination, status alerts.Status, browsers int, push bool, display pages.TimeDisplay) pages.AlertDestinationView {
	view := pages.AlertDestinationView{
		ID: destination.ID, Label: destination.Label(), Format: alertFormatKey(destination.Format), FormatLabel: destination.FormatLabel(),
		Everything: len(destination.Sends) == 0, Problem: alertDestinationProblem(destination, browsers, push),
	}
	for _, group := range destination.Sends {
		view.Groups = append(view.Groups, pages.AlertGroupLabel(group))
	}
	switch destination.Format {
	case config.AlertFormatBrowser:
		if browsers > 0 {
			view.Address = fmt.Sprintf("%d %s", browsers, ifThenString(browsers == 1, "browser", "browsers"))
		}
	case config.AlertFormatPushover:
		// Pushover always posts to its own API, so its user key is what tells
		// two Pushover destinations apart.
		if destination.PushoverUser != "" {
			view.Address = "user key " + alerts.MaskSecret(destination.PushoverUser)
		}
	default:
		view.Address = alerts.MaskURL(destination)
	}
	if !status.LastSent.IsZero() {
		view.LastSent, view.LastSentTitle = pages.FormatShortDateTime(status.LastSent, display, false), status.LastSentTitle
	}
	if status.Failing() {
		view.LastError, view.LastErrorAt = status.LastError, pages.FormatShortDateTime(status.LastErrorAt, display, false)
	}
	return view
}

// alertDestinationFormView lays out the Add or Edit Destination form for a
// destination whose secrets are filled in. Each secret reaches it cut short.
func alertDestinationFormView(configuration config.Alerts, destination config.AlertDestination, push bool) pages.AlertDestinationFormView {
	form := pages.AlertDestinationFormView{
		ID: destination.ID, Name: destination.Name, Format: alertFormatKey(destination.Format), NtfyReceipt: destination.NtfyReceipt,
		Sends: slices.Clone(destination.Sends), Push: push,
		BrowsersTaken: slices.ContainsFunc(configuration.Destinations, func(other config.AlertDestination) bool {
			return other.Format == config.AlertFormatBrowser && other.ID != destination.ID
		}),
	}
	if kept := keptAlertSecrets(destination); kept.URL != "" {
		form.SavedURL = alerts.MaskURL(config.AlertDestination{URL: kept.URL})
	}
	if destination.PushoverToken != "" {
		form.SavedPushoverToken = alerts.MaskSecret(destination.PushoverToken)
	}
	if destination.PushoverUser != "" {
		form.SavedPushoverUser = alerts.MaskSecret(destination.PushoverUser)
	}
	for _, header := range destination.Headers {
		form.Headers = append(form.Headers, pages.AlertHeaderView{Name: header.Name, Saved: alerts.MaskSecret(header.Value)})
	}
	for _, group := range config.AlertGroupNames() {
		form.Groups = append(form.Groups, pages.AlertGroupChoice{
			Key: group, Label: pages.AlertGroupLabel(group), Off: !configuration.Send.Allows(group, true),
		})
	}
	return form
}

// alertDestinationFormPanel loads the Add or Edit Destination form into its
// dialog.
func (server *Server) alertDestinationFormPanel(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	configuration := server.config.Current().Config.Alerts
	destination := config.AlertDestination{}
	if id := request.URL.Query().Get("id"); id != "" {
		index := slices.IndexFunc(configuration.Destinations, hasAlertDestinationID(id))
		if index < 0 {
			// The dialog stays shut, and the panel shows what is there now.
			writer.Header().Set("HX-Retarget", "#alerts-panel")
			writer.Header().Set("HX-Reswap", "outerHTML")
			server.renderAlertsPanel(writer, request, console, http.StatusNotFound, "", alertSentence(errAlertDestinationGone))
			return
		}
		destination = server.alertSecrets.Hydrate(request.Context(), configuration.Destinations[index:index+1])[0]
	}
	_, push := server.alertPushStore()
	writeFragmentStatus(writer, http.StatusOK)
	if err := pages.AlertDestinationForm(alertDestinationFormView(configuration, destination, push)).Render(request.Context(), writer); err != nil {
		server.logger.Error("render alert destination form", "error", err)
	}
}

// draftAlertDestination reads the dialog's form, filling in the secrets saved
// for the destination it changes, if any. It checks nothing: saving and
// previewing each check what they need.
func (server *Server) draftAlertDestination(ctx context.Context, configuration config.Alerts, form url.Values) (alertDestinationDraft, error) {
	var draft alertDestinationDraft
	var saved alerts.Secrets
	id := strings.TrimSpace(form.Get("id"))
	if id != "" {
		index := slices.IndexFunc(configuration.Destinations, hasAlertDestinationID(id))
		if index < 0 {
			return draft, errAlertDestinationGone
		}
		saved = keptAlertSecrets(server.alertSecrets.Hydrate(ctx, configuration.Destinations[index:index+1])[0])
		draft.existing = true
	}
	destination := config.AlertDestination{
		ID: id, Name: form.Get("name"), Format: strings.ToLower(strings.TrimSpace(form.Get("format"))),
		NtfyReceipt: form.Get("ntfy_receipt") == "true",
		URL:         strings.TrimSpace(form.Get("url")), PushoverToken: strings.TrimSpace(form.Get("pushover_token")),
		PushoverUser: strings.TrimSpace(form.Get("pushover_user")),
	}
	destination.URL = cmp.Or(destination.URL, saved.URL)
	destination.PushoverToken = cmp.Or(destination.PushoverToken, saved.PushoverToken)
	destination.PushoverUser = cmp.Or(destination.PushoverUser, saved.PushoverUser)
	// The dialog asks Pushover for no URL: its own API is the one to use.
	if destination.Format == config.AlertFormatPushover {
		destination.URL = ""
	}
	names, values := form["header_name"], form["header_value"]
	used := make([]bool, len(saved.Headers))
	for index, name := range names {
		value := ""
		if index < len(values) {
			value = values[index]
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if name == "" && value == "" {
			continue
		}
		// A saved header shows its name with its value left blank, and keeps
		// the saved value unless a new one is typed.
		kept := false
		if value == "" {
			for savedIndex, savedHeader := range saved.Headers {
				if !used[savedIndex] && strings.EqualFold(savedHeader.Name, name) {
					value, used[savedIndex], kept = savedHeader.Value, true, true
					break
				}
			}
		}
		destination.Headers = append(destination.Headers, config.AlertHeader{Name: name, Value: value})
		draft.keptHeaders = append(draft.keptHeaders, kept)
	}
	if form.Get("sends_all") == "false" {
		destination.Sends = form["sends"]
		draft.noGroups = len(destination.Sends) == 0
	}
	destination.Normalize()
	// Formats that send no headers lose them in Normalize.
	if len(destination.Headers) == 0 {
		draft.keptHeaders = nil
	}
	draft.destination = destination
	return draft, nil
}

// keptAlertSecrets are the saved secrets the dialog keeps for a field left
// blank. Pushover posts to its own API, so a URL saved for it is no address
// to keep if the destination moves to another format.
func keptAlertSecrets(destination config.AlertDestination) alerts.Secrets {
	secrets := alerts.SecretsOf(destination)
	if destination.Format == config.AlertFormatPushover {
		secrets.URL = ""
	}
	return secrets
}

// alertDraftProblem says why a draft cannot be saved, in words for the
// dialog, or nothing when it can.
func alertDraftProblem(draft alertDestinationDraft) string {
	destination := draft.destination
	switch {
	case utf8.RuneCountInString(destination.Name) > alertDestinationNameLimit:
		return fmt.Sprintf("Keep the name to %d characters.", alertDestinationNameLimit)
	case draft.noGroups:
		return "Pick at least one group, or choose Everything."
	}
	if destination.URL != "" {
		parsed, err := url.Parse(destination.URL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return "Enter a URL that starts with https:// or http://."
		}
	}
	if err := config.ValidateAlertDestination(destination); err != nil {
		return alertValidationSentence(err)
	}
	if err := destination.ValidateSecrets(); err != nil {
		return alertSentence(err)
	}
	return ""
}

// saveAlertDestination adds a destination or changes one. Its secrets go to
// the vault and the rest to sable.toml, and a secret left blank stays as it
// was saved. A new destination sends nothing it did not see come up.
func (server *Server) saveAlertDestination(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderAlertDestinationProblem(writer, request, http.StatusBadRequest, "Sable could not read the form.")
		return
	}
	editor, editable := server.config.(settingsEditor)
	if !editable || server.alerts == nil {
		server.renderAlertDestinationProblem(writer, request, http.StatusNotImplemented, alertSentence(errAlertsUnavailable))
		return
	}
	ctx := request.Context()
	configuration := server.config.Current().Config.Alerts
	draft, err := server.draftAlertDestination(ctx, configuration, request.Form)
	if err != nil {
		server.renderAlertDestinationProblem(writer, request, http.StatusNotFound, alertSentence(err))
		return
	}
	destination := draft.destination
	if !draft.existing {
		destination.ID = newAlertDestinationID(configuration.Destinations, destination.Format)
		draft.destination = destination
	}
	if problem := alertDraftProblem(draft); problem != "" {
		server.renderAlertDestinationProblem(writer, request, http.StatusUnprocessableEntity, problem)
		return
	}
	if destination.Format == config.AlertFormatBrowser && slices.ContainsFunc(configuration.Destinations, otherBrowserDestination(destination.ID)) {
		server.renderAlertDestinationProblem(writer, request, http.StatusConflict, alertSentence(errAlertBrowsersTaken))
		return
	}
	previous, hadPrevious := server.alertSecrets.Secrets(ctx, destination.ID)
	if err := server.alertSecrets.Put(ctx, destination.ID, alerts.SecretsOf(destination)); err != nil {
		server.logger.Error("store alert destination secrets", "destination", destination.Label(), "error", err)
		server.renderAlertDestinationProblem(writer, request, http.StatusInternalServerError, "Sable could not store its secrets: "+err.Error()+".")
		return
	}
	stripped := alerts.Strip(destination)
	err = editor.Update(ctx, func(candidate *config.Config) error {
		// The checks run again here, against what is saved now, in case
		// another change landed since the form was read.
		destinations := slices.Clone(candidate.Alerts.Destinations)
		index := slices.IndexFunc(destinations, hasAlertDestinationID(stripped.ID))
		others := destinations
		if index >= 0 && draft.existing {
			others = slices.Delete(slices.Clone(destinations), index, index+1)
		}
		switch {
		case draft.existing && index < 0:
			return errAlertDestinationGone
		case stripped.Format == config.AlertFormatBrowser && slices.ContainsFunc(others, isBrowserDestination):
			return errAlertBrowsersTaken
		case !draft.existing && index >= 0:
			return errors.New("another destination was added at the same moment; save again")
		case draft.existing:
			destinations[index] = stripped
		default:
			destinations = append(destinations, stripped)
		}
		candidate.Alerts.Destinations = destinations
		return nil
	})
	if err != nil {
		// Put back what the vault held, so a destination that stays as it was
		// keeps its secrets, and a new one that was never added leaves none.
		if hadPrevious {
			err = errors.Join(err, server.alertSecrets.Put(ctx, destination.ID, previous))
		} else {
			err = errors.Join(err, server.alertSecrets.Forget(ctx, destination.ID))
		}
		status := http.StatusUnprocessableEntity
		switch {
		case errors.Is(err, errAlertDestinationGone):
			status = http.StatusNotFound
		case errors.Is(err, errAlertBrowsersTaken):
			status = http.StatusConflict
		}
		server.renderAlertDestinationProblem(writer, request, status, alertSentence(err))
		return
	}
	label := destination.Label()
	server.recordControlPlaneAudit(request, "alerts", fmt.Sprintf("%s alert destination %s (%s)", ifThenString(draft.existing, "changed", "added"), label, destination.FormatLabel()))
	message := "Saved " + label + "."
	if !draft.existing {
		message = "Added " + label + "."
		if destination.Format == config.AlertFormatBrowser {
			if subscriptions, _ := server.alertBrowserSubscriptions(ctx); len(subscriptions) == 0 {
				message += " Turn on alerts in this browser to start getting them."
			}
		} else {
			message += " Send a test to make sure it arrives."
		}
	}
	if configuration.Paused {
		message += " Alerts are paused."
	}
	server.renderAlertsPanel(writer, request, console, http.StatusOK, message, "")
}

// removeAlertDestination stops sending to a destination, and forgets its
// secrets.
func (server *Server) removeAlertDestination(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
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
	var removed config.AlertDestination
	err := editor.Update(request.Context(), func(candidate *config.Config) error {
		index := slices.IndexFunc(candidate.Alerts.Destinations, hasAlertDestinationID(id))
		if index < 0 {
			return errAlertDestinationGone
		}
		removed = candidate.Alerts.Destinations[index]
		destinations := slices.Delete(slices.Clone(candidate.Alerts.Destinations), index, index+1)
		if len(destinations) == 0 {
			// With nowhere to send, there is nothing left to pause.
			destinations, candidate.Alerts.Paused = nil, false
		}
		candidate.Alerts.Destinations = destinations
		return nil
	})
	switch {
	case errors.Is(err, errAlertDestinationGone):
		server.renderAlertsPanel(writer, request, console, http.StatusNotFound, "", "That destination was already removed.")
		return
	case err != nil:
		server.renderAlertsPanel(writer, request, console, http.StatusUnprocessableEntity, "", alertSentence(err))
		return
	}
	// The destination is gone either way; secrets left behind are only
	// ciphertext nothing reads, so a failure here is logged, not shown.
	if err := server.alertSecrets.Forget(request.Context(), id); err != nil {
		server.logger.Warn("forget alert destination secrets", "destination", removed.Label(), "error", err)
	}
	server.recordControlPlaneAudit(request, "alerts", "removed alert destination "+removed.Label())
	server.renderAlertsPanel(writer, request, console, http.StatusOK, "Removed "+removed.Label()+".", "")
}

// testAlertDestination sends a sample alert to a saved destination, even while
// alerts are paused, and says what the destination answered.
func (server *Server) testAlertDestination(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderAlertsPanel(writer, request, console, http.StatusBadRequest, "", "Sable could not read the form.")
		return
	}
	if server.alerts == nil {
		server.renderAlertsPanel(writer, request, console, http.StatusNotImplemented, "", alertSentence(errAlertsUnavailable))
		return
	}
	destination, receipt, err := server.alerts.Test(request.Context(), strings.TrimSpace(request.FormValue("id")), time.Now())
	switch {
	case errors.Is(err, alerts.ErrNoDestination):
		server.renderAlertsPanel(writer, request, console, http.StatusNotFound, "", alertSentence(err))
	case err != nil:
		// The destination's answer is the result of the test, not a fault in
		// the request, so the panel shows it like any other result.
		server.renderAlertsPanel(writer, request, console, http.StatusOK, "", alertSentence(err))
	default:
		server.renderAlertsPanel(writer, request, console, http.StatusOK, alertTestMessage(destination, receipt), "")
	}
}

// alertTestMessage says what a destination answered a test with, in the words
// of the service that answered.
func alertTestMessage(destination config.AlertDestination, receipt alerts.Receipt) string {
	switch {
	case destination.Format == config.AlertFormatBrowser:
		return fmt.Sprintf("Test sent to %d %s.", receipt.Browsers, ifThenString(receipt.Browsers == 1, "browser", "browsers"))
	case destination.Format == config.AlertFormatSlack:
		return "Test sent. Slack posted it."
	case destination.Format == config.AlertFormatDiscord:
		return "Test sent. Discord posted it."
	case receipt.ID != "" && destination.Format == config.AlertFormatPushover:
		return "Test sent. Pushover accepted it as request " + receipt.ID + "."
	case receipt.ID != "":
		return "Test sent. ntfy published it as message " + receipt.ID + "."
	default:
		return "Test sent."
	}
}

// previewAlertDestination shows what a sample alert would send to the
// destination the dialog describes, saved or not, with secrets cut short.
func (server *Server) previewAlertDestination(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		writeFragmentStatus(writer, http.StatusBadRequest)
		return
	}
	snapshot := server.config.Current().Config
	preview := pages.AlertPreview{Method: http.MethodPost}
	if draft, err := server.draftAlertDestination(request.Context(), snapshot.Alerts, request.Form); err != nil {
		preview.Error = alertSentence(err)
	} else {
		preview = alertPreview(draft, server.alertLinks(snapshot))
	}
	writeFragmentStatus(writer, http.StatusOK)
	if err := pages.AlertPreviewPanel(preview).Render(request.Context(), writer); err != nil {
		server.logger.Error("render alert preview", "error", err)
	}
}

// alertPreview lays a sample alert out the way a draft would send it, with
// every secret cut short: the URL's token, Pushover's keys, an Authorization
// header, and any header value that came from what is saved.
func alertPreview(draft alertDestinationDraft, links alerts.Links) pages.AlertPreview {
	destination := draft.destination
	built, err := alerts.Build(destination, alerts.Sample(time.Now()), links)
	preview := pages.AlertPreview{Method: http.MethodPost, URL: alerts.MaskURL(destination), ContentType: built.ContentType}
	switch destination.Format {
	case config.AlertFormatPushover:
		if preview.URL == "" {
			preview.URL = config.PushoverMessagesURL
		}
	case config.AlertFormatBrowser:
		// What each push service gets is sealed for one browser, so show what
		// the browser opens.
		preview.URL, preview.ContentType = "(each browser's push service)", "application/json, encrypted for each browser"
	}
	if err != nil {
		preview.Error = alertSentence(err)
	}
	// The destination's own headers come last, after any the format adds.
	offset := len(built.Headers) - len(destination.Headers)
	for index, header := range alerts.PreviewHeaders(built) {
		if saved := index - offset; saved >= 0 && saved < len(draft.keptHeaders) && draft.keptHeaders[saved] {
			header.Value = alerts.MaskSecret(built.Headers[index].Value)
		}
		preview.Headers = append(preview.Headers, pages.AlertHeaderPreview{Name: header.Name, Value: header.Value})
	}
	preview.Body = alerts.PreviewBody(built)
	return preview
}

// alertLinks is how alerts point back at the console.
func (server *Server) alertLinks(snapshot config.Config) alerts.Links {
	if server.alerts != nil {
		return server.alerts.Links()
	}
	return alerts.Links{Base: snapshot.AdvertisedBaseURL()}
}

// setAlertsPaused pauses or resumes every alert without forgetting where they
// go. Alerts that come up while paused are never sent.
func (server *Server) setAlertsPaused(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderAlertsPanel(writer, request, console, http.StatusBadRequest, "", "Sable could not read the form.")
		return
	}
	editor, editable := server.config.(settingsEditor)
	if !editable || server.alerts == nil {
		server.renderAlertsPanel(writer, request, console, http.StatusNotImplemented, "", alertSentence(errAlertsUnavailable))
		return
	}
	paused := request.FormValue("paused") == "true"
	err := editor.Update(request.Context(), func(candidate *config.Config) error {
		if len(candidate.Alerts.Destinations) == 0 {
			return errNoAlertDestinations
		}
		candidate.Alerts.Paused = paused
		return nil
	})
	if err != nil {
		server.renderAlertsPanel(writer, request, console, http.StatusUnprocessableEntity, "", alertSentence(err))
		return
	}
	server.recordControlPlaneAudit(request, "alerts", ifThenString(paused, "paused alerts", "resumed alerts"))
	server.renderAlertsPanel(writer, request, console, http.StatusOK,
		ifThenString(paused, "Alerts paused.", "Alerts resumed. Only alerts from now on will be sent."), "")
}

// saveAlertGroups turns whole groups of alerts on or off, and sets when failed
// sign-ins are worth an alert.
func (server *Server) saveAlertGroups(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderAlertsPanel(writer, request, console, http.StatusBadRequest, "", "Sable could not read the form.")
		return
	}
	editor, editable := server.config.(settingsEditor)
	if !editable || server.alerts == nil {
		server.renderAlertsPanel(writer, request, console, http.StatusNotImplemented, "", alertSentence(errAlertsUnavailable))
		return
	}
	on := func(group string) bool { return request.FormValue(group) == "true" }
	send := config.AlertSwitches{
		Insights: on(config.AlertGroupInsights), Cluster: on(config.AlertGroupCluster), Updates: on(config.AlertGroupUpdates),
		Integrations: on(config.AlertGroupIntegrations), Backups: strings.TrimSpace(request.FormValue(config.AlertGroupBackups)),
		Server: on(config.AlertGroupServer), SignIns: on(config.AlertGroupSignIns),
	}
	switch send.Backups {
	case config.AlertBackupsFailures, config.AlertBackupsAll, config.AlertBackupsOff:
	default:
		server.renderAlertsPanel(writer, request, console, http.StatusUnprocessableEntity, "", "Choose which backups send alerts.")
		return
	}
	after, err := strconv.Atoi(strings.TrimSpace(request.FormValue("sign_ins_after")))
	if err != nil || after < 1 || after > maximumAlertSignInsAfter {
		server.renderAlertsPanel(writer, request, console, http.StatusUnprocessableEntity, "",
			fmt.Sprintf("Failed sign-ins must be a number from 1 to %d.", maximumAlertSignInsAfter))
		return
	}
	within, err := strconv.Atoi(strings.TrimSpace(request.FormValue("sign_ins_within")))
	if err != nil || within < 1 || within > maximumAlertSignInsWithin {
		server.renderAlertsPanel(writer, request, console, http.StatusUnprocessableEntity, "",
			fmt.Sprintf("Minutes must be a number from 1 to %d, which is a day.", maximumAlertSignInsWithin))
		return
	}
	err = editor.Update(request.Context(), func(candidate *config.Config) error {
		candidate.Alerts.Send = send
		candidate.Alerts.SignIns = config.AlertSignIns{After: after, Within: config.Duration{Duration: time.Duration(within) * time.Minute}}
		return nil
	})
	if err != nil {
		server.renderAlertsPanel(writer, request, console, http.StatusUnprocessableEntity, "", alertSentence(err))
		return
	}
	server.recordControlPlaneAudit(request, "alerts", "changed which alerts are sent")
	server.renderAlertsPanel(writer, request, console, http.StatusOK, "Saved which alerts Sable sends.", "")
}

// alertBrowserPushKey hands a browser the public key to subscribe with. The key
// is made the first time a browser asks, not before, so a server that never
// uses browser alerts never makes one.
func (server *Server) alertBrowserPushKey(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	if _, available := server.alertPushStore(); !available {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "Browser alerts are not available on this server."})
		return
	}
	key, err := server.pushKeys.PushKey(request.Context())
	public := ""
	if err == nil {
		public, err = webpush.PublicKey(key)
	}
	if err != nil {
		server.logger.Error("read push key", "error", err)
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "Sable could not read its push key."})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"key": public})
}

// addAlertBrowser keeps the browser that just subscribed. With no destination
// sending to browsers yet, it adds one, so turning a browser on is all it
// takes.
func (server *Server) addAlertBrowser(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderAlertsPanel(writer, request, console, http.StatusBadRequest, "", "Sable could not read the form.")
		return
	}
	store, available := server.alertPushStore()
	editor, editable := server.config.(settingsEditor)
	var form pushSubscriptionForm
	err := json.Unmarshal([]byte(request.FormValue("push_subscription")), &form)
	subscription := webpush.Subscription{
		Endpoint: form.Endpoint, P256DH: form.Keys.P256DH, Auth: form.Keys.Auth,
		Label: browserLabel(request.UserAgent()), CreatedBy: console.Username, CreatedAt: time.Now(),
	}
	switch {
	case !available || !editable:
		err = errors.New("browser alerts are not available on this server")
	case err != nil:
		err = errors.New("the browser sent a subscription Sable could not read")
	default:
		err = subscription.Valid()
	}
	if err == nil {
		err = store.SavePushSubscription(request.Context(), subscription)
	}
	added := false
	if err == nil {
		err = editor.Update(request.Context(), func(candidate *config.Config) error {
			if slices.ContainsFunc(candidate.Alerts.Destinations, isBrowserDestination) {
				return nil
			}
			destination := config.AlertDestination{
				ID: newAlertDestinationID(candidate.Alerts.Destinations, config.AlertFormatBrowser), Format: config.AlertFormatBrowser,
			}
			candidate.Alerts.Destinations = append(slices.Clone(candidate.Alerts.Destinations), destination)
			added = true
			return nil
		})
	}
	if err != nil {
		server.renderAlertsPanel(writer, request, console, http.StatusUnprocessableEntity, "", alertSentence(err))
		return
	}
	message := "This browser will get alerts."
	details := "turned on alerts in " + subscription.Label
	if added {
		message += " Browsers is now one of your destinations."
		details += ", adding Browsers to the destinations"
	}
	server.recordControlPlaneAudit(request, "alerts", details)
	server.renderAlertsPanel(writer, request, console, http.StatusOK, message, "")
}

// removeAlertBrowser stops alerts to one browser.
func (server *Server) removeAlertBrowser(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderAlertsPanel(writer, request, console, http.StatusBadRequest, "", "Sable could not read the form.")
		return
	}
	store, available := server.alertPushStore()
	if !available {
		server.renderAlertsPanel(writer, request, console, http.StatusNotImplemented, "", "Browser alerts are not available on this server.")
		return
	}
	subscriptions, err := store.PushSubscriptions(request.Context())
	var removed *webpush.Subscription
	for index := range subscriptions {
		if err == nil && subscriptions[index].ID() == request.FormValue("browser") {
			err = store.DeletePushSubscription(request.Context(), subscriptions[index].Endpoint)
			removed = &subscriptions[index]
			break
		}
	}
	switch {
	case err != nil:
		server.renderAlertsPanel(writer, request, console, http.StatusUnprocessableEntity, "", alertSentence(err))
	case removed == nil:
		server.renderAlertsPanel(writer, request, console, http.StatusNotFound, "", "That browser was already removed.")
	default:
		name := alertBrowserName(*removed)
		server.recordControlPlaneAudit(request, "alerts", "stopped alerts in "+name)
		server.renderAlertsPanel(writer, request, console, http.StatusOK, name+" will no longer get alerts.", "")
	}
}

// renderAlertsPanel answers a change on the Alerts tab with the whole tab,
// which swaps itself in place.
func (server *Server) renderAlertsPanel(writer http.ResponseWriter, request *http.Request, console pages.DashboardView, status int, message, problem string) {
	view := server.alertsView(request.Context(), console)
	view.Message, view.Error = message, problem
	writeFragmentStatus(writer, status)
	if err := pages.SettingsAlertsPanel(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render alerts", "error", err)
	}
}

// renderAlertDestinationProblem says in the open dialog why a destination was
// not saved. Only the notice is replaced, so what was typed stays.
func (server *Server) renderAlertDestinationProblem(writer http.ResponseWriter, request *http.Request, status int, problem string) {
	writer.Header().Set("HX-Retarget", "#alert-destination-notice")
	writer.Header().Set("HX-Reswap", "innerHTML")
	writeFragmentStatus(writer, status)
	if err := pages.ToastSticky(problem, "error").Render(request.Context(), writer); err != nil {
		server.logger.Error("render alert destination problem", "error", err)
	}
}

// alertPushStore is where browsers that turn alerts on are kept, and whether
// this server can push to them at all: it needs that store, a key to sign
// with, and a dispatcher that pushes.
func (server *Server) alertPushStore() (pushSubscriptionStore, bool) {
	store, ok := server.queries.(pushSubscriptionStore)
	if !ok || server.pushKeys == nil || server.alerts == nil || !server.alerts.Browsers.Available() {
		return nil, false
	}
	return store, true
}

// alertBrowserSubscriptions lists the browsers that turned alerts on, and
// whether this server can push to browsers at all.
func (server *Server) alertBrowserSubscriptions(ctx context.Context) ([]webpush.Subscription, bool) {
	store, available := server.alertPushStore()
	if !available {
		return nil, false
	}
	subscriptions, err := store.PushSubscriptions(ctx)
	if err != nil {
		server.logger.Warn("read push subscriptions", "error", err)
	}
	return subscriptions, true
}

// newAlertDestinationID names a new destination with sixteen random hex
// characters no other destination has. The one that pushes to browsers is
// called "browser", as older releases named it, unless that is taken.
func newAlertDestinationID(destinations []config.AlertDestination, format string) string {
	taken := func(id string) bool { return slices.ContainsFunc(destinations, hasAlertDestinationID(id)) }
	if format == config.AlertFormatBrowser && !taken(config.AlertFormatBrowser) {
		return config.AlertFormatBrowser
	}
	for {
		random := make([]byte, alertDestinationIDBytes)
		// crypto/rand never fails; it would stop the program first.
		_, _ = rand.Read(random)
		if id := hex.EncodeToString(random); !taken(id) {
			return id
		}
	}
}

func hasAlertDestinationID(id string) func(config.AlertDestination) bool {
	return func(destination config.AlertDestination) bool { return destination.ID == id }
}

func isBrowserDestination(destination config.AlertDestination) bool {
	return destination.Format == config.AlertFormatBrowser
}

// otherBrowserDestination matches a destination other than id that pushes to
// browsers, of which there can be only one.
func otherBrowserDestination(id string) func(config.AlertDestination) bool {
	return func(destination config.AlertDestination) bool {
		return destination.Format == config.AlertFormatBrowser && destination.ID != id
	}
}

// alertFormatKey names a format for the page, which calls the plain JSON
// webhook "json" where sable.toml leaves it unset.
func alertFormatKey(format string) string {
	if format == "" {
		return config.AlertFormatJSON
	}
	return format
}

// alertSignInMinutes shows the failed sign-in window in whole minutes, the
// unit the tab asks for, rounding a hand-written part minute up.
func alertSignInMinutes(within time.Duration) int {
	return int((within + time.Minute - 1) / time.Minute)
}

// alertBrowserName is what a browser is called, even one saved without a
// label.
func alertBrowserName(subscription webpush.Subscription) string {
	return cmp.Or(subscription.Label, "A browser")
}

// alertBrowserAdded says when a browser turned alerts on, and who did.
func alertBrowserAdded(subscription webpush.Subscription, display pages.TimeDisplay) string {
	added := "Added " + display.In(subscription.CreatedAt).Format("Jan 2, 2006")
	if subscription.CreatedBy != "" {
		added += " by " + subscription.CreatedBy
	}
	return added
}

// alertSentence words an error as a sentence for the console.
func alertSentence(err error) string {
	message := strings.TrimSpace(err.Error())
	// ntfy writes its name in lowercase, even to start a sentence, as in
	// "ntfy needs a URL".
	if !strings.HasPrefix(message, "ntfy ") {
		message = capitalizeFirst(message)
	}
	if message != "" && !strings.HasSuffix(message, ".") {
		message += "."
	}
	return message
}

// alertValidationSentence words a validation error for the dialog, without the
// place in sable.toml it names.
func alertValidationSentence(err error) string {
	message := strings.TrimPrefix(err.Error(), "alerts.destinations[0]")
	message = strings.TrimPrefix(message, ".")
	for _, field := range []string{"headers: ", "sends: "} {
		message = strings.TrimPrefix(message, field)
	}
	return alertSentence(errors.New(message))
}
