package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/unifi"
	"github.com/drudge/sable/internal/web/pages"
	"github.com/drudge/sable/internal/zone"
)

// unifiController is the console's view of the UniFi host synchronizer.
type unifiController interface {
	Status() unifi.Status
	SyncNow()
	Preview(context.Context, config.UniFi) (unifi.Plan, error)
	Inventory(context.Context, config.UniFi) (unifi.Inventory, error)
	PutCredentials(context.Context, unifi.Credentials) error
	StoredCredentials(context.Context) (unifi.Credentials, bool)
	ForgetCredentials(context.Context) error
}

// SetUniFiController attaches the host synchronizer to the console.
func (server *Server) SetUniFiController(controller unifiController) {
	server.unifi = controller
}

func (server *Server) integrationsPage(writer http.ResponseWriter, request *http.Request) {
	view := server.integrationsView(request, "", "")
	if request.URL.Query().Get("setup") == "unifi" {
		view.UniFi.Wizard = server.newUniFiWizard(request)
	}
	if err := pages.IntegrationsPage(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render integrations page", "error", err)
	}
}

func (server *Server) integrationsView(request *http.Request, message, errorMessage string) pages.IntegrationsPageView {
	settings := server.config.Current().Config.UniFi
	view := pages.IntegrationsPageView{
		Console: server.consoleView(request),
		Message: message,
		Error:   errorMessage,
		UniFi: pages.UniFiAppView{
			Available:        server.unifi != nil,
			Configured:       len(settings.Networks) > 0,
			Enabled:          settings.Enabled,
			ControllerURL:    settings.ControllerURL,
			Site:             settings.Site,
			Interval:         settings.Interval.String(),
			SyncReservations: settings.SyncsReservations(),
			SyncActive:       settings.SyncsActiveClients(),
			CAFile:           settings.CAFile,
			Insecure:         settings.Insecure,
			Mappings:         unifiMappingViews(settings),
		},
	}
	if server.unifi == nil {
		return view
	}
	credentials, configured := server.unifi.StoredCredentials(request.Context())
	view.UniFi.CredentialsConfigured = configured
	view.UniFi.AuthMode = unifiAuthMode(credentials)
	view.UniFi.Username = credentials.Username
	view.UniFi.Status = unifiStatusView(server.unifi.Status(), view.Console.TimeDisplay)
	return view
}

func unifiAuthMode(credentials unifi.Credentials) string {
	if strings.TrimSpace(credentials.APIKey) == "" && strings.TrimSpace(credentials.Username) != "" {
		return "account"
	}
	return "api-key"
}

func unifiMappingViews(settings config.UniFi) []pages.UniFiMappingView {
	mappings := make([]pages.UniFiMappingView, 0, len(settings.Networks))
	for _, network := range settings.Networks {
		mappings = append(mappings, pages.UniFiMappingView{
			ID: network.ID, Name: network.DisplayName(), Zone: network.Zone,
			Template: network.HostnameTemplate, TTL: network.TTL,
			Reverse: network.Reverse, Enabled: network.Enabled,
			Preview: unifiPreviewName(network.HostnameTemplate, network.DisplayName(), network.Zone),
		})
	}
	return mappings
}

// unifiPreviewName renders a sample fully qualified name so the operator can
// see the effect of a template before saving it.
func unifiPreviewName(template, network, zoneName string) string {
	parsed, err := unifi.ParseTemplate(template)
	if err != nil {
		return ""
	}
	preview, err := parsed.Render("macbook-pro", network, zoneName)
	if err != nil {
		return ""
	}
	return preview
}

func unifiStatusView(status unifi.Status, display pages.TimeDisplay) pages.UniFiStatusView {
	view := pages.UniFiStatusView{
		Running: status.Running, LastError: status.LastError, Hosts: status.Hosts,
		Added: status.Added, Updated: status.Updated, Removed: status.Removed,
		ZonesCreated: status.ZonesCreated,
	}
	if !status.LastSuccess.IsZero() {
		view.LastSuccess = pages.FormatShortDateTime(status.LastSuccess, display, true)
	}
	if !status.NextAttempt.IsZero() {
		view.NextAttempt = pages.FormatShortDateTime(status.NextAttempt, display, true)
	}
	if status.Duration > 0 {
		view.Duration = status.Duration.Round(time.Millisecond).String()
	}
	return view
}

func (server *Server) unifiStatusPanel(writer http.ResponseWriter, request *http.Request) {
	view := server.integrationsView(request, "", "")
	if err := pages.UniFiStatusPanel(view.UniFi).Render(request.Context(), writer); err != nil {
		server.logger.Error("render UniFi status", "error", err)
		return
	}
	// The action row lives outside the polled fragment, so it rides along as an
	// out-of-band swap to keep Sync Now in step with the run state.
	if err := pages.UniFiCardActions(view.UniFi, true).Render(request.Context(), writer); err != nil {
		server.logger.Error("render UniFi actions", "error", err)
	}
}

func (server *Server) syncUniFiNow(writer http.ResponseWriter, request *http.Request) {
	if server.unifi == nil {
		server.renderIntegrationsMutation(writer, request, http.StatusNotImplemented, "", "The UniFi synchronizer is unavailable.")
		return
	}
	if !server.config.Current().Config.UniFi.Runnable() {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", "Finish UniFi setup before running a synchronization.")
		return
	}
	server.unifi.SyncNow()
	server.recordControlPlaneAudit(request, "integrations.unifi.sync", "requested an immediate UniFi synchronization")
	server.renderIntegrationsMutation(writer, request, http.StatusOK, "Synchronization started.", "")
}

func (server *Server) setUniFiEnabled(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusBadRequest, "", "Invalid request.")
		return
	}
	enabled := request.FormValue("enabled") == "true"
	editor, ok := server.config.(settingsEditor)
	if !ok {
		server.renderIntegrationsMutation(writer, request, http.StatusNotImplemented, "", "Settings are read-only.")
		return
	}
	if err := editor.Update(request.Context(), func(candidate *config.Config) error {
		candidate.UniFi.Enabled = enabled
		return nil
	}); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	action, message := "integrations.unifi.disable", "UniFi synchronization paused. Existing records were left in place."
	if enabled {
		action, message = "integrations.unifi.enable", "UniFi synchronization resumed."
		if server.unifi != nil {
			server.unifi.SyncNow()
		}
	}
	server.recordControlPlaneAudit(request, action, message)
	server.renderIntegrationsMutation(writer, request, http.StatusOK, message, "")
}

// removeUniFi resets the integration: the configuration, the stored
// credentials, and every record the synchronizer published. Zones it created
// are left alone because they may also hold hand-authored records.
func (server *Server) removeUniFi(writer http.ResponseWriter, request *http.Request) {
	if server.unifi == nil {
		server.renderIntegrationsMutation(writer, request, http.StatusNotImplemented, "", "The UniFi synchronizer is unavailable.")
		return
	}
	editor, ok := server.config.(settingsEditor)
	if !ok {
		server.renderIntegrationsMutation(writer, request, http.StatusNotImplemented, "", "Settings are read-only.")
		return
	}
	if err := editor.Update(request.Context(), func(candidate *config.Config) error {
		candidate.UniFi = config.UniFi{Site: "default", Interval: config.Duration{Duration: 2 * time.Minute}}
		return nil
	}); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	removed, err := server.removeSourcedRecords(request, zone.SourceUniFi)
	if err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	if err := server.unifi.ForgetCredentials(request.Context()); err != nil {
		server.logger.Warn("clear UniFi credentials", "error", err)
	}
	server.recordControlPlaneAudit(request, "integrations.unifi.remove",
		fmt.Sprintf("removed the UniFi integration and %d published records", removed))
	server.renderIntegrationsMutation(writer, request, http.StatusOK,
		fmt.Sprintf("UniFi integration removed. %d published records were deleted.", removed), "")
}

// removeSourcedRecords deletes every record an integration owns and reports how
// many went away.
func (server *Server) removeSourcedRecords(request *http.Request, source string) (int, error) {
	editor, ok := server.zones.(zoneEditor)
	if !ok {
		return 0, errors.New("zones are read-only")
	}
	removed := 0
	err := editor.UpdateZones(request.Context(), func(zones *[]zone.Zone) error {
		removed = 0
		now := time.Now()
		for index := range *zones {
			target := &(*zones)[index]
			kept := make([]zone.Record, 0, len(target.Records))
			for _, record := range target.Records {
				if record.Source == source {
					removed++
					continue
				}
				kept = append(kept, record)
			}
			if len(kept) == len(target.Records) {
				continue
			}
			target.Records = kept
			zone.AdvanceSerial(target, now)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}

func (server *Server) renderIntegrationsMutation(writer http.ResponseWriter, request *http.Request, status int, message, errorMessage string) {
	view := server.integrationsView(request, message, errorMessage)
	writer.WriteHeader(status)
	if err := pages.IntegrationsContent(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render integrations content", "error", err)
	}
}

// unifiSettingsFromWizard turns the wizard's accumulated choices into the
// configuration the reconciler consumes. Passing nil networks yields
// connection-only settings, which is all the discovery steps need.
func unifiSettingsFromWizard(wizard pages.UniFiWizardView, networks []pages.UniFiWizardNetworkView) config.UniFi {
	settings := config.UniFi{
		ControllerURL: wizard.ControllerURL,
		Site:          wizard.Site,
		CAFile:        wizard.CAFile,
		Insecure:      wizard.Insecure,
		Interval:      config.Duration{Duration: 2 * time.Minute},
	}
	if parsed, err := time.ParseDuration(wizard.Interval); err == nil && parsed > 0 {
		settings.Interval = config.Duration{Duration: parsed}
	}
	if wizard.SyncReservations {
		settings.Sources = append(settings.Sources, "reservations")
	}
	if wizard.SyncActive {
		settings.Sources = append(settings.Sources, "active")
	}
	for _, network := range networks {
		template := network.Template
		if template == "" {
			template = unifi.DefaultHostnameTemplate
		}
		settings.Networks = append(settings.Networks, config.UniFiNetwork{
			ID: network.ID, Name: network.Name, Zone: normalizeZoneName(network.Zone),
			HostnameTemplate: template, TTL: network.TTL, Reverse: network.Reverse, Enabled: true,
		})
	}
	return settings
}

// Wizard.

const (
	unifiStepConnect  = "connect"
	unifiStepNetworks = "networks"
	unifiStepZones    = "zones"
	unifiStepReview   = "review"
)

func (server *Server) newUniFiWizard(request *http.Request) pages.UniFiWizardView {
	settings := server.config.Current().Config.UniFi
	wizard := pages.UniFiWizardView{
		Open: true, Step: unifiStepConnect,
		ControllerURL: settings.ControllerURL, Site: settings.Site,
		Interval: settings.Interval.String(), CAFile: settings.CAFile, Insecure: settings.Insecure,
		SyncReservations: settings.SyncsReservations(), SyncActive: settings.SyncsActiveClients(),
		AuthMode: "api-key",
	}
	if settings.Site == "" {
		wizard.Site = "default"
	}
	if len(settings.Networks) == 0 {
		wizard.SyncReservations, wizard.SyncActive = true, true
	}
	if server.unifi != nil {
		credentials, configured := server.unifi.StoredCredentials(request.Context())
		wizard.CredentialsConfigured = configured
		wizard.AuthMode = unifiAuthMode(credentials)
		wizard.Username = credentials.Username
	}
	return wizard
}

// runUniFiWizard advances the setup wizard. Each step is a server round trip
// because the network and zone steps need live data from the controller, and
// the review step needs the same plan the reconciler would apply.
func (server *Server) runUniFiWizard(writer http.ResponseWriter, request *http.Request) {
	if server.unifi == nil {
		server.renderIntegrationsMutation(writer, request, http.StatusNotImplemented, "", "The UniFi synchronizer is unavailable.")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusBadRequest, "", "Invalid setup form.")
		return
	}
	wizard := server.unifiWizardFromRequest(request)
	// A completed step marker or the Back button asks to revisit an earlier
	// step rather than advance, so that wins over the step being submitted.
	if target := strings.TrimSpace(request.FormValue("wizard_target")); target != "" {
		server.unifiWizardBack(writer, request, wizard, target)
		return
	}
	switch request.FormValue("wizard_step") {
	case unifiStepConnect:
		server.unifiWizardConnect(writer, request, wizard)
	case unifiStepNetworks:
		server.unifiWizardZones(writer, request, wizard)
	case unifiStepZones:
		server.unifiWizardReview(writer, request, wizard)
	case unifiStepReview:
		server.unifiWizardFinish(writer, request, wizard)
	default:
		server.renderWizard(writer, request, http.StatusBadRequest, wizard)
	}
}

// unifiWizardFromRequest rebuilds the operator's choices from the posted form
// and fills in anything the current step has not collected yet.
func (server *Server) unifiWizardFromRequest(request *http.Request) pages.UniFiWizardView {
	wizard := unifiWizardFromForm(request)
	// The connection step no longer asks what to publish, so those choices are
	// absent until the networks step submits them. Seed them from the saved
	// configuration instead of reading unchecked boxes as deliberate answers.
	if !request.Form.Has("sources_present") {
		settings := server.config.Current().Config.UniFi
		wizard.SyncReservations = settings.SyncsReservations()
		wizard.SyncActive = settings.SyncsActiveClients()
		if len(settings.Networks) == 0 {
			wizard.SyncReservations, wizard.SyncActive = true, true
		}
		if interval := settings.Interval.String(); interval != "" {
			wizard.Interval = interval
		}
	}
	return wizard
}

// unifiWizardBack re-renders an earlier step with everything the operator has
// entered so far. Discovery steps re-read the controller so the lists are never
// stale.
func (server *Server) unifiWizardBack(writer http.ResponseWriter, request *http.Request, wizard pages.UniFiWizardView, target string) {
	switch target {
	case unifiStepNetworks, unifiStepZones:
		inventory, err := server.unifi.Inventory(request.Context(), unifiSettingsFromWizard(wizard, nil))
		if err != nil {
			wizard.Step, wizard.Error = unifiStepConnect, unifiConnectionMessage(err)
			server.renderWizard(writer, request, http.StatusBadGateway, wizard)
			return
		}
		wizard.Networks = unifiWizardNetworks(inventory, server.config.Current().Config.UniFi, wizard)
		if target == unifiStepNetworks {
			wizard.Step = unifiStepNetworks
			break
		}
		wizard.Step = unifiStepZones
		wizard.ZoneOptions = server.primaryZoneNames()
		// Zone choices already entered survive the trip back; a first visit
		// falls back to whatever the networks step selected.
		if unifiFormNetworkCount(request) > 0 {
			wizard.Networks = make([]pages.UniFiWizardNetworkView, unifiFormNetworkCount(request))
			unifiZoneChoicesFromForm(request, &wizard)
		} else {
			wizard.Networks = unifiSelectedNetworks(wizard)
		}
		server.applyUniFiPreviews(&wizard)
	default:
		wizard.Step = unifiStepConnect
		if server.unifi != nil {
			_, configured := server.unifi.StoredCredentials(request.Context())
			wizard.CredentialsConfigured = configured
		}
	}
	server.renderWizard(writer, request, http.StatusOK, wizard)
}

// unifiWizardFromForm rebuilds the operator's choices from the posted form.
// Secrets are never carried between steps: the connection step seals them in
// the vault and every later step reads them back from there.
func unifiWizardFromForm(request *http.Request) pages.UniFiWizardView {
	wizard := pages.UniFiWizardView{
		Open:             true,
		ControllerURL:    strings.TrimRight(strings.TrimSpace(request.FormValue("controller_url")), "/"),
		Site:             strings.TrimSpace(request.FormValue("site")),
		AuthMode:         strings.TrimSpace(request.FormValue("auth_mode")),
		Username:         strings.TrimSpace(request.FormValue("username")),
		CAFile:           strings.TrimSpace(request.FormValue("tls_ca_file")),
		Insecure:         request.FormValue("tls_insecure") == "true",
		Interval:         strings.TrimSpace(request.FormValue("interval")),
		SyncReservations: request.FormValue("source_reservations") == "true",
		SyncActive:       request.FormValue("source_active") == "true",
		Selected:         request.Form["network"],
	}
	if wizard.Site == "" {
		wizard.Site = "default"
	}
	if wizard.AuthMode != "account" {
		wizard.AuthMode = "api-key"
	}
	if wizard.Interval == "" {
		wizard.Interval = "2m"
	}
	return wizard
}

func (server *Server) unifiWizardConnect(writer http.ResponseWriter, request *http.Request, wizard pages.UniFiWizardView) {
	wizard.Step = unifiStepConnect
	credentials, err := server.unifiWizardCredentials(request, wizard)
	if err != nil {
		wizard.Error = err.Error()
		server.renderWizard(writer, request, http.StatusUnprocessableEntity, wizard)
		return
	}
	if err := server.unifi.PutCredentials(request.Context(), credentials); err != nil {
		wizard.Error = err.Error()
		server.renderWizard(writer, request, http.StatusUnprocessableEntity, wizard)
		return
	}
	wizard.CredentialsConfigured = true
	server.recordControlPlaneAudit(request, "integrations.unifi.credentials", "stored UniFi controller credentials")
	inventory, err := server.unifi.Inventory(request.Context(), unifiSettingsFromWizard(wizard, nil))
	if err != nil {
		wizard.Error = unifiConnectionMessage(err)
		server.renderWizard(writer, request, http.StatusBadGateway, wizard)
		return
	}
	wizard.Step = unifiStepNetworks
	wizard.Networks = unifiWizardNetworks(inventory, server.config.Current().Config.UniFi, wizard)
	if len(wizard.Networks) == 0 {
		wizard.Error = "The controller reported no networks for this site. Check the site name and try again."
		wizard.Step = unifiStepConnect
		server.renderWizard(writer, request, http.StatusUnprocessableEntity, wizard)
		return
	}
	server.renderWizard(writer, request, http.StatusOK, wizard)
}

// unifiWizardCredentials builds credentials from the connection form, keeping
// the stored secret when the operator left the field blank on a re-run.
func (server *Server) unifiWizardCredentials(request *http.Request, wizard pages.UniFiWizardView) (unifi.Credentials, error) {
	stored, _ := server.unifi.StoredCredentials(request.Context())
	if wizard.AuthMode == "account" {
		password := request.FormValue("password")
		if strings.TrimSpace(password) == "" {
			password = stored.Password
		}
		if wizard.Username == "" || strings.TrimSpace(password) == "" {
			return unifi.Credentials{}, errors.New("Enter the local account username and password.")
		}
		return unifi.Credentials{Username: wizard.Username, Password: password}, nil
	}
	apiKey := strings.TrimSpace(request.FormValue("api_key"))
	if apiKey == "" {
		apiKey = strings.TrimSpace(stored.APIKey)
	}
	if apiKey == "" {
		return unifi.Credentials{}, errors.New("Enter the UniFi API key.")
	}
	return unifi.Credentials{APIKey: apiKey}, nil
}

func unifiConnectionMessage(err error) string {
	if errors.Is(err, unifi.ErrUnauthorized) {
		return "The controller rejected these credentials. Check the API key, or switch to a local account."
	}
	if strings.Contains(err.Error(), "certificate") {
		return err.Error() + ". UniFi consoles use a self-signed certificate: pin its issuer with a CA file, or accept the risk below."
	}
	return err.Error()
}

// unifiWizardNetworks merges what the controller reports with any mapping the
// operator already saved, so re-running the wizard shows current choices.
func unifiWizardNetworks(inventory unifi.Inventory, settings config.UniFi, wizard pages.UniFiWizardView) []pages.UniFiWizardNetworkView {
	counts := inventory.HostCounts()
	existing := make(map[string]config.UniFiNetwork, len(settings.Networks))
	for _, network := range settings.Networks {
		existing[network.ID] = network
	}
	reselecting := len(wizard.Selected) > 0
	networks := make([]pages.UniFiWizardNetworkView, 0, len(inventory.Networks))
	for _, network := range inventory.Networks {
		view := pages.UniFiWizardNetworkView{
			ID: network.ID, Name: network.Name, Hosts: counts[network.ID],
			Subnet: unifiSubnetLabel(network.Subnets), Template: unifi.DefaultHostnameTemplate,
			TTL: 300, Reverse: true,
		}
		if mapping, found := existing[network.ID]; found {
			view.Selected = mapping.Enabled
			view.Zone, view.Template, view.TTL, view.Reverse = mapping.Zone, mapping.HostnameTemplate, mapping.TTL, mapping.Reverse
		}
		if reselecting {
			view.Selected = slices.Contains(wizard.Selected, network.ID)
		}
		view.ReverseZones = unifiReverseZoneNames(network.Subnets)
		networks = append(networks, view)
	}
	sort.SliceStable(networks, func(left, right int) bool {
		return strings.ToLower(networks[left].Name) < strings.ToLower(networks[right].Name)
	})
	return networks
}

func unifiSubnetLabel(subnets []netip.Prefix) string {
	labels := make([]string, 0, len(subnets))
	for _, subnet := range subnets {
		labels = append(labels, subnet.String())
	}
	return strings.Join(labels, ", ")
}

func unifiReverseZoneNames(subnets []netip.Prefix) []string {
	names := make([]string, 0, len(subnets))
	for _, subnet := range subnets {
		name, err := dnsname.ReverseZone(subnet)
		if err != nil {
			continue
		}
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}

func (server *Server) unifiWizardZones(writer http.ResponseWriter, request *http.Request, wizard pages.UniFiWizardView) {
	inventory, err := server.unifi.Inventory(request.Context(), unifiSettingsFromWizard(wizard, nil))
	if err != nil {
		wizard.Step, wizard.Error = unifiStepConnect, unifiConnectionMessage(err)
		server.renderWizard(writer, request, http.StatusBadGateway, wizard)
		return
	}
	wizard.Networks = unifiWizardNetworks(inventory, server.config.Current().Config.UniFi, wizard)
	if len(wizard.Selected) == 0 {
		wizard.Step = unifiStepNetworks
		wizard.Error = "Select at least one network to synchronize."
		server.renderWizard(writer, request, http.StatusUnprocessableEntity, wizard)
		return
	}
	wizard.Step = unifiStepZones
	wizard.Networks = unifiSelectedNetworks(wizard)
	wizard.ZoneOptions = server.primaryZoneNames()
	server.applyUniFiPreviews(&wizard)
	server.renderWizard(writer, request, http.StatusOK, wizard)
}

func unifiSelectedNetworks(wizard pages.UniFiWizardView) []pages.UniFiWizardNetworkView {
	selected := make([]pages.UniFiWizardNetworkView, 0, len(wizard.Selected))
	for _, network := range wizard.Networks {
		if slices.Contains(wizard.Selected, network.ID) {
			network.Selected = true
			selected = append(selected, network)
		}
	}
	return selected
}

func (server *Server) primaryZoneNames() []string {
	zones := server.zones.Current().Zones
	names := make([]string, 0, len(zones))
	for _, current := range zones {
		if current.Type == "primary" {
			names = append(names, current.Name)
		}
	}
	sort.Strings(names)
	return names
}

// applyUniFiPreviews fills each row's sample name and reverse zone so the
// mapping step shows exactly what the templates produce.
func (server *Server) applyUniFiPreviews(wizard *pages.UniFiWizardView) {
	for index := range wizard.Networks {
		network := &wizard.Networks[index]
		if network.Zone == "" {
			continue
		}
		network.Preview = unifiPreviewName(network.Template, network.Name, network.Zone)
	}
}

// unifiZoneChoicesFromForm reads the per-network zone mapping fields. Field
// names are suffixed with the network index rather than its identifier because
// controller identifiers are opaque and would make brittle form keys.
func unifiZoneChoicesFromForm(request *http.Request, wizard *pages.UniFiWizardView) {
	for index := range wizard.Networks {
		network := &wizard.Networks[index]
		suffix := strconv.Itoa(index)
		network.ID = strings.TrimSpace(request.FormValue("network_id_" + suffix))
		network.Name = strings.TrimSpace(request.FormValue("network_name_" + suffix))
		network.Subnet = strings.TrimSpace(request.FormValue("network_subnet_" + suffix))
		network.Zone = strings.TrimSpace(request.FormValue("zone_" + suffix))
		network.Template = strings.TrimSpace(request.FormValue("template_" + suffix))
		network.Reverse = request.FormValue("reverse_"+suffix) == "true"
		network.Selected = true
		if ttl, err := strconv.ParseUint(request.FormValue("ttl_"+suffix), 10, 32); err == nil && ttl > 0 {
			network.TTL = uint32(ttl)
		} else {
			network.TTL = 300
		}
		network.ReverseZones = unifiReverseZoneNamesFromLabel(network.Subnet)
	}
}

func unifiReverseZoneNamesFromLabel(label string) []string {
	subnets := make([]netip.Prefix, 0, 2)
	for _, field := range strings.Split(label, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(field))
		if err != nil {
			continue
		}
		subnets = append(subnets, prefix)
	}
	return unifiReverseZoneNames(subnets)
}

func (server *Server) unifiWizardReview(writer http.ResponseWriter, request *http.Request, wizard pages.UniFiWizardView) {
	wizard.Networks = make([]pages.UniFiWizardNetworkView, unifiFormNetworkCount(request))
	unifiZoneChoicesFromForm(request, &wizard)
	wizard.ZoneOptions = server.primaryZoneNames()
	server.applyUniFiPreviews(&wizard)
	settings := unifiSettingsFromWizard(wizard, wizard.Networks)
	if err := settings.Validate(); err != nil {
		wizard.Step, wizard.Error = unifiStepZones, err.Error()
		server.renderWizard(writer, request, http.StatusUnprocessableEntity, wizard)
		return
	}
	plan, err := server.unifi.Preview(request.Context(), settings)
	if err != nil {
		wizard.Step, wizard.Error = unifiStepZones, unifiConnectionMessage(err)
		server.renderWizard(writer, request, http.StatusBadGateway, wizard)
		return
	}
	wizard.Step = unifiStepReview
	wizard.Plan = unifiPlanView(plan)
	server.renderWizard(writer, request, http.StatusOK, wizard)
}

func unifiFormNetworkCount(request *http.Request) int {
	count := 0
	for key := range request.Form {
		if strings.HasPrefix(key, "network_id_") {
			count++
		}
	}
	return count
}

func unifiPlanView(plan unifi.Plan) pages.UniFiPlanView {
	view := pages.UniFiPlanView{
		CreatedZones: plan.CreatedZones, Skipped: plan.Skipped, Hosts: plan.Hosts,
		Added:      unifiPlanRecordViews(plan.Added),
		Updated:    unifiPlanRecordViews(plan.Updated),
		Removed:    unifiPlanRecordViews(plan.Removed),
		Publishing: unifiPlanRecordViews(plan.Publishing),
	}
	view.Empty = plan.Empty()
	return view
}

func unifiPlanRecordViews(records []unifi.PlanRecord) []pages.UniFiPlanRecordView {
	views := make([]pages.UniFiPlanRecordView, 0, len(records))
	for _, record := range records {
		name := record.Name
		if name == "@" {
			name = record.Zone
		} else {
			name = record.Name + "." + record.Zone
		}
		views = append(views, pages.UniFiPlanRecordView{Name: name, Type: record.Type, Value: record.Value})
	}
	return views
}

func (server *Server) unifiWizardFinish(writer http.ResponseWriter, request *http.Request, wizard pages.UniFiWizardView) {
	wizard.Networks = make([]pages.UniFiWizardNetworkView, unifiFormNetworkCount(request))
	unifiZoneChoicesFromForm(request, &wizard)
	settings := unifiSettingsFromWizard(wizard, wizard.Networks)
	settings.Enabled = true
	editor, ok := server.config.(settingsEditor)
	if !ok {
		server.renderIntegrationsMutation(writer, request, http.StatusNotImplemented, "", "Settings are read-only.")
		return
	}
	if err := editor.Update(request.Context(), func(candidate *config.Config) error {
		candidate.UniFi = settings
		return nil
	}); err != nil {
		wizard.Step, wizard.Error = unifiStepZones, err.Error()
		wizard.ZoneOptions = server.primaryZoneNames()
		server.renderWizard(writer, request, http.StatusUnprocessableEntity, wizard)
		return
	}
	server.unifi.SyncNow()
	server.recordControlPlaneAudit(request, "integrations.unifi.configure",
		fmt.Sprintf("enabled UniFi synchronization for %d networks", len(settings.ActiveNetworks())))
	writer.Header().Set("HX-Replace-Url", "/integrations")
	server.renderIntegrationsMutation(writer, request, http.StatusOK, "UniFi synchronization is set up. The first sync is running now.", "")
}

func (server *Server) renderWizard(writer http.ResponseWriter, request *http.Request, status int, wizard pages.UniFiWizardView) {
	view := server.integrationsView(request, "", "")
	view.UniFi.Wizard = wizard
	writer.WriteHeader(status)
	if err := pages.IntegrationsContent(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render UniFi setup wizard", "error", err)
	}
}

// zoneRecordSourceLabel names the integration that owns a record so the zone
// editor can show why a row is read-only.
func zoneRecordSourceLabel(source string) string {
	switch source {
	case zone.SourceUniFi:
		return "UniFi"
	case "":
		return ""
	default:
		return source
	}
}
