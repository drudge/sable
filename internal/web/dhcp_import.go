package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dhcpimport"
	"github.com/drudge/sable/internal/web/pages"
)

// dhcpImportResult is what an import added to a scope and what it passed
// over, and why. A dry run fills it in without saving.
type dhcpImportResult struct {
	Format    string                   `json:"format"`
	Scope     string                   `json:"scope"`
	DryRun    bool                     `json:"dry_run"`
	Added     []config.DHCPReservation `json:"added"`
	Unchanged int                      `json:"unchanged"`
	Skipped   []dhcpImportNote         `json:"skipped"`
	Warnings  []dhcpImportNote         `json:"warnings"`
}

// dhcpImportNote points at the line, or JSON list position, it's about.
type dhcpImportNote struct {
	Line    int    `json:"line"`
	MAC     string `json:"mac,omitempty"`
	Address string `json:"address,omitempty"`
	Text    string `json:"text"`
}

// Import adds the reservations in another server's export to scope, or to
// the only scope when scope is empty. A MAC or address the scope already
// reserves is left as it is: an import never overwrites a reservation.
func (service dhcpService) Import(ctx context.Context, who actor, scope string, data []byte, dryRun bool) (dhcpImportResult, error) {
	if err := service.ready(who); err != nil {
		return dhcpImportResult{}, err
	}
	parsed, err := dhcpimport.Parse(data)
	if err != nil {
		return dhcpImportResult{}, refuse(http.StatusUnprocessableEntity, "%s", err.Error())
	}
	settings := service.server.config.Current().Config.DHCP.Clone()
	result, err := dhcpImportPlan(&settings, scope, parsed)
	if err != nil || dryRun || len(result.Added) == 0 {
		result.DryRun = dryRun
		return result, err
	}
	message := fmt.Sprintf("imported %d reservations from a %s export into scope %s", len(result.Added), parsed.Format, result.Scope)
	err = service.update(ctx, who, "dhcp.reservation.import", message, func(settings *config.DHCP) error {
		result, err = dhcpImportPlan(settings, scope, parsed)
		return err
	})
	if err != nil {
		return dhcpImportResult{}, err
	}
	return result, nil
}

// dhcpImportPlan adds each parsed entry that fits to its scope in settings.
// Each is checked by the same validation as a hand-made reservation; one
// that only fails on its name is kept without it.
func dhcpImportPlan(settings *config.DHCP, scope string, parsed dhcpimport.Result) (dhcpImportResult, error) {
	target, err := dhcpImportScope(settings, scope)
	if err != nil {
		return dhcpImportResult{}, err
	}
	result := dhcpImportResult{Format: parsed.Format, Scope: target.ID, Added: []config.DHCPReservation{}}
	for _, problem := range parsed.Problems {
		result.Skipped = append(result.Skipped, dhcpImportNote{Line: problem.Line, Text: problem.Text})
	}
	for _, entry := range parsed.Entries {
		note := dhcpImportNote{Line: entry.Line, MAC: entry.MAC, Address: entry.Address}
		if index := slices.IndexFunc(target.Reservations, func(current config.DHCPReservation) bool { return current.MAC == entry.MAC }); index >= 0 {
			if target.Reservations[index].Address == entry.Address {
				result.Unchanged++
				continue
			}
			note.Text = "already reserved on " + target.Reservations[index].Address
			result.Skipped = append(result.Skipped, note)
			continue
		}
		reservation := config.DHCPReservation{MAC: entry.MAC, Address: entry.Address, Name: entry.Name, Comment: entry.Comment}
		if err := dhcpImportFits(settings, target, reservation); err != nil {
			reservation.Name = ""
			if entry.Name == "" || dhcpImportFits(settings, target, reservation) != nil {
				note.Text = err.Error()
				result.Skipped = append(result.Skipped, note)
				continue
			}
			note.Text = fmt.Sprintf("imported without the name %s: %v", entry.Name, err)
			result.Warnings = append(result.Warnings, note)
		}
		target.Reservations = append(target.Reservations, reservation)
		result.Added = append(result.Added, reservation)
	}
	return result, nil
}

// dhcpImportScope is the scope named id, or the only one when id is empty.
func dhcpImportScope(settings *config.DHCP, id string) (*config.DHCPScope, error) {
	if id == "" && len(settings.Scopes) == 1 {
		return &settings.Scopes[0], nil
	}
	if id == "" {
		return nil, refuse(http.StatusUnprocessableEntity, "name the scope to import into")
	}
	return dhcpScope(settings, id)
}

// dhcpImportFits reports why settings would be invalid with reservation
// added to target, without changing settings. A clash with a reservation
// names the client that holds it; anything else is the validation's own
// reason, without its field path.
func dhcpImportFits(settings *config.DHCP, target *config.DHCPScope, reservation config.DHCPReservation) error {
	for _, current := range target.Reservations {
		if current.Address == reservation.Address {
			return fmt.Errorf("%s is already reserved for %s", reservation.Address, current.MAC)
		}
	}
	for _, scope := range settings.Scopes {
		for _, current := range scope.Reservations {
			if reservation.Name != "" && current.Name == reservation.Name {
				return fmt.Errorf("%s is already the name of %s", reservation.Name, current.MAC)
			}
		}
	}
	trial := settings.Clone()
	scope, err := dhcpScope(&trial, target.ID)
	if err != nil {
		return err
	}
	scope.Reservations = append(scope.Reservations, reservation)
	if err := trial.Validate(); err != nil {
		message := err.Error()
		if index := strings.LastIndex(message, "]."); index >= 0 {
			message = message[index+2:]
		}
		return errors.New(message)
	}
	return nil
}

// importDHCPAPI takes the export as the raw body; scope names the scope and
// dry_run=true reports what it would do.
func (server *Server) importDHCPAPI(writer http.ResponseWriter, request *http.Request) {
	data, err := io.ReadAll(request.Body)
	if err != nil {
		apiError(writer, http.StatusRequestEntityTooLarge, "the export must be under 1 MiB")
		return
	}
	query := request.URL.Query()
	dryRun := query.Get("dry_run") == "true"
	result, err := server.dhcpService().Import(request.Context(), requestActor(request, ""), query.Get("scope"), data, dryRun)
	if err != nil {
		apiError(writer, serviceStatus(err), err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

// importDHCPConsole runs the Import Reservations dialog: a preview first, as
// a dry run, then the import when the preview sends the same export back.
func (server *Server) importDHCPConsole(writer http.ResponseWriter, request *http.Request) {
	const notice = "#" + pages.DHCPImportNoticeID
	text, err := readImportText(request, dhcpSettingsLimit, "import_text", "export")
	if err != nil {
		server.renderDHCPProblem(writer, request, notice, refuse(http.StatusBadRequest, "%s", err.Error()))
		return
	}
	// The preview sends the export back in a hidden field, and Back shows it
	// in the text box. Both hold text, so a UTF-16 upload goes on as UTF-8.
	text = strings.TrimSpace(dhcpimport.Text([]byte(text)))
	who, scope, step := requestActor(request, ""), request.FormValue("scope"), request.FormValue("step")
	if step == "back" {
		server.render(writer, request, pages.DHCPImportSource(pages.DHCPImportSourceView{Scopes: server.dhcpImportScopes(who), Scope: scope, Text: text}))
		return
	}
	result, err := server.dhcpService().Import(request.Context(), who, scope, []byte(text), step != "apply")
	if err != nil {
		server.renderDHCPProblem(writer, request, notice, err)
		return
	}
	if step == "apply" {
		writer.Header().Set("HX-Retarget", "#dhcp-content")
		server.renderDHCP(writer, request, dhcpImportMessage(result, server.dhcpImportPreview(who, result, "").ScopeLabel))
		return
	}
	server.render(writer, request, pages.DHCPImportPreview(server.dhcpImportPreview(who, result, text)))
}

// dhcpImportScopes are the scopes the dialog offers, as the page lists them.
func (server *Server) dhcpImportScopes(who actor) []pages.DHCPImportScope {
	state, err := server.dhcpService().State(who)
	if err != nil {
		return nil
	}
	views := make([]pages.DHCPScopeView, 0, len(state.Settings.Scopes))
	for _, scope := range state.Settings.Scopes {
		views = append(views, dhcpScopeView(scope))
	}
	return pages.DHCPImportScopes(views)
}

func (server *Server) dhcpImportPreview(who actor, result dhcpImportResult, text string) pages.DHCPImportPreviewView {
	view := pages.DHCPImportPreviewView{Scope: result.Scope, ScopeLabel: result.Scope, Format: result.Format, Text: text, Unchanged: result.Unchanged}
	for _, scope := range server.dhcpImportScopes(who) {
		if scope.ID == result.Scope {
			view.ScopeLabel = scope.Label
		}
	}
	for _, reservation := range result.Added {
		view.Added = append(view.Added, pages.DHCPReservationRow{Scope: result.Scope, MAC: reservation.MAC, Address: reservation.Address, Name: reservation.Name})
	}
	notes := func(from []dhcpImportNote) []pages.DHCPImportNote {
		converted := make([]pages.DHCPImportNote, 0, len(from))
		for _, note := range from {
			converted = append(converted, pages.DHCPImportNote{Line: note.Line, MAC: note.MAC, Address: note.Address, Text: sentence(note.Text)})
		}
		return converted
	}
	view.Skipped, view.Warnings = notes(result.Skipped), notes(result.Warnings)
	return view
}

func dhcpImportMessage(result dhcpImportResult, scope string) string {
	count := len(result.Added)
	if count == 0 {
		return "Nothing to import: every reservation in the export is already here or was skipped"
	}
	return fmt.Sprintf("Imported %d %s into %s", count, pluralize(count, "reservation", "reservations"), scope)
}
