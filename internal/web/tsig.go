package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/drudge/sable/internal/tsig"
	"github.com/drudge/sable/internal/web/pages"
	"github.com/miekg/dns"
)

// tsigController edits both halves of a TSIG key: the name and algorithm in the
// configuration file and the shared secret in the encrypted vault.
type tsigController interface {
	Keys(context.Context) []tsig.Key
	Save(context.Context, tsig.Request) (tsig.Result, error)
	Delete(context.Context, string) error
}

// SetTSIGController attaches the TSIG key editor to the console.
func (server *Server) SetTSIGController(controller tsigController) {
	server.tsigKeys = controller
}

func (server *Server) saveTSIGKey(writer http.ResponseWriter, request *http.Request) {
	if server.tsigKeys == nil {
		server.renderSettingsMutation(writer, request, http.StatusNotImplemented, "", "TSIG keys are read-only.")
		return
	}
	if err := request.ParseForm(); err != nil {
		server.renderSettingsMutation(writer, request, http.StatusBadRequest, "", "Invalid TSIG key form.")
		return
	}
	result, err := server.tsigKeys.Save(request.Context(), tsig.Request{
		Name:      request.FormValue("tsig_name"),
		Algorithm: request.FormValue("tsig_algorithm"),
		Secret:    request.FormValue("tsig_secret"),
		Rotate:    request.FormValue("tsig_rotate") == "true",
	})
	if err != nil {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", capitalizeFirst(err.Error())+".")
		return
	}
	// Messages name the key the way the console shows it, without the root
	// label, so "Added TSIG key transfer-key." reads as one sentence.
	shown := pages.TSIGDisplayName(result.Name)
	action, message := "settings.tsig.update", fmt.Sprintf("Updated TSIG key %s.", shown)
	if result.Created {
		action, message = "settings.tsig.create", fmt.Sprintf("Added TSIG key %s.", shown)
	} else if result.Generated {
		action, message = "settings.tsig.rotate", fmt.Sprintf("Rotated the secret for TSIG key %s.", shown)
	}
	server.recordControlPlaneAudit(request, action, strings.TrimSuffix(message, "."))
	view := server.settingsView(request, message, "")
	view.ActiveTab = "tsig"
	// A generated secret is shown exactly once, on the render that created it.
	// Nothing reads it back out of the vault afterwards, so an operator who
	// loses it rotates the key rather than recovering the old value.
	view.TSIGGeneratedKey = result.Name
	view.TSIGGeneratedSecret = result.Secret
	server.renderSettingsView(writer, request, http.StatusOK, view)
}

func (server *Server) deleteTSIGKey(writer http.ResponseWriter, request *http.Request) {
	if server.tsigKeys == nil {
		server.renderSettingsMutation(writer, request, http.StatusNotImplemented, "", "TSIG keys are read-only.")
		return
	}
	if err := request.ParseForm(); err != nil {
		server.renderSettingsMutation(writer, request, http.StatusBadRequest, "", "Invalid TSIG key form.")
		return
	}
	name := normalizeTSIGKeyName(request.FormValue("tsig_name"))
	// The configuration manager refuses a key a zone still references, but it
	// reports that as a validation failure. Naming the zones first turns it
	// into something the operator can act on.
	if zones := server.zonesUsingTSIGKey(name); len(zones) > 0 {
		server.renderSettingsMutation(
			writer, request, http.StatusConflict, "",
			fmt.Sprintf("%s is still used by %s. Change those zones first.", pages.TSIGDisplayName(name), strings.Join(zones, ", ")),
		)
		return
	}
	if err := server.tsigKeys.Delete(request.Context(), name); err != nil {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", capitalizeFirst(err.Error())+".")
		return
	}
	server.recordControlPlaneAudit(request, "settings.tsig.delete", "removed TSIG key "+name)
	view := server.settingsView(request, "Removed TSIG key "+pages.TSIGDisplayName(name)+".", "")
	view.ActiveTab = "tsig"
	server.renderSettingsView(writer, request, http.StatusOK, view)
}

// tsigKeyViews lists the configured keys with the zones relying on each one, so
// the console can warn before a key is removed out from under a transfer.
func (server *Server) tsigKeyViews(ctx context.Context) []pages.SettingsTSIGKeyView {
	if server.tsigKeys == nil {
		return nil
	}
	keys := server.tsigKeys.Keys(ctx)
	views := make([]pages.SettingsTSIGKeyView, 0, len(keys))
	for _, key := range keys {
		views = append(views, pages.SettingsTSIGKeyView{
			Name: key.Name, Algorithm: key.Algorithm,
			Configured: key.Configured, Zones: server.zonesUsingTSIGKey(key.Name),
		})
	}
	return views
}

func (server *Server) tsigKeyNames(ctx context.Context) []string {
	names := make([]string, 0)
	if server.tsigKeys == nil {
		return names
	}
	for _, key := range server.tsigKeys.Keys(ctx) {
		names = append(names, key.Name)
	}
	return names
}

func (server *Server) zonesUsingTSIGKey(name string) []string {
	if server.zones == nil || name == "" {
		return nil
	}
	using := make([]string, 0)
	for _, configured := range server.zones.Current().Zones {
		if normalizeTSIGKeyName(configured.TSIGKey) == name {
			using = append(using, configured.Name)
		}
	}
	return using
}

func normalizeTSIGKeyName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}
	return strings.ToLower(dns.Fqdn(trimmed))
}

func capitalizeFirst(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}
