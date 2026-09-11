package web

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/web/pages"
	zonemodel "github.com/drudge/sable/internal/zone"
	"github.com/miekg/dns"
)

// Catalog imports deliberately do not subscribe to the source catalog.
func (server *Server) importCatalog(writer http.ResponseWriter, request *http.Request) {
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	if server.securityEnabled && !auth.Authorize(principal, auth.PermissionZonesCreate, "", "") {
		http.Error(writer, "Permission to create zones is required.", http.StatusForbidden)
		return
	}
	view := pages.CatalogImportView{Console: server.consoleView(request), Protocol: "tcp", TSIGKeys: server.tsigKeyNames(request.Context())}
	if request.Method == http.MethodPost {
		request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
		if err := request.ParseForm(); err != nil {
			http.Error(writer, "Invalid import form", 400)
			return
		}
		view.Catalog = request.FormValue("catalog")
		view.Source = request.FormValue("primary_servers")
		view.Protocol = request.FormValue("primary_protocol")
		view.Key = request.FormValue("tsig_key")
		view.Selected = request.Form["member"]
		view.ImportType = request.FormValue("import_type")
		if request.FormValue("step") != "connect" {
			if err := server.prepareCatalogImport(request, &view); err != nil {
				view.Error = err.Error()
			}
		}
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	zonesView := server.zonesView(request, "", "", "")
	zonesView.CatalogImport = &view
	component := pages.ZonesPage(zonesView)
	if request.Header.Get("HX-Request") == "true" {
		component = pages.ZonesContent(zonesView)
	}
	if err := component.Render(request.Context(), writer); err != nil {
		server.logger.Error("render catalog import", "error", err)
	}
}

func (server *Server) prepareCatalogImport(request *http.Request, view *pages.CatalogImportView) error {
	view.ImportType = request.FormValue("import_type")
	if view.ImportType == "" {
		view.ImportType = "secondary"
	}
	name, err := dnsname.Normalize(view.Catalog)
	if err != nil {
		return fmt.Errorf("catalog name: %w", err)
	}
	view.Catalog = name
	if view.Protocol != "tcp" && view.Protocol != "tls" {
		return errors.New("choose TCP or DNS-over-TLS")
	}
	primaries, err := normalizeZonePrimaryServers(view.Source, view.Protocol)
	if err != nil {
		return err
	}
	view.Key = strings.TrimSpace(view.Key)
	if view.Key != "" {
		view.Key = strings.ToLower(dns.Fqdn(view.Key))
	}
	if view.Key != "" && !slices.Contains(view.TSIGKeys, view.Key) {
		return errors.New("select a configured TSIG key")
	}
	synchronizer, ok := any(server.stats).(zoneSynchronizer)
	if !ok {
		return errors.New("zone synchronization is unavailable")
	}
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Minute)
	defer cancel()
	transferCtx, transferCancel := context.WithTimeout(ctx, conversionSyncTimeout)
	records, err := synchronizer.FetchZone(transferCtx, name, "catalog", primaries, view.Protocol, view.Key)
	transferCancel()
	if err != nil {
		return fmt.Errorf("catalog transfer failed: %w", err)
	}
	catalog, err := zonemodel.ParseCatalog(name, configuredZoneRecords(records))
	if err != nil {
		return fmt.Errorf("cannot read catalog: %w", err)
	}
	if len(catalog.Members) > 1000 {
		return errors.New("catalog exceeds the 1,000-member import limit")
	}
	// Bind review to membership and source, without invalidating it on SOA refreshes.
	binding, _ := json.Marshal([]any{name, primaries, view.Protocol, view.Key, catalog.Members})
	view.Confirmation = fmt.Sprintf("%x", sha256.Sum256(binding))
	for _, member := range catalog.Members {
		view.Members = append(view.Members, pages.CatalogImportMember{Name: member.Zone, Exists: findZone(server.zones.Current().Zones, member.Zone) != nil})
	}
	if request.FormValue("step") != "stage" {
		return nil
	}
	if request.FormValue("confirmation") != view.Confirmation {
		return errors.New("catalog membership or source changed; review the list and select zones again")
	}
	if view.ImportType != "secondary" && view.ImportType != "primary" {
		return errors.New("choose Primary or Secondary for imported zones")
	}
	if view.ImportType == "primary" && request.FormValue("freeze_confirmed") != "true" {
		return errors.New("confirm that source edits and automatic update writers are paused before importing Primary zones")
	}
	selected := slices.Compact(slices.Sorted(slices.Values(request.Form["member"])))
	if len(selected) == 0 || len(selected) > 25 {
		return errors.New("select between 1 and 25 zones per import")
	}
	for _, name := range selected {
		if !slices.ContainsFunc(catalog.Members, func(m zonemodel.CatalogMember) bool { return m.Zone == name }) {
			return errors.New("selected zone is not a catalog member; discover the catalog again")
		}
	}
	for _, name := range selected {
		result := pages.CatalogImportResult{Name: name}
		current, err := server.stageCatalogMember(ctx, request, synchronizer, name, primaries, view.Protocol, view.Key)
		if err != nil {
			result.Message = err.Error()
		} else {
			result.Success = true
			result.Message = "Synchronized as an independent Secondary. Ready to review for conversion."
			if current.Type == "primary" {
				result.Message = "Imported as an independent Primary. Sable is now the writable source; verify answers before moving clients."
			} else if err := zonemodel.CheckPrimaryConversion(current); err != nil {
				result.Warning = true
				result.Message = "Synchronized as an independent Secondary. Conversion blocked: " + err.Error()
			}
		}
		view.Results = append(view.Results, result)
	}
	for i := range view.Members {
		view.Members[i].Exists = findZone(server.zones.Current().Zones, view.Members[i].Name) != nil
	}
	return nil
}

func (server *Server) stageCatalogMember(ctx context.Context, request *http.Request, synchronizer zoneSynchronizer, name string, primaries []string, protocol, key string) (zonemodel.Zone, error) {
	current := zonemodel.Zone{Name: name, Type: "secondary", DefaultTTL: defaultZoneTTL, ZoneTransfer: "deny", PrimaryServers: primaries, PrimaryProtocol: protocol, TSIGKey: key}
	editor, ok := server.zones.(zoneEditor)
	if !ok {
		return current, errors.New("configuration is read-only")
	}
	if findZone(server.zones.Current().Zones, name) != nil {
		return current, errors.New("already exists in Sable; left unchanged")
	}
	transferCtx, cancel := context.WithTimeout(ctx, conversionSyncTimeout)
	defer cancel()
	records, err := synchronizer.FetchZone(transferCtx, name, "secondary", primaries, protocol, key)
	if err != nil {
		return current, fmt.Errorf("transfer failed; no zone created: %w", err)
	}
	current.Records = configuredZoneRecords(records)
	for _, record := range current.Records {
		if strings.EqualFold(record.Type, "FWD") {
			return current, errors.New("forwarder configuration must be recreated separately; no zone created")
		}
	}
	if err := zonemodel.ValidateAll([]zonemodel.Zone{current}, server.tsigKeyNames(ctx)); err != nil {
		return current, fmt.Errorf("invalid transferred zone; no zone created: %w", err)
	}
	err = editor.UpdateZones(ctx, func(zones *[]zonemodel.Zone) error {
		if server.cluster != nil && writeRequiresPrimary(server.cluster.Snapshot(), http.MethodPost, request.URL.Path) {
			return errors.New("import requires the cluster primary")
		}
		if findZone(*zones, name) != nil {
			return errors.New("already exists in Sable; left unchanged")
		}
		if request.FormValue("import_type") == "primary" {
			if request.FormValue("freeze_confirmed") != "true" {
				return errors.New("confirm that source writes are paused; no zone created")
			}
			if err := zonemodel.ConvertToPrimary(&current, time.Now()); err != nil {
				return fmt.Errorf("Primary import blocked; no zone created: %w", err)
			}
		}
		*zones = append(*zones, current)
		return nil
	})
	server.logZoneOperation(request, name, err)
	if err == nil {
		server.auditZoneMutation(request, name)
		server.notifyZoneChange(ctx, name)
	}
	return current, err
}
