package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/durationfmt"
	"github.com/drudge/sable/internal/web/pages"
	zonemodel "github.com/drudge/sable/internal/zone"
)

const maximumRenderedZoneChanges = 100

func zoneRevisionViews(revisions []zonemodel.Revision, current uint64, display pages.TimeDisplay) []pages.ZoneRevisionView {
	views := make([]pages.ZoneRevisionView, 0, len(revisions))
	for _, revision := range revisions {
		views = append(views, pages.ZoneRevisionView{
			Number: revision.Number, Kind: revision.ChangeKind,
			KindLabel:  zoneRevisionKindLabel(revision.ChangeKind),
			OccurredAt: pages.FormatDateTimeZoned(revision.CreatedAt, display),
			Current:    revision.Number == current,
		})
	}
	return views
}

func zoneRevisionKindLabel(kind string) string {
	switch kind {
	case "created":
		return "Created"
	case "deleted":
		return "Deleted"
	default:
		return "Updated"
	}
}

func (server *Server) zoneRevisionDiff(writer http.ResponseWriter, request *http.Request) {
	name := normalizeZoneName(request.URL.Query().Get("zone"))
	current := findZone(server.zones.Current().Zones, name)
	if current == nil || !server.authorizeZoneRequest(request, auth.PermissionZonesRead, *current) {
		writeFragmentStatus(writer, http.StatusForbidden)
		_ = pages.ZoneRevisionDiff(pages.ZoneRevisionDiffView{Error: "This zone revision is not available."}).Render(request.Context(), writer)
		return
	}
	revisionNumber, err := strconv.ParseUint(request.URL.Query().Get("revision"), 10, 64)
	if err != nil || revisionNumber == 0 {
		writeFragmentStatus(writer, http.StatusBadRequest)
		_ = pages.ZoneRevisionDiff(pages.ZoneRevisionDiffView{Error: "The revision number is invalid."}).Render(request.Context(), writer)
		return
	}
	history, ok := server.zones.(zoneRevisionStore)
	if !ok {
		writeFragmentStatus(writer, http.StatusNotImplemented)
		_ = pages.ZoneRevisionDiff(pages.ZoneRevisionDiffView{Error: "Change history is unavailable."}).Render(request.Context(), writer)
		return
	}
	target, err := history.ZoneRevision(request.Context(), name, revisionNumber)
	if err != nil {
		status := http.StatusInternalServerError
		message := "Unable to load this revision."
		if errors.Is(err, zonemodel.ErrRevisionNotFound) {
			status, message = http.StatusNotFound, "This revision is no longer retained."
		}
		writeFragmentStatus(writer, status)
		_ = pages.ZoneRevisionDiff(pages.ZoneRevisionDiffView{Error: message}).Render(request.Context(), writer)
		return
	}
	view := pages.ZoneRevisionDiffView{ZoneName: name, Revision: revisionNumber}
	var previous zonemodel.Zone
	if target.ChangeKind != "created" && target.ChangeKind != "deleted" {
		prior, priorErr := history.PreviousZoneRevision(request.Context(), name, revisionNumber)
		if priorErr == nil {
			previous = prior.Zone
		} else if errors.Is(priorErr, zonemodel.ErrRevisionNotFound) {
			view.Notice = "The preceding revision is no longer retained, so an exact diff is unavailable."
		} else {
			server.logger.Warn("load previous zone revision", "zone", name, "revision", revisionNumber, "error", priorErr)
			view.Notice = "The preceding revision could not be loaded, so an exact diff is unavailable."
		}
	}
	if view.Notice == "" {
		view.Changes, view.HiddenChanges, view.Summary = diffZoneRevision(target, previous)
	} else {
		view.Summary = zoneRevisionKindLabel(target.ChangeKind) + " revision"
	}
	view.CanRollback = revisionNumber != current.Revision && target.ChangeKind != "deleted" &&
		(target.Zone.ID == "" || target.Zone.ID == current.ID) && server.canRollbackZone(request, *current)
	_ = pages.ZoneRevisionDiff(view).Render(request.Context(), writer)
}

func (server *Server) canRollbackZone(request *http.Request, current zonemodel.Zone) bool {
	if !server.securityEnabled {
		return true
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	return auth.Authorize(principal, auth.PermissionZonesRecords, auth.ResourceZone, current.ID) &&
		auth.Authorize(principal, auth.PermissionZonesSettings, auth.ResourceZone, current.ID)
}

func (server *Server) rollbackZone(writer http.ResponseWriter, request *http.Request) {
	selected := ""
	server.updateZones(writer, request, &selected, "Zone restored as a new revision", func(zones *[]zonemodel.Zone) error {
		selected = normalizeZoneName(request.FormValue("zone"))
		current := findZone(*zones, selected)
		if current == nil {
			return errors.New("zone was not found")
		}
		if owner := catalogManagingZone(*zones, *current); owner != "" {
			return fmt.Errorf("this zone is managed by catalog %q and cannot be restored here", owner)
		}
		number, err := strconv.ParseUint(request.FormValue("revision"), 10, 64)
		if err != nil || number == 0 {
			return errors.New("revision number is invalid")
		}
		history, ok := server.zones.(zoneRevisionStore)
		if !ok {
			return zonemodel.ErrRevisionHistoryUnavailable
		}
		target, err := history.ZoneRevision(request.Context(), selected, number)
		if err != nil {
			return err
		}
		return restoreZoneRevision(zones, selected, target, time.Now())
	})
}

func restoreZoneRevision(zones *[]zonemodel.Zone, selected string, target zonemodel.Revision, now time.Time) error {
	current := findZone(*zones, selected)
	if current == nil {
		return errors.New("zone was not found")
	}
	if target.Number == current.Revision {
		return errors.New("that revision is already current")
	}
	if target.ChangeKind == "deleted" {
		return errors.New("a deletion marker cannot be restored")
	}
	if target.Zone.ID != "" && target.Zone.ID != current.ID {
		return errors.New("this revision belongs to an earlier zone with the same name")
	}
	restored := target.Zone
	restored.ID = current.ID
	restored.Name = current.Name
	restored.Revision = current.Revision
	advanceRestoredSOASerial(&restored, *current, now)
	*current = restored
	return nil
}

func advanceRestoredSOASerial(restored *zonemodel.Zone, current zonemodel.Zone, now time.Time) {
	currentSerial := uint32(0)
	for _, record := range current.Records {
		if record.Name == "@" && record.Type == "SOA" {
			currentSerial = zoneRecordSOASerial(record.Value)
			break
		}
	}
	for index := range restored.Records {
		record := &restored.Records[index]
		if record.Name != "@" || record.Type != "SOA" {
			continue
		}
		serial := max(currentSerial, zoneRecordSOASerial(record.Value))
		record.Value = replaceZoneRecordSOASerial(record.Value, zonemodel.NextSerial(serial, now))
		return
	}
}

func diffZoneRevision(revision zonemodel.Revision, previous zonemodel.Zone) ([]pages.ZoneRevisionChangeView, int, string) {
	current := revision.Zone
	if revision.ChangeKind == "deleted" {
		previous, current = revision.Zone, zonemodel.Zone{}
	}
	changes := make([]pages.ZoneRevisionChangeView, 0)
	if revision.ChangeKind != "created" && revision.ChangeKind != "deleted" {
		changes = appendZoneSettingChanges(changes, previous, current)
	}
	changes = appendZoneRecordChanges(changes, previous.Records, current.Records)
	added, removed, changed := 0, 0, 0
	for _, change := range changes {
		switch change.Kind {
		case "added":
			added++
		case "removed":
			removed++
		default:
			changed++
		}
	}
	summary := summarizeZoneChanges(revision.ChangeKind, len(current.Records), added, removed, changed)
	hidden := 0
	if len(changes) > maximumRenderedZoneChanges {
		hidden = len(changes) - maximumRenderedZoneChanges
		changes = changes[:maximumRenderedZoneChanges]
	}
	return changes, hidden, summary
}

func appendZoneSettingChanges(changes []pages.ZoneRevisionChangeView, previous, current zonemodel.Zone) []pages.ZoneRevisionChangeView {
	settings := []struct{ label, before, after string }{
		{"Zone type", previous.Type, current.Type},
		{"Default TTL", formatTTL(previous.DefaultTTL), formatTTL(current.DefaultTTL)},
		{"Status", enabledStatus(previous.Disabled), enabledStatus(current.Disabled)},
		{"Zone transfers", valueOrNone(previous.ZoneTransfer), valueOrNone(current.ZoneTransfer)},
		{"Transfer ACL", formatStringList(previous.TransferACL), formatStringList(current.TransferACL)},
		{"Notify targets", formatStringList(previous.Notify), formatStringList(current.Notify)},
		{"Primary servers", formatStringList(previous.PrimaryServers), formatStringList(current.PrimaryServers)},
		{"Primary protocol", valueOrNone(previous.PrimaryProtocol), valueOrNone(current.PrimaryProtocol)},
		{"Alias source", valueOrNone(previous.AliasZone), valueOrNone(current.AliasZone)},
		{"Catalog", valueOrNone(previous.CatalogZone), valueOrNone(current.CatalogZone)},
		{"Catalog group", valueOrNone(previous.CatalogGroup), valueOrNone(current.CatalogGroup)},
		{"Catalog member ID", valueOrNone(previous.CatalogMemberID), valueOrNone(current.CatalogMemberID)},
		{"Catalog change owner", valueOrNone(previous.CatalogChangeOwner), valueOrNone(current.CatalogChangeOwner)},
		{"TSIG key", valueOrNone(previous.TSIGKey), valueOrNone(current.TSIGKey)},
		{"Dynamic updates", booleanStatus(previous.DynamicUpdates), booleanStatus(current.DynamicUpdates)},
		{"DNSSEC signing", booleanStatus(previous.DNSSEC), booleanStatus(current.DNSSEC)},
		{"DNSSEC validation", booleanStatus(!previous.DNSSECValidationDisabled), booleanStatus(!current.DNSSECValidationDisabled)},
		{"DNSSEC algorithm", valueOrNone(previous.DNSSECAlgorithm), valueOrNone(current.DNSSECAlgorithm)},
		{"DNSSEC denial", valueOrNone(previous.DNSSECDenial), valueOrNone(current.DNSSECDenial)},
		{"NSEC3 iterations", formatUint(uint64(previous.NSEC3Iterations)), formatUint(uint64(current.NSEC3Iterations))},
		{"NSEC3 salt", valueOrNone(previous.NSEC3Salt), valueOrNone(current.NSEC3Salt)},
		{"ZSK lifetime", durationfmt.Format(previous.ZSKLifetime.Duration), durationfmt.Format(current.ZSKLifetime.Duration)},
		{"KSK lifetime", durationfmt.Format(previous.KSKLifetime.Duration), durationfmt.Format(current.KSKLifetime.Duration)},
		{"Key prepublish", durationfmt.Format(previous.KeyPrepublish.Duration), durationfmt.Format(current.KeyPrepublish.Duration)},
		{"Key retirement", durationfmt.Format(previous.KeyRetireAfter.Duration), durationfmt.Format(current.KeyRetireAfter.Duration)},
		{"Parent DS key tag", formatUint(uint64(previous.ParentDSKeyTag)), formatUint(uint64(current.ParentDSKeyTag))},
	}
	for _, setting := range settings {
		if setting.before != setting.after {
			changes = append(changes, pages.ZoneRevisionChangeView{Kind: "changed", Label: setting.label, Before: setting.before, After: setting.after})
		}
	}
	return changes
}

func appendZoneRecordChanges(changes []pages.ZoneRevisionChangeView, previous, current []zonemodel.Record) []pages.ZoneRevisionChangeView {
	previousByID := make(map[string]zonemodel.Record, len(previous))
	matchedPrevious := make(map[string]struct{}, len(previous))
	for _, record := range previous {
		previousByID[zonemodel.RecordID(record)] = record
	}
	unmatchedCurrent := make([]zonemodel.Record, 0)
	for _, record := range current {
		identity := zonemodel.RecordID(record)
		before, found := previousByID[identity]
		switch {
		case !found:
			unmatchedCurrent = append(unmatchedCurrent, record)
		case zoneRevisionRecordState(before) != zoneRevisionRecordState(record):
			changes = append(changes, pages.ZoneRevisionChangeView{Kind: "changed", Label: zoneRevisionRecordLabel(record), Before: zoneRevisionRecordState(before), After: zoneRevisionRecordState(record)})
		}
		if found {
			matchedPrevious[identity] = struct{}{}
		}
	}
	unmatchedPrevious := make([]zonemodel.Record, 0)
	for _, record := range previous {
		if _, found := matchedPrevious[zonemodel.RecordID(record)]; !found {
			unmatchedPrevious = append(unmatchedPrevious, record)
		}
	}
	pairedPrevious := make([]bool, len(unmatchedPrevious))
	for _, record := range unmatchedCurrent {
		pair := -1
		for index, before := range unmatchedPrevious {
			if !pairedPrevious[index] && before.Name == record.Name && before.Type == record.Type {
				pair = index
				break
			}
		}
		if pair < 0 {
			changes = append(changes, pages.ZoneRevisionChangeView{Kind: "added", Label: zoneRevisionRecordLabel(record), After: zoneRevisionRecordState(record)})
			continue
		}
		pairedPrevious[pair] = true
		changes = append(changes, pages.ZoneRevisionChangeView{
			Kind: "changed", Label: zoneRevisionRecordOwnerLabel(record),
			Before: zoneRevisionRecordValueState(unmatchedPrevious[pair]), After: zoneRevisionRecordValueState(record),
		})
	}
	for index, record := range unmatchedPrevious {
		if !pairedPrevious[index] {
			changes = append(changes, pages.ZoneRevisionChangeView{Kind: "removed", Label: zoneRevisionRecordLabel(record), Before: zoneRevisionRecordState(record)})
		}
	}
	return changes
}

func zoneRevisionRecordLabel(record zonemodel.Record) string {
	return zoneRevisionRecordOwnerLabel(record) + " → " + record.Value
}

func zoneRevisionRecordOwnerLabel(record zonemodel.Record) string {
	owner := record.Name
	if owner == "" {
		owner = "@"
	}
	return strings.TrimSpace(record.Type + " " + owner)
}

func zoneRevisionRecordValueState(record zonemodel.Record) string {
	return record.Value + " · " + zoneRevisionRecordState(record)
}

func zoneRevisionRecordState(record zonemodel.Record) string {
	parts := []string{"TTL " + strconv.FormatUint(uint64(record.TTL), 10) + "s"}
	if record.Disabled {
		parts = append(parts, "disabled")
	}
	if record.Comments != "" {
		parts = append(parts, "comment: "+record.Comments)
	}
	if record.Source != "" {
		parts = append(parts, "source: "+record.Source)
	}
	if !record.ExpiresAt.IsZero() {
		parts = append(parts, "expires "+record.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return strings.Join(parts, " · ")
}

func summarizeZoneChanges(kind string, records, added, removed, changed int) string {
	switch kind {
	case "created":
		return fmt.Sprintf("Zone created with %d %s.", records, pluralize(records, "record", "records"))
	case "deleted":
		return fmt.Sprintf("Zone deleted with %d %s in its final snapshot.", removed, pluralize(removed, "record", "records"))
	}
	parts := make([]string, 0, 3)
	if added > 0 {
		parts = append(parts, fmt.Sprintf("%d added", added))
	}
	if removed > 0 {
		parts = append(parts, fmt.Sprintf("%d removed", removed))
	}
	if changed > 0 {
		parts = append(parts, fmt.Sprintf("%d changed", changed))
	}
	if len(parts) == 0 {
		return "No content changes were detected."
	}
	return strings.Join(parts, " · ")
}

func formatTTL(value uint32) string  { return strconv.FormatUint(uint64(value), 10) + "s" }
func formatUint(value uint64) string { return strconv.FormatUint(value, 10) }
func enabledStatus(disabled bool) string {
	if disabled {
		return "Disabled"
	}
	return "Active"
}
func booleanStatus(enabled bool) string {
	if enabled {
		return "Enabled"
	}
	return "Disabled"
}
func valueOrNone(value string) string {
	if strings.TrimSpace(value) == "" {
		return "None"
	}
	return value
}
func formatStringList(values []string) string {
	if len(values) == 0 {
		return "None"
	}
	return strings.Join(values, ", ")
}
