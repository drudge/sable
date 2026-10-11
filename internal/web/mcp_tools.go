package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web/pages"
	zonemodel "github.com/drudge/sable/internal/zone"
)

type mcpTool struct {
	Name        string             `json:"name"`
	Title       string             `json:"title"`
	Description string             `json:"description"`
	InputSchema map[string]any     `json:"inputSchema"`
	Annotations mcpToolAnnotations `json:"annotations"`
	call        func(*Server, *http.Request, json.RawMessage) (any, error)
	// section groups the tool in the setup wizard, and grant is the
	// permission it asks of a token, shown beside it there.
	section string
	grant   string
}

type mcpToolAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    bool   `json:"readOnlyHint"`
	DestructiveHint bool   `json:"destructiveHint"`
	IdempotentHint  bool   `json:"idempotentHint"`
	OpenWorldHint   bool   `json:"openWorldHint"`
}

// mcpRecord is a record as an assistant sees it. Value is always the stored
// zone-file text, so it can be passed back unchanged to identify the record.
type mcpRecord struct {
	Name      string     `json:"name"`
	FQDN      string     `json:"fqdn"`
	Type      string     `json:"type"`
	Value     string     `json:"value"`
	TTL       uint32     `json:"ttl"`
	Enabled   bool       `json:"enabled"`
	Comment   string     `json:"comment,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	ManagedBy string     `json:"managed_by,omitempty"`
}

type mcpZoneSummary struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Enabled  bool   `json:"enabled"`
	DNSSEC   bool   `json:"dnssec"`
	Serial   uint32 `json:"serial,omitempty"`
	Records  int    `json:"records"`
	Editable bool   `json:"editable"`
}

type mcpChange struct {
	Zone    string      `json:"zone"`
	Changed bool        `json:"changed"`
	Serial  uint32      `json:"serial,omitempty"`
	Message string      `json:"message"`
	Added   []mcpRecord `json:"added,omitempty"`
	Removed []mcpRecord `json:"removed,omitempty"`
	Records []mcpRecord `json:"records,omitempty"`
}

var mcpRecordTools = []mcpTool{
	{
		Name:  "list_zones",
		Title: "List DNS zones",
		Description: "List the zones this token can read, with their type, SOA serial, record count, and whether " +
			"this token may change their records. Only Primary and Forwarder zones have editable records.",
		InputSchema: mcpObjectSchema(nil, nil),
		Annotations: mcpToolAnnotations{Title: "List DNS zones", ReadOnlyHint: true, IdempotentHint: true},
		call:        (*Server).mcpListZones,
		section:     "records",
		grant:       "zones.read",
	},
	{
		Name:  "list_records",
		Title: "List DNS records",
		Description: "List the records in one zone. Filter by owner name and record type to check what a " +
			"name currently resolves to before changing it.",
		InputSchema: mcpObjectSchema(map[string]any{
			"zone": mcpString("Zone name, for example example.com."),
			"name": mcpString("Optional owner name: relative (www), @ for the apex, or fully qualified."),
			"type": mcpString("Optional record type, for example A, CNAME, or TXT."),
		}, []string{"zone"}),
		Annotations: mcpToolAnnotations{Title: "List DNS records", ReadOnlyHint: true, IdempotentHint: true},
		call:        (*Server).mcpListRecords,
		section:     "records",
		grant:       "zones.read",
	},
	{
		Name:  "add_record",
		Title: "Add a DNS record",
		Description: "Add one record to a Primary or Forwarder zone. Adding a record that already exists " +
			"changes nothing. A CNAME cannot share its name with any other record.",
		InputSchema: mcpObjectSchema(map[string]any{
			"zone":    mcpString("Zone name, for example example.com."),
			"name":    mcpString("Owner name: relative (www), @ for the apex, or fully qualified."),
			"type":    mcpString("Record type, for example A, AAAA, CNAME, MX, TXT, SRV, or CAA."),
			"value":   mcpString("Record data in zone-file syntax, for example 192.0.2.10 or \"10 mail.example.com.\"."),
			"ttl":     mcpInteger("Optional TTL in seconds. Defaults to the zone's default TTL.", 0),
			"comment": mcpString("Optional note shown beside the record in Sable."),
		}, []string{"zone", "name", "type", "value"}),
		Annotations: mcpToolAnnotations{Title: "Add a DNS record", IdempotentHint: true},
		call:        (*Server).mcpAddRecord,
		section:     "records",
		grant:       "zones.records.write",
	},
	{
		Name:  "set_records",
		Title: "Set a DNS record set",
		Description: "Make every record of one name and type match the given values: missing values are " +
			"added and any other values of that name and type are removed. Running it again changes nothing, " +
			"so it is the safest way to point a name at a deployment.",
		InputSchema: mcpObjectSchema(map[string]any{
			"zone": mcpString("Zone name, for example example.com."),
			"name": mcpString("Owner name: relative (www), @ for the apex, or fully qualified."),
			"type": mcpString("Record type, for example A, AAAA, CNAME, or TXT."),
			"values": map[string]any{
				"type": "array", "minItems": 1, "items": map[string]any{"type": "string"},
				"description": "Every value the set should hold, in zone-file syntax. A CNAME takes exactly one.",
			},
			"ttl":     mcpInteger("Optional TTL in seconds for every record in the set. Defaults to the zone's default TTL for new records and leaves existing ones alone.", 0),
			"comment": mcpString("Optional note for records this call adds."),
		}, []string{"zone", "name", "type", "values"}),
		Annotations: mcpToolAnnotations{Title: "Set a DNS record set", DestructiveHint: true, IdempotentHint: true},
		call:        (*Server).mcpSetRecords,
		section:     "records",
		grant:       "zones.records.write",
	},
	{
		Name:  "update_record",
		Title: "Update a DNS record",
		Description: "Change one existing record, found by its zone, name, type, and current value. Only the " +
			"fields you pass change.",
		InputSchema: mcpObjectSchema(map[string]any{
			"zone":        mcpString("Zone name, for example example.com."),
			"name":        mcpString("Current owner name of the record."),
			"type":        mcpString("Record type. The type cannot be changed."),
			"value":       mcpString("Current value of the record, as list_records shows it."),
			"new_name":    mcpString("Optional new owner name."),
			"new_value":   mcpString("Optional new value in zone-file syntax."),
			"new_ttl":     mcpInteger("Optional new TTL in seconds.", 1),
			"new_comment": mcpString("Optional new note. Pass an empty string to clear it."),
			"enabled":     map[string]any{"type": "boolean", "description": "Optional. False keeps the record but stops serving it."},
		}, []string{"zone", "name", "type", "value"}),
		Annotations: mcpToolAnnotations{Title: "Update a DNS record", DestructiveHint: true, IdempotentHint: true},
		call:        (*Server).mcpUpdateRecord,
		section:     "records",
		grant:       "zones.records.write",
	},
	{
		Name:        "delete_record",
		Title:       "Delete a DNS record",
		Description: "Remove one record, found by its zone, name, type, and value.",
		InputSchema: mcpObjectSchema(map[string]any{
			"zone":  mcpString("Zone name, for example example.com."),
			"name":  mcpString("Owner name of the record."),
			"type":  mcpString("Record type."),
			"value": mcpString("Value of the record, as list_records shows it."),
		}, []string{"zone", "name", "type", "value"}),
		Annotations: mcpToolAnnotations{Title: "Delete a DNS record", DestructiveHint: true, IdempotentHint: true},
		call:        (*Server).mcpDeleteRecord,
		section:     "records",
		grant:       "zones.records.write",
	},
}

var mcpCreateZoneTool = mcpTool{
	Name:  "create_zone",
	Title: "Create a Primary zone",
	Description: "Create a new Primary zone on this server with an SOA and one apex NS record, ready for records. " +
		"Devices that use Sable see it at once. The public internet only sees it after the domain's registrar " +
		"or parent zone delegates it to Sable's name servers. Creating a zone that already exists fails.",
	InputSchema: mcpObjectSchema(map[string]any{
		"name":        mcpString("Zone name, for example internal.example.com."),
		"primary_ns":  mcpString("Optional primary name server for the SOA and apex NS. Defaults to ns1.<zone>."),
		"responsible": mcpString("Optional contact email for the SOA. Defaults to hostmaster@<zone>."),
		"default_ttl": mcpInteger("Optional default TTL in seconds for the zone's records. Defaults to 300.", 1),
	}, []string{"name"}),
	Annotations: mcpToolAnnotations{Title: "Create a Primary zone"},
	call:        (*Server).mcpCreateZone,
	// Creating a zone cannot be limited to chosen zones, so like delete_zone
	// it is off until an operator adds it.
	section: "records",
	grant:   "zones.create",
}

// mcpAllTools is every tool Sable has, whether or not it is switched on.
func mcpAllTools() []mcpTool {
	return slices.Concat(mcpRecordTools, []mcpTool{mcpCreateZoneTool}, mcpDNSTools, mcpScheduleTools, mcpAdvancedTools, mcpServerTools, []mcpTool{mcpServerLogTool})
}

// mcpToolList is what assistants are offered with these settings.
func mcpToolList(settings config.MCP) []mcpTool {
	return slices.DeleteFunc(mcpAllTools(), func(tool mcpTool) bool { return mcpToolOff(tool, settings) != "" })
}

// mcpToolOff says why a tool is not offered, or nothing when it is.
func mcpToolOff(tool mcpTool, settings config.MCP) string {
	if !slices.Contains(settings.Tools, tool.Name) {
		return fmt.Sprintf("the %s tool is turned off in Sable under Integrations, MCP Server", tool.Name)
	}
	return ""
}

func mcpToolByName(name string) (mcpTool, bool) {
	tools := mcpAllTools()
	index := slices.IndexFunc(tools, func(tool mcpTool) bool { return tool.Name == name })
	if index < 0 {
		return mcpTool{}, false
	}
	return tools[index], true
}

func mcpObjectSchema(properties map[string]any, required []string) map[string]any {
	if properties == nil {
		properties = map[string]any{}
	}
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func mcpString(description string) map[string]any {
	return map[string]any{"type": "string", "description": description}
}

func mcpInteger(description string, minimum int) map[string]any {
	return map[string]any{"type": "integer", "minimum": minimum, "maximum": 2147483647, "description": description}
}

func (server *Server) mcpListZones(request *http.Request, arguments json.RawMessage) (any, error) {
	if err := decodeMCPArguments(arguments, &struct{}{}); err != nil {
		return nil, err
	}
	zones := []mcpZoneSummary{}
	for _, current := range server.zones.Current().Zones {
		if !server.authorizeZoneRequest(request, auth.PermissionZonesRead, current) {
			continue
		}
		zones = append(zones, mcpZoneSummary{
			Name: current.Name, Type: current.Type, Enabled: !current.Disabled, DNSSEC: current.DNSSEC,
			Serial: mcpZoneSerial(current), Records: len(current.Records),
			Editable: zoneRecordsEditable(current.Type) && server.authorizeZoneRequest(request, auth.PermissionZonesRecords, current),
		})
	}
	result := map[string]any{"zones": zones}
	if server.mcpReplica() {
		result["note"] = replicaWriteMessage
	}
	return result, nil
}

func (server *Server) mcpListRecords(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Zone string `json:"zone"`
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	current, err := server.mcpReadableZone(request, input.Zone)
	if err != nil {
		return nil, err
	}
	owner := ""
	if strings.TrimSpace(input.Name) != "" {
		owner = ownerFQDN(current.Name, input.Name)
	}
	recordType := strings.ToUpper(strings.TrimSpace(input.Type))
	records := []mcpRecord{}
	for _, record := range current.Records {
		if owner != "" && ownerFQDN(current.Name, record.Name) != owner {
			continue
		}
		if recordType != "" && record.Type != recordType {
			continue
		}
		records = append(records, mcpRecordView(current, record))
	}
	return map[string]any{"zone": current.Name, "serial": mcpZoneSerial(current), "records": records}, nil
}

func (server *Server) mcpAddRecord(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Zone    string `json:"zone"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		Value   string `json:"value"`
		TTL     uint32 `json:"ttl"`
		Comment string `json:"comment"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	change, err := server.zoneService().AddRecord(request.Context(), requestActor(request, "mcp"), input.Zone, recordInput{
		Name: input.Name, Type: input.Type, Value: input.Value, TTL: input.TTL, Comment: input.Comment,
	})
	if err != nil {
		return nil, err
	}
	result := mcpChangeView(change)
	if change.Changed {
		result.Message = "Record added"
	} else {
		result.Message = "That record already exists, so nothing changed"
	}
	return result, nil
}

func (server *Server) mcpSetRecords(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Zone    string   `json:"zone"`
		Name    string   `json:"name"`
		Type    string   `json:"type"`
		Values  []string `json:"values"`
		TTL     uint32   `json:"ttl"`
		Comment string   `json:"comment"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	if len(input.Values) == 0 {
		return nil, errors.New("values must hold at least one value; use delete_record to remove records")
	}
	change, err := server.zoneService().SetRecords(request.Context(), requestActor(request, "mcp"), input.Zone, recordSet{
		Name: input.Name, Type: input.Type, Values: input.Values, TTL: input.TTL, Comment: input.Comment,
	})
	if err != nil {
		return nil, err
	}
	result := mcpChangeView(change)
	result.Records = mcpRecordViews(zonemodel.Zone{Name: change.Zone}, append(change.Kept, change.Added...))
	if change.Changed {
		result.Message = fmt.Sprintf("Record set updated: %d added, %d removed", len(change.Added), len(change.Removed))
	} else {
		result.Message = "The record set already matches, so nothing changed"
	}
	return result, nil
}

func (server *Server) mcpUpdateRecord(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Zone       string  `json:"zone"`
		Name       string  `json:"name"`
		Type       string  `json:"type"`
		Value      string  `json:"value"`
		NewName    *string `json:"new_name"`
		NewValue   *string `json:"new_value"`
		NewTTL     *uint32 `json:"new_ttl"`
		NewComment *string `json:"new_comment"`
		Enabled    *bool   `json:"enabled"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	if input.NewTTL != nil && *input.NewTTL == 0 {
		return nil, errors.New("new_ttl must be at least 1 second")
	}
	// The console may edit the SOA's timers; an assistant may not.
	if strings.EqualFold(strings.TrimSpace(input.Type), "SOA") {
		return nil, errors.New("Sable manages the zone SOA record automatically")
	}
	change, err := server.zoneService().UpdateRecord(request.Context(), requestActor(request, "mcp"), input.Zone, recordUpdate{
		Key:  recordKey{Name: input.Name, Type: input.Type, Value: input.Value},
		Name: input.NewName, Value: input.NewValue, TTL: input.NewTTL, Comment: input.NewComment, Enabled: input.Enabled,
	})
	if err != nil {
		return nil, mcpRecordHint(err)
	}
	result := mcpChangeView(change)
	if change.Changed {
		result.Message = "Record updated"
	} else {
		result.Message = "The record already matches, so nothing changed"
		result.Records = mcpRecordViews(zonemodel.Zone{Name: change.Zone}, change.Kept)
	}
	return result, nil
}

func (server *Server) mcpDeleteRecord(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Zone  string `json:"zone"`
		Name  string `json:"name"`
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	change, err := server.zoneService().DeleteRecord(request.Context(), requestActor(request, "mcp"), input.Zone, recordKey{
		Name: input.Name, Type: input.Type, Value: input.Value,
	})
	if err != nil {
		return nil, mcpRecordHint(err)
	}
	result := mcpChangeView(change)
	result.Message = "Record removed"
	return result, nil
}

func (server *Server) mcpCreateZone(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Name        string `json:"name"`
		PrimaryNS   string `json:"primary_ns"`
		Responsible string `json:"responsible"`
		DefaultTTL  uint32 `json:"default_ttl"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	created, err := server.zoneService().CreateZone(request.Context(), requestActor(request, "mcp"), zoneCreate{
		Name: input.Name, Type: "primary", PrimaryNS: input.PrimaryNS, Responsible: input.Responsible, DefaultTTL: input.DefaultTTL,
	})
	if err != nil {
		return nil, err
	}
	if findZone(server.zones.Current().Zones, created.Name) == nil {
		return nil, fmt.Errorf("zone %s was created but is not active yet", created.Name)
	}
	result := map[string]any{"zone": created.Name, "serial": mcpZoneSerial(created), "records": mcpRecordViews(created, created.Records)}
	// A token limited to chosen zones cannot see a zone that did not exist
	// when its group was set up, so say so rather than fail on the next call.
	if server.authorizeZoneRequest(request, auth.PermissionZonesRecords, created) {
		result["message"] = "Zone created"
	} else {
		result["message"] = "Zone created, but this token cannot change its records. Add the zone to the token's group in Administration."
	}
	return result, nil
}

// mcpRecordHint points an assistant that named a missing record at the tool
// that lists what exists.
func mcpRecordHint(err error) error {
	if missing := (*missingRecordError)(nil); errors.As(err, &missing) {
		return fmt.Errorf("%w; call list_records to see what exists", err)
	}
	return err
}

// mcpChangeView is a record change as the tools report it.
func mcpChangeView(change recordChange) mcpChange {
	zone := zonemodel.Zone{Name: change.Zone}
	return mcpChange{
		Zone: change.Zone, Changed: change.Changed, Serial: change.Serial,
		Added: mcpRecordViews(zone, change.Added), Removed: mcpRecordViews(zone, change.Removed),
	}
}

// mcpReadableZone hides zones the token cannot read behind the same message
// as a missing zone, so a scoped token cannot probe for zone names.
func (server *Server) mcpReadableZone(request *http.Request, name string) (zonemodel.Zone, error) {
	normalized := normalizeZoneName(name)
	if normalized == "" {
		return zonemodel.Zone{}, errors.New("zone is required")
	}
	current := findZone(server.zones.Current().Zones, normalized)
	if current == nil || !server.authorizeZoneRequest(request, auth.PermissionZonesRead, *current) {
		return zonemodel.Zone{}, fmt.Errorf("zone %s was not found", normalized)
	}
	return *current, nil
}

func (server *Server) mcpReplica() bool {
	return server.cluster != nil && controlPlaneReadOnly(server.cluster.Snapshot())
}

func mcpRecordManager(record zonemodel.Record) string {
	switch {
	case record.Type == "SOA", strings.HasPrefix(record.Comments, "sable:dnssec"):
		return "sable"
	default:
		return record.Source
	}
}

func mcpRecordView(zone zonemodel.Zone, record zonemodel.Record) mcpRecord {
	view := mcpRecord{
		Name: record.Name, FQDN: strings.TrimSuffix(ownerFQDN(zone.Name, record.Name), "."),
		Type: record.Type, Value: record.Value, TTL: record.TTL, Enabled: !record.Disabled,
		Comment: record.Comments, ManagedBy: mcpRecordManager(record),
	}
	if strings.HasPrefix(view.Comment, "sable:") {
		view.Comment = ""
	}
	if !record.ExpiresAt.IsZero() {
		expires := record.ExpiresAt
		view.ExpiresAt = &expires
	}
	return view
}

func mcpRecordViews(zone zonemodel.Zone, records []zonemodel.Record) []mcpRecord {
	views := make([]mcpRecord, 0, len(records))
	for _, record := range records {
		views = append(views, mcpRecordView(zone, record))
	}
	return views
}

func mcpZoneSerial(zone zonemodel.Zone) uint32 {
	return zoneRecordSOASerial(apexSOA(zone))
}

// mcpToolSections are the setup wizard's sections, in order.
var mcpToolSections = []struct{ Key, Title, Description string }{
	{"records", "Records & Zones", "Read and change records, and create and delete zones."},
	{"blocking", "Blocking", "Allow and block domains, and manage block lists."},
	{"lookups", "Lookups & Logs", "Resolve names through Sable, forget cached answers, and share what each device does with the AI provider."},
	{"server", "Server", "Check the version, how DNS is doing, Dynamic DNS, and the cluster, and update Dynamic DNS now."},
}

func mcpToolSectionViews(settings config.MCP) []pages.MCPToolSectionView {
	views := make([]pages.MCPToolSectionView, 0, len(mcpToolSections))
	for _, section := range mcpToolSections {
		view := pages.MCPToolSectionView{Key: section.Key, Title: section.Title, Description: section.Description}
		for _, name := range config.MCPTools {
			tool, _ := mcpToolByName(name)
			if tool.section != section.Key {
				continue
			}
			view.Tools = append(view.Tools, pages.MCPToolView{
				Name: tool.Name, Grant: tool.grant, Description: tool.Description,
				ReadOnly: tool.Annotations.ReadOnlyHint, On: slices.Contains(settings.Tools, tool.Name),
			})
		}
		views = append(views, view)
	}
	return views
}
