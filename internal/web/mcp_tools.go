package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsname"
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
	return slices.Concat(mcpRecordTools, []mcpTool{mcpCreateZoneTool}, mcpDNSTools, mcpAdvancedTools, mcpServerTools)
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
		owner = mcpOwnerFQDN(current.Name, input.Name)
	}
	recordType := strings.ToUpper(strings.TrimSpace(input.Type))
	records := []mcpRecord{}
	for _, record := range current.Records {
		if owner != "" && mcpOwnerFQDN(current.Name, record.Name) != owner {
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
	var added zonemodel.Record
	result, err := server.mcpChangeRecords(request, input.Zone, "zone.record.create", func(zone *zonemodel.Zone) (bool, error) {
		record, err := mcpNewRecord(*zone, input.Name, input.Type, input.Value, input.TTL, input.Comment)
		if err != nil {
			return false, err
		}
		added = record
		if index := slices.IndexFunc(zone.Records, func(existing zonemodel.Record) bool { return mcpSameRecord(*zone, existing, record) }); index >= 0 {
			if zone.Records[index].Disabled {
				return false, errors.New("that record exists but is disabled; call update_record with enabled true to serve it")
			}
			return false, nil
		}
		zone.Records = append(zone.Records, record)
		return true, zonemodel.CheckCNAMEExclusivity(*zone, record.Name, time.Now())
	})
	if err != nil {
		return nil, err
	}
	if result.Changed {
		result.Message = "Record added"
		result.Added = []mcpRecord{mcpRecordView(zonemodel.Zone{Name: result.Zone}, added)}
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
	var added, removed, kept []zonemodel.Record
	result, err := server.mcpChangeRecords(request, input.Zone, "zone.record.set", func(zone *zonemodel.Zone) (bool, error) {
		desired := make([]zonemodel.Record, 0, len(input.Values))
		for _, value := range input.Values {
			record, err := mcpNewRecord(*zone, input.Name, input.Type, value, input.TTL, input.Comment)
			if err != nil {
				return false, err
			}
			if !slices.ContainsFunc(desired, func(other zonemodel.Record) bool { return mcpSameRecord(*zone, other, record) }) {
				desired = append(desired, record)
			}
		}
		if desired[0].Type == "CNAME" && len(desired) > 1 {
			return false, errors.New("a CNAME record set holds exactly one value")
		}
		owner := mcpOwnerFQDN(zone.Name, desired[0].Name)
		changed := false
		next := make([]zonemodel.Record, 0, len(zone.Records)+len(desired))
		matched := make([]bool, len(desired))
		for _, existing := range zone.Records {
			if existing.Type != desired[0].Type || mcpOwnerFQDN(zone.Name, existing.Name) != owner {
				next = append(next, existing)
				continue
			}
			if err := mcpRecordEditable(existing); err != nil {
				return false, err
			}
			index := slices.IndexFunc(desired, func(record zonemodel.Record) bool { return mcpSameRecord(*zone, existing, record) })
			if index < 0 || matched[index] {
				removed = append(removed, existing)
				changed = true
				continue
			}
			matched[index] = true
			if input.TTL != 0 && existing.TTL != input.TTL {
				existing.TTL = input.TTL
				changed = true
			}
			if existing.Disabled {
				existing.Disabled = false
				changed = true
			}
			kept = append(kept, existing)
			next = append(next, existing)
		}
		for index, record := range desired {
			if matched[index] {
				continue
			}
			added = append(added, record)
			next = append(next, record)
			changed = true
		}
		zone.Records = next
		if !changed {
			return false, nil
		}
		return true, zonemodel.CheckCNAMEExclusivity(*zone, desired[0].Name, time.Now())
	})
	if err != nil {
		return nil, err
	}
	view := zonemodel.Zone{Name: result.Zone}
	result.Added = mcpRecordViews(view, added)
	result.Removed = mcpRecordViews(view, removed)
	result.Records = mcpRecordViews(view, append(kept, added...))
	if result.Changed {
		result.Message = fmt.Sprintf("Record set updated: %d added, %d removed", len(added), len(removed))
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
	var before, after zonemodel.Record
	result, err := server.mcpChangeRecords(request, input.Zone, "zone.record.update", func(zone *zonemodel.Zone) (bool, error) {
		index, err := mcpFindRecord(*zone, input.Name, input.Type, input.Value)
		if err != nil {
			return false, err
		}
		before = zone.Records[index]
		after = before
		if input.NewName != nil {
			after.Name = mcpStoredOwner(zone.Name, *input.NewName)
		}
		if input.NewValue != nil {
			after.Value, err = mcpRecordValue(zone.Name, after.Type, *input.NewValue)
			if err != nil {
				return false, err
			}
		}
		if input.NewTTL != nil {
			after.TTL = *input.NewTTL
		}
		if input.NewComment != nil {
			after.Comments = strings.TrimSpace(*input.NewComment)
		}
		if input.Enabled != nil {
			after.Disabled = !*input.Enabled
		}
		if after == before {
			return false, nil
		}
		if _, err := zonemodel.ParseRecord(*zone, after); err != nil {
			return false, err
		}
		zone.Records[index] = after
		if after.Name != before.Name || after.Value != before.Value {
			for other, record := range zone.Records {
				if other != index && mcpSameRecord(*zone, record, after) {
					return false, errors.New("another record already has that name and value")
				}
			}
		}
		return true, zonemodel.CheckCNAMEExclusivity(*zone, after.Name, time.Now())
	})
	if err != nil {
		return nil, err
	}
	view := zonemodel.Zone{Name: result.Zone}
	if result.Changed {
		result.Message = "Record updated"
		result.Removed = []mcpRecord{mcpRecordView(view, before)}
		result.Added = []mcpRecord{mcpRecordView(view, after)}
	} else {
		result.Message = "The record already matches, so nothing changed"
		result.Records = []mcpRecord{mcpRecordView(view, before)}
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
	var removed zonemodel.Record
	result, err := server.mcpChangeRecords(request, input.Zone, "zone.record.delete", func(zone *zonemodel.Zone) (bool, error) {
		index, err := mcpFindRecord(*zone, input.Name, input.Type, input.Value)
		if err != nil {
			return false, err
		}
		removed = zone.Records[index]
		zone.Records = slices.Delete(zone.Records, index, index+1)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	result.Message = "Record removed"
	result.Removed = []mcpRecord{mcpRecordView(zonemodel.Zone{Name: result.Zone}, removed)}
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
	// Creating a zone is not tied to any existing zone, so only a grant that
	// covers every zone allows it, exactly as in the console.
	if !server.mcpHasPermission(request, auth.PermissionZonesCreate) {
		return nil, errors.New("this token needs zones.create to create zones")
	}
	if server.mcpReplica() {
		return nil, errors.New(replicaWriteMessage)
	}
	name, err := dnsname.Normalize(input.Name)
	if err != nil {
		return nil, fmt.Errorf("zone name: %w", err)
	}
	primaryNS := strings.TrimSpace(input.PrimaryNS)
	if primaryNS == "" {
		primaryNS = "ns1." + name
	}
	if primaryNS, err = dnsname.Normalize(primaryNS); err != nil {
		return nil, fmt.Errorf("primary name server: %w", err)
	}
	responsible := strings.TrimSpace(input.Responsible)
	if responsible == "" {
		responsible = "hostmaster@" + name
	}
	if responsible, err = soaResponsibleName(responsible); err != nil {
		return nil, err
	}
	ttl := input.DefaultTTL
	if ttl == 0 {
		ttl = defaultZoneTTL
	}
	editor, ok := server.zones.(zoneEditor)
	if !ok {
		return nil, errors.New("this configuration source is read-only")
	}
	err = editor.UpdateZones(request.Context(), func(zones *[]zonemodel.Zone) error {
		if findZone(*zones, name) != nil {
			return fmt.Errorf("zone %s already exists", name)
		}
		*zones = append(*zones, zonemodel.Zone{Name: name, Type: "primary", DefaultTTL: ttl, Records: []zonemodel.Record{
			newZoneSOA(primaryNS, responsible, ttl, time.Now()),
			{Name: "@", Type: "NS", TTL: ttl, Value: dns.Fqdn(primaryNS)},
		}})
		return nil
	})
	server.logMCPZoneOperation(request, "zone.create", name, err)
	if err != nil {
		return nil, err
	}
	server.auditMCPZoneMutation(request, "zone.create", name)
	created := findZone(server.zones.Current().Zones, name)
	if created == nil {
		return nil, fmt.Errorf("zone %s was created but is not active yet", name)
	}
	result := map[string]any{"zone": name, "serial": mcpZoneSerial(*created), "records": mcpRecordViews(*created, created.Records)}
	// A token limited to chosen zones cannot see a zone that did not exist
	// when its group was set up, so say so rather than fail on the next call.
	if server.authorizeZoneRequest(request, auth.PermissionZonesRecords, *created) {
		result["message"] = "Zone created"
	} else {
		result["message"] = "Zone created, but this token cannot change its records. Add the zone to the token's group in Administration."
	}
	return result, nil
}

// mcpChangeRecords applies one record change through the same path the
// console uses: zone-scoped authorization, the zone manager's validation and
// persistence, an SOA serial bump, the audit log, and NOTIFY to secondaries.
// The mutation reports whether it changed anything so a repeated call leaves
// the serial and the audit log alone.
func (server *Server) mcpChangeRecords(
	request *http.Request,
	zoneName, action string,
	mutate func(*zonemodel.Zone) (bool, error),
) (mcpChange, error) {
	if server.mcpReplica() {
		return mcpChange{}, errors.New(replicaWriteMessage)
	}
	current, err := server.mcpReadableZone(request, zoneName)
	if err != nil {
		return mcpChange{}, err
	}
	if !server.authorizeZoneRequest(request, auth.PermissionZonesRecords, current) {
		return mcpChange{}, fmt.Errorf("this token may read zone %s but not change its records", current.Name)
	}
	if !zoneRecordsEditable(current.Type) {
		return mcpChange{}, fmt.Errorf("zone %s is a %s zone; only Primary and Forwarder zones have editable records", current.Name, current.Type)
	}
	editor, ok := server.zones.(zoneEditor)
	if !ok {
		return mcpChange{}, errors.New("this configuration source is read-only")
	}
	changed := false
	err = editor.UpdateZones(request.Context(), func(zones *[]zonemodel.Zone) error {
		zone := findZone(*zones, current.Name)
		// The zone ID pins authorization to the zone that was checked, even if
		// it was deleted and recreated under the same name in the meantime.
		if zone == nil || zone.ID != current.ID {
			return fmt.Errorf("zone %s was not found", current.Name)
		}
		var mutateErr error
		changed, mutateErr = mutate(zone)
		if mutateErr != nil || !changed {
			return mutateErr
		}
		advanceSOASerial(zone, time.Now())
		return nil
	})
	server.logMCPZoneOperation(request, action, current.Name, err)
	if err != nil {
		return mcpChange{}, err
	}
	result := mcpChange{Zone: current.Name, Changed: changed}
	if updated := findZone(server.zones.Current().Zones, current.Name); updated != nil {
		result.Serial = mcpZoneSerial(*updated)
	}
	if changed {
		server.auditMCPZoneMutation(request, action, current.Name)
		server.notifyZoneChange(request.Context(), current.Name)
	}
	return result, nil
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

func (server *Server) logMCPZoneOperation(request *http.Request, action, zoneName string, operationErr error) {
	attributes := []any{"operation", action, "zone", zoneName, "client", requestClientIP(request), "via", "mcp"}
	if operationErr != nil {
		server.logger.Warn("zone operation failed", append(attributes, "error", operationErr)...)
		return
	}
	server.logger.Info("zone operation completed", attributes...)
}

func (server *Server) auditMCPZoneMutation(request *http.Request, action, zoneName string) {
	recorder, ok := server.queries.(interface {
		RecordAuditEvent(context.Context, auth.AuditEvent) error
	})
	if !ok {
		return
	}
	event := auth.AuditEvent{
		OccurredAt: time.Now(), Action: action, ClientIP: requestClientIP(request),
		UserAgent: request.UserAgent(), Details: "zone=" + zoneName + " via=mcp",
	}
	if principal, ok := request.Context().Value(principalContextKey{}).(auth.Principal); ok && principal.UserID != 0 {
		event.UserID = &principal.UserID
	}
	if err := recorder.RecordAuditEvent(request.Context(), event); err != nil {
		server.logger.Warn("record zone audit event", "action", action, "zone", zoneName, "error", err)
	}
}

// mcpNewRecord builds a record from assistant input and checks it parses, so
// a bad value is reported against the field that caused it.
func mcpNewRecord(zone zonemodel.Zone, name, recordType, value string, ttl uint32, comment string) (zonemodel.Record, error) {
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	if recordType == "" {
		return zonemodel.Record{}, errors.New("type is required")
	}
	normalized, err := mcpRecordValue(zone.Name, recordType, value)
	if err != nil {
		return zonemodel.Record{}, err
	}
	if ttl == 0 {
		ttl = zone.DefaultTTL
	}
	record := zonemodel.Record{
		Name: mcpStoredOwner(zone.Name, name), Type: recordType, Value: normalized, TTL: ttl,
		Comments: strings.TrimSpace(comment),
	}
	if _, err := zonemodel.ParseRecord(zone, record); err != nil {
		return zonemodel.Record{}, err
	}
	return record, nil
}

// mcpRecordValue accepts the forms an assistant is likely to send and stores
// them the way the console would: canonical addresses, quoted TXT text, and
// bare in-zone targets qualified against the zone.
func mcpRecordValue(zoneName, recordType, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("value is required")
	}
	switch recordType {
	case "SOA":
		return "", errors.New("Sable manages the zone SOA record")
	case "RRSIG", "DNSKEY", "NSEC", "NSEC3", "NSEC3PARAM":
		return "", errors.New("DNSSEC records are managed automatically")
	case "A", "AAAA":
		address, err := netip.ParseAddr(value)
		if err != nil || (recordType == "A" && !address.Is4()) || (recordType == "AAAA" && !address.Is6()) {
			return "", fmt.Errorf("%s is not a valid %s address", value, recordType)
		}
		return address.String(), nil
	case "TXT", "SPF":
		if !strings.HasPrefix(value, `"`) {
			value = quoteDNSString(value)
		}
	}
	return zonemodel.QualifyRecordValue(zoneName, recordType, value), nil
}

func mcpFindRecord(zone zonemodel.Zone, name, recordType, value string) (int, error) {
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	target, err := mcpNewRecord(zone, name, recordType, value, 0, "")
	if err != nil {
		// The stored value may predate today's input rules, so fall back to an
		// exact match before giving up.
		target = zonemodel.Record{Name: mcpStoredOwner(zone.Name, name), Type: recordType, Value: strings.TrimSpace(value)}
	}
	var matches []int
	for index, record := range zone.Records {
		if mcpSameRecord(zone, record, target) {
			matches = append(matches, index)
		}
	}
	switch len(matches) {
	case 0:
		return 0, fmt.Errorf("no %s record %s with value %s was found in zone %s; call list_records to see what exists",
			recordType, mcpOwnerFQDN(zone.Name, name), strings.TrimSpace(value), zone.Name)
	case 1:
	default:
		return 0, errors.New("more than one record matches; change it in the Sable console")
	}
	if err := mcpRecordEditable(zone.Records[matches[0]]); err != nil {
		return 0, err
	}
	return matches[0], nil
}

func mcpRecordEditable(record zonemodel.Record) error {
	switch mcpRecordManager(record) {
	case "":
		return nil
	case "sable":
		return fmt.Errorf("Sable manages this %s record automatically", record.Type)
	default:
		return recordSourceEditable(record)
	}
}

func mcpRecordManager(record zonemodel.Record) string {
	switch {
	case record.Type == "SOA", strings.HasPrefix(record.Comments, "sable:dnssec"):
		return "sable"
	default:
		return record.Source
	}
}

// mcpSameRecord compares owner, type, and data the way DNS does, so a value
// spelled with different case or spacing still finds the stored record. TTL
// is not part of a record's identity.
func mcpSameRecord(zone zonemodel.Zone, left, right zonemodel.Record) bool {
	if left.Type != right.Type || mcpOwnerFQDN(zone.Name, left.Name) != mcpOwnerFQDN(zone.Name, right.Name) {
		return false
	}
	leftRR, leftErr := zonemodel.ParseRecord(zone, left)
	rightRR, rightErr := zonemodel.ParseRecord(zone, right)
	if leftErr != nil || rightErr != nil {
		return strings.TrimSpace(left.Value) == strings.TrimSpace(right.Value)
	}
	return dns.IsDuplicate(leftRR, rightRR)
}

func mcpStoredOwner(zoneName, name string) string {
	owner := normalizeZoneRecordOwner(zoneName, name)
	if owner == "" {
		return "@"
	}
	return strings.ToLower(owner)
}

// mcpOwnerFQDN expands an owner name the way the zone file does: @ is the
// apex, a trailing dot is absolute, and anything else is relative to the zone
// unless it already ends with the zone name.
func mcpOwnerFQDN(zoneName, name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch {
	case name == "" || name == "@":
		return dns.Fqdn(zoneName)
	case strings.HasSuffix(name, "."):
		return name
	case name == zoneName || strings.HasSuffix(name, "."+zoneName):
		return dns.Fqdn(name)
	default:
		return dns.Fqdn(name + "." + zoneName)
	}
}

func mcpRecordView(zone zonemodel.Zone, record zonemodel.Record) mcpRecord {
	view := mcpRecord{
		Name: record.Name, FQDN: strings.TrimSuffix(mcpOwnerFQDN(zone.Name, record.Name), "."),
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
	for _, record := range zone.Records {
		if record.Type == "SOA" && (record.Name == "@" || record.Name == "") {
			return zoneRecordSOASerial(record.Value)
		}
	}
	return 0
}

// mcpToolSections are the setup wizard's sections, in order.
var mcpToolSections = []struct{ Key, Title, Description string }{
	{"records", "Records & Zones", "Read and change records, and create and delete zones."},
	{"blocking", "Blocking", "Allow and block domains, and manage block lists."},
	{"lookups", "Lookups & Cache", "Resolve names through Sable, and forget cached answers."},
	{"server", "Server", "Check which version runs and whether a newer one is out."},
	{"insights", "Insights & Logs", "Share what each device does with the AI provider."},
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
