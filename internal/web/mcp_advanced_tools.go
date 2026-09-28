package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/web/pages"
	zonemodel "github.com/drudge/sable/internal/zone"
)

const (
	mcpDefaultQueryLimit = 50
	mcpMaximumQueryLimit = 200
	mcpMaximumQueryHours = 24 * 31
)

// mcpAdvancedTools belong to groups that are off until an operator turns
// them on. Each reaches further than records and blocking rules: deleting a
// zone cannot be undone from the console, lists change blocking for every
// device, and Insights and the query log describe what each device does.
var mcpAdvancedTools = []mcpTool{
	{
		Name:  "delete_zone",
		Title: "Delete a zone",
		Description: "Delete a zone and every record in it. A deleted zone cannot be restored from the console. " +
			"Before calling this, tell the user which zone will be deleted and ask them to confirm; then pass " +
			"the zone name again as confirm.",
		InputSchema: mcpObjectSchema(map[string]any{
			"zone":    mcpString("Zone name, for example preview-42.example.com."),
			"confirm": mcpString("The zone name again, exactly, to confirm the deletion."),
		}, []string{"zone", "confirm"}),
		Annotations: mcpToolAnnotations{Title: "Delete a zone", DestructiveHint: true},
		call:        (*Server).mcpDeleteZone,
		section:     "records",
		grant:       "zones.delete",
	},
	{
		Name:  "list_block_lists",
		Title: "List block lists",
		Description: "List the block lists Sable downloads, with how many domains each contributes and whether " +
			"its last update worked.",
		InputSchema: mcpObjectSchema(nil, nil),
		Annotations: mcpToolAnnotations{Title: "List block lists", ReadOnlyHint: true, IdempotentHint: true},
		call:        (*Server).mcpListBlockLists,
		section:     "blocking",
		grant:       "blocking.read",
	},
	{
		Name:  "add_block_list",
		Title: "Add a block list",
		Description: "Download a block list from an HTTPS URL and start blocking what it names. Sable checks the " +
			"list downloads and parses before adding it.",
		InputSchema: mcpObjectSchema(map[string]any{
			"url":  mcpString("HTTPS address of the list, in hosts, domain, or Adblock format."),
			"name": mcpString("Optional name shown in Sable. Defaults to one taken from the URL."),
		}, []string{"url"}),
		Annotations: mcpToolAnnotations{Title: "Add a block list", OpenWorldHint: true},
		call:        (*Server).mcpAddBlockList,
		section:     "blocking",
		grant:       "blocking.write",
	},
	{
		Name:        "remove_block_list",
		Title:       "Remove a block list",
		Description: "Stop using a block list, found by its name or URL as list_block_lists shows them.",
		InputSchema: mcpObjectSchema(map[string]any{
			"list": mcpString("The list's name or URL."),
		}, []string{"list"}),
		Annotations: mcpToolAnnotations{Title: "Remove a block list", DestructiveHint: true, IdempotentHint: true},
		call:        (*Server).mcpRemoveBlockList,
		section:     "blocking",
		grant:       "blocking.write",
	},
	{
		Name:        "refresh_block_lists",
		Title:       "Refresh block lists",
		Description: "Download every block list again now instead of waiting for the next scheduled update.",
		InputSchema: mcpObjectSchema(nil, nil),
		Annotations: mcpToolAnnotations{Title: "Refresh block lists", IdempotentHint: true, OpenWorldHint: true},
		call:        (*Server).mcpRefreshBlockLists,
		section:     "blocking",
		grant:       "blocking.write",
	},
	{
		Name:  "list_findings",
		Title: "List Insights findings",
		Description: "List what Sable's Insights noticed about the network over a period, such as new devices, " +
			"traffic spikes, devices that went quiet, or failing updates, each with the evidence behind it. " +
			"Findings the operator hid or turned off are left out.",
		InputSchema: mcpObjectSchema(map[string]any{
			"range": map[string]any{
				"type": "string", "enum": []string{"day", "week", "month", "year"},
				"description": "How far back to look. Defaults to month.",
			},
		}, nil),
		Annotations: mcpToolAnnotations{Title: "List Insights findings", ReadOnlyHint: true, IdempotentHint: true},
		call:        (*Server).mcpListFindings,
		section:     "insights",
		grant:       "logs.read",
	},
	{
		Name:  "search_queries",
		Title: "Search the query log",
		Description: "Search the DNS lookups devices made, newest first. Filter by device address, by part of a " +
			"name, or to blocked lookups only.",
		InputSchema: mcpObjectSchema(map[string]any{
			"client":       mcpString("Optional device address, matched exactly, for example 10.0.0.5."),
			"name":         mcpString("Optional part of a name, for example netflix."),
			"blocked_only": map[string]any{"type": "boolean", "description": "Only lookups that blocking stopped."},
			"hours":        mcpInteger("How many hours back to search. Defaults to 24.", 1),
			"limit":        mcpInteger("Most lookups to return, up to 200. Defaults to 50.", 1),
		}, nil),
		Annotations: mcpToolAnnotations{Title: "Search the query log", ReadOnlyHint: true, IdempotentHint: true},
		call:        (*Server).mcpSearchQueries,
		section:     "insights",
		grant:       "logs.read",
	},
}

func (server *Server) mcpDeleteZone(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Zone    string `json:"zone"`
		Confirm string `json:"confirm"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	if server.mcpReplica() {
		return nil, errors.New(replicaWriteMessage)
	}
	current, err := server.mcpReadableZone(request, input.Zone)
	if err != nil {
		return nil, err
	}
	if !server.authorizeZoneRequest(request, auth.PermissionZonesDelete, current) {
		return nil, fmt.Errorf("this token needs zones.delete to delete zone %s", current.Name)
	}
	if normalizeZoneName(input.Confirm) != current.Name {
		return nil, fmt.Errorf("confirm must repeat the zone name %s exactly; a deleted zone cannot be restored from the console", current.Name)
	}
	editor, ok := server.zones.(zoneEditor)
	if !ok {
		return nil, errors.New("this configuration source is read-only")
	}
	err = editor.UpdateZones(request.Context(), func(zones *[]zonemodel.Zone) error {
		index := slices.IndexFunc(*zones, func(zone zonemodel.Zone) bool { return zone.Name == current.Name })
		// The zone ID pins the delete to the zone that was checked.
		if index < 0 || (*zones)[index].ID != current.ID {
			return fmt.Errorf("zone %s was not found", current.Name)
		}
		*zones = slices.Delete(*zones, index, index+1)
		return nil
	})
	server.logMCPZoneOperation(request, "zone.delete", current.Name, err)
	if err != nil {
		return nil, err
	}
	server.auditMCPZoneMutation(request, "zone.delete", current.Name)
	return map[string]any{
		"zone": current.Name, "deleted": true,
		"message": "Zone deleted. It cannot be restored from the console; a backup can bring it back.",
	}, nil
}

func (server *Server) mcpListBlockLists(request *http.Request, arguments json.RawMessage) (any, error) {
	if err := decodeMCPArguments(arguments, &struct{}{}); err != nil {
		return nil, err
	}
	if !server.mcpHasPermission(request, auth.PermissionBlockingRead) {
		return nil, errors.New("this token needs blocking.read to list block lists")
	}
	snapshot := server.config.Current().Config.Blocking
	stats := server.stats.Stats()
	accepted := make(map[string]int, len(stats.BlockSources))
	for _, source := range stats.BlockSources {
		accepted[source.Name] = source.Accepted
	}
	status := server.blockLists.Status()
	health := make(map[string]blockcompiler.SourceHealth, len(status.Sources))
	for _, source := range status.Sources {
		health[source.URL] = source
	}
	lists := make([]map[string]any, 0, len(snapshot.Lists))
	for _, list := range snapshot.Lists {
		entry := map[string]any{"name": list.Name, "url": list.URL, "domains": accepted[list.Name], "healthy": true}
		if source, tracked := health[list.URL]; tracked && !source.Healthy() {
			entry["healthy"] = false
			entry["problem"] = blockListHealthDetail(source)
		}
		lists = append(lists, entry)
	}
	result := map[string]any{
		"blocking_enabled": snapshot.Enabled, "blocked_domains": stats.BlockedDomains, "lists": lists,
	}
	if !status.LastUpdate.IsZero() {
		result["last_update"] = status.LastUpdate
	}
	if !status.NextUpdate.IsZero() {
		result["next_update"] = status.NextUpdate
	}
	return result, nil
}

func (server *Server) mcpAddBlockList(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		URL  string `json:"url"`
		Name string `json:"name"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	editor, err := server.mcpBlockListEditor(request)
	if err != nil {
		return nil, err
	}
	remoteURL := strings.TrimSpace(input.URL)
	if err := blockcompiler.ValidateURL(remoteURL); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = blockListDisplayName(remoteURL)
	}
	duplicate := func(lists []config.BlockList) bool {
		return slices.ContainsFunc(lists, func(list config.BlockList) bool {
			return strings.EqualFold(list.Name, name) || list.URL == remoteURL
		})
	}
	if duplicate(server.config.Current().Config.Blocking.Lists) {
		return map[string]any{"name": name, "url": remoteURL, "changed": false, "message": "This block list is already added."}, nil
	}
	path := blockcompiler.CachePath(remoteURL)
	if err := server.blockLists.Download(request.Context(), blockcompiler.RemoteSource{Name: name, URL: remoteURL, Path: path}); err != nil {
		return nil, fmt.Errorf("download block list: %w", err)
	}
	err = editor.UpdateBlocking(request.Context(), func(policy *config.Blocking) error {
		if duplicate(policy.Lists) {
			return errors.New("this block list is already added")
		}
		policy.Lists = append(policy.Lists, config.BlockList{Name: name, Path: path, URL: remoteURL, Format: "auto"})
		server.blockLists.Schedule(time.Now().Add(policy.UpdateInterval.Duration))
		return nil
	})
	server.logMCPBlockingOperation(request, "blocking.list.add", name, err)
	if err != nil {
		return nil, err
	}
	server.recordControlPlaneAudit(request, "blocking.list.add", "added block list "+name+" via=mcp")
	return map[string]any{"name": name, "url": remoteURL, "changed": true, "message": "Block list added and compiled."}, nil
}

func (server *Server) mcpRemoveBlockList(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		List string `json:"list"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	editor, err := server.mcpBlockListEditor(request)
	if err != nil {
		return nil, err
	}
	target := strings.TrimSpace(input.List)
	matches := func(list config.BlockList) bool { return strings.EqualFold(list.Name, target) || list.URL == target }
	index := slices.IndexFunc(server.config.Current().Config.Blocking.Lists, matches)
	if index < 0 {
		return map[string]any{"list": target, "changed": false, "message": "No block list has that name or URL; call list_block_lists to see them."}, nil
	}
	name := server.config.Current().Config.Blocking.Lists[index].Name
	err = editor.UpdateBlocking(request.Context(), func(policy *config.Blocking) error {
		index := slices.IndexFunc(policy.Lists, matches)
		if index < 0 {
			return errors.New("block list was not found")
		}
		policy.Lists = slices.Delete(policy.Lists, index, index+1)
		if len(remoteBlockSources(*policy)) == 0 {
			server.blockLists.Schedule(time.Time{})
		}
		return nil
	})
	server.logMCPBlockingOperation(request, "blocking.list.delete", name, err)
	if err != nil {
		return nil, err
	}
	server.recordControlPlaneAudit(request, "blocking.list.delete", "removed block list "+name+" via=mcp")
	return map[string]any{"list": name, "changed": true, "message": "Block list removed."}, nil
}

func (server *Server) mcpRefreshBlockLists(request *http.Request, arguments json.RawMessage) (any, error) {
	if err := decodeMCPArguments(arguments, &struct{}{}); err != nil {
		return nil, err
	}
	if _, err := server.mcpBlockListEditor(request); err != nil {
		return nil, err
	}
	// An assistant asking for a refresh expects every list to be tried now,
	// as an operator clicking Update does.
	server.blockLists.ClearBackoff()
	err := server.refreshRemoteBlockLists(request.Context())
	server.logMCPBlockingOperation(request, "blocking.list.update", "", err)
	if err != nil {
		return nil, err
	}
	server.recordControlPlaneAudit(request, "blocking.list.update", "refreshed block lists via=mcp")
	return map[string]any{"refreshed": true, "blocked_domains": server.stats.Stats().BlockedDomains}, nil
}

// mcpBlockListEditor checks everything a block-list change needs before any
// download starts.
func (server *Server) mcpBlockListEditor(request *http.Request) (blockingEditor, error) {
	if !server.mcpHasPermission(request, auth.PermissionBlockingWrite) {
		return nil, errors.New("this token needs blocking.write to change block lists")
	}
	if server.mcpReplica() {
		return nil, errors.New(replicaWriteMessage)
	}
	editor, ok := server.config.(blockingEditor)
	if !ok {
		return nil, errors.New("this configuration source is read-only")
	}
	return editor, nil
}

func (server *Server) logMCPBlockingOperation(request *http.Request, action, list string, operationErr error) {
	attributes := []any{"operation", action, "client", requestClientIP(request), "via", "mcp"}
	if list != "" {
		attributes = append(attributes, "list", list)
	}
	if operationErr != nil {
		server.logger.Warn("blocking operation failed", append(attributes, "error", operationErr)...)
		return
	}
	server.logger.Info("blocking operation completed", attributes...)
}

type mcpFinding struct {
	ID           string            `json:"id"`
	Kind         string            `json:"kind"`
	Tone         string            `json:"tone,omitempty"`
	Title        string            `json:"title"`
	Subject      map[string]string `json:"subject,omitempty"`
	Summary      string            `json:"summary"`
	Reasons      []string          `json:"reasons,omitempty"`
	Facts        map[string]string `json:"facts,omitempty"`
	Clients      []mcpCount        `json:"clients,omitempty"`
	Domains      []string          `json:"domains,omitempty"`
	Explanations []string          `json:"possible_explanations,omitempty"`
	Method       string            `json:"method,omitempty"`
	ObservedAt   *time.Time        `json:"observed_at,omitempty"`
	// URL opens the finding in the console.
	URL string `json:"url"`
}

type mcpCount struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

// mcpListFindings runs the same analyzers the Insights page does, with the
// token's permissions, and hands back their typed findings and evidence.
func (server *Server) mcpListFindings(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Range string `json:"range"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	if !server.mcpHasPermission(request, auth.PermissionLogsRead) {
		return nil, errors.New("this token needs logs.read to read Insights findings")
	}
	if !server.insightsEnabled() {
		return nil, errInsightsOff
	}
	console := server.consoleView(request)
	window := insightsWindow(strings.ToLower(strings.TrimSpace(input.Range)), time.Now())
	analyzers, _, _ := server.insightAnalyzers(console, window)
	findings := insights.Collect(request.Context(), insights.Window{Start: window.Start, End: window.End}, analyzers,
		func(analyzer insights.Analyzer, err error) {
			server.logger.Warn("analyze insights", "analyzer", fmt.Sprintf("%T", analyzer), "error", err)
		})
	findings = insightModesOf(server.config.Current().Config.Insights.Findings).shown(findings)
	if feedbackStore, ok := server.queries.(insightFeedbackStore); ok {
		feedback, err := feedbackStore.InsightFeedback(request.Context(), time.Now())
		if err != nil {
			server.logger.Warn("read insight feedback", "error", err)
		}
		findings, _ = insights.Hide(findings, feedback, time.Now())
	}
	given := server.givenClientNames(request.Context(), window.Start)
	base := strings.TrimRight(server.config.Current().Config.AdvertisedBaseURL(), "/")
	views := make([]mcpFinding, 0, len(findings))
	for _, finding := range findings {
		view := mcpFindingView(finding, given.Address)
		view.URL = base + pages.InsightFindingPath(finding.ID, window.Range)
		views = append(views, view)
	}
	return map[string]any{
		"range": window.Label, "start": window.Start, "end": window.End, "findings": views,
	}, nil
}

func mcpFindingView(finding insights.Finding, nameFor func(string) string) mcpFinding {
	view := mcpFinding{
		ID: finding.ID, Kind: finding.Kind, Tone: string(finding.Tone), Title: finding.Title,
		Summary: finding.Summary, Explanations: finding.Explanations, Method: finding.Method,
	}
	subject := map[string]string{}
	for key, value := range map[string]string{
		"label": finding.Subject.Label, "device": finding.Subject.Device,
		"domain": finding.Subject.Domain, "block_list": finding.Subject.BlockList,
	} {
		if value != "" {
			subject[key] = value
		}
	}
	if len(subject) > 0 {
		view.Subject = subject
	}
	for _, reason := range finding.Reasons {
		text := reason.Text
		if reason.Code != "" {
			text += " " + reason.Code
		}
		view.Reasons = append(view.Reasons, text)
	}
	if len(finding.Facts) > 0 {
		view.Facts = make(map[string]string, len(finding.Facts))
		for _, fact := range finding.Facts {
			value := fact.Value
			if !fact.Time.IsZero() {
				value = fact.Time.UTC().Format(time.RFC3339)
			}
			view.Facts[fact.Label] = value
		}
	}
	for _, client := range finding.Clients {
		name := client.Name
		if given := nameFor(client.Name); given != "" {
			name = given + " (" + client.Name + ")"
		}
		view.Clients = append(view.Clients, mcpCount{Name: name, Count: client.Hits})
	}
	for _, domain := range finding.Domains {
		view.Domains = append(view.Domains, domain.Name)
	}
	if !finding.ObservedAt.IsZero() {
		observed := finding.ObservedAt
		view.ObservedAt = &observed
	}
	return view
}

type mcpQueryEntry struct {
	At         time.Time `json:"at"`
	Client     string    `json:"client"`
	Device     string    `json:"device,omitempty"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Result     string    `json:"result"`
	Source     string    `json:"answered_from"`
	Answer     string    `json:"answer,omitempty"`
	BlockedBy  string    `json:"blocked_by,omitempty"`
	DurationMS float64   `json:"duration_ms"`
}

func (server *Server) mcpSearchQueries(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Client      string `json:"client"`
		Name        string `json:"name"`
		BlockedOnly bool   `json:"blocked_only"`
		Hours       int    `json:"hours"`
		Limit       int    `json:"limit"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	if !server.mcpHasPermission(request, auth.PermissionLogsRead) {
		return nil, errors.New("this token needs logs.read to search the query log")
	}
	pager, ok := server.queries.(queryEventPager)
	if !ok {
		return nil, errors.New("the query log is unavailable on this server")
	}
	hours := input.Hours
	if hours <= 0 {
		hours = 24
	}
	hours = min(hours, mcpMaximumQueryHours)
	limit := input.Limit
	if limit <= 0 {
		limit = mcpDefaultQueryLimit
	}
	limit = min(limit, mcpMaximumQueryLimit)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	filter := querylog.Filter{
		Page: 1, PageSize: limit, Since: since,
		ClientIP: strings.TrimSpace(input.Client), Name: strings.ToLower(strings.TrimSpace(input.Name)),
	}
	if input.BlockedOnly {
		filter.Source = querylog.SourceBlocked
	}
	page, err := pager.QueryEvents(request.Context(), filter)
	if err != nil {
		return nil, fmt.Errorf("search the query log: %w", err)
	}
	given := server.givenClientNames(request.Context(), since)
	entries := make([]mcpQueryEntry, 0, len(page.Entries))
	for _, entry := range page.Entries {
		view := mcpQueryEntry{
			At: entry.OccurredAt, Client: entry.ClientIP, Device: given.Address(entry.ClientIP), Name: entry.Name,
			Type: dns.TypeToString[entry.RecordType], Result: dns.RcodeToString[entry.ResponseCode],
			Source: string(entry.Source), Answer: entry.Answer,
			DurationMS: float64(entry.Duration.Microseconds()) / 1000,
		}
		if entry.Source == querylog.SourceBlocked {
			view.BlockedBy = entry.Decision.PolicyRule
		}
		entries = append(entries, view)
	}
	result := map[string]any{"hours": hours, "matching": page.TotalEntries, "queries": entries}
	if !server.config.Current().Config.QueryLog.Enabled {
		result["note"] = "Query logging is turned off, so no new lookups are being recorded."
	}
	return result, nil
}
