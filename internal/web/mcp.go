package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/version"
)

// mcpPath serves the Model Context Protocol over Streamable HTTP. The server
// is stateless: every POST carries one JSON-RPC message and receives one JSON
// reply, so there is no session to resume and no event stream to hold open.
const mcpPath = "/mcp"

const (
	mcpMaximumBodyBytes   = 1 << 20
	mcpProtocolHeader     = "MCP-Protocol-Version"
	mcpLatestProtocol     = "2025-11-25"
	mcpParseError         = -32700
	mcpInvalidRequest     = -32600
	mcpMethodNotFound     = -32601
	mcpInvalidParams      = -32602
	mcpServerInstructions = "Sable is an authoritative and recursive DNS server with ad and tracker blocking. Use these tools to " +
		"read and change records in its Primary zones, create zones, look names up through Sable, and explain or " +
		"change what blocking allows. Record names may be relative to the zone (www), the zone apex (@), or fully " +
		"qualified (www.example.com). Values use zone-file syntax, for example \"10 mail.example.com.\" for MX; TXT " +
		"text may be given unquoted. Every change advances the zone's SOA serial and notifies its secondaries. " +
		"Prefer set_records for deployments because repeating it changes nothing."
)

// mcpProtocols lists the revisions this server speaks, newest first. The
// methods used here did not change between them.
var mcpProtocols = []string{mcpLatestProtocol, "2025-06-18", "2025-03-26"}

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (server *Server) mcp(writer http.ResponseWriter, request *http.Request) {
	if !server.config.Current().Config.MCP.Enabled {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": mcpDisabledMessage})
		return
	}
	// MCP clients are programs, not web pages. Refusing cross-site browser
	// requests and anything but JSON keeps a page the operator happens to
	// visit from driving the endpoint, including through DNS rebinding.
	if server.crossOrigin.Check(request) != nil {
		writeMCPError(writer, http.StatusForbidden, nil, mcpInvalidRequest, "cross-origin requests are not allowed")
		return
	}
	if mediaType, _, _ := mime.ParseMediaType(request.Header.Get("Content-Type")); mediaType != "application/json" {
		writeMCPError(writer, http.StatusUnsupportedMediaType, nil, mcpInvalidRequest, "Content-Type must be application/json")
		return
	}
	if requested := request.Header.Get(mcpProtocolHeader); requested != "" && !slices.Contains(mcpProtocols, requested) {
		writeMCPError(writer, http.StatusBadRequest, nil, mcpInvalidRequest, "unsupported MCP protocol version "+requested)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, mcpMaximumBodyBytes))
	if err != nil {
		writeMCPError(writer, http.StatusRequestEntityTooLarge, nil, mcpInvalidRequest, "request body is too large")
		return
	}
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && trimmed[0] == '[' {
		writeMCPError(writer, http.StatusBadRequest, nil, mcpInvalidRequest, "JSON-RPC batches are not supported")
		return
	}
	var message mcpRequest
	if err := json.Unmarshal(body, &message); err != nil {
		writeMCPError(writer, http.StatusBadRequest, nil, mcpParseError, "request is not valid JSON")
		return
	}
	if message.JSONRPC != "2.0" {
		writeMCPError(writer, http.StatusBadRequest, message.ID, mcpInvalidRequest, `jsonrpc must be "2.0"`)
		return
	}
	// Notifications and client responses need no reply. Streamable HTTP
	// acknowledges them with 202 and an empty body.
	if len(message.ID) == 0 || bytes.Equal(message.ID, []byte("null")) || message.Method == "" {
		writer.WriteHeader(http.StatusAccepted)
		return
	}

	var result any
	var failure *mcpError
	switch message.Method {
	case "initialize":
		result, failure = mcpInitialize(message.Params)
	case "ping":
		result = struct{}{}
	case "tools/list":
		result = map[string]any{"tools": mcpToolList(server.config.Current().Config.MCP)}
	case "tools/call":
		result, failure = server.callMCPTool(request, message.Params)
	default:
		failure = &mcpError{Code: mcpMethodNotFound, Message: "method not found: " + message.Method}
	}
	response := mcpResponse{JSONRPC: "2.0", ID: message.ID, Result: result, Error: failure}
	writeJSON(writer, http.StatusOK, response)
}

func mcpInitialize(params json.RawMessage) (any, *mcpError) {
	var input struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &input); err != nil {
			return nil, &mcpError{Code: mcpInvalidParams, Message: "initialize params are invalid"}
		}
	}
	// A client that asks for a revision we do not speak gets our newest one and
	// decides for itself whether to continue.
	protocol := mcpLatestProtocol
	if slices.Contains(mcpProtocols, input.ProtocolVersion) {
		protocol = input.ProtocolVersion
	}
	return map[string]any{
		"protocolVersion": protocol,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo": map[string]any{
			"name": "sable", "title": "Sable DNS", "version": version.Current().Release,
		},
		"instructions": mcpServerInstructions,
	}, nil
}

func (server *Server) callMCPTool(request *http.Request, params json.RawMessage) (any, *mcpError) {
	var input struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, &mcpError{Code: mcpInvalidParams, Message: "tools/call params are invalid"}
	}
	tool, found := mcpToolByName(input.Name)
	if !found {
		return nil, &mcpError{Code: mcpInvalidParams, Message: "unknown tool: " + input.Name}
	}
	// A client may still hold a tool list from before an option was turned
	// off, so say so plainly instead of calling the tool unknown.
	if tool.option != nil && !tool.option(server.config.Current().Config.MCP) {
		return mcpToolFailure(fmt.Errorf("the %s tool is turned off in Sable under Integrations, MCP Server", tool.Name)), nil
	}
	arguments := input.Arguments
	if len(arguments) == 0 || bytes.Equal(arguments, []byte("null")) {
		arguments = []byte("{}")
	}
	server.recordMCPUse(request, tool.Name)
	// Tool failures go back to the model as a result, not a protocol error, so
	// it can read what went wrong and correct its next call.
	output, err := tool.call(server, request, arguments)
	if err != nil {
		return mcpToolFailure(err), nil
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return mcpToolFailure(fmt.Errorf("encode %s result: %w", input.Name, err)), nil
	}
	return map[string]any{
		"content":           []map[string]string{{"type": "text", "text": string(encoded)}},
		"structuredContent": output,
		"isError":           false,
	}, nil
}

type mcpUseStore interface {
	LoadMCPUse(context.Context) (store.MCPUse, error)
	SaveMCPUse(context.Context, store.MCPUse) error
}

// recordMCPUse notes who last called a tool, with what, so the card can show
// an assistant is really connected. A failure to save never fails the call.
func (server *Server) recordMCPUse(request *http.Request, tool string) {
	uses, ok := server.queries.(mcpUseStore)
	if !ok {
		return
	}
	username := ""
	if principal, ok := request.Context().Value(principalContextKey{}).(auth.Principal); ok {
		username = principal.Username
	}
	// Calls are counted by reading, adding one, and saving, so concurrent
	// calls take turns rather than overwrite each other's count.
	server.mcpUseMu.Lock()
	defer server.mcpUseMu.Unlock()
	use, err := uses.LoadMCPUse(request.Context())
	if err != nil {
		server.logger.Warn("load MCP use", "error", err)
	}
	use.RecordCall(time.Now(), username, mcpClientName(request.UserAgent()), tool)
	if err := uses.SaveMCPUse(request.Context(), use); err != nil {
		server.logger.Warn("record MCP use", "error", err)
	}
}

func (server *Server) lastMCPUse(ctx context.Context) store.MCPUse {
	uses, ok := server.queries.(mcpUseStore)
	if !ok {
		return store.MCPUse{}
	}
	use, err := uses.LoadMCPUse(ctx)
	if err != nil {
		server.logger.Warn("load MCP use", "error", err)
	}
	return use
}

// mcpClientName keeps the product from a User-Agent, such as claude-code from
// "claude-code/2.1.0 (cli)", which is enough to tell assistants apart.
func mcpClientName(userAgent string) string {
	product, _, _ := strings.Cut(strings.TrimSpace(userAgent), " ")
	product, _, _ = strings.Cut(product, "/")
	if len(product) > 64 {
		product = product[:64]
	}
	return product
}

func mcpToolFailure(err error) map[string]any {
	return map[string]any{
		"content": []map[string]string{{"type": "text", "text": err.Error()}},
		"isError": true,
	}
}

// decodeMCPArguments rejects unknown fields so a misspelled argument fails
// loudly instead of silently changing nothing.
func decodeMCPArguments(arguments json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(arguments))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	if decoder.More() {
		return errors.New("invalid arguments: trailing data")
	}
	return nil
}

func writeMCPError(writer http.ResponseWriter, status int, id json.RawMessage, code int, message string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	writeJSON(writer, status, mcpResponse{JSONRPC: "2.0", ID: id, Error: &mcpError{Code: code, Message: message}})
}

const mcpDisabledMessage = "Sable's MCP server is off. Set it up under Integrations, MCP Server."

// setMCPEnabled sets up, pauses, or resumes the MCP server. It is a
// cluster-wide setting, so a replica refuses it before it gets here and takes
// the primary's value instead.
func (server *Server) setMCPEnabled(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusBadRequest, "", "Invalid request.")
		return
	}
	enabled := request.FormValue("enabled") == "true"
	wasConfigured := server.config.Current().Config.MCP.Configured
	if err := server.updateMCP(request, func(settings *config.MCP) {
		settings.Enabled = enabled
		settings.Configured = settings.Configured || enabled
	}); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	action, message := "integrations.mcp.disable", "MCP server paused. API tokens still work everywhere else."
	switch {
	case enabled && !wasConfigured:
		action, message = "integrations.mcp.setup", "MCP server set up."
	case enabled:
		action, message = "integrations.mcp.enable", "MCP server resumed."
	}
	// Setting up from the dialog must not leave ?setup=mcp behind to reopen it.
	writer.Header().Set("HX-Replace-Url", "/integrations")
	server.logger.Info("MCP server changed", "enabled", enabled, "client", requestClientIP(request))
	server.recordControlPlaneAudit(request, action, message)
	server.renderIntegrationsMutation(writer, request, http.StatusOK, message, "")
}

// saveMCPSetup saves the setup dialog. The first save sets the server up
// and turns it on; later saves change only the advanced tools, so editing
// the setup never resumes a paused server. Like the server itself it is
// cluster-wide, so only the primary accepts it.
func (server *Server) saveMCPSetup(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusBadRequest, "", "Invalid request.")
		return
	}
	on := func(name string) bool { return request.FormValue(name) == "true" }
	settingUp := !server.config.Current().Config.MCP.Configured
	var enabled []string
	if err := server.updateMCP(request, func(settings *config.MCP) {
		if !settings.Configured {
			settings.Configured, settings.Enabled = true, true
		}
		settings.DeleteZones, settings.BlockLists = on("delete_zones"), on("block_lists")
		settings.InsightFindings, settings.QueryLog = on("insight_findings"), on("query_log")
		for name, value := range map[string]bool{
			"delete_zones": settings.DeleteZones, "block_lists": settings.BlockLists,
			"insight_findings": settings.InsightFindings, "query_log": settings.QueryLog,
		} {
			if value {
				enabled = append(enabled, name)
			}
		}
	}); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	slices.Sort(enabled)
	details := "advanced MCP tools: none"
	if len(enabled) > 0 {
		details = "advanced MCP tools: " + strings.Join(enabled, ", ")
	}
	action, message := "integrations.mcp.configure", "MCP server saved. Assistants see changes the next time they connect."
	if settingUp {
		action, message = "integrations.mcp.setup", "MCP server set up."
	}
	writer.Header().Set("HX-Replace-Url", "/integrations")
	server.logger.Info("MCP server saved", "set_up", settingUp, "advanced_tools", strings.Join(enabled, ","), "client", requestClientIP(request))
	server.recordControlPlaneAudit(request, action, details)
	server.renderIntegrationsMutation(writer, request, http.StatusOK, message, "")
}

// removeMCP turns the server off and returns the card to setup. API tokens
// are left alone: they belong to people, not to this integration.
func (server *Server) removeMCP(writer http.ResponseWriter, request *http.Request) {
	if err := server.updateMCP(request, func(settings *config.MCP) { *settings = config.MCP{} }); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	message := "MCP server removed. API tokens were left in place."
	writer.Header().Set("HX-Replace-Url", "/integrations")
	server.logger.Info("MCP server removed", "client", requestClientIP(request))
	server.recordControlPlaneAudit(request, "integrations.mcp.remove", message)
	server.renderIntegrationsMutation(writer, request, http.StatusOK, message, "")
}

func (server *Server) updateMCP(request *http.Request, change func(*config.MCP)) error {
	editor, ok := server.config.(settingsEditor)
	if !ok {
		return errors.New("settings are read-only")
	}
	return editor.Update(request.Context(), func(candidate *config.Config) error {
		change(&candidate.MCP)
		return nil
	})
}

// mcpAddress is the address an assistant should be given. Changes are only
// accepted by the cluster primary, and a token should only cross the network
// encrypted, so it prefers the primary's advertised HTTPS URL, then this
// node's own HTTPS identity, and only then the address this browser used.
func (server *Server) mcpAddress(ctx context.Context, request *http.Request) (address string, secure bool) {
	if server.cluster != nil {
		if state := server.cluster.Snapshot(); state.Initialized {
			if address, ok := mcpAddressFromURL(state.PrimaryURL); ok {
				return address, true
			}
		}
	}
	if server.config != nil {
		configuration := server.config.Current().Config
		if address, ok := mcpAddressFromURL(configuration.Cluster.AdvertiseURL); ok {
			return address, true
		}
		if request.TLS == nil && !strings.EqualFold(request.Header.Get("X-Forwarded-Proto"), "https") {
			if name, port := server.httpsIdentity(ctx, configuration); name != "" {
				host := name
				if port != "" && port != "443" {
					host = net.JoinHostPort(name, port)
				}
				return "https://" + host + mcpPath, true
			}
		}
	}
	address = absoluteURL(request, mcpPath)
	return address, strings.HasPrefix(address, "https://")
}

func mcpAddressFromURL(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", false
	}
	return "https://" + parsed.Host + mcpPath, true
}

// httpsIdentity names this node's HTTPS console: the first name its
// certificate covers and the port it listens on.
func (server *Server) httpsIdentity(ctx context.Context, configuration config.Config) (string, string) {
	if configuration.Server.HTTPSListen == "" {
		return "", ""
	}
	_, port, err := net.SplitHostPort(configuration.Server.HTTPSListen)
	if err != nil {
		return "", ""
	}
	names := configuration.EncryptedDNS.ACME.Domains
	if configuration.EncryptedDNS.CertificateMode != "acme" {
		names = nil
		if server.certificates != nil {
			names = server.certificates.Status(ctx, configuration.EncryptedDNS).CoveredNames
		}
	}
	for _, name := range names {
		if name = strings.TrimSpace(name); name != "" && !strings.HasPrefix(name, "*") {
			return name, port
		}
	}
	return "", ""
}

func mcpMethodNotAllowed(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Allow", http.MethodPost)
	writeJSON(writer, http.StatusMethodNotAllowed, map[string]string{"error": "Sable's MCP endpoint accepts POST only"})
}
