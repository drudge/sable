package web

import (
	"crypto/tls"
	"crypto/x509"
	json "encoding/json/v2"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/dnsclient"
	"github.com/drudge/sable/internal/web/pages"
)

func (server *Server) dnsClientPage(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	view := pages.DNSClientPageView{
		Console: console, QueryName: strings.TrimSpace(request.URL.Query().Get("name")),
		RecordType: strings.ToUpper(strings.TrimSpace(request.URL.Query().Get("type"))),
	}
	if server.cluster != nil && console.CanCluster {
		state := server.cluster.Snapshot()
		if state.Initialized {
			nodes := append([]cluster.Node(nil), state.Nodes...)
			sort.SliceStable(nodes, func(left, right int) bool {
				if nodes[left].Role != nodes[right].Role {
					return nodes[left].Role == cluster.RolePrimary
				}
				return strings.ToLower(nodes[left].Name) < strings.ToLower(nodes[right].Name)
			})
			view.ClusterNodes = make([]pages.ResolverOption, 0, len(nodes))
			for _, node := range nodes {
				if node.ID == state.NodeID {
					continue
				}
				label := node.Name
				if strings.TrimSpace(label) == "" {
					label = node.ID
				}
				detail := clusterRoleLabel(node.Role)
				if len(node.Addresses) > 0 {
					detail += " · " + node.Addresses[0]
				}
				view.ClusterNodes = append(view.ClusterNodes, pages.ResolverOption{
					Value:  "cluster-node:" + node.ID,
					Label:  label,
					Detail: detail,
					Search: strings.Join(node.Addresses, " "),
				})
			}
		}
	}
	if err := pages.DNSClientPage(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render DNS client", "error", err)
	}
}

func (server *Server) query(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		writeFragmentStatus(writer, http.StatusBadRequest)
		_ = pages.QueryResult(pages.QueryView{Error: err.Error()}).Render(request.Context(), writer)
		return
	}
	resolver := request.FormValue("resolver")
	var queryServer resolvedDNSServer
	var dohTLSConfig *tls.Config
	var err error
	if strings.HasPrefix(strings.TrimSpace(resolver), clusterResolverPrefix) {
		if server.cluster == nil {
			err = fmt.Errorf("cluster DNS resolver is unavailable")
		} else {
			queryServer, err = resolveClusterDNSClientServer(
				resolver,
				server.cluster.Snapshot(),
				request.FormValue("local_server"),
				request.FormValue("transport"),
			)
			if err == nil && request.FormValue("transport") == "doh" {
				nodeID := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(resolver), clusterResolverPrefix))
				dohTLSConfig, err = server.cluster.TLSConfigForNode(nodeID)
			}
		}
	} else {
		localServer := request.FormValue("local_server")
		var localDoH resolvedDNSServer
		if request.FormValue("transport") == "doh" &&
			(strings.TrimSpace(resolver) == "this-server" || strings.TrimSpace(resolver) == "recursive-resolver") {
			localDoH = server.localDoHServer(request)
			localServer = localDoH.address
		}
		queryServer, err = resolveDNSClientServer(
			resolver,
			request.FormValue("server"),
			request.FormValue("custom_name"),
			request.FormValue("custom_ip"),
			localServer,
			request.FormValue("transport"),
		)
		if err == nil && localDoH.address != "" {
			queryServer.dialIP = localDoH.dialIP
			dohTLSConfig = server.localDoHTLSConfig(queryServer.address)
		}
	}
	if err != nil {
		writeFragmentStatus(writer, http.StatusUnprocessableEntity)
		_ = pages.QueryResult(pages.QueryView{Error: err.Error()}).Render(request.Context(), writer)
		return
	}
	queryRequest := dnsclient.Request{
		Name:       request.FormValue("name"),
		Type:       request.FormValue("type"),
		Server:     queryServer.address,
		TLSName:    queryServer.tlsName,
		DialIP:     queryServer.dialIP,
		Transport:  request.FormValue("transport"),
		EDNSSubnet: request.FormValue("edns_subnet"),
		DNSSEC:     request.FormValue("dnssec") == "true",
		Timeout:    5 * time.Second,
	}
	queryRequest.DoHTLSConfig = dohTLSConfig
	result, err := dnsclient.Query(request.Context(), queryRequest)
	if err != nil {
		writeFragmentStatus(writer, http.StatusUnprocessableEntity)
		_ = pages.QueryResult(pages.QueryView{Error: err.Error()}).Render(request.Context(), writer)
		return
	}
	question := dns.Fqdn(queryRequest.Name)
	if len(result.Response.Question) > 0 {
		question = result.Response.Question[0].Name
	}
	flags := make([]string, 0, 4)
	if result.Response.Authoritative {
		flags = append(flags, "AA")
	}
	if result.Response.RecursionAvailable {
		flags = append(flags, "RA")
	}
	if result.Response.AuthenticatedData {
		flags = append(flags, "AD")
	}
	if result.Response.Truncated {
		flags = append(flags, "TC")
	}
	view := pages.QueryView{
		Success:    true,
		Question:   question,
		RecordType: strings.ToUpper(queryRequest.Type),
		Server:     result.Server,
		Protocol:   queryProtocolLabel(queryRequest.Transport),
		Elapsed:    result.Elapsed.Round(time.Microsecond).String(),
		Size:       fmt.Sprintf("%d bytes", result.Response.Len()),
		RCode:      dns.RcodeToString[result.Response.Rcode],
		Flags:      flags,
		Answers:    recordViews(result.Response.Answer),
		Authority:  recordViews(result.Response.Ns),
		Additional: recordViews(result.Response.Extra),
		Response:   result.Response.String(),
	}
	view.JSON = queryResultJSON(view)
	_ = pages.QueryResult(view).Render(request.Context(), writer)
}

// localDoHServer turns the console hostname the operator is already using into
// this server's DoH URL and pins the connection to the configured local
// listener. Pinning avoids sending a self-query through external DNS or NAT.
func (server *Server) localDoHServer(request *http.Request) resolvedDNSServer {
	if server.config == nil || request == nil {
		return resolvedDNSServer{}
	}
	configuration := server.config.Current().Config
	if len(configuration.EncryptedDNS.DoHListen) == 0 {
		return resolvedDNSServer{}
	}

	listener := configuration.EncryptedDNS.DoHListen[0]
	shared := configuration.SharesHTTPSWithDoH()
	if shared {
		listener = configuration.Server.HTTPSListen
	}
	requestHost := (&url.URL{Host: request.Host}).Hostname()
	listenerHost, port, err := net.SplitHostPort(listener)
	if requestHost == "" || err != nil {
		return resolvedDNSServer{}
	}
	endpointHost := net.JoinHostPort(requestHost, port)
	if port == "443" {
		endpointHost = urlHost(requestHost)
	}
	return resolvedDNSServer{address: (&url.URL{
		Scheme: "https",
		Host:   endpointHost,
		Path:   "/dns-query",
	}).String(), dialIP: localListenerDialIP(listenerHost)}
}

func localListenerDialIP(host string) string {
	host = strings.Trim(host, "[]")
	if host == "" || host == "0.0.0.0" {
		return "127.0.0.1"
	}
	if host == "::" {
		return "::1"
	}
	return host
}

// localDoHTLSConfig trusts the exact certificate Sable is currently serving.
// This keeps the installed self-signed certificate usable for a local query
// without disabling hostname or certificate verification.
func (server *Server) localDoHTLSConfig(endpoint string) *tls.Config {
	certificate := server.certificate.Load()
	parsedEndpoint, err := url.Parse(endpoint)
	if certificate == nil || err != nil || parsedEndpoint.Hostname() == "" {
		return nil
	}
	roots := x509.NewCertPool()
	trusted := false
	for _, encoded := range certificate.Certificate {
		parsed, err := x509.ParseCertificate(encoded)
		if err != nil {
			continue
		}
		roots.AddCert(parsed)
		trusted = true
	}
	if !trusted {
		return nil
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: parsedEndpoint.Hostname(),
	}
}

func queryResultJSON(view pages.QueryView) string {
	export := struct {
		Question   string             `json:"question"`
		RecordType string             `json:"record_type"`
		Server     string             `json:"server"`
		Protocol   string             `json:"protocol"`
		Elapsed    string             `json:"elapsed"`
		Size       string             `json:"size"`
		RCode      string             `json:"rcode"`
		Flags      []string           `json:"flags"`
		Answers    []pages.RecordView `json:"answers"`
		Authority  []pages.RecordView `json:"authority"`
		Additional []pages.RecordView `json:"additional"`
	}{
		Question: view.Question, RecordType: view.RecordType, Server: view.Server,
		Protocol: view.Protocol, Elapsed: view.Elapsed, Size: view.Size, RCode: view.RCode,
		Flags: view.Flags, Answers: view.Answers, Authority: view.Authority, Additional: view.Additional,
	}
	encoded, err := json.Marshal(export)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func queryProtocolLabel(transport string) string {
	switch transport {
	case "tcp":
		return "TCP"
	case "tcp-tls":
		return "TLS"
	case "doh":
		return "HTTPS"
	case "quic":
		return "QUIC"
	default:
		return "UDP"
	}
}

func recordViews(records []dns.RR) []pages.RecordView {
	views := make([]pages.RecordView, 0, len(records))
	for _, record := range records {
		if opt, ok := record.(*dns.OPT); ok && len(opt.Option) == 0 {
			continue
		}
		fields := strings.Fields(record.String())
		data := ""
		if len(fields) > 4 {
			data = strings.Join(fields[4:], " ")
		}
		header := record.Header()
		views = append(views, pages.RecordView{
			Name: header.Name, Type: dns.TypeToString[header.Rrtype], Data: data, TTL: header.Ttl,
		})
	}
	return views
}
