package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web/pages"
)

type clusterController interface {
	Snapshot() cluster.State
	LocalConfiguration() cluster.LocalConfiguration
	Initialize(context.Context, string, []string) error
	CreateEnrollmentToken(context.Context, time.Duration) (cluster.EnrollmentToken, error)
	Enroll(context.Context, cluster.JoinRequest) (cluster.JoinConfiguration, error)
	Join(context.Context, cluster.JoinOptions) error
	Promote(context.Context, string) error
	Remove(context.Context, string) error
	Leave(context.Context) error
	Synchronize(context.Context, cluster.Heartbeat, string) (cluster.SyncConfiguration, error)
	Delete(context.Context) error
}

func (server *Server) SetClusterController(controller clusterController) { server.cluster = controller }

func (server *Server) clusterPage(writer http.ResponseWriter, request *http.Request) {
	if err := pages.ClusterPage(server.clusterView(request, "", "")).Render(request.Context(), writer); err != nil {
		server.logger.Error("render cluster page", "error", err)
	}
}

func (server *Server) clusterLiveStatus(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	view := server.clusterView(request, "", "")
	if !view.Initialized {
		writer.Header().Set("HX-Retarget", "#cluster-content")
		writer.Header().Set("HX-Reswap", "outerHTML")
		if err := pages.ClusterContent(view).Render(request.Context(), writer); err != nil {
			server.logger.Error("render unconfigured cluster state", "error", err)
		}
		return
	}
	if err := pages.ClusterLiveStatus(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render live cluster status", "error", err)
	}
}

func (server *Server) initializeCluster(writer http.ResponseWriter, request *http.Request) {
	if !server.clusterAvailable(writer, request) {
		return
	}
	if server.clusterView(request, "", "").RestartRequired {
		server.renderClusterMutation(writer, request, http.StatusConflict, "", "Restart Sable to activate the saved node identity before initializing a cluster")
		return
	}
	if !server.cluster.Snapshot().NetworkReady {
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", "Configure an HTTPS Console / API URL before initializing a cluster")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderClusterMutation(writer, request, http.StatusBadRequest, "", "Invalid cluster form")
		return
	}
	domain := strings.TrimSpace(request.FormValue("domain"))
	if err := server.cluster.Initialize(request.Context(), domain, formLines(request.FormValue("addresses"))); err != nil {
		server.logger.Warn("initialize cluster", "domain", domain, "client", requestClientIP(request), "error", err)
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	state := server.cluster.Snapshot()
	writer.Header().Set("HX-Replace-Url", "/cluster")
	server.logger.Info("primary cluster initialized", "cluster_id", state.ClusterID, "node_id", state.NodeID, "domain", state.ClusterDomain, "client", requestClientIP(request))
	server.recordControlPlaneAudit(request, "cluster.initialize", fmt.Sprintf("initialized primary cluster %s (%s)", state.ClusterDomain, state.ClusterID))
	server.renderClusterMutation(writer, request, http.StatusOK, "Cluster initialized", "")
}

func (server *Server) updateClusterSettings(writer http.ResponseWriter, request *http.Request) {
	if !server.clusterAvailable(writer, request) {
		return
	}
	initialized := server.cluster.Snapshot().Initialized
	editor, ok := server.config.(settingsEditor)
	if !ok {
		server.renderClusterMutation(writer, request, http.StatusNotImplemented, "", "Cluster settings are read-only")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderClusterMutation(writer, request, http.StatusBadRequest, "", "Invalid cluster settings form")
		return
	}
	nodeName := strings.TrimSpace(request.FormValue("node_name"))
	advertiseURL := strings.TrimSpace(request.FormValue("advertise_url"))
	if nodeName == "" || advertiseURL == "" {
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", "Node name and HTTPS Console / API URL are required")
		return
	}
	if err := config.ValidateClusterAdvertiseURL(advertiseURL); err != nil {
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", "HTTPS Console / API URL must be an absolute HTTPS URL without credentials, query, or fragment")
		return
	}
	err := editor.Update(request.Context(), func(candidate *config.Config) error {
		if !initialized {
			candidate.Cluster.DataDirectory = strings.TrimSpace(request.FormValue("data_dir"))
		}
		candidate.Cluster.NodeName = nodeName
		candidate.Cluster.AdvertiseURL = advertiseURL
		return nil
	})
	if err != nil {
		server.logger.Warn("stage cluster settings", "client", requestClientIP(request), "error", err)
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	server.logger.Info("cluster node identity staged", "client", requestClientIP(request), "cluster_initialized", initialized, "restart_required", true)
	server.recordControlPlaneAudit(request, "cluster.settings.update", "updated node-local cluster identity; controlled restart required")
	server.renderClusterMutation(writer, request, http.StatusOK, "Cluster node settings saved. Restart Sable to activate them.", "")
}

func (server *Server) updateClusterOnboarding(writer http.ResponseWriter, request *http.Request) {
	if !server.clusterAvailable(writer, request) {
		return
	}
	if server.cluster.Snapshot().Initialized {
		server.renderClusterMutation(writer, request, http.StatusConflict, "", "Leave the current cluster before changing this node's identity")
		return
	}
	editor, ok := server.config.(settingsEditor)
	if !ok {
		server.renderClusterMutation(writer, request, http.StatusNotImplemented, "", "Cluster settings are read-only")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderClusterMutation(writer, request, http.StatusBadRequest, "", "Invalid cluster onboarding form")
		return
	}
	workflow := normalizeClusterWorkflow(request.FormValue("workflow"))
	request.Form.Set("workflow", workflow)
	nodeName := strings.TrimSpace(request.FormValue("node_name"))
	advertiseURL := strings.TrimSpace(request.FormValue("advertise_url"))
	dataDirectory := strings.TrimSpace(request.FormValue("data_dir"))
	if nodeName == "" || advertiseURL == "" || dataDirectory == "" {
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", "Node name, HTTPS Console / API URL, and cluster state directory are required")
		return
	}
	if err := config.ValidateClusterAdvertiseURL(advertiseURL); err != nil {
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", "HTTPS Console / API URL must be an absolute HTTPS URL without credentials, query, or fragment")
		return
	}
	source := strings.ToLower(strings.TrimSpace(request.FormValue("certificate_source")))
	if source != "external" && source != "acme" && source != "import" && source != "generated" {
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", "Choose how HTTPS is provided")
		return
	}

	var imported certificates.GeneratedCertificate
	if source == "import" {
		generator, generated := server.certificates.(certificateGenerator)
		if !generated {
			server.renderClusterMutation(writer, request, http.StatusNotImplemented, "", "Certificate import is unavailable")
			return
		}
		var err error
		imported, err = generator.ImportKeyPair(request.Context(), certificates.ImportCertificateOptions{
			CertificatePEM:   []byte(strings.TrimSpace(request.FormValue("manual_certificate_pem")) + "\n"),
			PrivateKeyPEM:    []byte(strings.TrimSpace(request.FormValue("manual_private_key_pem")) + "\n"),
			StorageDirectory: strings.TrimSpace(request.FormValue("manual_import_storage_dir")),
		})
		if err != nil {
			server.logger.Warn("import cluster onboarding certificate", "client", requestClientIP(request), "error", err)
			server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
			return
		}
	}
	if source == "generated" {
		generator, generated := server.certificates.(certificateGenerator)
		if !generated {
			server.renderClusterMutation(writer, request, http.StatusNotImplemented, "", "Self-signed certificate generation is unavailable")
			return
		}
		validFor, err := certificateValidity(request.FormValue("generated_valid_days"), 365)
		if err != nil {
			server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
			return
		}
		advertised, err := url.Parse(advertiseURL)
		if err != nil || advertised.Hostname() == "" {
			server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", "HTTPS Console / API URL must include a hostname or IP address")
			return
		}
		names := append([]string{advertised.Hostname()}, formLines(request.FormValue("generated_additional_names"))...)
		imported, err = generator.GenerateClusterPKI(request.Context(), certificates.ClusterPKIOptions{
			NodeName:         nodeName,
			Names:            names,
			StorageDirectory: strings.TrimSpace(request.FormValue("generated_storage_dir")),
			ValidFor:         validFor,
		})
		if err != nil {
			server.logger.Warn("generate cluster onboarding certificate", "client", requestClientIP(request), "error", err)
			server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
			return
		}
	}

	acmeRenewBefore := 30 * 24 * time.Hour
	if source == "acme" {
		if server.certificates == nil {
			server.renderClusterMutation(writer, request, http.StatusServiceUnavailable, "", "Certificate automation service is unavailable")
			return
		}
		var err error
		acmeRenewBefore, err = time.ParseDuration(strings.TrimSpace(request.FormValue("acme_renew_before")))
		if err != nil {
			server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", "ACME renewal window is invalid")
			return
		}
		provider := strings.ToLower(strings.TrimSpace(request.FormValue("acme_dns_provider")))
		credentials := certificateCredentialsFromForm(request, provider)
		if credentials != (certificates.Credentials{}) {
			if err := server.certificates.PutCredentials(request.Context(), provider, credentials); err != nil {
				server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
				return
			}
		}
	}

	applyCandidate := func(candidate *config.Config) error {
		candidate.Cluster.DataDirectory = dataDirectory
		candidate.Cluster.NodeName = nodeName
		candidate.Cluster.AdvertiseURL = advertiseURL
		candidate.Cluster.TrustAnchorFile = ""
		switch source {
		case "import", "generated":
			listenField := "import_https_listen"
			if source == "generated" {
				listenField = "generated_https_listen"
			}
			candidate.Server.HTTPSListen = strings.TrimSpace(request.FormValue(listenField))
			candidate.EncryptedDNS.CertificateMode = "manual"
			candidate.EncryptedDNS.CertificateFile = imported.CertificateFile
			candidate.EncryptedDNS.PrivateKeyFile = imported.PrivateKeyFile
			if source == "generated" {
				candidate.Cluster.TrustAnchorFile = imported.CAFile
			}
		case "acme":
			candidate.Server.HTTPSListen = strings.TrimSpace(request.FormValue("https_listen"))
			candidate.EncryptedDNS.CertificateMode = "acme"
			candidate.EncryptedDNS.ACME.Email = strings.TrimSpace(request.FormValue("acme_email"))
			candidate.EncryptedDNS.ACME.Domains = formLines(request.FormValue("acme_domains"))
			candidate.EncryptedDNS.ACME.DirectoryURL = strings.TrimSpace(request.FormValue("acme_directory_url"))
			candidate.EncryptedDNS.ACME.DNSProvider = strings.ToLower(strings.TrimSpace(request.FormValue("acme_dns_provider")))
			candidate.EncryptedDNS.ACME.DNSZone = strings.TrimSpace(request.FormValue("acme_dns_zone"))
			candidate.EncryptedDNS.ACME.StorageDirectory = strings.TrimSpace(request.FormValue("acme_storage_dir"))
			candidate.EncryptedDNS.ACME.RenewBefore = config.Duration{Duration: acmeRenewBefore}
		}
		return nil
	}
	preview := server.config.Current().Config
	if err := applyCandidate(&preview); err != nil {
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	if err := preview.Validate(); err != nil {
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	if source == "acme" {
		if _, err := server.certificates.Ensure(request.Context(), preview.EncryptedDNS, true); err != nil {
			server.logger.Warn("issue cluster onboarding certificate", "client", requestClientIP(request), "error", err)
			server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", "The certificate could not be issued: "+err.Error())
			return
		}
	}
	err := editor.Update(request.Context(), applyCandidate)
	if err != nil {
		server.logger.Warn("stage cluster onboarding", "client", requestClientIP(request), "error", err)
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	request.Form.Del("wizard_step")
	restartRequired := server.clusterView(request, "", "").RestartRequired
	writer.Header().Set("HX-Replace-Url", "/cluster?onboarding="+workflow)
	server.logger.Info("cluster onboarding staged", "client", requestClientIP(request), "workflow", workflow, "https_source", source, "restart_required", restartRequired)
	server.recordControlPlaneAudit(request, "cluster.onboarding.configure", "configured node identity and HTTPS for cluster onboarding")
	message := "Node identity and HTTPS are ready."
	if restartRequired {
		message = "Node identity and HTTPS are ready to activate."
	}
	server.renderClusterMutation(writer, request, http.StatusOK, message, "")
}

func (server *Server) deleteCluster(writer http.ResponseWriter, request *http.Request) {
	if !server.clusterAvailable(writer, request) {
		return
	}
	state := server.cluster.Snapshot()
	if err := server.cluster.Delete(request.Context()); err != nil {
		server.logger.Warn("delete cluster", "cluster_id", state.ClusterID, "client", requestClientIP(request), "error", err)
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	server.logger.Info("cluster deleted", "cluster_id", state.ClusterID, "node_id", state.NodeID, "client", requestClientIP(request))
	server.recordControlPlaneAudit(request, "cluster.delete", fmt.Sprintf("deleted cluster %s", state.ClusterID))
	server.renderClusterMutation(writer, request, http.StatusOK, "Cluster configuration deleted", "")
}

func (server *Server) leaveCluster(writer http.ResponseWriter, request *http.Request) {
	if !server.clusterAvailable(writer, request) {
		return
	}
	state := server.cluster.Snapshot()
	if err := server.cluster.Leave(request.Context()); err != nil {
		server.logger.Warn("leave cluster", "cluster_id", state.ClusterID, "node_id", state.NodeID, "client", requestClientIP(request), "error", err)
		server.renderClusterUIFailure(writer, request, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writer.Header().Set("HX-Replace-Url", "/cluster")
	server.logger.Info("cluster replica left", "cluster_id", state.ClusterID, "node_id", state.NodeID, "client", requestClientIP(request))
	server.recordControlPlaneAudit(request, "cluster.leave", fmt.Sprintf("left cluster %s as replica %s", state.ClusterID, state.NodeID))
	server.renderClusterMutation(writer, request, http.StatusOK, "This server left the cluster and is now operating independently", "")
}

func (server *Server) createClusterEnrollmentToken(writer http.ResponseWriter, request *http.Request) {
	if !server.clusterAvailable(writer, request) {
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderClusterMutation(writer, request, http.StatusBadRequest, "", "Invalid enrollment token form")
		return
	}
	ttl, err := time.ParseDuration(firstNonEmpty(strings.TrimSpace(request.FormValue("ttl")), "15m"))
	if err != nil {
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", "Enter a valid token lifetime")
		return
	}
	token, err := server.cluster.CreateEnrollmentToken(request.Context(), ttl)
	if err != nil {
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	view := server.clusterView(request, "Enrollment token created", "")
	view.EnrollmentToken, view.EnrollmentExpiresAt = token.Token, token.ExpiresAt
	server.logger.Info("cluster enrollment token created", "expires_at", token.ExpiresAt, "trust_bundled", strings.HasPrefix(token.Token, "sable-enroll-v1."), "client", requestClientIP(request))
	server.recordControlPlaneAudit(request, "cluster.enrollment-token.create", fmt.Sprintf("created cluster enrollment token expiring %s", token.ExpiresAt.Format(time.RFC3339)))
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusCreated)
	if err := pages.ClusterContent(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render cluster enrollment token", "error", err)
	}
}

func (server *Server) joinCluster(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if !server.clusterAvailable(writer, request) {
		return
	}
	if server.clusterView(request, "", "").RestartRequired {
		server.renderClusterUIFailure(writer, request, http.StatusConflict, "Restart Sable to activate the saved node identity before joining a cluster")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderClusterUIFailure(writer, request, http.StatusBadRequest, "Invalid cluster join form")
		return
	}
	options := cluster.JoinOptions{
		PrimaryURL: strings.TrimSpace(request.FormValue("primary_url")),
		Token:      strings.TrimSpace(request.FormValue("token")), Addresses: formLines(request.FormValue("addresses")),
	}
	if err := server.cluster.Join(request.Context(), options); err != nil {
		server.logger.Warn("join cluster", "primary", options.PrimaryURL, "trust_bundled", strings.HasPrefix(options.Token, "sable-enroll-v1."), "client", requestClientIP(request), "error", err)
		server.renderClusterUIFailure(writer, request, http.StatusUnprocessableEntity, clusterJoinError(err))
		return
	}
	state := server.cluster.Snapshot()
	writer.Header().Set("HX-Replace-Url", "/cluster")
	server.logger.Info("cluster joined", "cluster_id", state.ClusterID, "node_id", state.NodeID, "primary", state.PrimaryID, "client", requestClientIP(request))
	server.recordControlPlaneAudit(request, "cluster.join", fmt.Sprintf("joined cluster %s as replica %s", state.ClusterID, state.NodeID))
	server.renderClusterMutation(writer, request, http.StatusOK, "Cluster joined; this node is synchronizing from the primary", "")
}

func (server *Server) promoteClusterNode(writer http.ResponseWriter, request *http.Request) {
	if !server.clusterAvailable(writer, request) {
		return
	}
	nodeID := strings.TrimSpace(request.PathValue("node"))
	before := server.cluster.Snapshot()
	plannedHandoff := before.LocalRole == cluster.RolePrimary && nodeID != before.NodeID
	if err := server.cluster.Promote(request.Context(), nodeID); err != nil {
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	if plannedHandoff {
		server.logger.Info("cluster primary handoff initiated", "node_id", nodeID, "client", requestClientIP(request))
		server.recordControlPlaneAudit(request, "cluster.node.handoff", fmt.Sprintf("handed primary role to replica %s", nodeID))
		server.renderClusterMutation(writer, request, http.StatusOK, "Primary role handed off; the replica will take over on its next synchronization", "")
		return
	}
	server.logger.Warn("cluster replica promoted for recovery", "node_id", nodeID, "client", requestClientIP(request))
	server.recordControlPlaneAudit(request, "cluster.node.promote", fmt.Sprintf("promoted local replica %s for recovery", nodeID))
	server.renderClusterMutation(writer, request, http.StatusOK, "This node is now the cluster primary", "")
}

func (server *Server) removeClusterNode(writer http.ResponseWriter, request *http.Request) {
	if !server.clusterAvailable(writer, request) {
		return
	}
	nodeID := strings.TrimSpace(request.PathValue("node"))
	if err := server.cluster.Remove(request.Context(), nodeID); err != nil {
		server.renderClusterMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	server.logger.Info("cluster replica removed", "node_id", nodeID, "client", requestClientIP(request))
	server.recordControlPlaneAudit(request, "cluster.node.remove", fmt.Sprintf("removed cluster replica %s", nodeID))
	server.renderClusterMutation(writer, request, http.StatusOK, "Cluster replica removed", "")
}

func (server *Server) clusterAPI(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if server.cluster == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "cluster service is unavailable"})
		return
	}
	writeJSON(writer, http.StatusOK, server.cluster.Snapshot())
}

func (server *Server) clusterNodeAPI(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if server.cluster == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "cluster service is unavailable"})
		return
	}
	for _, node := range server.cluster.Snapshot().Nodes {
		if node.ID == request.PathValue("node") {
			writeJSON(writer, http.StatusOK, node)
			return
		}
	}
	writeJSON(writer, http.StatusNotFound, map[string]string{"error": "cluster node was not found"})
}

func (server *Server) initializeClusterAPI(writer http.ResponseWriter, request *http.Request) {
	if server.cluster == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "cluster service is unavailable"})
		return
	}
	if server.clusterView(request, "", "").RestartRequired {
		writeJSON(writer, http.StatusConflict, map[string]string{"error": "restart Sable to activate the saved node identity before initializing a cluster"})
		return
	}
	if !server.cluster.Snapshot().NetworkReady {
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"error": "configure an HTTPS advertised URL before initializing a cluster"})
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	var input struct {
		Domain    string   `json:"domain"`
		Addresses []string `json:"addresses"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid cluster request"})
		return
	}
	if err := server.cluster.Initialize(request.Context(), input.Domain, input.Addresses); err != nil {
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusCreated, server.cluster.Snapshot())
}

func (server *Server) deleteClusterAPI(writer http.ResponseWriter, request *http.Request) {
	if server.cluster == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "cluster service is unavailable"})
		return
	}
	if err := server.cluster.Delete(request.Context()); err != nil {
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusOK, server.cluster.Snapshot())
}

func (server *Server) leaveClusterAPI(writer http.ResponseWriter, request *http.Request) {
	if server.cluster == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "cluster service is unavailable"})
		return
	}
	if err := server.cluster.Leave(request.Context()); err != nil {
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusOK, server.cluster.Snapshot())
}

func (server *Server) createClusterEnrollmentTokenAPI(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		TTL string `json:"ttl"`
	}
	if server.cluster == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "cluster service is unavailable"})
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid enrollment token request"})
		return
	}
	ttl, err := time.ParseDuration(firstNonEmpty(strings.TrimSpace(input.TTL), "15m"))
	if err != nil {
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"error": "ttl must be a Go duration such as 15m"})
		return
	}
	token, err := server.cluster.CreateEnrollmentToken(request.Context(), ttl)
	if err != nil {
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusCreated, token)
}

func (server *Server) enrollClusterNodeAPI(writer http.ResponseWriter, request *http.Request) {
	if server.cluster == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "cluster service is unavailable"})
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	var input cluster.JoinRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid cluster enrollment request"})
		return
	}
	configuration, err := server.cluster.Enroll(request.Context(), input)
	if err != nil {
		server.logger.Warn("enroll cluster replica", "node_id", input.NodeID, "client", requestClientIP(request), "error", err)
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	server.logger.Info("cluster replica enrolled", "node_id", input.NodeID, "client", requestClientIP(request))
	writeJSON(writer, http.StatusCreated, configuration)
}

func (server *Server) clusterSyncAPI(writer http.ResponseWriter, request *http.Request) {
	if server.cluster == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "cluster service is unavailable"})
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	var heartbeat cluster.Heartbeat
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&heartbeat); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid cluster synchronization request"})
		return
	}
	configuration, err := server.cluster.Synchronize(request.Context(), heartbeat, request.Header.Get("X-Sable-Cluster-Signature"))
	if err != nil {
		if errors.Is(err, cluster.ErrNodeRemoved) {
			writeJSON(writer, http.StatusGone, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusOK, configuration)
}

func (server *Server) promoteClusterNodeAPI(writer http.ResponseWriter, request *http.Request) {
	if server.cluster == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "cluster service is unavailable"})
		return
	}
	if err := server.cluster.Promote(request.Context(), strings.TrimSpace(request.PathValue("node"))); err != nil {
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusOK, server.cluster.Snapshot())
}

func (server *Server) removeClusterNodeAPI(writer http.ResponseWriter, request *http.Request) {
	if server.cluster == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "cluster service is unavailable"})
		return
	}
	if err := server.cluster.Remove(request.Context(), strings.TrimSpace(request.PathValue("node"))); err != nil {
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusOK, server.cluster.Snapshot())
}

func (server *Server) clusterAvailable(writer http.ResponseWriter, request *http.Request) bool {
	if server.cluster != nil {
		return true
	}
	server.renderClusterMutation(writer, request, http.StatusServiceUnavailable, "", "Cluster service is unavailable")
	return false
}

func (server *Server) renderClusterMutation(writer http.ResponseWriter, request *http.Request, status int, message, errorMessage string) {
	writer.WriteHeader(status)
	if err := pages.ClusterContent(server.clusterView(request, message, errorMessage)).Render(request.Context(), writer); err != nil {
		server.logger.Error("render cluster mutation", "error", err)
	}
}

// HTMX swaps successful responses by default but intentionally ignores 4xx
// bodies. A rejected cluster action is still a successful UI round-trip:
// render its validation result with 200 so the page can show it. Direct HTTP
// clients continue receiving the original error status.
func (server *Server) renderClusterUIFailure(writer http.ResponseWriter, request *http.Request, status int, message string) {
	if strings.EqualFold(strings.TrimSpace(request.Header.Get("HX-Request")), "true") {
		status = http.StatusOK
	}
	server.renderClusterMutation(writer, request, status, "", message)
}

func (server *Server) clusterView(request *http.Request, message, errorMessage string) pages.ClusterPageView {
	view := pages.ClusterPageView{Console: server.consoleView(request), Message: message, Error: errorMessage, OnboardingMode: clusterWorkflow(request), OnboardingStep: 1}
	if request != nil {
		switch request.URL.Query().Get("configure") {
		case "node":
			view.ConfigureNode = true
		case "https":
			view.ConfigureNode = true
			view.OnboardingStep = 2
		}
	}
	if server.cluster == nil {
		view.Error = firstNonEmpty(errorMessage, "Cluster service is unavailable")
		return view
	}
	state := server.cluster.Snapshot()
	desired := server.config.Current().Config.Cluster
	active := server.cluster.LocalConfiguration()
	baseDirectory := "."
	if located, ok := server.config.(interface{ BaseDirectory() string }); ok {
		baseDirectory = located.BaseDirectory()
	}
	view.DataDirectory = desired.DataDirectory
	view.NodeName = firstNonEmpty(desired.NodeName, active.NodeName)
	view.AdvertiseURL = firstNonEmpty(desired.AdvertiseURL, active.AdvertiseURL)
	configuration := server.config.Current().Config
	view.CertificateSource = clusterCertificateSource(configuration)
	view.HTTPSListen = configuration.Server.HTTPSListen
	view.CertificateMode = configuration.EncryptedDNS.CertificateMode
	view.CertificateFile = configuration.EncryptedDNS.CertificateFile
	view.PrivateKeyFile = configuration.EncryptedDNS.PrivateKeyFile
	view.ACMEEmail = configuration.EncryptedDNS.ACME.Email
	view.ACMEDomains = strings.Join(configuration.EncryptedDNS.ACME.Domains, "\n")
	view.ACMEDirectoryURL = configuration.EncryptedDNS.ACME.DirectoryURL
	view.ACMEDNSProvider = configuration.EncryptedDNS.ACME.DNSProvider
	view.ACMEDNSZone = configuration.EncryptedDNS.ACME.DNSZone
	view.ACMEStorageDirectory = configuration.EncryptedDNS.ACME.StorageDirectory
	view.ACMERenewBefore = configuration.EncryptedDNS.ACME.RenewBefore.String()
	if server.certificates != nil {
		view.ACMECredentialsConfigured = server.certificates.Status(request.Context(), configuration.EncryptedDNS).CredentialsConfigured
	}
	if view.OnboardingMode != "" && request.Form != nil {
		if request.FormValue("wizard_step") == "https" {
			view.ConfigureNode = true
			view.OnboardingStep = 2
		}
		view.NodeName = firstNonEmpty(strings.TrimSpace(request.FormValue("node_name")), view.NodeName)
		view.AdvertiseURL = firstNonEmpty(strings.TrimSpace(request.FormValue("advertise_url")), view.AdvertiseURL)
		view.DataDirectory = firstNonEmpty(strings.TrimSpace(request.FormValue("data_dir")), view.DataDirectory)
		view.CertificateSource = firstNonEmpty(strings.TrimSpace(request.FormValue("certificate_source")), view.CertificateSource)
		view.HTTPSListen = firstNonEmpty(strings.TrimSpace(request.FormValue("https_listen")), strings.TrimSpace(request.FormValue("import_https_listen")), view.HTTPSListen)
		view.ACMEEmail = firstNonEmpty(strings.TrimSpace(request.FormValue("acme_email")), view.ACMEEmail)
		view.ACMEDomains = firstNonEmpty(strings.TrimSpace(request.FormValue("acme_domains")), view.ACMEDomains)
		view.ACMEDNSProvider = firstNonEmpty(strings.TrimSpace(request.FormValue("acme_dns_provider")), view.ACMEDNSProvider)
		view.ACMEDNSZone = firstNonEmpty(strings.TrimSpace(request.FormValue("acme_dns_zone")), view.ACMEDNSZone)
		view.ACMEStorageDirectory = firstNonEmpty(strings.TrimSpace(request.FormValue("acme_storage_dir")), view.ACMEStorageDirectory)
		if view.OnboardingMode == "join" {
			view.JoinPrimaryURL = strings.TrimSpace(request.FormValue("primary_url"))
			view.JoinToken = strings.TrimSpace(request.FormValue("token"))
			view.JoinAddresses = strings.TrimSpace(request.FormValue("addresses"))
		}
	}
	view.RestartRequired = active.DataDirectory != server.config.Current().Config.ClusterDataPath(baseDirectory) || active.NodeName != view.NodeName || active.AdvertiseURL != view.AdvertiseURL || active.HTTPSListen != configuration.Server.HTTPSListen || active.TrustAnchorFile != configuration.ClusterTrustAnchorPath(baseDirectory)
	view.Initialized, view.NetworkReady = state.Initialized, state.NetworkReady
	view.NodeID, view.ClusterID, view.ClusterDomain = state.NodeID, state.ClusterID, state.ClusterDomain
	view.Generation, view.Mode, view.LocalRole = state.Generation, state.Mode, clusterRoleLabel(state.LocalRole)
	view.PrimaryID, view.PrimaryURL, view.ObservedAt = state.PrimaryID, state.PrimaryURL, state.ObservedAt
	view.Connected, view.Synchronized = state.Connected, state.Synchronized
	view.Nodes = make([]pages.ClusterNodeView, 0, len(state.Nodes))
	for _, node := range state.Nodes {
		uptime := ""
		if !node.UpSince.IsZero() {
			uptime = time.Since(node.UpSince).Truncate(time.Second).String()
			if strings.HasPrefix(uptime, "-") {
				uptime = "0s"
			}
		}
		view.Nodes = append(view.Nodes, pages.ClusterNodeView{
			ID: node.ID, Name: node.Name, AdvertiseURL: node.AdvertiseURL,
			Addresses: append([]string(nil), node.Addresses...), Role: clusterRoleLabel(node.Role),
			State: node.State, Version: node.Version, UpSince: uptime, SyncState: node.SyncState,
			CurrentGeneration: node.CurrentGeneration, AppliedGeneration: node.AppliedGeneration, Lag: node.Lag,
			LastContact: clusterRelativeTime(node.LastContact, state.ObservedAt), LastSync: clusterRelativeTime(node.LastSync, state.ObservedAt),
			LastContactAt: clusterTimestamp(node.LastContact, view.Console.TimeDisplay), LastSyncAt: clusterTimestamp(node.LastSync, view.Console.TimeDisplay),
			Local: node.ID == state.NodeID,
		})
	}
	return view
}

func clusterJoinError(err error) string {
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		host := strings.TrimSpace(dnsError.Name)
		if host == "" {
			host = "the primary host"
		}
		return fmt.Sprintf("Could not resolve primary host %q. Check the Primary URL and try again.", host)
	}
	return err.Error()
}

func clusterCertificateSource(configuration config.Config) string {
	if configuration.Cluster.TrustAnchorFile != "" {
		return "generated"
	}
	if configuration.EncryptedDNS.CertificateMode == "acme" {
		return "acme"
	}
	certificate := strings.ReplaceAll(configuration.EncryptedDNS.CertificateFile, "\\", "/")
	if certificate != "" {
		return "import"
	}
	return "external"
}

func clusterWorkflow(request *http.Request) string {
	if request == nil {
		return ""
	}
	value := request.URL.Query().Get("onboarding")
	if value == "" {
		value = request.FormValue("workflow")
	}
	if value == "primary" || value == "join" {
		return value
	}
	return ""
}

func normalizeClusterWorkflow(value string) string {
	if strings.TrimSpace(value) == "join" {
		return "join"
	}
	return "primary"
}

func clusterRoleLabel(role string) string {
	switch role {
	case cluster.RolePrimary:
		return "Primary"
	case cluster.RoleReplica:
		return "Replica"
	default:
		return firstNonEmpty(role, "Unknown")
	}
}

func clusterRelativeTime(value, observedAt time.Time) string {
	if value.IsZero() {
		return "Never"
	}
	age := observedAt.Sub(value)
	if age < 0 {
		age = 0
	}
	switch {
	case age < 5*time.Second:
		return "Just now"
	case age < time.Minute:
		return fmt.Sprintf("%ds ago", int(age.Seconds()))
	case age < time.Hour:
		return fmt.Sprintf("%dm ago", int(age.Minutes()))
	case age < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(age.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(age.Hours()/24))
	}
}

func clusterTimestamp(value time.Time, display pages.TimeDisplay) string {
	if value.IsZero() {
		return "No successful contact"
	}
	return pages.FormatShortDateTime(value, display, true)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
