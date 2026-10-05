package web

import (
	"fmt"
	"net/http"

	"github.com/drudge/sable/internal/notices"
	"github.com/drudge/sable/internal/version"
	"github.com/drudge/sable/internal/web/pages"
)

func (server *Server) aboutPage(writer http.ResponseWriter, request *http.Request) {
	current := version.Current()
	view := pages.AboutPageView{
		Console:      server.consoleView(request),
		Commit:       current.Commit,
		BuiltAt:      current.BuiltAt,
		GoVersion:    current.Go,
		ScrapeConfig: prometheusScrapeConfig(request),
		Update:       server.updateView(request, server.updateStatus()),
	}
	if err := pages.AboutPage(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render about page", "error", err)
	}
}

// thirdPartyLicense renders the license files of one piece of third-party
// software, for its row in About's Third-Party Licenses.
func (server *Server) thirdPartyLicense(writer http.ResponseWriter, request *http.Request) {
	notice, found := notices.Named(request.URL.Query().Get("name"))
	if !found {
		http.NotFound(writer, request)
		return
	}
	if err := pages.ThirdPartyLicenseText(notice).Render(request.Context(), writer); err != nil {
		server.logger.Error("render third-party license", "error", err)
	}
}

func prometheusScrapeConfig(request *http.Request) string {
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf(`scrape_configs:
  - job_name: "sable-dns"
    metrics_path: "/metrics"
    scheme: %q
    authorization:
      credentials: "YOUR_API_TOKEN"
    static_configs:
      - targets: [%q]`, scheme, request.Host)
}
