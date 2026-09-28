package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestThirdPartyLicenseRendersOneNoticeWhenItsRowOpens(t *testing.T) {
	t.Parallel()
	server := updateTestServer(t, &testUpdateController{})

	response := serveRequest(server, http.MethodGet, "/ui/about/license?name="+url.QueryEscape("github.com/miekg/dns"))
	if response.Code != http.StatusOK {
		t.Fatalf("license status = %d", response.Code)
	}
	body := response.Body.String()
	for _, expected := range []string{
		"Redistribution and use in source and binary forms",
		`href="https://pkg.go.dev/github.com/miekg/dns"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("license is missing %q", expected)
		}
	}

	// Go's license and its patent grant arrive together, each under its name.
	goLicense := serveRequest(server, http.MethodGet, "/ui/about/license?name=Go").Body.String()
	for _, expected := range []string{"<h4>LICENSE</h4>", "<h4>PATENTS</h4>", "The Go Authors"} {
		if !strings.Contains(goLicense, expected) {
			t.Errorf("Go's license is missing %q", expected)
		}
	}

	if missing := serveRequest(server, http.MethodGet, "/ui/about/license?name=not-a-module"); missing.Code != http.StatusNotFound {
		t.Errorf("unknown software status = %d, want 404", missing.Code)
	}
}
