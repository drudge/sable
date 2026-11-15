package web

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// dhcpImportConsoleRequest posts the Import Reservations dialog the way the
// browser does: multipart, with the export pasted or uploaded as a file.
func dhcpImportConsoleRequest(t *testing.T, server *Server, fields map[string]string, file string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for name, value := range fields {
		if err := form.WriteField(name, value); err != nil {
			t.Fatal(err)
		}
	}
	if file != "" {
		part, err := form.CreateFormFile("file", "dnsmasq.conf")
		if err != nil {
			t.Fatal(err)
		}
		part.Write([]byte(file))
	}
	form.Close()
	request := httptest.NewRequest(http.MethodPost, "/ui/dhcp/reservations/import", &body)
	request.Header.Set("HX-Request", "true")
	request.Header.Set("Content-Type", form.FormDataContentType())
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

func TestDHCPConsoleImportPreviewsThenImports(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPConsoleServer(t)
	export := "dhcp-host=00:11:22:33:44:02,192.0.2.11,nas.lan\ndhcp-host=00:11:22:33:44:04,198.51.100.4,away\n"

	revision := configuration.snapshot.Revision
	response := dhcpImportConsoleRequest(t, server, map[string]string{"scope": "lan"}, export)
	body := response.Body.String()
	if response.Code != http.StatusOK || configuration.snapshot.Revision != revision {
		t.Fatalf("preview = %d, saved %v: %s", response.Code, configuration.snapshot.Revision != revision, body)
	}
	for _, want := range []string{"00:11:22:33:44:02", "192.0.2.11", "Line 2", "Import 1 Reservation", `name="step" value="apply"`, "dhcp-host=00:11:22:33:44:02"} {
		if !strings.Contains(body, want) {
			t.Errorf("preview lacks %q:\n%s", want, body)
		}
	}

	response = dhcpImportConsoleRequest(t, server, map[string]string{"scope": "lan", "step": "apply", "import_text": export}, "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Imported 1 reservation") {
		t.Fatalf("apply = %d: %s", response.Code, response.Body)
	}
	reservations := configuration.snapshot.Config.DHCP.Scopes[0].Reservations
	if len(reservations) != 2 || reservations[1].MAC != "00:11:22:33:44:02" || reservations[1].Name != "nas" {
		t.Fatalf("reservations = %+v; want nas added", reservations)
	}
}

func TestDHCPConsoleImportRefusesWhatItCantRead(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPConsoleServer(t)
	revision := configuration.snapshot.Revision
	for name, fields := range map[string]map[string]string{
		"nothing":        {"scope": "lan"},
		"unknown format": {"scope": "lan", "import_text": `{"zones":[]}`},
		"unknown scope":  {"scope": "guest", "import_text": "dhcp-host=00:11:22:33:44:02,192.0.2.11"},
	} {
		response := dhcpImportConsoleRequest(t, server, fields, "")
		if response.Code < 400 || response.Header().Get("HX-Retarget") != "#dhcp-import-notice" {
			t.Errorf("%s = %d retarget %q; want a refusal in the dialog's notice", name, response.Code, response.Header().Get("HX-Retarget"))
		}
	}
	if configuration.snapshot.Revision != revision {
		t.Fatal("a refused import saved the settings")
	}
}
