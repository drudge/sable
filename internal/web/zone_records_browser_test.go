//go:build browser

package web

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/a-h/templ"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	webassets "github.com/drudge/sable/internal/web/assets"
	"github.com/drudge/sable/internal/web/pages"
	zonemodel "github.com/drudge/sable/internal/zone"
)

// Delete Record in the record dialog asks first and then removes the record,
// instead of saving the form as an update.
func TestBrowserZoneRecordDelete(t *testing.T) {
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	configuration.zoneSnapshot.Zones = []zonemodel.Zone{{
		Name: "example.test", Type: "primary", Records: []zonemodel.Record{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 2026100601 3600 600 1209600 300"},
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.10"},
			{Name: "mail", Type: "A", TTL: 300, Value: "192.0.2.20"},
		},
	}}
	app, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration,
		configuration.zoneStore(),
		"sqlite",
		testQueryLog{},
		testQueryLog{},
		func(context.Context) error { return nil },
		nil,
		false,
		false,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/zone-records.cjs", server.URL)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser zone records: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
	records := configuration.zoneSnapshot.Zones[0].Records
	if slices.ContainsFunc(records, func(record zonemodel.Record) bool { return record.Name == "www" }) ||
		!slices.ContainsFunc(records, func(record zonemodel.Record) bool { return record.Name == "mail" }) {
		t.Fatalf("records after delete = %+v", records)
	}
}

// Roll ZSK, Roll KSK, and Confirm Parent DS sit inside the DNSSEC settings
// form, and each posts to its own endpoint with its own value instead of
// saving the settings.
func TestBrowserZoneDNSSECActions(t *testing.T) {
	zone := pages.ZoneView{Name: "example.test", Type: "primary", DNSSEC: true, DNSSECKeys: []pages.DNSSECKeyView{
		{Role: "KSK", State: "ready", KeyTag: 12345, DS: "example.test. IN DS 12345 15 2 ABCDEF"},
		{Role: "ZSK", State: "active", KeyTag: 23456},
	}}
	mux := http.NewServeMux()
	mux.Handle("/assets/", webassets.Handler())
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		content := templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := io.WriteString(w, `<div id="zones-content">`); err != nil {
				return err
			}
			if err := pages.ZoneSigningDNSSECDialog(zone, "dnssec-dialog").Render(ctx, w); err != nil {
				return err
			}
			_, err := io.WriteString(w, `</div>`)
			return err
		})
		_ = pages.AppDocument(pages.DashboardView{CSRFToken: "fixture-csrf", CanZones: true}, "Zones", "zones", content).Render(r.Context(), w)
	})
	reply := func(w http.ResponseWriter, r *http.Request, field string) {
		if err := r.ParseForm(); err != nil || r.Form.Get("zone") != "example.test" {
			http.Error(w, "incorrect DNSSEC request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div id="zones-content"><p data-fixture-result>%s %s=%s</p></div>`, r.URL.Path, field, r.Form.Get(field))
	}
	mux.HandleFunc("POST /ui/zones/dnssec/rollover", func(w http.ResponseWriter, r *http.Request) { reply(w, r, "role") })
	mux.HandleFunc("POST /ui/zones/dnssec/confirm-ds", func(w http.ResponseWriter, r *http.Request) { reply(w, r, "key_tag") })
	mux.HandleFunc("POST /ui/zones/dnssec", func(w http.ResponseWriter, r *http.Request) { reply(w, r, "enabled") })
	server := httptest.NewServer(secureHeaders(mux, false))
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/zone-dnssec-actions.cjs", server.URL)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser zone DNSSEC actions: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
