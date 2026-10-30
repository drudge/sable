package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
)

type memoryAbuseCHKeys struct{ key string }

func (store *memoryAbuseCHKeys) Get(context.Context) (string, bool) {
	return store.key, store.key != ""
}
func (store *memoryAbuseCHKeys) Lookup(context.Context) string { return store.key }
func (store *memoryAbuseCHKeys) Clear(context.Context) error   { store.key = ""; return nil }
func (store *memoryAbuseCHKeys) Put(_ context.Context, key string) error {
	if key == "" {
		return errors.New("an abuse.ch Auth-Key is required")
	}
	store.key = key
	return nil
}

func TestSavingAnAbuseCHKeyMovesURLhausAndRemovingItMovesItBack(t *testing.T) {
	t.Parallel()

	initial := config.Defaults()
	initial.Blocking.Lists = []config.BlockList{
		{Name: "URLhaus Malicious URLs", URL: blockcompiler.URLhausURL, Path: "data/blocklists/urlhaus.txt", Format: "auto"},
		{Name: "OISD Big", URL: "https://big.oisd.nl/", Path: "data/blocklists/oisd.txt", Format: "auto"},
	}
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: initial, Revision: 1}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration, configuration.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	keys := &memoryAbuseCHKeys{}
	server.SetAbuseCHKeyStore(keys)

	save := func(extra url.Values) string {
		t.Helper()
		form := url.Values{
			"query_log_retention": {"2w"}, "server_log_retention": {"3mo"}, "statistics_retention": {"2y"},
			"blocking_update_hours": {"24"}, "blocking_response_type": {"nxdomain"}, "blocking_response_ttl": {"60"},
			"cache_minimum_ttl": {"10"}, "cache_maximum_ttl": {"604800"}, "cache_negative_ttl": {"300"}, "cache_failure_ttl": {"10"},
			"cache_stale_ttl": {"259200"}, "cache_stale_answer_ttl": {"30"}, "cache_stale_reset_ttl": {"30"},
			"cache_stale_max_wait_ms": {"1800"}, "cache_prefetch_minimum_ttl": {"2"}, "cache_prefetch_trigger_ttl": {"9"},
			"cache_prefetch_sample_interval": {"5m"}, "cache_prefetch_hits_per_hour": {"30"},
			"dns_listen": {"127.0.0.1:5353"}, "forwarders": {"1.1.1.1:53"}, "resolver_timeout": {"2s"},
			"resolver_retries": {"2"}, "resolver_retry_timeout": {"800ms"}, "cache_size": {"2048"},
			"max_concurrent": {"512"}, "max_concurrent_per_client": {"16"}, "recursion": {"allow"}, "resolver_mode": {"recursive"},
			"settings_tab": {"blocking"},
		}
		for name, values := range extra {
			form[name] = values
		}
		request := httptest.NewRequest(http.MethodPost, "/ui/settings", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("settings update = %d %s", response.Code, response.Body.String())
		}
		return response.Body.String()
	}
	list := func(name string) config.BlockList {
		for _, list := range configuration.Current().Config.Blocking.Lists {
			if list.Name == name {
				return list
			}
		}
		t.Fatalf("no list named %q", name)
		return config.BlockList{}
	}
	urlhaus := func() string { return list("URLhaus Malicious URLs").URL }

	body := save(url.Values{"blocking_abusech_key": {"  my-key  "}})
	if keys.key != "my-key" || strings.Contains(body, "my-key") {
		t.Fatalf("stored key = %q, or the page echoed it back", keys.key)
	}
	if urlhaus() != blockcompiler.URLhausKeyedURL || list("OISD Big").URL != "https://big.oisd.nl/" {
		t.Fatalf("lists after saving a key = %+v", configuration.Current().Config.Blocking.Lists)
	}
	if list("URLhaus Malicious URLs").Path != "data/blocklists/urlhaus.txt" {
		t.Fatal("URLhaus lost its cached copy when it moved")
	}

	save(nil)
	if keys.key != "my-key" || urlhaus() != blockcompiler.URLhausKeyedURL {
		t.Fatalf("a save without the key field changed it: key=%q URLhaus=%s", keys.key, urlhaus())
	}

	save(url.Values{"blocking_abusech_key_remove": {"true"}})
	if keys.key != "" || urlhaus() != blockcompiler.URLhausURL {
		t.Fatalf("after removing the key: key=%q URLhaus=%s", keys.key, urlhaus())
	}
}
