package blocking

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingDownloadTransport struct{ err error }

func (transport failingDownloadTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, transport.err
}

func TestUpdaterExplainsDNSFailuresWithoutReplacingCachedLists(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name string
		err  error
		hint string
	}{
		{"docker", &net.DNSError{Name: "big.oisd.nl", Server: "127.0.0.11:53", Err: "server misbehaving", IsTemporary: true}, "configure working DNS servers for the container using --dns or Compose dns"},
		{"host", &net.DNSError{Name: "big.oisd.nl", Server: "192.0.2.53:53", Err: "server misbehaving"}, "check the host's DNS settings"},
		{"missing hostname", &net.DNSError{Name: "missing.example", Err: "no such host", IsNotFound: true}, "that the list hostname is correct"},
		{"connection", errors.New("connection refused"), ""},
		{"canceled", context.Canceled, ""},
		{"deadline", context.DeadlineExceeded, ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			source := RemoteSource{Name: "OISD Big", URL: "https://big.oisd.nl/", Path: "cached.txt"}
			cached := []byte("ads.example\n")
			if err := os.WriteFile(filepath.Join(root, source.Path), cached, 0o644); err != nil {
				t.Fatal(err)
			}
			updater := NewUpdater(root)
			updater.client.Transport = failingDownloadTransport{testCase.err}
			err := updater.Download(context.Background(), source)
			if !errors.Is(err, testCase.err) {
				t.Fatalf("Download() = %v, want underlying error %v preserved", err, testCase.err)
			}
			if testCase.hint != "" && !strings.Contains(err.Error(), testCase.hint) {
				t.Fatalf("Download() = %v, want actionable hint %q", err, testCase.hint)
			}
			if testCase.hint == "" && strings.Contains(err.Error(), "DNS") {
				t.Fatalf("Download() misdiagnosed a non-DNS failure: %v", err)
			}
			contents, readErr := os.ReadFile(filepath.Join(root, source.Path))
			if readErr != nil || string(contents) != string(cached) {
				t.Fatalf("cached list = %q, %v; want previous contents preserved", contents, readErr)
			}
			status := updater.Status()
			if status.Degraded != 1 || len(status.Sources) != 1 || status.Sources[0].LastError != err.Error() {
				t.Fatalf("download failure was not recorded for update diagnostics: %+v", status)
			}
		})
	}
}

func TestUpdaterDownloadsRemoteList(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("0.0.0.0 ads.example\n"))
	}))
	defer server.Close()

	root := t.TempDir()
	updater := NewUpdater(root)
	source := RemoteSource{Name: "test", URL: server.URL + "/hosts", Path: "data/lists/test.txt"}
	if err := updater.Download(context.Background(), source); err != nil {
		t.Fatalf("Download() error = %v", err)
	}
	contents, err := os.ReadFile(filepath.Join(root, source.Path))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(contents) != "0.0.0.0 ads.example\n" {
		t.Fatalf("downloaded contents = %q", contents)
	}
	if updater.Status().LastUpdate.IsZero() || updater.Status().Updating {
		t.Fatalf("update status = %+v", updater.Status())
	}
}

func TestUpdaterRestoresEveryListWhenActivationFails(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("new " + request.URL.Path))
	}))
	defer server.Close()

	root := t.TempDir()
	sources := []RemoteSource{
		{Name: "one", URL: server.URL + "/one", Path: "lists/one.txt"},
		{Name: "two", URL: server.URL + "/two", Path: "lists/two.txt"},
	}
	for _, source := range sources {
		path := filepath.Join(root, source.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("original "+source.Name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	updater := NewUpdater(root)
	err := updater.Refresh(context.Background(), sources, func(context.Context) error {
		return errors.New("compile rejected update")
	})
	if err == nil {
		t.Fatal("Refresh() error = nil")
	}
	for _, source := range sources {
		contents, readErr := os.ReadFile(filepath.Join(root, source.Path))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(contents) != "original "+source.Name {
			t.Fatalf("restored %s contents = %q", source.Name, contents)
		}
	}
	if !updater.Status().LastUpdate.IsZero() || updater.Status().Updating {
		t.Fatalf("update status after rollback = %+v", updater.Status())
	}
}
