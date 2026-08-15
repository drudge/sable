package blocking

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

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
