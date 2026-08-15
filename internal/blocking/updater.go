package blocking

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const maximumDownloadedListBytes = 128 << 20

type RemoteSource struct {
	Name string
	URL  string
	Path string
}

type UpdateStatus struct {
	LastUpdate time.Time
	NextUpdate time.Time
	Updating   bool
}

type stagedBlockListFile struct {
	temporary string
	target    string
	backup    string
}

type Updater struct {
	baseDirectory string
	client        *http.Client
	updateMu      sync.Mutex
	lastUpdate    atomic.Int64
	nextUpdate    atomic.Int64
	updating      atomic.Bool
	wake          chan struct{}
}

func NewUpdater(baseDirectory string) *Updater {
	return &Updater{
		baseDirectory: baseDirectory,
		client: &http.Client{
			Timeout: 45 * time.Second,
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				return nil
			},
		},
		wake: make(chan struct{}, 1),
	}
}

func (updater *Updater) Status() UpdateStatus {
	return UpdateStatus{
		LastUpdate: unixTime(updater.lastUpdate.Load()),
		NextUpdate: unixTime(updater.nextUpdate.Load()),
		Updating:   updater.updating.Load(),
	}
}

func (updater *Updater) Schedule(next time.Time) {
	updater.SetNext(next)
	select {
	case updater.wake <- struct{}{}:
	default:
	}
}

func (updater *Updater) SetNext(next time.Time) {
	if next.IsZero() {
		updater.nextUpdate.Store(0)
	} else {
		updater.nextUpdate.Store(next.Unix())
	}
}

func (updater *Updater) Wake() <-chan struct{} { return updater.wake }

func (updater *Updater) Download(ctx context.Context, source RemoteSource) error {
	updater.updateMu.Lock()
	defer updater.updateMu.Unlock()
	updater.updating.Store(true)
	defer updater.updating.Store(false)

	temporary, target, err := updater.downloadTemporary(ctx, source)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, target); err != nil {
		return fmt.Errorf("activate block list %q: %w", source.Name, err)
	}
	updater.lastUpdate.Store(time.Now().Unix())
	return nil
}

func (updater *Updater) Refresh(ctx context.Context, sources []RemoteSource, activate func(context.Context) error) error {
	updater.updateMu.Lock()
	defer updater.updateMu.Unlock()
	updater.updating.Store(true)
	defer updater.updating.Store(false)

	staged := make([]stagedBlockListFile, 0, len(sources))
	defer func() {
		for _, file := range staged {
			_ = os.Remove(file.temporary)
			_ = os.Remove(file.backup)
		}
	}()
	for _, source := range sources {
		temporary, target, err := updater.downloadTemporary(ctx, source)
		if err != nil {
			return err
		}
		staged = append(staged, stagedBlockListFile{temporary: temporary, target: target})
	}
	for index := range staged {
		file := &staged[index]
		if _, err := os.Stat(file.target); err == nil {
			backup, err := os.CreateTemp(filepath.Dir(file.target), ".sable-blocklist-backup-*")
			if err != nil {
				return fmt.Errorf("prepare block list rollback: %w", err)
			}
			file.backup = backup.Name()
			if err := backup.Close(); err != nil {
				return fmt.Errorf("prepare block list rollback: %w", err)
			}
			if err := os.Remove(file.backup); err != nil {
				return fmt.Errorf("prepare block list rollback: %w", err)
			}
			if err := os.Rename(file.target, file.backup); err != nil {
				return fmt.Errorf("preserve block list: %w", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect block list: %w", err)
		}
		if err := os.Rename(file.temporary, file.target); err != nil {
			updater.restore(staged[:index+1])
			return fmt.Errorf("activate downloaded block list: %w", err)
		}
		file.temporary = ""
	}
	if err := activate(ctx); err != nil {
		updater.restore(staged)
		return fmt.Errorf("activate updated block lists: %w", err)
	}
	updater.lastUpdate.Store(time.Now().Unix())
	return nil
}

func (updater *Updater) downloadTemporary(ctx context.Context, source RemoteSource) (string, string, error) {
	if err := ValidateURL(source.URL); err != nil {
		return "", "", fmt.Errorf("block list %q URL: %w", source.Name, err)
	}
	target := source.Path
	if !filepath.IsAbs(target) {
		target = filepath.Join(updater.baseDirectory, target)
	}
	target = filepath.Clean(target)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", "", fmt.Errorf("create block list directory: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return "", "", fmt.Errorf("build block list request: %w", err)
	}
	request.Header.Set("User-Agent", "Sable DNS block-list updater")
	response, err := updater.client.Do(request)
	if err != nil {
		return "", "", fmt.Errorf("download block list %q: %w", source.Name, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", "", fmt.Errorf("download block list %q: server returned %s", source.Name, response.Status)
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".sable-blocklist-download-*")
	if err != nil {
		return "", "", fmt.Errorf("create block list download: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	written, err := io.Copy(temporary, io.LimitReader(response.Body, maximumDownloadedListBytes+1))
	if err != nil {
		return "", "", fmt.Errorf("write block list %q: %w", source.Name, err)
	}
	if written > maximumDownloadedListBytes {
		return "", "", fmt.Errorf("block list %q exceeds the %d MiB limit", source.Name, maximumDownloadedListBytes>>20)
	}
	if err := temporary.Chmod(0o644); err != nil {
		return "", "", fmt.Errorf("set block list permissions: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return "", "", fmt.Errorf("sync block list: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", "", fmt.Errorf("close block list: %w", err)
	}
	removeTemporary = false
	return temporaryPath, target, nil
}

func (updater *Updater) restore(staged []stagedBlockListFile) {
	for index := len(staged) - 1; index >= 0; index-- {
		file := staged[index]
		_ = os.Remove(file.target)
		if file.backup != "" {
			_ = os.Rename(file.backup, file.target)
		}
	}
}

func unixTime(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(value, 0)
}
