package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

func Watch(
	ctx context.Context,
	path string,
	debounce time.Duration,
	logger *slog.Logger,
	reload func(context.Context) error,
	dependencies func() []string,
) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create configuration watcher: %w", err)
	}
	defer watcher.Close()

	watchedDirectories := make(map[string]struct{})
	if err := addWatchDirectories(watcher, watchedFiles(path, dependencies), watchedDirectories); err != nil {
		return err
	}

	var timer *time.Timer
	var timerChannel <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		case event, open := <-watcher.Events:
			if !open {
				return errors.New("configuration watcher event channel closed")
			}
			if !isConfigurationEvent(event, watchedFiles(path, dependencies)) {
				continue
			}
			if timer == nil {
				timer = time.NewTimer(debounce)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(debounce)
			}
			timerChannel = timer.C
		case <-timerChannel:
			timerChannel = nil
			if err := reload(ctx); err != nil {
				logger.Error("configuration reload rejected", "error", err)
				continue
			}
			logger.Info("configuration reloaded")
			if err := addWatchDirectories(watcher, watchedFiles(path, dependencies), watchedDirectories); err != nil {
				logger.Error("watch reloaded configuration dependencies", "error", err)
			}
		case err, open := <-watcher.Errors:
			if !open {
				return errors.New("configuration watcher error channel closed")
			}
			logger.Error("configuration watcher error", "error", err)
		}
	}
}

func isConfigurationEvent(event fsnotify.Event, paths map[string]struct{}) bool {
	if _, watched := paths[filepath.Clean(event.Name)]; !watched {
		return false
	}
	return event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename)
}

func watchedFiles(path string, dependencies func() []string) map[string]struct{} {
	paths := map[string]struct{}{filepath.Clean(path): {}}
	if dependencies == nil {
		return paths
	}
	for _, dependency := range dependencies() {
		paths[filepath.Clean(dependency)] = struct{}{}
	}
	return paths
}

func addWatchDirectories(
	watcher *fsnotify.Watcher,
	paths map[string]struct{},
	watchedDirectories map[string]struct{},
) error {
	for path := range paths {
		directory := filepath.Dir(path)
		if _, watched := watchedDirectories[directory]; watched {
			continue
		}
		if err := watcher.Add(directory); err != nil {
			return fmt.Errorf("watch configuration dependency directory %s: %w", directory, err)
		}
		watchedDirectories[directory] = struct{}{}
	}
	return nil
}
