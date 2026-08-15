package config

import (
	"testing"

	"github.com/fsnotify/fsnotify"
)

func TestConfigurationEventIncludesManagedDependency(t *testing.T) {
	t.Parallel()

	paths := watchedFiles("/etc/sable/sable.toml", func() []string {
		return []string{"/etc/sable/lists/ads.txt"}
	})
	event := fsnotify.Event{Name: "/etc/sable/lists/ads.txt", Op: fsnotify.Write}
	if !isConfigurationEvent(event, paths) {
		t.Fatal("isConfigurationEvent() = false for managed block list")
	}
	ignored := fsnotify.Event{Name: "/etc/sable/unrelated.txt", Op: fsnotify.Write}
	if isConfigurationEvent(ignored, paths) {
		t.Fatal("isConfigurationEvent() = true for unrelated file")
	}
}
