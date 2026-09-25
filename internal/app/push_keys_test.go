package app

import (
	"context"
	"testing"
)

func TestPushKeyIsMadeOnceAndKeptInTheVault(t *testing.T) {
	t.Parallel()
	vault := &memoryBackupVault{}
	first, err := newPushKeyStore(vault).PushKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(vault.values[pushKeyEntry]) == 0 {
		t.Fatal("the push key was not sealed in the vault")
	}
	// A restarted node reads the same key back, so subscriptions keep working.
	again, err := newPushKeyStore(vault).PushKey(context.Background())
	if err != nil || !again.Equal(first) {
		t.Fatalf("the push key changed across restarts: %v", err)
	}
}
