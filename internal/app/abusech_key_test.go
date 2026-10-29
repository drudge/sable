package app

import (
	"context"
	"testing"

	"github.com/drudge/sable/internal/config"
)

func TestAbuseCHKeyReachesReplicasAndCanBeCleared(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	source := newAbuseCHKeyStore(&memoryTSIGVault{values: make(map[string][]byte)})
	if err := source.Put(ctx, " primary-key "); err != nil {
		t.Fatal(err)
	}
	sourceReplicator := newClusterStateReplicator(newTestConfigurationManager(t, config.Defaults()), newTestZoneManager(t, nil), nil, newTestTSIGStore(), newTestUniFiCredentials(), newTestOIDCSecrets())
	sourceReplicator.setAbuseCHKey(source)
	contents, err := sourceReplicator.Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}

	target := newAbuseCHKeyStore(&memoryTSIGVault{values: make(map[string][]byte)})
	targetManager := newTestConfigurationManager(t, config.Defaults())
	targetReplicator := newClusterStateReplicator(targetManager, newTestZoneManager(t, nil), nil, newTestTSIGStore(), newTestUniFiCredentials(), newTestOIDCSecrets())
	targetReplicator.setAbuseCHKey(target)
	if err := targetReplicator.Apply(ctx, contents); err != nil {
		t.Fatal(err)
	}
	if key, found := target.Get(ctx); !found || key != "primary-key" {
		t.Fatalf("replica key = %q, %v", key, found)
	}

	if err := target.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if key, found := target.Get(ctx); found || target.Lookup(ctx) != "" {
		t.Fatalf("cleared key still reads back as %q", key)
	}
}
