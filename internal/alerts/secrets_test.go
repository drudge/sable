package alerts

import (
	"context"
	"testing"

	"github.com/drudge/sable/internal/config"
)

func TestSecretsMoveToTheVaultAndComeBackForSending(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vault := newMemoryVault()
	store := NewSecretStore(vault)
	configuration := config.Defaults()
	configuration.Alerts.Destinations = []config.AlertDestination{
		{ID: "ntfy", Format: config.AlertFormatText, URL: "https://ntfy.sh/sable", Headers: []config.AlertHeader{{Name: "Authorization", Value: "Bearer tk"}}},
		{ID: "phone", Format: config.AlertFormatPushover, PushoverToken: "app", PushoverUser: "user"},
		{ID: "browser", Format: config.AlertFormatBrowser},
	}
	if !Pending(configuration) {
		t.Fatal("secrets in the file are not pending")
	}
	moved, err := store.Migrate(ctx, &configuration)
	if err != nil || moved != 2 {
		t.Fatalf("moved %d, %v", moved, err)
	}
	if Pending(configuration) {
		t.Fatalf("secrets are still in the file: %+v", configuration.Alerts.Destinations)
	}
	for _, destination := range configuration.Alerts.Destinations {
		if destination.HasSecrets() {
			t.Fatalf("%s kept a secret: %+v", destination.ID, destination)
		}
	}
	// Running it again is harmless.
	if moved, err := store.Migrate(ctx, &configuration); err != nil || moved != 0 {
		t.Fatalf("moving again = %d, %v", moved, err)
	}
	hydrated := store.Hydrate(ctx, configuration.Alerts.Destinations)
	if ntfy := hydrated[0]; ntfy.URL != "https://ntfy.sh/sable" || len(ntfy.Headers) != 1 || ntfy.Headers[0].Value != "Bearer tk" {
		t.Fatalf("ntfy = %+v", ntfy)
	}
	if phone := hydrated[1]; phone.PushoverToken != "app" || phone.PushoverUser != "user" || phone.ValidateSecrets() != nil {
		t.Fatalf("phone = %+v", phone)
	}
	// A secret written in the file by hand replaces the stored one, and
	// leaves the rest as the vault has them.
	configuration.Alerts.Destinations[1].PushoverToken = "new-app"
	if _, err := store.Migrate(ctx, &configuration); err != nil {
		t.Fatal(err)
	}
	if secrets, _ := store.Secrets(ctx, "phone"); secrets.PushoverToken != "new-app" || secrets.PushoverUser != "user" {
		t.Fatalf("phone secrets = %+v", secrets)
	}
	if err := store.Forget(ctx, "ntfy"); err != nil {
		t.Fatal(err)
	}
	if _, found := store.Secrets(ctx, "ntfy"); found {
		t.Fatal("forgotten secrets are still there")
	}
	// Headers kept from before a destination moved to Slack are not sent.
	if err := store.Put(ctx, "chat", Secrets{URL: "https://hooks.slack.com/x", Headers: []config.AlertHeader{{Name: "X", Value: "y"}}}); err != nil {
		t.Fatal(err)
	}
	if chat := store.Hydrate(ctx, []config.AlertDestination{{ID: "chat", Format: config.AlertFormatSlack}})[0]; chat.Headers != nil || chat.URL == "" {
		t.Fatalf("chat = %+v", chat)
	}
}
