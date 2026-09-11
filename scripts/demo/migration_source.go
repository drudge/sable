package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const migrationTSIGName = "migration-transfer"
const migrationTSIGSecret = "bWlncmF0aW9uLWxhYi1vbmx5LXNlY3JldC0yMDI2ISE="

const migrationPassword = "MigrationLabOnly2026!"
const migrationCatalog = "catalog.migration.test"
const subscribedCatalog = "subscribed-catalog.migration.test"
const standaloneMigrationZone = "standalone.migration.test"
const memberMigrationZone = "member.migration.test"
const signedMigrationZone = "signed.migration.test"
const managedMigrationZone = "managed.migration.test"

type migrationSource struct {
	name, url, dns, token, directory string
	client                           *http.Client
	created                          bool
}

func dockerCommand(ctx context.Context, args ...string) (string, error) {
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func (source *migrationSource) start(ctx context.Context, image string) error {
	if _, err := dockerCommand(ctx, "info", "--format", "{{.ServerVersion}}"); err != nil {
		return err
	}
	// Never reuse a benchmark or user container. Docker owns the disposable volume.
	_, err := dockerCommand(ctx, "run", "--detach", "--name", source.name, "--label", "sable.fixture=migration",
		"--publish", "127.0.0.1::5380/tcp", "--publish", "127.0.0.1::53/tcp", "--publish", "127.0.0.1::53/udp",
		"--env", "DNS_SERVER_DOMAIN=source.migration.test", "--env", "DNS_SERVER_ADMIN_PASSWORD="+migrationPassword,
		"--env", "DNS_SERVER_RECURSION=Deny", "--env", "DNS_SERVER_ENABLE_BLOCKING=false", image)
	if err != nil {
		return err
	}
	source.created = true
	for port, destination := range map[string]*string{"5380/tcp": &source.url, "53/tcp": &source.dns} {
		address, err := dockerCommand(ctx, "port", source.name, port)
		if err != nil {
			return err
		}
		*destination = address
	}
	source.url = "http://" + source.url
	source.client = &http.Client{Timeout: 10 * time.Second}
	metadata, err := dockerCommand(ctx, "inspect", "--format", "{{.Config.Image}} {{.Image}}", source.name)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(source.directory, "source-image.txt"), []byte(metadata+"\n"), 0600); err != nil {
		return err
	}
	return migrationWait(ctx, "Technitium login", func() error {
		var login struct{ Token string }
		if err := source.call(ctx, "/api/user/login", url.Values{"user": {"admin"}, "pass": {migrationPassword}}, &login); err != nil {
			return err
		}
		if login.Token == "" {
			return fmt.Errorf("empty login token")
		}
		source.token = login.Token
		return nil
	})
}

func (source *migrationSource) close() error {
	if !source.created {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logs, logErr := dockerCommand(ctx, "logs", source.name)
	writeErr := os.WriteFile(filepath.Join(source.directory, "technitium.log"), []byte(logs), 0600)
	_, removeErr := dockerCommand(ctx, "rm", "--force", "--volumes", source.name)
	return errors.Join(logErr, writeErr, removeErr)
}

func (source *migrationSource) call(ctx context.Context, path string, form url.Values, result any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, source.url+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if source.token != "" {
		request.Header.Set("Authorization", "Bearer "+source.token)
	}
	response, err := source.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return err
	}
	var status struct {
		Status       string
		ErrorMessage string
	}
	if err := json.Unmarshal(data, &status); err != nil {
		return fmt.Errorf("Technitium %s: invalid JSON (%s)", path, response.Status)
	}
	if response.StatusCode != 200 || status.Status != "ok" {
		return fmt.Errorf("Technitium %s: %s %s", path, status.Status, status.ErrorMessage)
	}
	if result != nil {
		return json.Unmarshal(data, result)
	}
	return nil
}

func (source *migrationSource) setAddress(ctx context.Context, name, owner, address string) error {
	return source.call(ctx, "/api/zones/records/add", url.Values{"zone": {name}, "domain": {owner + "." + name}, "type": {"A"}, "ttl": {"30"}, "ipAddress": {address}, "overwrite": {"true"}}, nil)
}

func (source *migrationSource) fixture(ctx context.Context) error {
	if err := source.call(ctx, "/api/settings/set", url.Values{"tsigKeys": {migrationTSIGName + "|" + migrationTSIGSecret + "|hmac-sha256"}}, nil); err != nil {
		return err
	}
	for _, current := range []struct{ name, kind, catalog string }{
		{migrationCatalog, "Catalog", ""}, {subscribedCatalog, "Catalog", ""},
		{standaloneMigrationZone, "Primary", ""}, {memberMigrationZone, "Primary", migrationCatalog},
		{signedMigrationZone, "Primary", migrationCatalog}, {managedMigrationZone, "Primary", subscribedCatalog},
	} {
		form := url.Values{"zone": {current.name}, "type": {current.kind}}
		if current.catalog != "" {
			form.Set("catalog", current.catalog)
		}
		if err := source.call(ctx, "/api/zones/create", form, nil); err != nil {
			return err
		}
		// Loopback-only published ports keep this fixture policy local. Members
		// deliberately inherit transfer policy from their real source catalog.
		if current.catalog == "" {
			if err := source.transferPolicy(ctx, current.name, "Allow"); err != nil {
				return err
			}
		}
		if current.kind == "Primary" {
			if err := source.setAddress(ctx, current.name, "www", "192.0.2.10"); err != nil {
				return err
			}
		}
	}
	return source.call(ctx, "/api/zones/dnssec/sign", url.Values{"zone": {signedMigrationZone}, "algorithm": {"ECDSA"}, "curve": {"P256"}, "nxProof": {"NSEC"}}, nil)
}

func (source *migrationSource) transferPolicy(ctx context.Context, name, policy string) error {
	return source.call(ctx, "/api/zones/options/set", url.Values{"zone": {name}, "zoneTransfer": {policy}, "zoneTransferTsigKeyNames": {migrationTSIGName}}, nil)
}
