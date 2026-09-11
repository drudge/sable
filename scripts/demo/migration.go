package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/zone"
)

type migrationLab struct {
	source       *migrationSource
	nodes        []*node
	operator     *console
	root, binary string
}

func runMigration(binary, image string, keep bool) (runErr error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	absoluteBinary, err := filepath.Abs(binary)
	if err != nil {
		return err
	}
	if _, err := os.Stat(absoluteBinary); err != nil {
		return fmt.Errorf("build Sable first: %w", err)
	}
	if err := os.MkdirAll("_work", 0755); err != nil {
		return err
	}
	root, err := os.MkdirTemp("_work", "migration-")
	if err != nil {
		return err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	lab := &migrationLab{root: root, binary: absoluteBinary}
	lab.source = &migrationSource{name: "sable-" + filepath.Base(root), directory: root}
	defer func() {
		if keep {
			return
		}
		result := "PASS: Technitium migration scenarios completed\n"
		if runErr != nil {
			result = "FAIL: " + runErr.Error() + "\n"
		}
		runErr = errors.Join(runErr, os.WriteFile(filepath.Join(root, "result.txt"), []byte(result), 0600))
		fmt.Print(result)
	}()
	fmt.Println("Migration lab evidence:", root)
	defer func() { stopNodes(lab.nodes); runErr = errors.Join(runErr, lab.source.close()) }()
	if err := lab.source.start(ctx, image); err != nil {
		return err
	}
	fmt.Println("Creating Technitium catalogs, unsigned members, and signed member")
	if err := lab.source.fixture(ctx); err != nil {
		return err
	}
	if err := lab.startSable(ctx); err != nil {
		return err
	}
	if err := lab.stage(ctx); err != nil {
		return err
	}
	if err := lab.writeGuide(); err != nil {
		return err
	}
	fmt.Printf("Technitium: %s (admin / %s)\n", lab.source.url, migrationPassword)
	for _, member := range lab.nodes {
		fmt.Printf("%s: %s (DNS %s)\n", member.Name, member.ConsoleURL(), member.Ports.dns)
	}
	fmt.Printf("Sable primary: %s / %s\nWalkthrough: %s\n", operatorUsername, operatorPassword, filepath.Join(root, "README.md"))
	if keep {
		fmt.Println("Ready for manual conversion. Ctrl-C stops this lab; evidence is retained.")
		<-ctx.Done()
		return nil
	}
	return lab.verify(ctx)
}

func migrationWait(ctx context.Context, label string, check func() error) error {
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	var last error
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if last = check(); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("%s timed out: %w", label, last)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func migrationPort() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	address := listener.Addr().String()
	return address, listener.Close()
}

func (lab *migrationLab) startSable(ctx context.Context) error {
	for index := 0; index < 3; index++ {
		ports := nodePorts{}
		for _, field := range []*string{&ports.http, &ports.https, &ports.dns} {
			address, err := migrationPort()
			if err != nil {
				return err
			}
			*field = address
		}
		member, err := newNode(ctx, lab.root, fmt.Sprintf("migration-ns%d", index+1), ports, func(c *config.Config) {
			c.Security.Enabled = index == 0
			c.Resolver.DNSSECTrustAnchorUpdates = false
		})
		if err != nil {
			return err
		}
		lab.nodes = append(lab.nodes, member)
		if err := member.Start(ctx, lab.binary); err != nil {
			return err
		}
	}
	lab.operator = newConsole(lab.nodes[0].ConsoleURL())
	if err := lab.operator.CreateOperator(operatorUsername, operatorPassword, operatorName, operatorEmail); err != nil {
		return err
	}
	if err := lab.operator.InitializeCluster("sable-lab.test", []string{"192.0.2.101"}); err != nil {
		return err
	}
	for index, member := range lab.nodes[1:] {
		token, err := lab.operator.EnrollmentToken("15m")
		if err != nil {
			return err
		}
		if err := newConsole(member.ConsoleURL()).JoinCluster(lab.nodes[0].ClusterURL(), token, []string{fmt.Sprintf("192.0.2.%d", 102+index)}); err != nil {
			return err
		}
	}
	return waitForClusterSync(ctx, lab.operator, len(lab.nodes))
}

// Unlike the screenshot helper, migration mutations do not send HX-Request:
// ordinary HTTP status codes must expose validation and permission failures.
func (lab *migrationLab) request(ctx context.Context, client *console, method, path string, form url.Values) (int, []byte, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, body)
	if err != nil {
		return 0, nil, err
	}
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		token, err := client.sessionToken()
		if err != nil {
			return 0, nil, err
		}
		if token != "" {
			request.Header.Set("X-CSRF-Token", token)
		}
	}
	response, err := client.client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	return response.StatusCode, contents, err
}

func (lab *migrationLab) mutate(ctx context.Context, path string, form url.Values) error {
	status, body, err := lab.request(ctx, lab.operator, http.MethodPost, path, form)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("Sable %s: HTTP %d: %s", path, status, summarize(string(body)))
	}
	return nil
}

func (lab *migrationLab) zones(ctx context.Context, client *console) ([]zone.Zone, error) {
	status, body, err := lab.request(ctx, client, http.MethodGet, "/api/v1/zones", nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("zones: HTTP %d", status)
	}
	var zones []zone.Zone
	err = json.Unmarshal(body, &zones)
	return zones, err
}

func (lab *migrationLab) current(ctx context.Context, name string) (zone.Zone, error) {
	zones, err := lab.zones(ctx, lab.operator)
	if err != nil {
		return zone.Zone{}, err
	}
	for _, current := range zones {
		if current.Name == name {
			return current, nil
		}
	}
	return zone.Zone{}, fmt.Errorf("missing zone %s", name)
}

func (lab *migrationLab) stage(ctx context.Context) error {
	if err := lab.mutate(ctx, "/ui/settings/tsig/save", url.Values{"tsig_name": {migrationTSIGName}, "tsig_algorithm": {"hmac-sha256"}, "tsig_secret": {migrationTSIGSecret}}); err != nil {
		return err
	}
	for _, fixture := range []struct{ name, kind string }{
		{standaloneMigrationZone, "secondary"}, {subscribedCatalog, "secondary_catalog"},
	} {
		if err := lab.mutate(ctx, "/ui/zones/add", url.Values{"name": {fixture.name}, "type": {fixture.kind}, "primary_servers": {lab.source.dns}, "primary_protocol": {"tcp"}, "tsig_key": {migrationTSIGName}}); err != nil {
			return fmt.Errorf("stage %s: %w", fixture.name, err)
		}
	}
	form := url.Values{"catalog": {migrationCatalog}, "primary_servers": {lab.source.dns}, "primary_protocol": {"tcp"}, "tsig_key": {migrationTSIGName}, "step": {"discover"}}
	status, body, err := lab.request(ctx, lab.operator, http.MethodPost, "/ui/zones/import-catalog", form)
	if err != nil {
		return err
	}
	_, wizardBody, _ := strings.Cut(string(body), `id="catalog-import-dialog"`)
	confirmation := regexp.MustCompile(`name="confirmation" value="([^"]+)"`).FindStringSubmatch(wizardBody)
	if status != http.StatusOK || len(confirmation) != 2 {
		return fmt.Errorf("catalog discovery failed: %d %s", status, body)
	}
	form.Set("confirmation", confirmation[1])
	form.Set("step", "stage")
	form["member"] = []string{memberMigrationZone, signedMigrationZone}
	status, body, err = lab.request(ctx, lab.operator, http.MethodPost, "/ui/zones/import-catalog", form)
	if err != nil {
		return err
	}
	if status != http.StatusOK || strings.Count(string(body), "Synchronized as an independent Secondary.") != 2 {
		return fmt.Errorf("catalog staging failed: %d %s", status, body)
	}
	if err := migrationWait(ctx, "all zone transfers and cluster replication", func() error {
		for index, member := range lab.nodes {
			client := lab.operator
			if index > 0 {
				client = newConsole(member.ConsoleURL())
			}
			zones, err := lab.zones(ctx, client)
			if err != nil {
				return err
			}
			for _, name := range []string{standaloneMigrationZone, memberMigrationZone, signedMigrationZone, managedMigrationZone} {
				found := false
				for _, current := range zones {
					if current.Name != name {
						continue
					}
					found = true
					if len(current.Records) < 3 {
						return fmt.Errorf("%s on %s awaiting transfer", name, member.Name)
					}
					if name == managedMigrationZone && current.CatalogZone != subscribedCatalog {
						return fmt.Errorf("managed fixture lacks Sable catalog ownership")
					}
					if name == memberMigrationZone && current.CatalogZone != "" {
						return fmt.Errorf("individual fixture unexpectedly catalog managed")
					}
				}
				if !found {
					return fmt.Errorf("%s missing on %s", name, member.Name)
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	ids := []string{}
	for _, name := range []string{standaloneMigrationZone, memberMigrationZone} {
		current, err := lab.current(ctx, name)
		if err != nil {
			return err
		}
		ids = append(ids, current.ID)
	}
	return lab.mutate(ctx, "/ui/administration/roles", url.Values{"name": {"Migration readers"}, "description": {"Verify zone grants survive conversion"}, "web_permissions": {auth.PermissionZonesRead}, "web_zone_ids": ids})
}

func (lab *migrationLab) writeGuide() error {
	text := fmt.Sprintf(`# Technitium migration lab

Source console: %s — admin / %s
Sable primary: %s — %s / %s

This run owns container %s. Ctrl-C stops its containers and processes. Logs and
this directory remain for inspection; no benchmark or existing demo is modified.
The source's TCP DNS transfer endpoint is %s.

## Fixtures

- %s: standalone unsigned Secondary, ready to convert.
- %s: individual Secondary of a Technitium catalog member, ready to convert.
- %s: signed source catalog member, conversion must be rejected.
- %s: member provisioned by Sable's subscription to %s, conversion must be rejected.

Technitium's %s is deliberately not subscribed by Sable. Its membership alone
must not block conversion of the individually staged member.

## Walkthrough

1. Change www in the source member zone, then use Sable's Resync Zone action.
2. Compare answers and SOA serials on all Sable nodes.
3. Freeze source edits. Open Convert to Primary and review the source, serial,
   and record count. Keep final synchronization enabled and confirm.
4. Verify the same zone identity and history, then add a record on Sable.
5. Confirm every Sable node answers that new record and source changes no longer
   overwrite it. Leave the Technitium catalog intact.
6. Try the signed and Sable-managed fixtures to see the rejection explanations.

For a stale confirmation, open conversion in one tab, resync changed source data
in another tab, then submit the old confirmation. For transfer failure, deny
transfers in the source standalone zone's options, then try final synchronization.
Restore transfer access before retrying. No silent fallback should occur.

The source requires the shared migration-transfer TSIG key for fixture transfers
through loopback-published ports. Credentials
are disposable fixtures. This is a real Catalog zone, not a full Technitium cluster;
private signing-key migration and catalog detachment are outside this test.
`, lab.source.url, migrationPassword, lab.nodes[0].ConsoleURL(), operatorUsername, operatorPassword, lab.source.name, lab.source.dns, standaloneMigrationZone, memberMigrationZone, signedMigrationZone, managedMigrationZone, subscribedCatalog, migrationCatalog)
	return os.WriteFile(filepath.Join(lab.root, "README.md"), []byte(text), 0600)
}
