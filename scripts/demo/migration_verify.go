package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/zone"
	"github.com/miekg/dns"
)

func migrationQuery(ctx context.Context, address, protocol, name string) (*dns.Msg, error) {
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(name), dns.TypeA)
	request.RecursionDesired = false
	client := &dns.Client{Net: protocol, Timeout: time.Second}
	response, _, err := client.ExchangeContext(ctx, request, address)
	if err != nil {
		return nil, err
	}
	if response.Rcode != dns.RcodeSuccess || !response.Authoritative || len(response.Answer) == 0 {
		return nil, fmt.Errorf("%s %s: rcode=%s authoritative=%t answers=%d", address, name, dns.RcodeToString[response.Rcode], response.Authoritative, len(response.Answer))
	}
	return response, nil
}

func (lab *migrationLab) awaitAddress(ctx context.Context, name, address string) error {
	return migrationWait(ctx, "DNS answer "+name+" = "+address, func() error {
		for _, member := range lab.nodes {
			for _, protocol := range []string{"udp", "tcp"} {
				response, err := migrationQuery(ctx, member.Ports.dns, protocol, name)
				if err != nil {
					return err
				}
				found := false
				for _, rr := range response.Answer {
					if a, ok := rr.(*dns.A); ok && a.A.String() == address {
						found = true
					}
				}
				if !found {
					return fmt.Errorf("%s %s: expected %s, got %s", member.Name, protocol, address, response.Answer)
				}
			}
		}
		return nil
	})
}

func (lab *migrationLab) review(ctx context.Context, name string) (url.Values, error) {
	status, body, err := lab.request(ctx, lab.operator, http.MethodGet, "/api/v1/zones/convert-primary?zone="+url.QueryEscape(name), nil)
	if err != nil {
		return nil, err
	}
	var review struct {
		Confirmation string
		Serial       uint32
		RecordCount  int `json:"record_count"`
	}
	if status != 200 {
		return nil, fmt.Errorf("review %s: HTTP %d %s", name, status, body)
	}
	if err := json.Unmarshal(body, &review); err != nil {
		return nil, err
	}
	if review.Confirmation == "" || review.RecordCount == 0 {
		return nil, fmt.Errorf("empty conversion review for %s", name)
	}
	return url.Values{"zone": {name}, "confirmation": {review.Confirmation}, "freeze_confirmed": {"true"}, "final_sync": {"true"}}, nil
}

func (lab *migrationLab) reject(ctx context.Context, client *console, form url.Values, wantStatus int, explanation string) error {
	name := form.Get("zone")
	before, err := lab.current(ctx, name)
	if err != nil {
		return err
	}
	status, body, err := lab.request(ctx, client, http.MethodPost, "/api/v1/zones/convert-primary", form)
	if err != nil {
		return err
	}
	if status != wantStatus || !strings.Contains(strings.ToLower(string(body)), strings.ToLower(explanation)) {
		return fmt.Errorf("expected rejection %d %q: got %d %s", wantStatus, explanation, status, body)
	}
	after, err := lab.current(ctx, name)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, after) {
		return fmt.Errorf("rejected conversion changed %s", name)
	}
	return nil
}

func (lab *migrationLab) verify(ctx context.Context) error {
	for _, name := range []string{standaloneMigrationZone, memberMigrationZone} {
		if err := lab.source.setAddress(ctx, name, "removed", "192.0.2.22"); err != nil {
			return err
		}
		if err := lab.source.setAddress(ctx, name, "www", "192.0.2.20"); err != nil {
			return err
		}
		if err := lab.mutate(ctx, "/ui/zones/resync", url.Values{"zone": {name}}); err != nil {
			return err
		}
		if err := lab.awaitAddress(ctx, "www."+name, "192.0.2.20"); err != nil {
			return err
		}
	}
	fmt.Println("PASS: source changes transfer to all three Sable nodes")
	stale, err := lab.review(ctx, standaloneMigrationZone)
	if err != nil {
		return err
	}
	if err := lab.source.setAddress(ctx, standaloneMigrationZone, "www", "192.0.2.21"); err != nil {
		return err
	}
	if err := lab.mutate(ctx, "/ui/zones/resync", url.Values{"zone": {standaloneMigrationZone}}); err != nil {
		return err
	}
	if err := lab.reject(ctx, lab.operator, stale, 422, "changed since review"); err != nil {
		return err
	}
	fresh, err := lab.review(ctx, standaloneMigrationZone)
	if err != nil {
		return err
	}
	if err := lab.source.transferPolicy(ctx, standaloneMigrationZone, "Deny"); err != nil {
		return err
	}
	if err := lab.reject(ctx, lab.operator, fresh, 422, "final synchronization failed"); err != nil {
		return err
	}
	if err := lab.source.transferPolicy(ctx, standaloneMigrationZone, "Allow"); err != nil {
		return err
	}
	fmt.Println("PASS: stale confirmation and refused final transfer leave the Secondary unchanged")
	for _, test := range []struct{ name, reason string }{{signedMigrationZone, "signing"}, {managedMigrationZone, "catalog"}} {
		current, err := lab.current(ctx, test.name)
		if err != nil {
			return err
		}
		form := url.Values{"zone": {test.name}, "confirmation": {zone.ConversionFingerprint(current)}, "freeze_confirmed": {"true"}, "final_sync": {"true"}}
		if err := lab.reject(ctx, lab.operator, form, 422, test.reason); err != nil {
			return err
		}
	}
	if err := lab.reject(ctx, newConsole(lab.nodes[1].ConsoleURL()), fresh, 409, "replica"); err != nil {
		return err
	}
	fmt.Println("PASS: signed member, Sable-managed member, and replica writes are rejected")
	converted := make(map[string]zone.Zone)
	for _, name := range []string{standaloneMigrationZone, memberMigrationZone} {
		current, err := lab.convertAndProbe(ctx, name)
		if err != nil {
			return err
		}
		converted[name] = current
	}
	// The source's catalog membership must survive both staging and conversion.
	var options struct{ Response struct{ Catalog string } }
	if err := lab.source.call(ctx, "/api/zones/options/get", url.Values{"zone": {memberMigrationZone}}, &options); err != nil {
		return err
	}
	if options.Response.Catalog != migrationCatalog {
		return fmt.Errorf("source catalog membership changed: %q", options.Response.Catalog)
	}
	fmt.Println("PASS: source catalog membership retained")
	if _, err := dockerCommand(ctx, "stop", lab.source.name); err != nil {
		return err
	}
	stopNodes(lab.nodes)
	if err := lab.verifyDurableHistory(ctx, converted); err != nil {
		return err
	}
	for _, member := range lab.nodes {
		if err := member.Start(ctx, lab.binary); err != nil {
			return err
		}
	}
	for name, before := range converted {
		after, err := lab.current(ctx, name)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(before, after) {
			return fmt.Errorf("%s changed across restart", name)
		}
		if err := lab.awaitAddress(ctx, "sable."+name, "192.0.2.40"); err != nil {
			return err
		}
	}
	fmt.Println("PASS: restart preserves identity, scoped permissions, audit, history, and writable records with Technitium stopped")
	return nil
}

func (lab *migrationLab) convertAndProbe(ctx context.Context, name string) (zone.Zone, error) {
	before, err := lab.current(ctx, name)
	if err != nil {
		return zone.Zone{}, err
	}
	if before.TSIGKey != migrationTSIGName+"." {
		return zone.Zone{}, fmt.Errorf("missing transfer authentication")
	}
	form, err := lab.review(ctx, name)
	if err != nil {
		return zone.Zone{}, err
	}
	// Deliberately leave these changes un-resynced: final synchronization must
	// bring in both a replacement and an additional record before promotion.
	if err := lab.source.setAddress(ctx, name, "www", "192.0.2.30"); err != nil {
		return zone.Zone{}, err
	}
	if err := lab.source.setAddress(ctx, name, "final", "192.0.2.31"); err != nil {
		return zone.Zone{}, err
	}
	if err := lab.source.call(ctx, "/api/zones/records/delete", url.Values{"zone": {name}, "domain": {"removed." + name}, "type": {"A"}, "ipAddress": {"192.0.2.22"}}, nil); err != nil {
		return zone.Zone{}, err
	}
	soaRequest := new(dns.Msg)
	soaRequest.SetQuestion(dns.Fqdn(name), dns.TypeSOA)
	sourceReply, _, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).ExchangeContext(ctx, soaRequest, lab.source.dns)
	if err != nil {
		return zone.Zone{}, err
	}
	if sourceReply.Rcode != dns.RcodeSuccess || len(sourceReply.Answer) != 1 {
		return zone.Zone{}, fmt.Errorf("invalid source SOA response")
	}
	sourceSOA, ok := sourceReply.Answer[0].(*dns.SOA)
	if !ok {
		return zone.Zone{}, fmt.Errorf("source answer is not SOA")
	}
	probeCtx, cancel := context.WithCancel(ctx)
	probes := make(chan error, 1)
	go func() { probes <- lab.probeConversion(probeCtx, name) }()
	err = lab.mutate(ctx, "/api/v1/zones/convert-primary", form)
	if err == nil {
		err = lab.awaitAddress(ctx, "www."+name, "192.0.2.30")
	}
	if err == nil {
		err = lab.awaitAddress(ctx, "final."+name, "192.0.2.31")
	}
	cancel()
	err = errors.Join(err, <-probes)
	if err != nil {
		return zone.Zone{}, err
	}
	after, err := lab.current(ctx, name)
	if err != nil {
		return zone.Zone{}, err
	}
	serialAdvanced := false
	for _, record := range after.Records {
		if record.Name == "@" && record.Type == "SOA" {
			parsed, err := zone.ParseRecord(after, record)
			if err != nil {
				return zone.Zone{}, err
			}
			if soa, ok := parsed.(*dns.SOA); ok {
				serialAdvanced = int32(soa.Serial-sourceSOA.Serial) > 0
			}
		}
	}
	if !serialAdvanced {
		return zone.Zone{}, fmt.Errorf("converted serial did not advance beyond final source serial")
	}
	for _, record := range after.Records {
		if record.Name == "removed" {
			return zone.Zone{}, fmt.Errorf("final synchronization retained a source deletion")
		}
	}
	if after.Type != "primary" || after.ID != before.ID || after.Revision <= before.Revision || len(after.PrimaryServers) != 0 || after.PrimaryProtocol != "" ||
		after.ZoneTransfer != before.ZoneTransfer || after.TSIGKey != before.TSIGKey || after.DynamicUpdates != before.DynamicUpdates || !reflect.DeepEqual(after.TransferACL, before.TransferACL) {
		return zone.Zone{}, fmt.Errorf("conversion did not preserve %s identity/policy or clear upstreams", name)
	}
	if err := lab.mutate(ctx, "/ui/zones/records/add", url.Values{"zone": {name}, "name": {"sable"}, "type": {"A"}, "value": {"192.0.2.40"}, "ttl": {"30"}}); err != nil {
		return zone.Zone{}, err
	}
	if err := lab.awaitAddress(ctx, "sable."+name, "192.0.2.40"); err != nil {
		return zone.Zone{}, err
	}
	if err := lab.source.setAddress(ctx, name, "www", "192.0.2.99"); err != nil {
		return zone.Zone{}, err
	}
	// Force a resync attempt rather than trusting a short sleep to exercise the gate.
	status, _, err := lab.request(ctx, lab.operator, http.MethodPost, "/ui/zones/resync", url.Values{"zone": {name}})
	if err != nil {
		return zone.Zone{}, err
	}
	if status != 422 {
		return zone.Zone{}, fmt.Errorf("Primary resync returned %d", status)
	}
	if err := lab.awaitAddress(ctx, "www."+name, "192.0.2.30"); err != nil {
		return zone.Zone{}, err
	}
	fmt.Println("PASS:", name, "converted, final data retained, writable on Sable, protected from source changes")
	return lab.current(ctx, name)
}

func (lab *migrationLab) probeConversion(ctx context.Context, name string) error {
	file, err := os.OpenFile(filepath.Join(lab.root, "dns-probes.tsv"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	samples := 0
	for {
		for _, member := range lab.nodes {
			for _, protocol := range []string{"udp", "tcp"} {
				_, err := migrationQuery(ctx, member.Ports.dns, protocol, "www."+name)
				if ctx.Err() != nil {
					if samples == 0 {
						return fmt.Errorf("no DNS continuity samples collected")
					}
					return nil
				}
				_, writeErr := fmt.Fprintf(file, "%s\t%s\t%s\t%s\t%v\n", time.Now().UTC().Format(time.RFC3339Nano), name, member.Name, protocol, err)
				if err != nil || writeErr != nil {
					return errors.Join(err, writeErr)
				}
				samples++
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (lab *migrationLab) verifyDurableHistory(ctx context.Context, converted map[string]zone.Zone) error {
	database, err := store.Open(ctx, "sqlite", lab.nodes[0].Configuration.Database.DSN)
	if err != nil {
		return err
	}
	defer database.Close()
	roles, err := database.ListRoles(ctx)
	if err != nil {
		return err
	}
	grants := map[string]bool{}
	for _, role := range roles {
		if role.Name == "Migration readers" {
			for _, grant := range role.Grants {
				if grant.Permission != auth.PermissionZonesRead || grant.ResourceType != auth.ResourceZone || grant.Surface != auth.SurfaceWeb {
					return fmt.Errorf("migration grant changed")
				}
				grants[grant.ResourceID] = true
			}
		}
	}
	if len(grants) != len(converted) {
		return fmt.Errorf("migration grants missing or broadened")
	}
	audits, err := database.ListAuditRecords(ctx, 100)
	if err != nil {
		return err
	}
	conversionAudits := map[string]int{}
	for _, event := range audits {
		if event.Action == "zone.convert_primary" {
			conversionAudits[event.Details]++
		}
	}
	if len(conversionAudits) != len(converted) {
		return fmt.Errorf("unexpected conversion audit events")
	}
	for name, current := range converted {
		if !grants[current.ID] || conversionAudits["zone="+name] != 1 {
			return fmt.Errorf("%s lost permissions or conversion audit", name)
		}
		history, err := database.ListZoneRevisions(ctx, name, 128)
		if err != nil {
			return err
		}
		foundSecondary := false
		for _, revision := range history {
			if revision.ZoneID != current.ID {
				return fmt.Errorf("%s history lost identity", name)
			}
			full, err := database.ZoneRevision(ctx, name, revision.Number)
			if err != nil {
				return err
			}
			if full.Zone.Type == "secondary" {
				foundSecondary = true
			}
		}
		if !foundSecondary || len(history) < 3 {
			return fmt.Errorf("%s lost pre-conversion history", name)
		}
	}
	return nil
}
