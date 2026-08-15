package app

import (
	"context"
	"encoding/json"
	"net"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	dnssecstate "github.com/drudge/sable/internal/dnssec"
	"github.com/drudge/sable/internal/dnsserver"
	zonemodel "github.com/drudge/sable/internal/zone"
)

type memoryDNSSECVault map[string][]byte

type dnssecTestConfiguration struct {
	Config config.Config
	Zones  []zonemodel.Zone
}

func (vault memoryDNSSECVault) Put(_ context.Context, name string, value []byte) error {
	vault[name] = append([]byte(nil), value...)
	return nil
}

func (vault memoryDNSSECVault) Get(_ context.Context, name string) ([]byte, error) {
	value, found := vault[name]
	if !found {
		return nil, auth.ErrNotFound
	}
	return append([]byte(nil), value...), nil
}

func TestDNSSECSignerCreatesStableVerifiableZoneAndRotates(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	configuration := dnssecTestConfiguration{Config: config.Defaults()}
	configuration.Zones = []zonemodel.Zone{dnssecTestZone("ed25519")}
	signer := newDNSSECSigner(memoryDNSSECVault{})
	signer.now = func() time.Time { return now }

	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	zone := &configuration.Zones[0]
	zsk := verifySignedTestZone(t, *zone)
	ksk := zoneKeyByRole(t, *zone, true)
	if zsk.Flags != 256 || ksk.Flags != 257 || zsk.Algorithm != dns.ED25519 || ksk.Algorithm != dns.ED25519 {
		t.Fatalf("DNSKEY roles = ZSK flags %d, KSK flags %d", zsk.Flags, ksk.Flags)
	}
	if ds := ksk.ToDS(dns.SHA256); ds == nil || ds.KeyTag != ksk.KeyTag() {
		t.Fatalf("DS = %+v", ds)
	}
	first := append([]zonemodel.Record(nil), zone.Records...)
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, zone.Records) {
		t.Fatal("current signatures changed during an idempotent prepare")
	}

	oldTag := zsk.KeyTag()
	if err := signer.Rotate(context.Background(), zone); err != nil {
		t.Fatal(err)
	}
	if pendingTag := verifySignedTestZone(t, *zone).KeyTag(); pendingTag != oldTag {
		t.Fatalf("ZSK changed before its prepublication window: got %d, want %d", pendingTag, oldTag)
	}
	now = now.Add(zone.KeyPrepublish.Duration + time.Second)
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	if newTag := verifySignedTestZone(t, *zone).KeyTag(); newTag == oldTag {
		t.Fatalf("rotated key tag = %d, want a new key", newTag)
	}

	zone.DNSSEC = false
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	if hasManagedDNSSECRecords(zone.Records) {
		t.Fatal("managed DNSSEC records remain after disabling signing")
	}
}

func TestDNSSECSignerAlgorithms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		algorithm uint8
	}{
		{"ed25519", dns.ED25519},
		{"ecdsa-p256-sha256", dns.ECDSAP256SHA256},
		{"ecdsa-p384-sha384", dns.ECDSAP384SHA384},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := dnssecTestConfiguration{Zones: []zonemodel.Zone{dnssecTestZone(test.name)}}
			signer := newDNSSECSigner(memoryDNSSECVault{})
			signer.now = func() time.Time { return time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC) }
			if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
				t.Fatal(err)
			}
			if key := verifySignedTestZone(t, configuration.Zones[0]); key.Algorithm != test.algorithm {
				t.Fatalf("algorithm = %d, want %d", key.Algorithm, test.algorithm)
			}
		})
	}
}

func TestDNSSECSignerRejectsUncoordinatedAlgorithmTransition(t *testing.T) {
	t.Parallel()
	configuration := dnssecTestConfiguration{Zones: []zonemodel.Zone{dnssecTestZone("ed25519")}}
	signer := newDNSSECSigner(memoryDNSSECVault{})
	signer.now = func() time.Time { return time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC) }
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	configuration.Zones[0].DNSSECAlgorithm = "ecdsa-p256-sha256"
	if err := signer.Prepare(context.Background(), &configuration.Zones); err == nil {
		t.Fatal("algorithm transition succeeded without a parent-coordinated rollover")
	}
}

func TestDNSSECSignerRejectsInvalidPersistedKeyState(t *testing.T) {
	t.Parallel()
	configuration := dnssecTestConfiguration{Zones: []zonemodel.Zone{dnssecTestZone("ed25519")}}
	vault := memoryDNSSECVault{}
	signer := newDNSSECSigner(vault)
	signer.now = func() time.Time { return time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC) }
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	zone := configuration.Zones[0]
	secretName := dnssecStateSecretName(zone.Name, zone.DNSSECAlgorithm)
	var state dnssecstate.State
	if err := json.Unmarshal(vault[secretName], &state); err != nil {
		t.Fatal(err)
	}
	state.Keys[0].Role = dnssecstate.RoleZSK
	corrupt, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	vault[secretName] = corrupt
	if err := signer.Prepare(context.Background(), &configuration.Zones); err == nil {
		t.Fatal("invalid persisted key state was accepted")
	}
}

func TestDNSSECKSKRolloverWaitsForParentConfirmation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	configuration := dnssecTestConfiguration{Zones: []zonemodel.Zone{dnssecTestZone("ed25519")}}
	vault := memoryDNSSECVault{}
	signer := newDNSSECSigner(vault)
	signer.now = func() time.Time { return now }
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	zone := &configuration.Zones[0]
	original := zoneKeyByRole(t, *zone, true)
	zone.ParentDSKeyTag = original.KeyTag()
	if err := signer.RequestRollover(context.Background(), *zone, "ksk"); err != nil {
		t.Fatal(err)
	}
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	status, err := signer.KeyStatus(context.Background(), *zone)
	if err != nil {
		t.Fatal(err)
	}
	pending := keyStatusByRoleState(t, status, "ksk", "published")
	if pending.KeyTag == original.KeyTag() {
		t.Fatal("pending KSK reused the active key")
	}
	assertDNSKEYSignatureCount(t, *zone, 2)

	now = now.Add(zone.KeyPrepublish.Duration + time.Second)
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	status, err = signer.KeyStatus(context.Background(), *zone)
	if err != nil {
		t.Fatal(err)
	}
	ready := keyStatusByRoleState(t, status, "ksk", "ready")
	if active := keyStatusByRoleState(t, status, "ksk", "active"); active.KeyTag != original.KeyTag() {
		t.Fatalf("active KSK changed before parent confirmation: got %d, want %d", active.KeyTag, original.KeyTag())
	}

	zone.ParentDSKeyTag = ready.KeyTag
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	status, err = signer.KeyStatus(context.Background(), *zone)
	if err != nil {
		t.Fatal(err)
	}
	if active := keyStatusByRoleState(t, status, "ksk", "active"); active.KeyTag != ready.KeyTag {
		t.Fatalf("active KSK = %d, want confirmed key %d", active.KeyTag, ready.KeyTag)
	}
	keyStatusByRoleState(t, status, "ksk", "retiring")
	assertDNSKEYSignatureCount(t, *zone, 2)

	now = now.Add(zone.KeyRetireAfter.Duration + time.Second)
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	status, err = signer.KeyStatus(context.Background(), *zone)
	if err != nil {
		t.Fatal(err)
	}
	if len(keysByRole(status, "ksk")) != 1 || keysByRole(status, "ksk")[0].KeyTag != ready.KeyTag {
		t.Fatalf("KSK state after retirement = %+v", keysByRole(status, "ksk"))
	}
	assertDNSKEYSignatureCount(t, *zone, 1)
}

func TestDNSSECKeyLifecycleSchedulingAndPersistence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	zone := dnssecTestZone("ed25519")
	zone.ZSKLifetime.Duration = 2 * time.Hour
	zone.KeyPrepublish.Duration = 30 * time.Minute
	zone.KeyRetireAfter.Duration = 30 * time.Minute
	configuration := dnssecTestConfiguration{Zones: []zonemodel.Zone{zone}}
	vault := memoryDNSSECVault{}
	signer := newDNSSECSigner(vault)
	signer.now = func() time.Time { return now }
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	active := verifySignedTestZone(t, configuration.Zones[0]).KeyTag()

	now = now.Add(2 * time.Hour)
	due, err := signer.ZonesNeedingRefresh(context.Background(), configuration.Zones)
	if err != nil || !reflect.DeepEqual(due, []string{"example.test"}) {
		t.Fatalf("lifecycle due zones = %v, %v", due, err)
	}
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	status, err := signer.KeyStatus(context.Background(), configuration.Zones[0])
	if err != nil {
		t.Fatal(err)
	}
	keyStatusByRoleState(t, status, "zsk", "published")

	restarted := newDNSSECSigner(vault)
	restarted.now = func() time.Time { return now }
	restored, err := restarted.KeyStatus(context.Background(), configuration.Zones[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Keys) != len(status.Keys) {
		t.Fatalf("restored keys = %+v, want %+v", restored.Keys, status.Keys)
	}
	now = now.Add(30*time.Minute + time.Second)
	if err := restarted.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	if rotated := verifySignedTestZone(t, configuration.Zones[0]).KeyTag(); rotated == active {
		t.Fatalf("scheduled ZSK remained %d after prepublication", rotated)
	}
}

func TestDNSSECKeyLifecycleMigratesLegacyCombinedKeySafely(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	zone := dnssecTestZone("ed25519")
	vault := memoryDNSSECVault{}
	signer := newDNSSECSigner(vault)
	signer.now = func() time.Time { return now }
	legacy, _, err := signer.signingKey(context.Background(), zone, false)
	if err != nil {
		t.Fatal(err)
	}
	configuration := dnssecTestConfiguration{Zones: []zonemodel.Zone{zone}}
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	dataSigner := verifySignedTestZone(t, configuration.Zones[0])
	if dataSigner.KeyTag() != legacy.KeyTag() || dataSigner.Flags&dns.SEP == 0 {
		t.Fatalf("legacy CSK was not retained as the transitional data signer: got %d flags=%d, want %d", dataSigner.KeyTag(), dataSigner.Flags, legacy.KeyTag())
	}
	status, err := signer.KeyStatus(context.Background(), configuration.Zones[0])
	if err != nil {
		t.Fatal(err)
	}
	if keyStatusByRoleState(t, status, "ksk", "active").KeyTag != legacy.KeyTag() {
		t.Fatalf("migrated KSK state = %+v", status.Keys)
	}
	keyStatusByRoleState(t, status, "zsk", "published")
}

func TestDNSSECSignerCreatesNSEC3Chain(t *testing.T) {
	t.Parallel()
	configuration := dnssecTestConfiguration{Config: config.Defaults()}
	zone := dnssecTestZone("ed25519")
	zone.DNSSECDenial = "nsec3"
	zone.NSEC3Iterations = 0
	zone.NSEC3Salt = "A1B2C3D4"
	configuration.Zones = []zonemodel.Zone{zone}
	signer := newDNSSECSigner(memoryDNSSECVault{})
	signer.now = func() time.Time { return time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC) }
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	verifySignedTestZone(t, configuration.Zones[0])

	records, err := activeZoneRRs(configuration.Zones[0], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if containsRRType(records, dns.TypeNSEC) || !containsRRType(records, dns.TypeNSEC3) || !containsRRType(records, dns.TypeNSEC3PARAM) {
		t.Fatalf("NSEC3 zone denial records = %v", records)
	}
	for _, name := range []string{"example.test.", "www.example.test.", "child.example.test."} {
		if !slices.ContainsFunc(records, func(record dns.RR) bool {
			nsec3, ok := record.(*dns.NSEC3)
			return ok && nsec3.Match(name)
		}) {
			t.Errorf("NSEC3 chain has no exact hash for %s", name)
		}
	}
	for _, record := range records {
		nsec3, ok := record.(*dns.NSEC3)
		if ok && nsec3.Match("child.example.test.") && len(nsec3.TypeBitMap) != 0 {
			t.Fatalf("empty non-terminal NSEC3 bitmap = %v, want empty", nsec3.TypeBitMap)
		}
	}
}

func TestDNSSECSignerRefreshesExpiringSignaturesAndAdvancesSOAOnce(t *testing.T) {
	t.Parallel()
	configuration := dnssecTestConfiguration{Config: config.Defaults()}
	configuration.Zones = []zonemodel.Zone{dnssecTestZone("ed25519")}
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	signer := newDNSSECSigner(memoryDNSSECVault{})
	signer.now = func() time.Time { return now }
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	firstSerial := zoneSOASerial(t, configuration.Zones[0])
	_, _, firstExpiration := zoneDNSSECDetails(configuration.Zones[0])

	now = now.Add(6 * 24 * time.Hour)
	if zones, err := signer.ZonesNeedingRefresh(context.Background(), configuration.Zones); err != nil || !reflect.DeepEqual(zones, []string{"example.test"}) {
		t.Fatalf("ZonesNeedingRefresh() = %v", zones)
	}
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	if serial := zoneSOASerial(t, configuration.Zones[0]); serial != firstSerial+1 {
		t.Fatalf("refreshed SOA serial = %d, want %d", serial, firstSerial+1)
	}
	_, _, refreshedExpiration := zoneDNSSECDetails(configuration.Zones[0])
	zones, err := signer.ZonesNeedingRefresh(context.Background(), configuration.Zones)
	if err != nil {
		t.Fatal(err)
	}
	if !refreshedExpiration.After(firstExpiration) || len(zones) != 0 {
		t.Fatalf("refreshed expiration = %v, original %v", refreshedExpiration, firstExpiration)
	}

	zone := &configuration.Zones[0]
	for index := range zone.Records {
		if zone.Records[index].Name == "www" && zone.Records[index].Type == "A" {
			zone.Records[index].Value = "192.0.2.99"
		}
	}
	if err := advanceDynamicSOASerial(zone); err != nil {
		t.Fatal(err)
	}
	mutatedSerial := zoneSOASerial(t, *zone)
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	if serial := zoneSOASerial(t, *zone); serial != mutatedSerial {
		t.Fatalf("record mutation advanced SOA twice: got %d, want %d", serial, mutatedSerial)
	}
	verifySignedTestZone(t, *zone)
}

func TestSignedAuthoritativeResponsesIncludeProofsOnlyWithDO(t *testing.T) {
	t.Parallel()
	configuration := dnssecTestConfiguration{Config: config.Defaults()}
	configuration.Zones = []zonemodel.Zone{dnssecTestZone("ed25519")}
	signer := newDNSSECSigner(memoryDNSSECVault{})
	signer.now = func() time.Time { return time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC) }
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	key := verifySignedTestZone(t, configuration.Zones[0])
	runtime, err := compileRuntime(configuration.Config, configuration.Zones, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := dnsserver.NewHandler(runtime)

	positive := new(dns.Msg)
	positive.SetQuestion("www.example.test.", dns.TypeA)
	positive.SetEdns0(1232, true)
	positiveResponse := serveDNSSECRequest(t, handler, positive)
	verifyResponseRRSet(t, key, positiveResponse.Answer, dns.TypeA)

	negative := new(dns.Msg)
	negative.SetQuestion("missing.example.test.", dns.TypeA)
	negative.SetEdns0(1232, true)
	negativeResponse := serveDNSSECRequest(t, handler, negative)
	if negativeResponse.Rcode != dns.RcodeNameError {
		t.Fatalf("negative rcode = %s", dns.RcodeToString[negativeResponse.Rcode])
	}
	if !containsRRType(negativeResponse.Ns, dns.TypeSOA) || !containsRRType(negativeResponse.Ns, dns.TypeNSEC) || !containsRRType(negativeResponse.Ns, dns.TypeRRSIG) {
		t.Fatalf("negative authority section lacks DNSSEC proof: %v", negativeResponse.Ns)
	}
	verifyResponseRRSet(t, key, negativeResponse.Ns, dns.TypeSOA)
	verifyResponseSignatures(t, key, negativeResponse.Ns)

	emptyNonTerminal := new(dns.Msg)
	emptyNonTerminal.SetQuestion("child.example.test.", dns.TypeAAAA)
	emptyNonTerminal.SetEdns0(1232, true)
	emptyResponse := serveDNSSECRequest(t, handler, emptyNonTerminal)
	if emptyResponse.Rcode != dns.RcodeSuccess || !containsRRType(emptyResponse.Ns, dns.TypeNSEC) {
		t.Fatalf("empty non-terminal response = %+v", emptyResponse)
	}
	verifyResponseSignatures(t, key, emptyResponse.Ns)

	wildcardNoData := new(dns.Msg)
	wildcardNoData.SetQuestion("host.wild.example.test.", dns.TypeAAAA)
	wildcardNoData.SetEdns0(1232, true)
	wildcardResponse := serveDNSSECRequest(t, handler, wildcardNoData)
	if wildcardResponse.Rcode != dns.RcodeSuccess || !containsRRType(wildcardResponse.Ns, dns.TypeNSEC) {
		t.Fatalf("wildcard NODATA response = %+v", wildcardResponse)
	}
	verifyResponseSignatures(t, key, wildcardResponse.Ns)

	wildcardPositive := new(dns.Msg)
	wildcardPositive.SetQuestion("host.wild.example.test.", dns.TypeA)
	wildcardPositive.SetEdns0(1232, true)
	wildcardPositiveResponse := serveDNSSECRequest(t, handler, wildcardPositive)
	verifyResponseRRSet(t, key, wildcardPositiveResponse.Answer, dns.TypeA)
	if !containsRRType(wildcardPositiveResponse.Ns, dns.TypeNSEC) {
		t.Fatalf("wildcard positive response lacks NSEC proof: %+v", wildcardPositiveResponse)
	}
	verifyResponseSignatures(t, key, wildcardPositiveResponse.Ns)

	plain := new(dns.Msg)
	plain.SetQuestion("www.example.test.", dns.TypeA)
	plainResponse := serveDNSSECRequest(t, handler, plain)
	if containsRRType(plainResponse.Answer, dns.TypeRRSIG) || containsRRType(plainResponse.Ns, dns.TypeNSEC) {
		t.Fatalf("plain response exposed DNSSEC records: %+v", plainResponse)
	}
}

func TestSignedAuthoritativeNSEC3Responses(t *testing.T) {
	t.Parallel()
	configuration := dnssecTestConfiguration{Config: config.Defaults()}
	zone := dnssecTestZone("ed25519")
	zone.DNSSECDenial = "nsec3"
	configuration.Zones = []zonemodel.Zone{zone}
	signer := newDNSSECSigner(memoryDNSSECVault{})
	signer.now = func() time.Time { return time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC) }
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		t.Fatal(err)
	}
	key := verifySignedTestZone(t, configuration.Zones[0])
	runtime, err := compileRuntime(configuration.Config, configuration.Zones, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := dnsserver.NewHandler(runtime)

	positive := new(dns.Msg)
	positive.SetQuestion("www.example.test.", dns.TypeA)
	positive.SetEdns0(1232, true)
	verifyResponseRRSet(t, key, serveDNSSECRequest(t, handler, positive).Answer, dns.TypeA)

	missing := new(dns.Msg)
	missing.SetQuestion("missing.example.test.", dns.TypeA)
	missing.SetEdns0(1232, true)
	missingResponse := serveDNSSECRequest(t, handler, missing)
	if missingResponse.Rcode != dns.RcodeNameError || containsRRType(missingResponse.Ns, dns.TypeNSEC) || !containsRRType(missingResponse.Ns, dns.TypeNSEC3) {
		t.Fatalf("NSEC3 NXDOMAIN response = %+v", missingResponse)
	}
	verifyResponseSignatures(t, key, missingResponse.Ns)
	assertNSEC3Proof(t, missingResponse.Ns, "example.test.", "missing.example.test.", "*.example.test.")

	empty := new(dns.Msg)
	empty.SetQuestion("child.example.test.", dns.TypeAAAA)
	empty.SetEdns0(1232, true)
	emptyResponse := serveDNSSECRequest(t, handler, empty)
	if emptyResponse.Rcode != dns.RcodeSuccess {
		t.Fatalf("NSEC3 empty non-terminal rcode = %s", dns.RcodeToString[emptyResponse.Rcode])
	}
	assertNSEC3Match(t, emptyResponse.Ns, "child.example.test.")
	verifyResponseSignatures(t, key, emptyResponse.Ns)

	wildcard := new(dns.Msg)
	wildcard.SetQuestion("host.wild.example.test.", dns.TypeAAAA)
	wildcard.SetEdns0(1232, true)
	wildcardResponse := serveDNSSECRequest(t, handler, wildcard)
	assertNSEC3Proof(t, wildcardResponse.Ns, "*.wild.example.test.", "host.wild.example.test.")
	verifyResponseSignatures(t, key, wildcardResponse.Ns)

	wildcardPositive := new(dns.Msg)
	wildcardPositive.SetQuestion("host.wild.example.test.", dns.TypeA)
	wildcardPositive.SetEdns0(1232, true)
	wildcardPositiveResponse := serveDNSSECRequest(t, handler, wildcardPositive)
	verifyResponseRRSet(t, key, wildcardPositiveResponse.Answer, dns.TypeA)
	assertNSEC3Proof(t, wildcardPositiveResponse.Ns, "wild.example.test.", "host.wild.example.test.")
	verifyResponseSignatures(t, key, wildcardPositiveResponse.Ns)
}

func dnssecTestZone(algorithm string) zonemodel.Zone {
	return zonemodel.Zone{
		Name: "example.test", Type: "primary", DefaultTTL: 300,
		DNSSEC: true, DNSSECAlgorithm: algorithm,
		ZSKLifetime: zonemodel.Duration{Duration: 30 * 24 * time.Hour}, KSKLifetime: zonemodel.Duration{Duration: 365 * 24 * time.Hour},
		KeyPrepublish: zonemodel.Duration{Duration: 24 * time.Hour}, KeyRetireAfter: zonemodel.Duration{Duration: 7 * 24 * time.Hour},
		Records: []zonemodel.Record{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 2026080901 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "ns1", Type: "A", TTL: 300, Value: "192.0.2.53"},
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.10"},
			{Name: "deep.child", Type: "A", TTL: 300, Value: "192.0.2.11"},
			{Name: "*.wild", Type: "A", TTL: 300, Value: "192.0.2.12"},
		},
	}
}

func verifySignedTestZone(t *testing.T, zone zonemodel.Zone) *dns.DNSKEY {
	t.Helper()
	records, err := activeZoneRRs(zone, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keys := make(map[uint16]*dns.DNSKEY)
	var dataKey *dns.DNSKEY
	unsigned := make([]dns.RR, 0, len(records))
	signatures := make(map[string][]*dns.RRSIG)
	for _, record := range records {
		if typed, ok := record.(*dns.DNSKEY); ok {
			keys[typed.KeyTag()] = typed
		}
		if typed, ok := record.(*dns.RRSIG); ok {
			signatures[signingRRSetKey(typed.Hdr.Name, typed.TypeCovered)] = append(signatures[signingRRSetKey(typed.Hdr.Name, typed.TypeCovered)], typed)
			continue
		}
		unsigned = append(unsigned, record)
	}
	denialPresent := containsRRType(unsigned, dns.TypeNSEC)
	if zone.DNSSECDenial == "nsec3" {
		denialPresent = containsRRType(unsigned, dns.TypeNSEC3) && containsRRType(unsigned, dns.TypeNSEC3PARAM)
	}
	if len(keys) < 2 || !denialPresent {
		t.Fatalf("signed zone missing DNSKEY or denial records: %v", records)
	}
	for rrsetKey, rrset := range groupSigningRRSets(unsigned) {
		matching := signatures[rrsetKey]
		if len(matching) == 0 {
			t.Fatalf("%s has no signatures", rrsetKey)
		}
		for _, signature := range matching {
			key := keys[signature.KeyTag]
			if key == nil {
				t.Fatalf("%s signature references unpublished key %d", rrsetKey, signature.KeyTag)
			}
			if err := signature.Verify(key, rrset); err != nil {
				t.Fatalf("verify %s with key %d: %v", rrsetKey, signature.KeyTag, err)
			}
			if rrset[0].Header().Rrtype == dns.TypeSOA {
				dataKey = key
			}
		}
	}
	if dataKey == nil {
		t.Fatal("signed zone has no active data-signing key")
	}
	return dataKey
}

func keyStatusByRoleState(t *testing.T, status dnssecstate.Status, role, state string) dnssecstate.KeyStatus {
	t.Helper()
	for _, key := range status.Keys {
		if key.Role == role && key.State == state {
			return key
		}
	}
	t.Fatalf("DNSSEC status has no %s key in %s: %+v", role, state, status.Keys)
	return dnssecstate.KeyStatus{}
}

func keysByRole(status dnssecstate.Status, role string) []dnssecstate.KeyStatus {
	return slices.DeleteFunc(append([]dnssecstate.KeyStatus(nil), status.Keys...), func(key dnssecstate.KeyStatus) bool {
		return key.Role != role
	})
}

func assertDNSKEYSignatureCount(t *testing.T, zone zonemodel.Zone, expected int) {
	t.Helper()
	count := 0
	for _, record := range zone.Records {
		rr, err := configuredRecordRR(zone, record)
		if err != nil {
			t.Fatal(err)
		}
		if signature, ok := rr.(*dns.RRSIG); ok && signature.TypeCovered == dns.TypeDNSKEY {
			count++
		}
	}
	if count != expected {
		t.Fatalf("DNSKEY signatures = %d, want %d", count, expected)
	}
}

func zoneKeyByRole(t *testing.T, zone zonemodel.Zone, ksk bool) *dns.DNSKEY {
	t.Helper()
	records, err := activeZoneRRs(zone, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		key, ok := record.(*dns.DNSKEY)
		if ok && (key.Flags&dns.SEP != 0) == ksk {
			return key
		}
	}
	t.Fatalf("zone has no matching DNSSEC key role: %v", records)
	return nil
}

func assertNSEC3Proof(t *testing.T, records []dns.RR, exact string, covered ...string) {
	t.Helper()
	assertNSEC3Match(t, records, exact)
	for _, name := range covered {
		if !slices.ContainsFunc(records, func(record dns.RR) bool {
			nsec3, ok := record.(*dns.NSEC3)
			return ok && nsec3.Cover(name)
		}) {
			t.Errorf("NSEC3 response does not cover %s: %v", name, records)
		}
	}
}

func assertNSEC3Match(t *testing.T, records []dns.RR, name string) {
	t.Helper()
	if !slices.ContainsFunc(records, func(record dns.RR) bool {
		nsec3, ok := record.(*dns.NSEC3)
		return ok && nsec3.Match(name)
	}) {
		t.Errorf("NSEC3 response has no exact match for %s: %v", name, records)
	}
}

func containsRRType(records []dns.RR, recordType uint16) bool {
	for _, record := range records {
		if record.Header().Rrtype == recordType {
			return true
		}
	}
	return false
}

func verifyResponseRRSet(t *testing.T, key *dns.DNSKEY, records []dns.RR, recordType uint16) {
	t.Helper()
	var rrset []dns.RR
	var signature *dns.RRSIG
	for _, record := range records {
		if record.Header().Rrtype == recordType {
			rrset = append(rrset, record)
		}
		if typed, ok := record.(*dns.RRSIG); ok && typed.TypeCovered == recordType {
			signature = typed
		}
	}
	if len(rrset) == 0 || signature == nil {
		t.Fatalf("response lacks %s RRset or signature: %v", dns.TypeToString[recordType], records)
	}
	if err := signature.Verify(key, rrset); err != nil {
		t.Fatalf("verify response %s: %v", dns.TypeToString[recordType], err)
	}
}

func verifyResponseSignatures(t *testing.T, key *dns.DNSKEY, records []dns.RR) {
	t.Helper()
	rrsets := make(map[string][]dns.RR)
	var signatures []*dns.RRSIG
	for _, record := range records {
		if signature, ok := record.(*dns.RRSIG); ok {
			signatures = append(signatures, signature)
			continue
		}
		rrsets[signingRRSetKey(record.Header().Name, record.Header().Rrtype)] = append(rrsets[signingRRSetKey(record.Header().Name, record.Header().Rrtype)], record)
	}
	for _, signature := range signatures {
		rrset := rrsets[signingRRSetKey(signature.Hdr.Name, signature.TypeCovered)]
		if len(rrset) == 0 {
			t.Fatalf("signature has no response RRset: %s", signature)
		}
		if err := signature.Verify(key, rrset); err != nil {
			t.Fatalf("verify response signature %s: %v", signature, err)
		}
	}
}

type dnssecCaptureWriter struct{ message *dns.Msg }

func (writer *dnssecCaptureWriter) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (writer *dnssecCaptureWriter) RemoteAddr() net.Addr { return &net.UDPAddr{} }
func (writer *dnssecCaptureWriter) WriteMsg(message *dns.Msg) error {
	writer.message = message.Copy()
	return nil
}
func (writer *dnssecCaptureWriter) Write(value []byte) (int, error) { return len(value), nil }
func (writer *dnssecCaptureWriter) Close() error                    { return nil }
func (writer *dnssecCaptureWriter) TsigStatus() error               { return nil }
func (writer *dnssecCaptureWriter) TsigTimersOnly(bool)             {}
func (writer *dnssecCaptureWriter) Hijack()                         {}

func serveDNSSECRequest(t *testing.T, handler *dnsserver.Handler, request *dns.Msg) *dns.Msg {
	t.Helper()
	writer := new(dnssecCaptureWriter)
	handler.ServeDNS(writer, request)
	if writer.message == nil {
		t.Fatal("DNS handler did not write a response")
	}
	return writer.message
}

func BenchmarkDNSSECZoneResigning(b *testing.B) {
	configuration := dnssecTestConfiguration{Zones: []zonemodel.Zone{dnssecTestZone("ed25519")}}
	signer := newDNSSECSigner(memoryDNSSECVault{})
	signer.now = func() time.Time { return time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC) }
	if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		zone := &configuration.Zones[0]
		for index := range zone.Records {
			if zone.Records[index].Name == "www" && zone.Records[index].Type == "A" {
				if iteration%2 == 0 {
					zone.Records[index].Value = "192.0.2.20"
				} else {
					zone.Records[index].Value = "192.0.2.21"
				}
			}
		}
		if err := advanceDynamicSOASerial(zone); err != nil {
			b.Fatal(err)
		}
		if err := signer.Prepare(context.Background(), &configuration.Zones); err != nil {
			b.Fatal(err)
		}
	}
}
