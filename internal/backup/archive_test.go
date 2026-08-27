package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/trustanchor"
	"github.com/drudge/sable/internal/zone"
)

func sampleArchive() Archive {
	return Archive{
		Manifest: Manifest{
			CreatedAt:      time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
			SableVersion:   "v1.2.3",
			Hostname:       "ns1.example.internal",
			DatabaseDriver: "sqlite",
			Sections:       AllSections,
		},
		Configuration: []byte("[server]\nhttp_listen = \"127.0.0.1:5380\"\n"),
		Zones: []zone.Zone{{
			ID: "zone-one", Name: "example.internal.", Type: "primary", DefaultTTL: 300,
			Records: []zone.Record{{Name: "www", Type: "A", Value: "10.0.0.1", TTL: 300}},
		}},
		Authorization: store.AuthorizationState{
			Initialized: true,
			Users:       []store.AuthorizationUser{{ID: 1, Username: "admin", PasswordHash: "hash", RoleIDs: []int64{1}}},
			Roles:       []store.AuthorizationRole{{ID: 1, Name: "Administrator", BuiltIn: true}},
			Tokens:      []store.AuthorizationToken{},
		},
		Secrets:      []Secret{{Name: "dnssec/example.internal.", Ciphertext: "v1:abcd", UpdatedAt: time.Unix(1700000000, 0).UTC()}},
		VaultKey:     bytes.Repeat([]byte{0x2a}, 32),
		TrustAnchors: []trustanchor.Snapshot{{Status: trustanchor.Status{Owner: ".", Initialized: true}}},
		Files: []File{
			{Section: SectionCertificates, Path: "manual/certificate.pem", Mode: 0o600, Contents: []byte("certificate")},
			{Section: SectionCluster, Path: "data/cluster.json", Mode: 0o600, Contents: []byte(`{"cluster_id":"abc"}`)},
		},
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	original := sampleArchive()
	sealed, err := Encode(original, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(sealed, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.Manifest.FormatVersion != FormatVersion {
		t.Fatalf("format version = %d, want %d", decoded.Manifest.FormatVersion, FormatVersion)
	}
	if !bytes.Equal(decoded.Configuration, original.Configuration) {
		t.Fatalf("configuration = %q, want %q", decoded.Configuration, original.Configuration)
	}
	if !bytes.Equal(decoded.VaultKey, original.VaultKey) {
		t.Fatal("vault key did not survive the round trip")
	}
	if !reflect.DeepEqual(decoded.Zones, original.Zones) {
		t.Fatalf("zones = %+v, want %+v", decoded.Zones, original.Zones)
	}
	if !reflect.DeepEqual(decoded.Authorization, original.Authorization) {
		t.Fatalf("authorization = %+v, want %+v", decoded.Authorization, original.Authorization)
	}
	if !reflect.DeepEqual(decoded.Secrets, original.Secrets) {
		t.Fatalf("secrets = %+v, want %+v", decoded.Secrets, original.Secrets)
	}
	if !reflect.DeepEqual(decoded.TrustAnchors, original.TrustAnchors) {
		t.Fatalf("trust anchors = %+v, want %+v", decoded.TrustAnchors, original.TrustAnchors)
	}
	certificates := decoded.SectionFiles(SectionCertificates)
	if len(certificates) != 1 || certificates[0].Path != "manual/certificate.pem" ||
		string(certificates[0].Contents) != "certificate" {
		t.Fatalf("certificate files = %+v", certificates)
	}
	cluster := decoded.SectionFiles(SectionCluster)
	if len(cluster) != 1 || cluster[0].Path != "data/cluster.json" {
		t.Fatalf("cluster files = %+v", cluster)
	}
}

func TestEncodeRequiresPassphrase(t *testing.T) {
	if _, err := Encode(sampleArchive(), "   "); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("Encode() error = %v, want ErrPassphraseRequired", err)
	}
}

func TestDecodeRejectsWrongPassphrase(t *testing.T) {
	sealed, err := Encode(sampleArchive(), "right")
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if _, err := Decode(sealed, "wrong"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Decode() error = %v, want ErrWrongPassphrase", err)
	}
}

func TestDecodeRejectsTamperedArchive(t *testing.T) {
	sealed, err := Encode(sampleArchive(), "passphrase")
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	sealed[len(sealed)-1] ^= 0xff
	if _, err := Decode(sealed, "passphrase"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Decode() error = %v, want ErrWrongPassphrase", err)
	}
}

func TestDecodeRejectsTamperedHeader(t *testing.T) {
	sealed, err := Encode(sampleArchive(), "passphrase")
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	// The plaintext summary is authenticated, so editing the recorded hostname
	// has to fail the open rather than quietly mislead an operator.
	index := bytes.Index(sealed, []byte("ns1.example.internal"))
	if index < 0 {
		t.Fatal("envelope summary is not in the header")
	}
	sealed[index] = 'X'
	if _, err := Decode(sealed, "passphrase"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Decode() error = %v, want ErrWrongPassphrase", err)
	}
}

func TestInspectReportsSummaryWithoutPassphrase(t *testing.T) {
	original := sampleArchive()
	sealed, err := Encode(original, "passphrase")
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	summary, err := Inspect(sealed)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !summary.CreatedAt.Equal(original.Manifest.CreatedAt) {
		t.Fatalf("created at = %s, want %s", summary.CreatedAt, original.Manifest.CreatedAt)
	}
	if summary.Hostname != original.Manifest.Hostname || summary.SableVersion != original.Manifest.SableVersion {
		t.Fatalf("summary = %+v", summary)
	}
	if summary.FormatVersion != FormatVersion {
		t.Fatalf("format version = %d, want %d", summary.FormatVersion, FormatVersion)
	}
}

func TestInspectRejectsForeignFile(t *testing.T) {
	if _, err := Inspect([]byte("not a sable backup at all")); !errors.Is(err, ErrNotBackup) {
		t.Fatalf("Inspect() error = %v, want ErrNotBackup", err)
	}
}

func TestEncodeSkipsSectionsOutsideTheManifest(t *testing.T) {
	original := sampleArchive()
	original.Manifest.Sections = []string{SectionConfiguration, SectionZones}
	sealed, err := Encode(original, "passphrase")
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(sealed, "passphrase")
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(decoded.Secrets) != 0 || len(decoded.VaultKey) != 0 {
		t.Fatal("secrets travelled in an archive that does not claim them")
	}
	if len(decoded.Files) != 0 {
		t.Fatalf("files = %+v, want none", decoded.Files)
	}
	if len(decoded.Zones) != 1 {
		t.Fatalf("zones = %d, want 1", len(decoded.Zones))
	}
}

func TestDecodeRejectsTraversingMember(t *testing.T) {
	body := &bytes.Buffer{}
	compressor := gzip.NewWriter(body)
	writer := tar.NewWriter(compressor)
	if err := writeMember(writer, "../../etc/shadow", 0o600, []byte("nope")); err != nil {
		t.Fatalf("writeMember() error = %v", err)
	}
	writer.Close()
	compressor.Close()

	if _, err := decodeBody(body.Bytes()); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("decodeBody() error = %v, want an escape rejection", err)
	}
}

func TestDecodeRejectsUnsupportedFormatVersion(t *testing.T) {
	body := &bytes.Buffer{}
	compressor := gzip.NewWriter(body)
	writer := tar.NewWriter(compressor)
	manifest, err := json.Marshal(Manifest{FormatVersion: FormatVersion + 1, Sections: []string{SectionZones}})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := writeMember(writer, manifestEntry, 0o600, manifest); err != nil {
		t.Fatalf("writeMember() error = %v", err)
	}
	writer.Close()
	compressor.Close()

	if _, err := decodeBody(body.Bytes()); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("decodeBody() error = %v, want an unsupported version rejection", err)
	}
}

func TestDecodeRejectsUnknownSection(t *testing.T) {
	body := &bytes.Buffer{}
	compressor := gzip.NewWriter(body)
	writer := tar.NewWriter(compressor)
	manifest, err := json.Marshal(Manifest{FormatVersion: FormatVersion, Sections: []string{"applications"}})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := writeMember(writer, manifestEntry, 0o600, manifest); err != nil {
		t.Fatalf("writeMember() error = %v", err)
	}
	writer.Close()
	compressor.Close()

	if _, err := decodeBody(body.Bytes()); err == nil || !strings.Contains(err.Error(), "unknown section") {
		t.Fatalf("decodeBody() error = %v, want an unknown section rejection", err)
	}
}

func TestDecodeRejectsCumulativeExpandedSize(t *testing.T) {
	manifest, err := json.Marshal(Manifest{FormatVersion: FormatVersion, Sections: []string{SectionConfiguration}})
	if err != nil {
		t.Fatal(err)
	}
	body := archiveBody(t,
		testArchiveMember{name: manifestEntry, contents: manifest},
		testArchiveMember{name: configurationEntry, contents: []byte("sixteen bytes!!!")},
	)
	limit := int64(len(manifest) + len("sixteen bytes!!"))
	if _, err := decodeBodyWithLimit(body, limit); err == nil || !strings.Contains(err.Error(), "decoded size limit") {
		t.Fatalf("decodeBodyWithLimit() error = %v, want cumulative size rejection", err)
	}
}

func TestDecodeRejectsDuplicateNormalizedMember(t *testing.T) {
	manifest, err := json.Marshal(Manifest{FormatVersion: FormatVersion, Sections: []string{SectionCertificates}})
	if err != nil {
		t.Fatal(err)
	}
	body := archiveBody(t,
		testArchiveMember{name: manifestEntry, contents: manifest},
		testArchiveMember{name: certificatesPrefix + "tls/certificate.pem", contents: []byte("first")},
		testArchiveMember{name: certificatesPrefix + "tls/./certificate.pem", contents: []byte("second")},
	)
	if _, err := decodeBody(body); err == nil || !strings.Contains(err.Error(), "repeats member") {
		t.Fatalf("decodeBody() error = %v, want duplicate member rejection", err)
	}
}

type testArchiveMember struct {
	name     string
	contents []byte
}

func archiveBody(t *testing.T, members ...testArchiveMember) []byte {
	t.Helper()
	body := &bytes.Buffer{}
	compressor := gzip.NewWriter(body)
	writer := tar.NewWriter(compressor)
	for _, member := range members {
		if err := writeMember(writer, member.name, 0o600, member.contents); err != nil {
			t.Fatalf("writeMember(%q) error = %v", member.name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}
