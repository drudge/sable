// Package backup encodes and decodes the portable archive that carries a
// complete Sable deployment: its configuration, zones, authorization state,
// encrypted secrets, the vault key those secrets need, DNSSEC trust anchors,
// TLS material, and cluster membership. The archive is always sealed with an
// operator passphrase because it contains the vault key in the clear.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/trustanchor"
	"github.com/drudge/sable/internal/zone"
)

// FormatVersion identifies the archive layout. Restore refuses an archive it
// does not recognize rather than guessing at a future layout.
const FormatVersion = 1

// Section names the independently restorable parts of an archive. They are
// recorded in the manifest so an operator can see what a backup carries
// without decoding every member.
const (
	SectionConfiguration = "configuration"
	SectionZones         = "zones"
	SectionAuthorization = "authorization"
	SectionSecrets       = "secrets"
	SectionTrustAnchors  = "trust_anchors"
	SectionCertificates  = "certificates"
	SectionCluster       = "cluster"
)

// AllSections lists every section in restore order. Configuration comes first
// because the remaining sections are written to paths it resolves.
var AllSections = []string{
	SectionConfiguration,
	SectionZones,
	SectionAuthorization,
	SectionSecrets,
	SectionTrustAnchors,
	SectionCertificates,
	SectionCluster,
}

const (
	manifestEntry        = "manifest.json"
	configurationEntry   = "configuration/sable.toml"
	zonesEntry           = "zones/zones.json"
	authorizationEntry   = "authorization/authorization.json"
	secretsEntry         = "secrets/secrets.json"
	vaultKeyEntry        = "secrets/vault.key"
	trustAnchorsEntry    = "trust_anchors/trust_anchors.json"
	certificatesPrefix   = "certificates/"
	clusterPrefix        = "cluster/"
	maximumMemberSize    = 64 << 20
	maximumArchiveMember = 4096
)

// Manifest describes the archive to a human and to the restore path.
type Manifest struct {
	FormatVersion  int       `json:"format_version"`
	CreatedAt      time.Time `json:"created_at"`
	SableVersion   string    `json:"sable_version"`
	Hostname       string    `json:"hostname"`
	DatabaseDriver string    `json:"database_driver"`
	NodeID         string    `json:"node_id,omitempty"`
	ClusterID      string    `json:"cluster_id,omitempty"`
	Sections       []string  `json:"sections"`
}

// Secret is one row of the encrypted secret store. The ciphertext travels as
// stored; only the vault key alongside it can open the value.
type Secret struct {
	Name       string    `json:"name"`
	Ciphertext string    `json:"ciphertext"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// File is a captured file belonging to a file-backed section. Path is relative
// to that section's root directory on the restoring node, never absolute.
type File struct {
	Section  string      `json:"-"`
	Path     string      `json:"-"`
	Mode     fs.FileMode `json:"-"`
	Contents []byte      `json:"-"`
}

// Archive is the decoded content of a backup.
type Archive struct {
	Manifest      Manifest
	Configuration []byte
	Zones         []zone.Zone
	Authorization store.AuthorizationState
	Secrets       []Secret
	VaultKey      []byte
	TrustAnchors  []trustanchor.Snapshot
	Files         []File
}

// SectionFiles returns the captured files belonging to one file-backed section.
func (archive Archive) SectionFiles(section string) []File {
	files := make([]File, 0, len(archive.Files))
	for _, file := range archive.Files {
		if file.Section == section {
			files = append(files, file)
		}
	}
	return files
}

// HasSection reports whether the manifest claims the named section.
func (archive Archive) HasSection(section string) bool {
	return slices.Contains(archive.Manifest.Sections, section)
}

// Encode seals an archive with the passphrase. The passphrase is mandatory
// because a backup always carries the vault key that decrypts DNSSEC private
// keys and integration credentials.
func Encode(archive Archive, passphrase string) ([]byte, error) {
	if strings.TrimSpace(passphrase) == "" {
		return nil, ErrPassphraseRequired
	}
	body, err := encodeBody(archive)
	if err != nil {
		return nil, err
	}
	return seal(body, passphrase, envelopeSummary{
		CreatedAt:    archive.Manifest.CreatedAt,
		SableVersion: archive.Manifest.SableVersion,
		Hostname:     archive.Manifest.Hostname,
	})
}

// Decode opens a sealed archive.
func Decode(contents []byte, passphrase string) (Archive, error) {
	body, err := open(contents, passphrase)
	if err != nil {
		return Archive{}, err
	}
	return decodeBody(body)
}

// Inspect reads the unencrypted envelope header, which lets the console and
// the CLI describe a backup before an operator commits to a passphrase.
func Inspect(contents []byte) (Summary, error) {
	return inspect(contents)
}

func encodeBody(archive Archive) ([]byte, error) {
	archive.Manifest.FormatVersion = FormatVersion
	buffer := &bytes.Buffer{}
	compressor := gzip.NewWriter(buffer)
	writer := tar.NewWriter(compressor)

	manifest, err := json.MarshalIndent(archive.Manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode backup manifest: %w", err)
	}
	if err := writeMember(writer, manifestEntry, 0o600, manifest); err != nil {
		return nil, err
	}
	if archive.HasSection(SectionConfiguration) {
		if err := writeMember(writer, configurationEntry, 0o600, archive.Configuration); err != nil {
			return nil, err
		}
	}
	if archive.HasSection(SectionZones) {
		if err := writeJSONMember(writer, zonesEntry, archive.Zones); err != nil {
			return nil, err
		}
	}
	if archive.HasSection(SectionAuthorization) {
		if err := writeJSONMember(writer, authorizationEntry, archive.Authorization); err != nil {
			return nil, err
		}
	}
	if archive.HasSection(SectionSecrets) {
		if err := writeJSONMember(writer, secretsEntry, archive.Secrets); err != nil {
			return nil, err
		}
		if len(archive.VaultKey) > 0 {
			if err := writeMember(writer, vaultKeyEntry, 0o600, archive.VaultKey); err != nil {
				return nil, err
			}
		}
	}
	if archive.HasSection(SectionTrustAnchors) {
		if err := writeJSONMember(writer, trustAnchorsEntry, archive.TrustAnchors); err != nil {
			return nil, err
		}
	}
	for _, file := range archive.Files {
		prefix, err := sectionPrefix(file.Section)
		if err != nil {
			return nil, err
		}
		if !archive.HasSection(file.Section) {
			continue
		}
		relative, err := safeRelativePath(file.Path)
		if err != nil {
			return nil, err
		}
		mode := file.Mode.Perm()
		if mode == 0 {
			mode = 0o600
		}
		if err := writeMember(writer, prefix+relative, mode, file.Contents); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finish backup archive: %w", err)
	}
	if err := compressor.Close(); err != nil {
		return nil, fmt.Errorf("compress backup archive: %w", err)
	}
	return buffer.Bytes(), nil
}

func decodeBody(body []byte) (Archive, error) {
	decompressor, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return Archive{}, fmt.Errorf("decompress backup archive: %w", err)
	}
	defer decompressor.Close()

	archive := Archive{}
	manifestSeen := false
	reader := tar.NewReader(decompressor)
	for members := 0; ; members++ {
		if members > maximumArchiveMember {
			return Archive{}, errors.New("backup archive holds too many members")
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Archive{}, fmt.Errorf("read backup archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		name, err := safeRelativePath(header.Name)
		if err != nil {
			return Archive{}, err
		}
		contents, err := readMember(reader)
		if err != nil {
			return Archive{}, fmt.Errorf("read %s: %w", name, err)
		}
		switch {
		case name == manifestEntry:
			if err := json.Unmarshal(contents, &archive.Manifest); err != nil {
				return Archive{}, fmt.Errorf("decode backup manifest: %w", err)
			}
			manifestSeen = true
		case name == configurationEntry:
			archive.Configuration = contents
		case name == zonesEntry:
			if err := json.Unmarshal(contents, &archive.Zones); err != nil {
				return Archive{}, fmt.Errorf("decode backup zones: %w", err)
			}
		case name == authorizationEntry:
			if err := json.Unmarshal(contents, &archive.Authorization); err != nil {
				return Archive{}, fmt.Errorf("decode backup authorization: %w", err)
			}
		case name == secretsEntry:
			if err := json.Unmarshal(contents, &archive.Secrets); err != nil {
				return Archive{}, fmt.Errorf("decode backup secrets: %w", err)
			}
		case name == vaultKeyEntry:
			archive.VaultKey = contents
		case name == trustAnchorsEntry:
			if err := json.Unmarshal(contents, &archive.TrustAnchors); err != nil {
				return Archive{}, fmt.Errorf("decode backup trust anchors: %w", err)
			}
		case strings.HasPrefix(name, certificatesPrefix):
			archive.Files = append(archive.Files, File{
				Section:  SectionCertificates,
				Path:     strings.TrimPrefix(name, certificatesPrefix),
				Mode:     fs.FileMode(header.Mode).Perm(),
				Contents: contents,
			})
		case strings.HasPrefix(name, clusterPrefix):
			archive.Files = append(archive.Files, File{
				Section:  SectionCluster,
				Path:     strings.TrimPrefix(name, clusterPrefix),
				Mode:     fs.FileMode(header.Mode).Perm(),
				Contents: contents,
			})
		}
	}
	if !manifestSeen {
		return Archive{}, errors.New("backup archive has no manifest")
	}
	if archive.Manifest.FormatVersion != FormatVersion {
		return Archive{}, fmt.Errorf("backup format version %d is unsupported", archive.Manifest.FormatVersion)
	}
	for _, section := range archive.Manifest.Sections {
		if !slices.Contains(AllSections, section) {
			return Archive{}, fmt.Errorf("backup archive names unknown section %q", section)
		}
	}
	return archive, nil
}

func sectionPrefix(section string) (string, error) {
	switch section {
	case SectionCertificates:
		return certificatesPrefix, nil
	case SectionCluster:
		return clusterPrefix, nil
	default:
		return "", fmt.Errorf("section %q does not carry files", section)
	}
}

// safeRelativePath rejects the absolute and parent-relative member names an
// attacker would use to make restore write outside the data directory.
func safeRelativePath(name string) (string, error) {
	cleaned := path.Clean(strings.ReplaceAll(name, `\`, "/"))
	if cleaned == "." || cleaned == "/" || cleaned == "" {
		return "", fmt.Errorf("backup archive member %q has no name", name)
	}
	if path.IsAbs(cleaned) || strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return "", fmt.Errorf("backup archive member %q escapes the archive root", name)
	}
	return cleaned, nil
}

func writeJSONMember(writer *tar.Writer, name string, value any) error {
	contents, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	return writeMember(writer, name, 0o600, contents)
}

func writeMember(writer *tar.Writer, name string, mode fs.FileMode, contents []byte) error {
	header := &tar.Header{
		Name:     name,
		Mode:     int64(mode.Perm()),
		Size:     int64(len(contents)),
		Typeflag: tar.TypeReg,
		// A fixed modification time keeps two backups of identical state
		// byte-identical before sealing, which makes them easy to compare.
		ModTime: time.Unix(0, 0).UTC(),
	}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("write %s header: %w", name, err)
	}
	if _, err := writer.Write(contents); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

func readMember(reader io.Reader) ([]byte, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, maximumMemberSize+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > maximumMemberSize {
		return nil, errors.New("archive member is too large")
	}
	return contents, nil
}
