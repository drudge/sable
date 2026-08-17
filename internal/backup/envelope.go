package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
)

// ErrPassphraseRequired reports an empty passphrase. A backup always carries
// the vault key, so an unsealed archive would hand over every DNSSEC private
// key and integration credential in the deployment.
var ErrPassphraseRequired = errors.New("a backup passphrase is required")

// ErrWrongPassphrase reports a passphrase that does not open the archive. It
// is also returned for a corrupted or tampered archive, because authenticated
// encryption cannot tell the two apart.
var ErrWrongPassphrase = errors.New("the passphrase does not open this backup")

// ErrNotBackup reports a file that is not a Sable backup at all.
var ErrNotBackup = errors.New("file is not a Sable backup")

const (
	envelopeMagic     = "SABLEBAK"
	envelopeVersion   = 1
	envelopeSaltSize  = 16
	envelopeKeySize   = 32
	maximumHeaderSize = 64 << 10
	maximumSealedSize = 512 << 20

	// Argon2id parameters follow the RFC 9106 second recommended option, which
	// is sized for a server that also has to keep answering DNS while an
	// operator downloads a backup.
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
)

// envelopeSummary is the plaintext description of a sealed archive. It is
// authenticated as additional data, so a tampered summary fails to open.
type envelopeSummary struct {
	CreatedAt    time.Time `json:"created_at"`
	SableVersion string    `json:"sable_version"`
	Hostname     string    `json:"hostname"`
}

// Summary is what Inspect can report without the passphrase.
type Summary struct {
	FormatVersion int       `json:"format_version"`
	CreatedAt     time.Time `json:"created_at"`
	SableVersion  string    `json:"sable_version"`
	Hostname      string    `json:"hostname"`
}

type envelopeHeader struct {
	Version    int             `json:"version"`
	KDF        string          `json:"kdf"`
	Salt       []byte          `json:"salt"`
	Time       uint32          `json:"time"`
	Memory     uint32          `json:"memory"`
	Threads    uint8           `json:"threads"`
	Nonce      []byte          `json:"nonce"`
	Summary    envelopeSummary `json:"summary"`
	FormatHint int             `json:"format_hint"`
}

func seal(body []byte, passphrase string, summary envelopeSummary) ([]byte, error) {
	salt := make([]byte, envelopeSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate backup salt: %w", err)
	}
	aead, err := envelopeCipher(passphrase, salt, argonTime, argonMemory, argonThreads)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate backup nonce: %w", err)
	}
	header := envelopeHeader{
		Version: envelopeVersion, KDF: "argon2id", Salt: salt,
		Time: argonTime, Memory: argonMemory, Threads: argonThreads,
		Nonce: nonce, Summary: summary, FormatHint: FormatVersion,
	}
	encodedHeader, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("encode backup header: %w", err)
	}
	sealed := aead.Seal(nil, nonce, body, encodedHeader)

	output := make([]byte, 0, len(envelopeMagic)+5+len(encodedHeader)+len(sealed))
	output = append(output, envelopeMagic...)
	output = append(output, envelopeVersion)
	output = binary.BigEndian.AppendUint32(output, uint32(len(encodedHeader)))
	output = append(output, encodedHeader...)
	output = append(output, sealed...)
	return output, nil
}

func open(contents []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, ErrPassphraseRequired
	}
	header, encodedHeader, sealed, err := splitEnvelope(contents)
	if err != nil {
		return nil, err
	}
	aead, err := envelopeCipher(passphrase, header.Salt, header.Time, header.Memory, header.Threads)
	if err != nil {
		return nil, err
	}
	if len(header.Nonce) != aead.NonceSize() {
		return nil, ErrNotBackup
	}
	body, err := aead.Open(nil, header.Nonce, sealed, encodedHeader)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return body, nil
}

func inspect(contents []byte) (Summary, error) {
	header, _, _, err := splitEnvelope(contents)
	if err != nil {
		return Summary{}, err
	}
	return Summary{
		FormatVersion: header.FormatHint,
		CreatedAt:     header.Summary.CreatedAt,
		SableVersion:  header.Summary.SableVersion,
		Hostname:      header.Summary.Hostname,
	}, nil
}

func splitEnvelope(contents []byte) (envelopeHeader, []byte, []byte, error) {
	prefix := len(envelopeMagic) + 5
	if len(contents) < prefix || string(contents[:len(envelopeMagic)]) != envelopeMagic {
		return envelopeHeader{}, nil, nil, ErrNotBackup
	}
	if contents[len(envelopeMagic)] != envelopeVersion {
		return envelopeHeader{}, nil, nil, fmt.Errorf("backup envelope version %d is unsupported", contents[len(envelopeMagic)])
	}
	headerLength := binary.BigEndian.Uint32(contents[len(envelopeMagic)+1 : prefix])
	if headerLength == 0 || headerLength > maximumHeaderSize || int(headerLength) > len(contents)-prefix {
		return envelopeHeader{}, nil, nil, ErrNotBackup
	}
	encodedHeader := contents[prefix : prefix+int(headerLength)]
	var header envelopeHeader
	if err := json.Unmarshal(encodedHeader, &header); err != nil {
		return envelopeHeader{}, nil, nil, ErrNotBackup
	}
	if header.KDF != "argon2id" {
		return envelopeHeader{}, nil, nil, fmt.Errorf("backup key derivation %q is unsupported", header.KDF)
	}
	sealed := contents[prefix+int(headerLength):]
	if len(sealed) == 0 || len(sealed) > maximumSealedSize {
		return envelopeHeader{}, nil, nil, ErrNotBackup
	}
	return header, encodedHeader, sealed, nil
}

func envelopeCipher(passphrase string, salt []byte, iterations, memory uint32, threads uint8) (cipher.AEAD, error) {
	if len(salt) != envelopeSaltSize {
		return nil, ErrNotBackup
	}
	// Bound the work a hostile header can ask for; the sealing side never
	// exceeds these, so a larger request only ever comes from a crafted file.
	if iterations == 0 || iterations > 16 || memory == 0 || memory > 1<<20 || threads == 0 || threads > 16 {
		return nil, ErrNotBackup
	}
	key := argon2.IDKey([]byte(passphrase), salt, iterations, memory, threads, envelopeKeySize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize backup encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize backup authentication: %w", err)
	}
	return aead, nil
}
