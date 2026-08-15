package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strings"
)

const maximumExecutableBytes = 256 << 20

func expectedChecksum(checksums []byte, assetName string) (string, error) {
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if strings.TrimPrefix(fields[1], "*") == assetName {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("%s is missing from checksums.txt", assetName)
}

func verifyChecksum(contents []byte, expected string) error {
	digest := sha256.Sum256(contents)
	actual := hex.EncodeToString(digest[:])
	if actual != strings.ToLower(expected) {
		return fmt.Errorf("checksum verification failed: expected %s, got %s", expected, actual)
	}
	return nil
}

// extractExecutable returns the Sable executable stored in a release archive.
func extractExecutable(assetName string, archive []byte) ([]byte, error) {
	if strings.HasSuffix(assetName, ".zip") {
		return extractFromZip(archive)
	}
	return extractFromTarGzip(archive)
}

func extractFromTarGzip(archive []byte) ([]byte, error) {
	decompressor, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("read release archive: %w", err)
	}
	defer decompressor.Close()
	reader := tar.NewReader(decompressor)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read release archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg || !isExecutableEntry(header.Name) {
			continue
		}
		contents, err := io.ReadAll(io.LimitReader(reader, maximumExecutableBytes))
		if err != nil {
			return nil, fmt.Errorf("read Sable executable from release archive: %w", err)
		}
		return contents, nil
	}
	return nil, errMissingExecutable
}

func extractFromZip(archive []byte) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("read release archive: %w", err)
	}
	for _, entry := range reader.File {
		if entry.FileInfo().IsDir() || !isExecutableEntry(entry.Name) {
			continue
		}
		file, err := entry.Open()
		if err != nil {
			return nil, fmt.Errorf("read Sable executable from release archive: %w", err)
		}
		defer file.Close()
		contents, err := io.ReadAll(io.LimitReader(file, maximumExecutableBytes))
		if err != nil {
			return nil, fmt.Errorf("read Sable executable from release archive: %w", err)
		}
		return contents, nil
	}
	return nil, errMissingExecutable
}

func isExecutableEntry(name string) bool {
	base := path.Base(strings.ReplaceAll(name, "\\", "/"))
	return base == "sable" || base == "sable.exe"
}
