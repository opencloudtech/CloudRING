// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package velero118

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"path"
	"strings"
)

const (
	archiveMaxCompressedBytes = 64 << 20
	archiveMaxExpandedBytes   = 256 << 20
	archiveMaxEntries         = 65536
	archiveMaxEntryBytes      = 16 << 20
	archiveMaxDataUploadBytes = 2 << 20
	dataUploadResourcePrefix  = "resources/datauploads.velero.io/"
	preferredVersionPath      = "v2alpha1-preferredversion"
)

// ReadArchivedDataUpload extracts the exact normal and preferred-version copies
// of one explicitly selected DataUpload from a Velero BackupContents tar.gz.
// Other DataUploads in a multi-volume backup are ignored; the selected normal
// and preferred-version copies must still both exist and match exactly. It
// rejects links, traversal, duplicate paths, concatenated gzip streams and
// trailing tar data.
func ReadArchivedDataUpload(compressed io.Reader, namespace, name string) ([]byte, error) {
	if compressed == nil || !safeName(namespace) || !safeName(name) {
		return nil, errors.New("Velero BackupContents request is invalid")
	}
	compressedLimit := &io.LimitedReader{R: compressed, N: archiveMaxCompressedBytes + 1}
	bufferedCompressed := bufio.NewReader(compressedLimit)
	gzipReader, err := gzip.NewReader(bufferedCompressed)
	if err != nil {
		return nil, errors.New("Velero BackupContents is not a valid gzip stream")
	}
	gzipReader.Multistream(false)
	defer gzipReader.Close()
	expandedLimit := &io.LimitedReader{R: gzipReader, N: archiveMaxExpandedBytes + 1}
	bufferedExpanded := bufio.NewReader(expandedLimit)
	tarReader := tar.NewReader(bufferedExpanded)
	expected := map[string]bool{
		archivedDataUploadPath(namespace, name, false): true,
		archivedDataUploadPath(namespace, name, true):  true,
	}
	seen := map[string]bool{}
	seenAll := map[string]bool{}
	var selected []byte
	for entryCount := 0; ; entryCount++ {
		if entryCount >= archiveMaxEntries {
			zeroBytes(selected)
			return nil, errors.New("Velero BackupContents contains too many entries")
		}
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil || !safeArchivePath(header.Name) || seenAll[header.Name] {
			zeroBytes(selected)
			return nil, errors.New("Velero BackupContents tar path is malformed")
		}
		seenAll[header.Name] = true
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir || header.Size < 0 || header.Size > archiveMaxEntryBytes {
			zeroBytes(selected)
			return nil, errors.New("Velero BackupContents entry type or size is invalid")
		}
		relevant := expected[header.Name]
		if !relevant {
			copied, copyErr := io.CopyN(io.Discard, tarReader, header.Size)
			if copyErr != nil || copied != header.Size {
				zeroBytes(selected)
				return nil, errors.New("read Velero BackupContents entry")
			}
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size == 0 || header.Size > archiveMaxDataUploadBytes || seen[header.Name] {
			zeroBytes(selected)
			return nil, errors.New("archived Velero DataUpload entry is invalid")
		}
		payload, readErr := io.ReadAll(io.LimitReader(tarReader, archiveMaxDataUploadBytes+1))
		if readErr != nil || int64(len(payload)) != header.Size || len(payload) > archiveMaxDataUploadBytes {
			zeroBytes(payload)
			zeroBytes(selected)
			return nil, errors.New("read exact archived Velero DataUpload")
		}
		decoded, decodeErr := DecodeDataUpload(payload)
		if decodeErr != nil || decoded.Identity.Metadata.Namespace != namespace || decoded.Identity.Metadata.Name != name {
			zeroBytes(payload)
			zeroBytes(selected)
			return nil, errors.New("decode exact archived Velero DataUpload")
		}
		if selected == nil {
			selected = append([]byte(nil), payload...)
		} else if canonicalJSONSHA256(selected) != canonicalJSONSHA256(payload) {
			zeroBytes(payload)
			zeroBytes(selected)
			return nil, errors.New("archived Velero DataUpload copies differ")
		}
		zeroBytes(payload)
		seen[header.Name] = true
	}
	if len(seen) != len(expected) || selected == nil {
		zeroBytes(selected)
		return nil, errors.New("Velero BackupContents is missing the exact DataUpload")
	}
	if _, err := bufferedExpanded.ReadByte(); !errors.Is(err, io.EOF) || expandedLimit.N <= 0 {
		zeroBytes(selected)
		return nil, errors.New("Velero BackupContents contains trailing or excessive tar data")
	}
	if err := gzipReader.Close(); err != nil {
		zeroBytes(selected)
		return nil, errors.New("Velero BackupContents gzip checksum is invalid")
	}
	if _, err := bufferedCompressed.ReadByte(); !errors.Is(err, io.EOF) || compressedLimit.N <= 0 {
		zeroBytes(selected)
		return nil, errors.New("Velero BackupContents contains trailing compressed data")
	}
	return selected, nil
}

func archivedDataUploadPath(namespace, name string, preferred bool) string {
	base := dataUploadResourcePrefix
	if preferred {
		base += preferredVersionPath + "/"
	}
	return base + "namespaces/" + namespace + "/" + name + ".json"
}

func safeArchivePath(value string) bool {
	return value != "" && !strings.ContainsRune(value, '\x00') && !strings.Contains(value, "\\") && !strings.HasPrefix(value, "/") &&
		path.Clean(value) == value && value != "." && value != ".." && !strings.HasPrefix(value, "../")
}
