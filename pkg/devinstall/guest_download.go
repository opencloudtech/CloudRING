// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

const guestDownloadLimit int64 = 512 << 20

func guestDomainAllowed(host string, domains []string) bool {
	for _, domain := range domains {
		if host == domain || strings.HasPrefix(domain, "*.") && strings.HasSuffix(host, strings.TrimPrefix(domain, "*")) {
			return true
		}
	}
	return false
}

// Download redirects remain inside the explicitly declared egress policy. The
// checksum is verified before an archive or executable is ever consumed.
func guestDownload(ctx context.Context, root *os.Root, artifact Download, domains []string) (string, error) {
	location, err := anonymousHTTPS(artifact.URL)
	if err != nil || !hexDigest.MatchString(artifact.SHA256) || !guestDomainAllowed(location.Hostname(), domains) {
		return "", errors.New("guest artifact is outside declared egress")
	}
	name := "downloads/" + artifact.SHA256
	if info, statErr := root.Lstat(name); statErr == nil {
		if !guestOwnedFile(info, 0o600) {
			return "", ErrConflict
		}
		file, openErr := root.Open(name)
		if openErr != nil {
			return "", errors.New("open cached guest artifact")
		}
		sum := sha256.New()
		_, readErr := io.Copy(sum, io.LimitReader(file, guestDownloadLimit+1))
		closeErr := file.Close()
		if readErr == nil && closeErr == nil && hex.EncodeToString(sum.Sum(nil)) == artifact.SHA256 && info.Size() <= guestDownloadLimit {
			return name, nil
		}
		return "", errors.New("cached guest artifact checksum mismatch; preserved")
	} else if !os.IsNotExist(statErr) {
		return "", errors.New("inspect cached guest artifact")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Minute, CheckRedirect: func(request *http.Request, previous []*http.Request) error {
		if len(previous) >= 8 || request.URL.Scheme != "https" || request.URL.User != nil || !guestDomainAllowed(request.URL.Hostname(), domains) {
			return errors.New("guest artifact redirect is outside declared egress")
		}
		return nil
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return "", errors.New("build guest artifact request")
	}
	response, err := client.Do(request)
	if err != nil {
		return "", errors.New("download guest artifact")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > guestDownloadLimit {
		return "", errors.New("guest artifact response is invalid")
	}
	// A partial file is never accepted as a cached executable. Only this
	// process's freshly created temporary name may be removed after failure.
	temporary, err := randomHex()
	if err != nil {
		return "", err
	}
	temporary = "downloads/partial-" + temporary
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", errors.New("create guest artifact download")
	}
	defer func() { _ = file.Close(); _ = root.Remove(temporary) }()
	sum := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, sum), io.LimitReader(response.Body, guestDownloadLimit+1))
	if err != nil || written > guestDownloadLimit || hex.EncodeToString(sum.Sum(nil)) != artifact.SHA256 {
		return "", errors.New("guest artifact checksum mismatch")
	}
	if file.Sync() != nil || file.Close() != nil || root.Rename(temporary, name) != nil {
		return "", errors.New("commit verified guest artifact")
	}
	return name, nil
}

// guestExtract only accepts regular entries and directories with canonical
// relative paths. It never follows archive links, overwrites duplicates, or
// writes outside the caller-selected private directory.
func guestExtract(root *os.Root, archive, destination string, wanted map[string]string, flat bool) error {
	file, err := root.Open(archive)
	if err != nil {
		return errors.New("open verified guest archive")
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		return errors.New("decode verified guest archive")
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	seen := map[string]bool{}
	extracted := map[string]bool{}
	var total int64
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("read verified guest archive")
		}
		name := strings.TrimSuffix(strings.TrimPrefix(header.Name, "./"), "/")
		if name == "" && header.Typeflag == tar.TypeDir {
			continue
		}
		if name == "" || path.IsAbs(name) || name != path.Clean(name) || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\x00") || seen[name] {
			return errors.New("guest archive contains an unsafe or duplicate path")
		}
		seen[name] = true
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > guestDownloadLimit || total > guestDownloadLimit-header.Size {
			return errors.New("guest archive contains a link or oversized entry")
		}
		total += header.Size
		target, selected := wanted[name]
		if flat && !strings.Contains(name, "/") && name != "LICENSE" {
			target, selected = name, true
		}
		if !selected {
			continue
		}
		if target != path.Base(target) || target == "." || target == ".." || extracted[target] {
			return errors.New("guest archive extraction target conflicts")
		}
		payload, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(payload)) != header.Size {
			return errors.New("read guest archive executable")
		}
		if err := guestWrite(root, destination+"/"+target, payload, 0o700); err != nil {
			return err
		}
		extracted[target] = true
	}
	for _, target := range wanted {
		if !extracted[target] {
			return errors.New("guest archive is missing an expected executable")
		}
	}
	if flat && len(extracted) < 2 {
		return errors.New("guest CNI archive is incomplete")
	}
	return nil
}
