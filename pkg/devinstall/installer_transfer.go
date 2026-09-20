// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const maximumInstallerBytes = 128 << 20

func (engine *Engine) ensureInstaller(ctx context.Context) error {
	if err := engine.guard(); err != nil {
		return err
	}
	if file, err := engine.Store.openOwned("installer-linux-amd64", os.O_RDONLY); err == nil {
		defer file.Close()
		return verifyInstaller(file, engine.Store.State.Profile.Artifacts.Installer.SHA256)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	pin := engine.Store.State.Profile.Artifacts.Installer
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(request *http.Request, previous []*http.Request) error {
		if len(previous) > 5 || request.URL.Scheme != "https" || request.URL.User != nil || request.URL.Port() != "" {
			return errors.New("installer download redirect rejected")
		}
		switch request.URL.Hostname() {
		case "github.com", "release-assets.githubusercontent.com":
			return nil
		default:
			return errors.New("installer download redirect rejected")
		}
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pin.URL, nil)
	if err != nil {
		return ErrInvalidProfile
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("public pinned installer download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > maximumInstallerBytes {
		return errors.New("public installer response is invalid")
	}
	file, err := engine.Store.openOwned("installer.next", os.O_RDWR|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	defer file.Close()
	if count, err := io.Copy(file, io.LimitReader(response.Body, maximumInstallerBytes+1)); err != nil || count > maximumInstallerBytes {
		return errors.New("public installer download exceeds bound or was interrupted")
	}
	if err := file.Sync(); err != nil {
		return errors.New("persist pinned installer")
	}
	if err := verifyInstaller(file, pin.SHA256); err != nil {
		return err
	}
	if err := engine.Store.guard(); err != nil {
		return err
	}
	if err := engine.Store.root.Rename("installer.next", "installer-linux-amd64"); err != nil {
		return errors.New("commit pinned installer cache")
	}
	return engine.Store.syncDirectory()
}

func verifyInstaller(file *os.File, expected string) error {
	info, err := file.Stat()
	if err != nil || info.Size() < 64 || info.Size() > maximumInstallerBytes {
		return errors.New("pinned installer size is invalid")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.New("read pinned installer")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maximumInstallerBytes+1)); err != nil || hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("pinned installer SHA256 mismatch")
	}
	parsed, err := elf.NewFile(file)
	if err != nil || parsed.Class != elf.ELFCLASS64 || parsed.Machine != elf.EM_X86_64 || parsed.Data != elf.ELFDATA2LSB || parsed.Type != elf.ET_EXEC && parsed.Type != elf.ET_DYN {
		return errors.New("pinned installer is not Linux amd64 ELF")
	}
	for _, program := range parsed.Progs {
		if program.Type == elf.PT_INTERP {
			return errors.New("pinned installer must not require a dynamic interpreter")
		}
	}
	_, err = file.Seek(0, io.SeekStart)
	return err
}

func (engine *Engine) verifyGuestIdentity(ctx context.Context, guest *guestClient) error {
	payload, err := guest.runFixed(ctx, "sudo -n /usr/bin/cat /var/lib/cloudring-development/identity.json", nil)
	if err != nil {
		return err
	}
	var identity guestIdentity
	if len(payload) > 4096 || strictjson.DecodeExact(payload, &identity) != nil {
		return ErrConflict
	}
	expected := guestIdentity{InstallationID: engine.Store.State.InstallationID, OwnerNonce: engine.Store.State.OwnerNonce,
		ProfileSHA256: engine.Store.State.ProfileSHA256, GuestUUID: guestUUID(engine.Store.State.OwnerNonce)}
	if identity != expected {
		return ErrConflict
	}
	firmware, err := guest.runFixed(ctx, "sudo -n /usr/bin/cat /sys/class/dmi/id/product_uuid", nil)
	if err != nil || !strings.EqualFold(strings.TrimSpace(string(firmware)), expected.GuestUUID) {
		return ErrConflict
	}
	return nil
}

const inspectGuestInstaller = `sudo -n /bin/sh -c 'set -eu; p=/var/lib/cloudring-development/cloudring; if [ ! -e "$p" ] && [ ! -L "$p" ]; then printf "absent\n"; else test -f "$p"; test ! -L "$p"; test "$(/usr/bin/stat -c "%u:%h" "$p")" = "0:1"; /usr/bin/sha256sum "$p"; fi'`

// This fixed wrapper only transfers a previously verified Go executable.
// Installer policy, artifact extraction and the bootstrap engine remain Go.
const transferGuestInstaller = `sudo -n /bin/sh -c 'set -eu; umask 077; d=/var/lib/cloudring-development; test -d "$d"; test ! -L "$d"; test ! -L "$d/installer.lock"; exec 9>"$d/installer.lock"; /usr/bin/flock -n 9; test ! -e "$d/cloudring"; test ! -L "$d/cloudring"; if [ -e "$d/installer.next" ] || [ -L "$d/installer.next" ]; then test -f "$d/installer.next"; test ! -L "$d/installer.next"; test "$(/usr/bin/stat -c "%u:%h" "$d/installer.next")" = "0:1"; /usr/bin/rm -- "$d/installer.next"; fi; (set -C; /usr/bin/cat >"$d/installer.next"); /usr/bin/chmod 0700 "$d/installer.next"; /usr/bin/mv -T -n -- "$d/installer.next" "$d/cloudring"'`

const runGuestBootstrap = "sudo -n /usr/bin/timeout --signal=TERM --kill-after=10s 2700s /var/lib/cloudring-development/cloudring dev guest-bootstrap"

func (engine *Engine) bootstrapGuest(ctx context.Context, guest *guestClient) error {
	if err := engine.verifyGuestIdentity(ctx, guest); err != nil {
		return err
	}
	observed, err := guest.runFixed(ctx, inspectGuestInstaller, nil)
	if err != nil {
		return err
	}
	if string(observed) == "absent\n" {
		file, err := engine.Store.openOwned("installer-linux-amd64", os.O_RDONLY)
		if err != nil {
			return err
		}
		defer file.Close()
		if err := verifyInstaller(file, engine.Store.State.Profile.Artifacts.Installer.SHA256); err != nil {
			return err
		}
		if output, err := guest.runFixed(ctx, transferGuestInstaller, file); err != nil {
			return err
		} else if len(output) != 0 {
			return errors.New("owned guest installer transfer returned unexpected output")
		}
		observed, err = guest.runFixed(ctx, inspectGuestInstaller, nil)
		if err != nil {
			return err
		}
	}
	if string(observed) != engine.Store.State.Profile.Artifacts.Installer.SHA256+"  /var/lib/cloudring-development/cloudring\n" {
		return errors.New("owned guest installer SHA256 mismatch")
	}
	payload, err := json.Marshal(guestBootstrapInput{APIVersion: "cloudring.development-bootstrap/v1", State: engine.Store.State})
	if err != nil || len(payload) > maximumStateBytes {
		return errors.New("encode bounded owned guest bootstrap")
	}
	defer clear(payload)
	output, err := guest.runFixed(ctx, runGuestBootstrap, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer clear(output)
	decoder := json.NewDecoder(bytes.NewReader(output))
	complete := false
	for {
		var item struct {
			APIVersion     string `json:"apiVersion"`
			InstallationID string `json:"installationID"`
			Stage          string `json:"stage"`
			Status         string `json:"status"`
		}
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&item)
		if err == io.EOF {
			break
		}
		if err != nil || item.APIVersion != "cloudring.development-bootstrap-progress/v1" || item.InstallationID != engine.Store.State.InstallationID {
			return errors.New("owned guest returned an invalid bootstrap receipt")
		}
		complete = item.Stage == "bootstrap" && item.Status == "complete"
	}
	if !complete {
		return errors.New("owned guest bootstrap completion is unverified")
	}
	return nil
}
