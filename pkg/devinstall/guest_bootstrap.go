// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const guestDirectory = "/var/lib/cloudring-development"

type guestIdentity struct {
	InstallationID string `json:"installationID"`
	OwnerNonce     string `json:"ownerNonce"`
	ProfileSHA256  string `json:"profileSHA256"`
	GuestUUID      string `json:"guestUUID"`
}

type guestBootstrapInput struct {
	APIVersion string `json:"apiVersion"`
	State      State  `json:"state"`
}

type guestJournal struct {
	APIVersion        string                  `json:"apiVersion"`
	Identity          guestIdentity           `json:"identity"`
	Completed         []string                `json:"completed"`
	DatabaseDirectory *guestDirectoryIdentity `json:"databaseDirectory,omitempty"`
}

type guestDirectoryIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type guestBootstrap struct {
	state        State
	root         *os.Root
	rootIdentity fs.FileInfo
	identity     guestIdentity
	journal      guestJournal
	output       io.Writer
}

func parseGuestBootstrap(input io.Reader) (State, error) {
	if input == nil {
		return State{}, errors.New("guest bootstrap input is missing")
	}
	payload, err := io.ReadAll(io.LimitReader(input, maximumStateBytes+1))
	defer clear(payload)
	var request guestBootstrapInput
	if err != nil || len(payload) > maximumStateBytes || strictjson.DecodeExact(payload, &request) != nil ||
		request.APIVersion != "cloudring.development-bootstrap/v1" || Validate(request.State.Profile, Development) != nil {
		return State{}, errors.New("guest bootstrap request is invalid")
	}
	state := request.State
	if state.APIVersion != stateSchema || state.InstallationID != state.Profile.InstallationID || !hexDigest.MatchString(state.OwnerNonce) ||
		state.ProfileSHA256 != Fingerprint(state.Profile) || state.Sequence == 0 || !slices.Contains([]string{"creating", "ready"}, state.Phase) ||
		!hexDigest.MatchString(state.Credentials.OperatorToken) || !hexDigest.MatchString(state.Credentials.DatabaseAdminPassword) ||
		!hexDigest.MatchString(state.Credentials.DatabaseOwnerPassword) || !hexDigest.MatchString(state.Credentials.DatabaseApplicationPassword) ||
		!state.Credentials.CertificateExpiresAt.After(time.Now().Add(15*time.Minute)) {
		return State{}, ErrConflict
	}
	return state, nil
}

// BootstrapGuest is an internal subcommand. It only operates as root inside
// the exact disposable Linux guest whose firmware and cloud-init identity
// match the caller's durable ownership journal. No host fallback exists.
func BootstrapGuest(ctx context.Context, input io.Reader, output io.Writer) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return errors.New("guest bootstrap requires the owned Linux amd64 guest as root")
	}
	state, err := parseGuestBootstrap(input)
	if err != nil {
		return err
	}
	info, err := os.Lstat(guestDirectory)
	if err != nil || !ownedDirectory(info, false) || info.Mode().Perm()&0o022 != 0 {
		return ErrConflict
	}
	root, err := os.OpenRoot(guestDirectory)
	if err != nil {
		return errors.New("open owned guest directory")
	}
	defer root.Close()
	opened, err := root.Lstat(".")
	if err != nil || !os.SameFile(info, opened) {
		return ErrConflict
	}
	bootstrap := &guestBootstrap{state: state, root: root, rootIdentity: info, output: output, identity: guestIdentity{
		InstallationID: state.InstallationID, OwnerNonce: state.OwnerNonce, ProfileSHA256: state.ProfileSHA256, GuestUUID: guestUUID(state.OwnerNonce)}}
	if err := bootstrap.guard(); err != nil {
		return err
	}
	lock, err := root.OpenFile("bootstrap.lock", os.O_RDWR|os.O_CREATE|stateNoFollowFlag(), 0o600)
	if err != nil {
		return errors.New("open guest bootstrap lock")
	}
	defer lock.Close()
	lockInfo, err := lock.Stat()
	if err != nil || !ownedRegularFile(lockInfo, opened) || lockState(lock) != nil {
		return errors.New("owned guest bootstrap is locked")
	}
	if err := bootstrap.loadJournal(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Minute)
	defer cancel()
	for _, directory := range []string{"downloads", "bin", "cni", "cni/bin"} {
		if err := guestMkdir(root, directory); err != nil {
			return err
		}
	}
	stages := []struct {
		name string
		run  func(context.Context) error
	}{
		{"artifacts", bootstrap.installArtifacts},
		{"host", bootstrap.configureHost},
		{"kubernetes", bootstrap.installKubernetes},
		{"network", bootstrap.installNetwork},
		{"provider", bootstrap.installProvider},
	}
	for _, stage := range stages {
		if err := bootstrap.guard(); err != nil {
			return err
		}
		if err := bootstrap.report(stage.name, "running"); err != nil {
			return err
		}
		if err := stage.run(ctx); err != nil {
			return err
		}
		if err := bootstrap.report(stage.name, "complete"); err != nil {
			return err
		}
	}
	return bootstrap.report("bootstrap", "complete")
}

func (bootstrap *guestBootstrap) guard() error {
	current, err := os.Lstat(guestDirectory)
	if err != nil || bootstrap.rootIdentity == nil || !os.SameFile(current, bootstrap.rootIdentity) || !ownedDirectory(current, false) || current.Mode().Perm()&0o022 != 0 {
		return ErrConflict
	}
	info, err := bootstrap.root.Lstat("identity.json")
	if err != nil || !guestOwnedFile(info, 0o400) {
		return ErrConflict
	}
	file, err := bootstrap.root.Open("identity.json")
	if err != nil {
		return ErrConflict
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, 4097))
	closeErr := file.Close()
	var identity guestIdentity
	if readErr != nil || closeErr != nil || len(payload) > 4096 || strictjson.DecodeExact(payload, &identity) != nil || identity != bootstrap.identity {
		return ErrConflict
	}
	firmware, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err != nil || !strings.EqualFold(strings.TrimSpace(string(firmware)), bootstrap.identity.GuestUUID) {
		return ErrConflict
	}
	return nil
}

func (bootstrap *guestBootstrap) report(stage, status string) error {
	if bootstrap.output == nil {
		return nil
	}
	if json.NewEncoder(bootstrap.output).Encode(map[string]string{"apiVersion": "cloudring.development-bootstrap-progress/v1", "installationID": bootstrap.state.InstallationID, "stage": stage, "status": status}) != nil {
		return errors.New("write guest bootstrap progress")
	}
	return nil
}

func guestMkdir(root *os.Root, name string) error {
	if err := root.Mkdir(name, 0o700); err != nil && !os.IsExist(err) {
		return errors.New("create owned guest directory")
	}
	info, err := root.Lstat(name)
	if err != nil || !ownedDirectory(info, true) {
		return ErrConflict
	}
	return nil
}

func guestWrite(root *os.Root, name string, payload []byte, mode fs.FileMode) error {
	if info, err := root.Lstat(name); err == nil {
		if !guestOwnedFile(info, mode) {
			return ErrConflict
		}
		previous, err := root.ReadFile(name)
		if err != nil {
			return errors.New("read owned guest configuration")
		}
		equal := bytes.Equal(previous, payload)
		clear(previous)
		if equal {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return ErrConflict
	}
	nonce, err := randomHex()
	if err != nil {
		return err
	}
	temporary := name + ".next-" + nonce
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return errors.New("prepare owned guest configuration")
	}
	defer func() { _ = file.Close(); _ = root.Remove(temporary) }()
	if _, err = file.Write(payload); err != nil {
		return errors.New("write owned guest configuration")
	}
	if file.Sync() != nil || file.Close() != nil || root.Rename(temporary, name) != nil {
		return errors.New("commit owned guest configuration")
	}
	directory, err := root.Open(filepath.Dir(name))
	if err != nil {
		return errors.New("open guest configuration directory")
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return errors.New("sync owned guest configuration")
	}
	return nil
}

func (bootstrap *guestBootstrap) loadJournal() error {
	bootstrap.journal = guestJournal{APIVersion: "cloudring.development-guest-journal/v1", Identity: bootstrap.identity, Completed: []string{}}
	info, err := bootstrap.root.Lstat("bootstrap-journal.json")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !guestOwnedFile(info, 0o600) {
		return ErrConflict
	}
	payload, err := bootstrap.root.ReadFile("bootstrap-journal.json")
	if err != nil || len(payload) > 32768 || strictjson.DecodeExact(payload, &bootstrap.journal) != nil ||
		bootstrap.journal.APIVersion != "cloudring.development-guest-journal/v1" || bootstrap.journal.Identity != bootstrap.identity || len(bootstrap.journal.Completed) > 32 {
		return ErrConflict
	}
	return nil
}

func (bootstrap *guestBootstrap) phase(ctx context.Context, name string, run func(context.Context) error) error {
	if slices.Contains(bootstrap.journal.Completed, name) {
		return nil
	}
	if err := bootstrap.guard(); err != nil {
		return err
	}
	if err := run(ctx); err != nil {
		return err
	}
	bootstrap.journal.Completed = append(bootstrap.journal.Completed, name)
	return bootstrap.saveJournal()
}

func (bootstrap *guestBootstrap) saveJournal() error {
	payload, err := json.Marshal(bootstrap.journal)
	if err != nil {
		return errors.New("encode guest phase journal")
	}
	return guestWrite(bootstrap.root, "bootstrap-journal.json", payload, 0o600)
}

func (bootstrap *guestBootstrap) run(ctx context.Context, timeout time.Duration, program string, input []byte, arguments ...string) error {
	return bootstrap.runOutput(ctx, timeout, program, input, io.Discard, arguments...)
}

func (bootstrap *guestBootstrap) runOutput(ctx context.Context, timeout time.Duration, program string, input []byte, output io.Writer, arguments ...string) error {
	if err := bootstrap.guard(); err != nil {
		return err
	}
	switch program {
	case "/usr/sbin/modprobe", "/usr/sbin/swapoff", "/usr/sbin/sysctl", "/usr/bin/systemctl",
		guestDirectory + "/bin/crictl", guestDirectory + "/bin/kubeadm", guestDirectory + "/bin/kubectl",
		guestDirectory + "/bin/ctr", guestDirectory + "/bin/helm":
	default:
		return errors.New("guest command is outside the fixed bootstrap tool set")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(ctx, program, arguments...) // #nosec G204 -- The exact absolute executable allowlist above and the firmware/ownership guard restrict this to verified tools inside the owned guest; validated arguments are passed directly without a shell.
	command.Env = []string{"PATH=" + guestDirectory + "/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C.UTF-8", "KUBECONFIG=/etc/kubernetes/admin.conf"}
	command.Stdin = bytes.NewReader(input)
	// kubeadm and database utilities can print bootstrap credentials. Neither
	// their arguments nor their raw output belongs in returned diagnostics.
	command.Stdout = output
	command.Stderr = io.Discard
	command.WaitDelay = 5 * time.Second
	if command.Run() != nil {
		return errors.New("owned guest command failed: " + filepath.Base(program))
	}
	return nil
}

type guestLimitedBuffer struct {
	bytes.Buffer
	maximum int
}

func (buffer *guestLimitedBuffer) Write(payload []byte) (int, error) {
	if len(payload) > buffer.maximum-buffer.Len() {
		return 0, errors.New("guest command output exceeds its limit")
	}
	return buffer.Buffer.Write(payload)
}

// Capture is only used for nonsecret inventory and rendering. Neither raw
// output nor an external program's diagnostic text is exposed to the client.
func (bootstrap *guestBootstrap) capture(ctx context.Context, timeout time.Duration, program string, arguments ...string) ([]byte, error) {
	buffer := &guestLimitedBuffer{maximum: 32 << 20}
	if err := bootstrap.runOutput(ctx, timeout, program, nil, buffer, arguments...); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (bootstrap *guestBootstrap) installArtifacts(ctx context.Context) error {
	artifacts := bootstrap.state.Profile.Artifacts
	for _, item := range []struct {
		artifact Download
		name     string
		archive  map[string]string
		flat     bool
	}{
		{artifacts.Kubeadm, "kubeadm", nil, false}, {artifacts.Kubelet, "kubelet", nil, false}, {artifacts.Kubectl, "kubectl", nil, false},
		{artifacts.Runc, "runc", nil, false},
		{artifacts.Containerd, "", map[string]string{"bin/containerd": "containerd", "bin/containerd-shim-runc-v2": "containerd-shim-runc-v2", "bin/ctr": "ctr"}, false},
		{artifacts.CRICTL, "", map[string]string{"crictl": "crictl"}, false},
		{artifacts.Helm, "", map[string]string{"linux-amd64/helm": "helm"}, false},
		{artifacts.CNIPlugins, "", nil, true},
	} {
		name, err := guestDownload(ctx, bootstrap.root, item.artifact, bootstrap.state.Profile.Network.EgressDomains)
		if err != nil {
			return err
		}
		if item.archive != nil || item.flat {
			destination := "bin"
			if item.flat {
				destination = "cni/bin"
			}
			if err := guestExtract(bootstrap.root, name, destination, item.archive, item.flat); err != nil {
				return err
			}
			continue
		}
		payload, err := bootstrap.root.ReadFile(name)
		if err != nil {
			return errors.New("read verified guest executable")
		}
		if err := guestWrite(bootstrap.root, "bin/"+item.name, payload, 0o700); err != nil {
			return err
		}
	}
	_, err := guestDownload(ctx, bootstrap.root, artifacts.CiliumChart, bootstrap.state.Profile.Network.EgressDomains)
	return err
}
