//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func openTestState(t *testing.T) (*StateStore, Profile) {
	t.Helper()
	profile := testProfile()
	store, err := OpenState(filepath.Join(t.TempDir(), "installation"), profile, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, profile
}

func TestStateRetainsCredentialsAndOwnershipAcrossProcessRestart(t *testing.T) {
	store, profile := openTestState(t)
	before := store.State
	store.State.Phase = "creating"
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenState(store.Path, profile, true)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reflect.DeepEqual(before.Credentials, reopened.State.Credentials) || before.OwnerNonce != reopened.State.OwnerNonce ||
		reopened.State.Phase != "creating" || reopened.State.Sequence != before.Sequence+1 {
		t.Fatal("restart replaced durable ownership or credentials")
	}
	if err := reopened.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(reopened.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned local state remains: %v", err)
	}
}

func TestExistingDirectoryAndChangedProfileAreNeverAdopted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(path, "keep")
	if err := os.WriteFile(sentinel, []byte("pre-existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(path, testProfile(), true); err == nil {
		t.Fatal("unowned directory adopted")
	}
	// #nosec G304 -- sentinel is created above inside t.TempDir and checks preservation.
	if value, err := os.ReadFile(sentinel); err != nil || string(value) != "pre-existing" {
		t.Fatal("existing content changed")
	}
	store, profile := openTestState(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	profile.Guest.CPUs++
	if _, err := OpenState(store.Path, profile, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed profile accepted: %v", err)
	}
}

func TestConcurrentClientIsRejectedAndLockRecoversAfterClose(t *testing.T) {
	store, profile := openTestState(t)
	if _, err := OpenState(store.Path, profile, true); err == nil {
		t.Fatal("second controller acquired an active state")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenState(store.Path, profile, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
}

func TestStatePreservesOutsideSymlinkHardlinkAndUnknownFiles(t *testing.T) {
	for _, link := range []string{"symlink", "hardlink"} {
		t.Run(link, func(t *testing.T) {
			store, _ := openTestState(t)
			outside := filepath.Join(t.TempDir(), "private")
			if err := os.WriteFile(outside, []byte("untouched"), 0o600); err != nil {
				t.Fatal(err)
			}
			inside := filepath.Join(store.Path, "operator-token")
			var err error
			if link == "symlink" {
				err = os.Symlink(outside, inside)
			} else {
				err = os.Link(outside, inside)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := store.WriteCredentialFile("operator-token", []byte("replacement")); err == nil {
				t.Fatal("outside file was writable")
			}
			if err := store.Remove(); err == nil {
				t.Fatal("unrecognized inode was removed")
			}
			// #nosec G304 -- outside is a test-created sentinel under t.TempDir.
			if value, err := os.ReadFile(outside); err != nil || string(value) != "untouched" {
				t.Fatal("outside content changed")
			}
		})
	}
	store, _ := openTestState(t)
	sentinel := filepath.Join(store.Path, "not-created-by-installer")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(); err == nil {
		t.Fatal("unknown local content was removed")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatal("unknown file missing")
	}
}

func TestRenamedStateDirectoryAndModifiedMarkerRefuseCleanup(t *testing.T) {
	store, _ := openTestState(t)
	if err := os.Rename(store.Path, store.Path+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(store.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacement root accepted: %v", err)
	}
	second, _ := openTestState(t)
	if err := os.WriteFile(filepath.Join(second.Path, ".owner.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := second.Remove(); !errors.Is(err, ErrConflict) {
		t.Fatalf("modified ownership accepted: %v", err)
	}
}

func TestInterruptedAtomicWriteDoesNotReplaceAcceptedOwnership(t *testing.T) {
	store, profile := openTestState(t)
	before := store.State
	pending := before
	pending.Sequence++
	pending.Phase = "creating"
	if err := store.writeExclusiveJSON("state.next", pending); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenState(store.Path, profile, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.State.Sequence != before.Sequence || reopened.State.Phase != before.Phase {
		t.Fatal("uncommitted local write became accepted state")
	}
	if _, err := os.Lstat(filepath.Join(reopened.Path, "state.next")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned interrupted write not cleaned")
	}
}

func TestGeneratedTLSVerifiesOnlyTheOwnedNamesAndCA(t *testing.T) {
	store, profile := openTestState(t)
	credentials := store.State.Credentials
	api, err := tls.X509KeyPair([]byte(credentials.APICertificate), []byte(credentials.APIKey))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(api.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(credentials.CACertificate)) {
		t.Fatal("CA does not parse")
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: apiHostname(profile)}); err != nil {
		t.Fatal(err)
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: "another-installation.localhost"}); err == nil {
		t.Fatal("foreign hostname accepted")
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: x509.NewCertPool(), DNSName: apiHostname(profile)}); err == nil {
		t.Fatal("foreign trust accepted")
	}
	if credentials.OperatorToken == credentials.DatabaseApplicationPassword || !hexDigest.MatchString(credentials.OperatorToken) ||
		!strings.HasPrefix(credentials.SSHHostPublicKey, "ssh-ed25519 ") || credentials.SSHHostPrivateKey == credentials.SSHClientPrivateKey {
		t.Fatal("generated identities are not distinct")
	}
}
