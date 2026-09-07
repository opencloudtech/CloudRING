// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const (
	stateSchema       = "cloudring.development-state/v1"
	maximumStateBytes = 256 << 10
)

var stateFiles = []string{".owner.json", ".lock", "state.json", "state.next", "ssh-client.key", "ssh-known-hosts", "api-ca.pem", "operator-token", "installer-linux-amd64", "installer.next"}

type OwnedObject struct {
	Object
	DesiredSHA256 string `json:"desiredSHA256"`
}

// State is an installation-specific ownership journal, not runtime data.
// Accepted API/domain state lives only in the real PostgreSQL provider.
type State struct {
	APIVersion        string        `json:"apiVersion"`
	InstallationID    string        `json:"installationID"`
	OwnerNonce        string        `json:"ownerNonce"`
	ProfileSHA256     string        `json:"profileSHA256"`
	Profile           Profile       `json:"profile"`
	Credentials       Credentials   `json:"credentials"`
	CreatedAt         time.Time     `json:"createdAt"`
	UpdatedAt         time.Time     `json:"updatedAt"`
	Sequence          uint64        `json:"sequence"`
	Phase             string        `json:"phase"`
	Objects           []OwnedObject `json:"objects"`
	DerivedObjects    []Object      `json:"derivedObjects,omitempty"`
	Volumes           []OwnedVolume `json:"volumes,omitempty"`
	GuestBootstrapped bool          `json:"guestBootstrapped"`
	FailureCode       string        `json:"failureCode,omitempty"`
}

type stateOwner struct {
	APIVersion     string `json:"apiVersion"`
	InstallationID string `json:"installationID"`
	OwnerNonce     string `json:"ownerNonce"`
}

// StateStore keeps a process-wide exclusive lock and root directory handle.
// The root must be a new directory or a complete owned journal. No existing
// arbitrary directory is adopted, even when its name looks correct.
type StateStore struct {
	Path           string
	State          State
	root           *os.Root
	parent         *os.Root
	parentPath     string
	base           string
	rootIdentity   fs.FileInfo
	parentIdentity fs.FileInfo
	owner          stateOwner
	lock           *os.File
	removed        bool
}

func OpenState(path string, profile Profile, create bool) (_ *StateStore, resultErr error) {
	if err := Validate(profile, Development); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil || filepath.Base(absolute) == "." || filepath.Base(absolute) == string(filepath.Separator) {
		return nil, errors.New("development state path is invalid")
	}
	parentPath, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, errors.New("development state parent must already exist")
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, errors.New("open development state parent")
	}
	store := &StateStore{Path: filepath.Join(parentPath, filepath.Base(absolute)), parentPath: parentPath,
		parent: parent, base: filepath.Base(absolute)}
	defer func() {
		if resultErr != nil {
			_ = store.Close()
		}
	}()
	store.parentIdentity, err = parent.Lstat(".")
	if err != nil || !ownedDirectory(store.parentIdentity, false) {
		return nil, errors.New("development state parent ownership is invalid")
	}
	created := false
	info, err := parent.Lstat(store.base)
	if errors.Is(err, fs.ErrNotExist) && create {
		// #nosec G302 -- this private state directory needs owner search access.
		if err = parent.Mkdir(store.base, 0o700); err != nil {
			return nil, errors.New("create exclusive development state directory")
		}
		created = true
		info, err = parent.Lstat(store.base)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil || !ownedDirectory(info, true) {
		return nil, errors.New("development state directory is not privately owned")
	}
	store.rootIdentity = info
	store.root, err = parent.OpenRoot(store.base)
	if err != nil {
		return nil, errors.New("open development state directory")
	}
	if err := store.guardDirectory(); err != nil {
		return nil, err
	}
	if !created {
		if err := store.readJSON(".owner.json", &store.owner, 4096); err != nil ||
			store.owner.APIVersion != stateSchema || store.owner.InstallationID != profile.InstallationID || !hexDigest.MatchString(store.owner.OwnerNonce) {
			return nil, ErrConflict
		}
	}
	store.lock, err = store.openOwned(".lock", os.O_RDWR|os.O_CREATE)
	if err != nil || lockState(store.lock) != nil {
		return nil, errors.New("development installation is locked by another process")
	}
	if created {
		nonce, err := randomHex()
		if err != nil {
			return nil, err
		}
		store.owner = stateOwner{APIVersion: stateSchema, InstallationID: profile.InstallationID, OwnerNonce: nonce}
		if err := store.writeExclusiveJSON(".owner.json", store.owner); err != nil {
			return nil, err
		}
		credentials, err := newCredentials(profile, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		store.State = State{APIVersion: stateSchema, InstallationID: profile.InstallationID, OwnerNonce: nonce,
			ProfileSHA256: Fingerprint(profile), Profile: profile, Credentials: credentials,
			CreatedAt: time.Now().UTC(), Phase: "prepared", Objects: []OwnedObject{}}
		if err := store.Save(); err != nil {
			return nil, err
		}
	} else {
		if err := store.readJSON("state.json", &store.State, maximumStateBytes); err != nil {
			// Only a complete first atomic write may be recovered without a
			// committed journal. No remote command starts before that rename.
			if !errors.Is(err, fs.ErrNotExist) || store.readJSON("state.next", &store.State, maximumStateBytes) != nil ||
				store.State.Sequence != 1 || store.validateState(profile) != nil || store.root.Rename("state.next", "state.json") != nil {
				return nil, errors.New("development state is incomplete; preserved for recovery")
			}
		}
		if err := store.validateState(profile); err != nil {
			return nil, err
		}
		if err := store.discardInterruptedWrite(); err != nil {
			return nil, err
		}
	}
	if err := store.checkInventory(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *StateStore) validateState(profile Profile) error {
	state := store.State
	if state.APIVersion != stateSchema || state.InstallationID != profile.InstallationID || state.OwnerNonce != store.owner.OwnerNonce ||
		state.ProfileSHA256 != Fingerprint(profile) || state.ProfileSHA256 != Fingerprint(state.Profile) || state.Sequence == 0 ||
		!hexDigest.MatchString(state.Credentials.OperatorToken) || !hexDigest.MatchString(state.Credentials.DatabaseAdminPassword) ||
		!hexDigest.MatchString(state.Credentials.DatabaseOwnerPassword) || !hexDigest.MatchString(state.Credentials.DatabaseApplicationPassword) ||
		!slices.Contains([]string{"prepared", "creating", "ready", "destroying"}, state.Phase) || len(state.Objects) > 32 || len(state.DerivedObjects) > 256 || len(state.Volumes) > 4 {
		return ErrConflict
	}
	return nil
}

func (store *StateStore) Save() error {
	if err := store.guard(); err != nil {
		return err
	}
	if err := store.discardInterruptedWrite(); err != nil {
		return err
	}
	store.State.Sequence++
	store.State.UpdatedAt = time.Now().UTC()
	if err := store.writeExclusiveJSON("state.next", store.State); err != nil {
		store.State.Sequence--
		return err
	}
	if err := store.root.Rename("state.next", "state.json"); err != nil {
		store.State.Sequence--
		return errors.New("commit development ownership journal")
	}
	return store.syncDirectory()
}

func (store *StateStore) discardInterruptedWrite() error {
	var pending State
	err := store.readJSON("state.next", &pending, maximumStateBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || pending.OwnerNonce != store.owner.OwnerNonce || pending.InstallationID != store.owner.InstallationID ||
		pending.APIVersion != stateSchema || pending.ProfileSHA256 != store.State.ProfileSHA256 || pending.Sequence != store.State.Sequence+1 {
		return errors.New("unrecognized interrupted state write; preserved")
	}
	return store.root.Remove("state.next")
}

func (store *StateStore) guardDirectory() error {
	parentInfo, err := os.Lstat(store.parentPath)
	if err != nil || !os.SameFile(parentInfo, store.parentIdentity) {
		return ErrConflict
	}
	current, err := store.parent.Lstat(store.base)
	if err != nil || !ownedDirectory(current, true) || !os.SameFile(current, store.rootIdentity) || store.removed {
		return ErrConflict
	}
	opened, err := store.root.Lstat(".")
	if err != nil || !os.SameFile(opened, store.rootIdentity) {
		return ErrConflict
	}
	return nil
}

func (store *StateStore) guard() error {
	if err := store.guardDirectory(); err != nil {
		return err
	}
	var owner stateOwner
	if err := store.readJSON(".owner.json", &owner, 4096); err != nil || owner != store.owner {
		return ErrConflict
	}
	return nil
}

func (store *StateStore) openOwned(name string, flags int) (*os.File, error) {
	if !slices.Contains(stateFiles, name) {
		return nil, errors.New("unrecognized development state file")
	}
	if info, err := store.root.Lstat(name); err == nil && !ownedRegularFile(info, store.rootIdentity) {
		return nil, ErrConflict
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, ErrConflict
	}
	file, err := store.root.OpenFile(name, flags & ^os.O_TRUNC | stateNoFollowFlag(), 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !ownedRegularFile(info, store.rootIdentity) {
		_ = file.Close()
		return nil, ErrConflict
	}
	if flags&os.O_TRUNC != 0 {
		if err := file.Truncate(0); err != nil {
			_ = file.Close()
			return nil, errors.New("truncate owned development state file")
		}
	}
	return file, nil
}

func (store *StateStore) readJSON(name string, destination any, maximum int64) error {
	file, err := store.openOwned(name, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	defer clear(payload)
	if err != nil || int64(len(payload)) > maximum || strictjson.DecodeExact(payload, destination) != nil {
		return errors.New("development state format is invalid")
	}
	return nil
}

func (store *StateStore) writeExclusiveJSON(name string, value any) error {
	payload, err := json.Marshal(value)
	defer clear(payload)
	if err != nil || len(payload) > maximumStateBytes {
		return errors.New("encode bounded development state")
	}
	file, err := store.openOwned(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return errors.New("create exclusive development state file")
	}
	_, writeErr := file.Write(payload)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("persist development state file")
	}
	return nil
}

func (store *StateStore) WriteCredentialFile(name string, payload []byte) error {
	if !slices.Contains([]string{"ssh-client.key", "ssh-known-hosts", "api-ca.pem", "operator-token"}, name) || len(payload) == 0 || len(payload) > 16384 {
		return errors.New("invalid development credential file")
	}
	if err := store.guard(); err != nil {
		return err
	}
	file, err := store.openOwned(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(payload)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("persist development credential file")
	}
	return nil
}

func (store *StateStore) syncDirectory() error {
	file, err := store.root.Open(".")
	if err != nil {
		return errors.New("open development journal directory for persistence")
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return errors.New("persist development journal directory")
	}
	return nil
}

func (store *StateStore) checkInventory() error {
	entries, err := fs.ReadDir(store.root.FS(), ".")
	if err != nil {
		return errors.New("inspect development state inventory")
	}
	for _, entry := range entries {
		info, err := store.root.Lstat(entry.Name())
		if err != nil || !slices.Contains(stateFiles, entry.Name()) || !ownedRegularFile(info, store.rootIdentity) {
			return errors.New("unrecognized development state content; preserved")
		}
	}
	return nil
}

// Remove is called only after the backend's complete owned-resource absence
// sweep has succeeded. Unexpected local content is preserved, never recursed.
func (store *StateStore) Remove() error {
	if err := store.guard(); err != nil {
		return err
	}
	if err := store.checkInventory(); err != nil {
		return err
	}
	for _, name := range stateFiles {
		if name == ".owner.json" || name == ".lock" || name == "state.json" {
			continue
		}
		if err := store.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return errors.New("remove owned development state file")
		}
	}
	if err := store.guard(); err != nil {
		return err
	}
	if err := store.root.Remove("state.json"); err != nil {
		return errors.New("remove final development ownership journal")
	}
	if err := store.root.Remove(".owner.json"); err != nil {
		return errors.New("remove development ownership marker")
	}
	if err := store.root.Remove(".lock"); err != nil {
		return errors.New("remove development state lock")
	}
	if err := store.parent.Remove(store.base); err != nil {
		return errors.New("remove development state directory")
	}
	if _, err := store.parent.Lstat(store.base); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("development state absence is unverified")
	}
	store.removed = true
	return nil
}

func (store *StateStore) Close() error {
	var results []error
	if store == nil {
		return nil
	}
	if store.lock != nil {
		results = append(results, store.lock.Close())
		store.lock = nil
	}
	if store.root != nil {
		results = append(results, store.root.Close())
		store.root = nil
	}
	if store.parent != nil {
		results = append(results, store.parent.Close())
		store.parent = nil
	}
	return errors.Join(results...)
}
