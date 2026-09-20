// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

type OwnedVolume struct {
	PersistentVolume Object `json:"persistentVolume"`
	ClaimUID         string `json:"claimUID"`
	Driver           string `json:"driver"`
	Handle           string `json:"handle"`
	Backend          Object `json:"backend"`
}

func (engine *Engine) recordVolume(ctx context.Context, pv apiObject, claimUID string) error {
	meta, _ := metadata(pv)
	spec := nested(pv, "spec")
	claim := nested(spec, "claimRef")
	csi := nested(spec, "csi")
	ref := Object{APIVersion: "v1", Kind: "PersistentVolume", Resource: "persistentvolumes", Name: stringField(meta, "name"), UID: stringField(meta, "uid")}
	if !validDNS(ref.Name) || !kubernetesUID.MatchString(ref.UID) || !kubernetesUID.MatchString(claimUID) ||
		stringField(claim, "uid") != claimUID || stringField(claim, "namespace") != engine.Store.State.Profile.Target.Namespace ||
		stringField(spec, "persistentVolumeReclaimPolicy") != "Delete" || stringField(spec, "storageClassName") != engine.Store.State.Profile.Target.StorageClass ||
		stringField(csi, "driver") != "driver.longhorn.io" || !validName(stringField(csi, "volumeHandle"), 63) {
		return ErrConflict
	}
	for _, volume := range engine.Store.State.Volumes {
		if volume.PersistentVolume.UID == ref.UID {
			if volume.ClaimUID != claimUID || volume.Handle != stringField(csi, "volumeHandle") {
				return ErrConflict
			}
			return nil
		}
	}
	if len(engine.Store.State.Volumes) >= 4 {
		return errors.New("owned development volume count exceeds bound")
	}
	backendItems, err := engine.Client.list(ctx, "/apis/longhorn.io/v1beta2/volumes", url.Values{"fieldSelector": {"metadata.name=" + stringField(csi, "volumeHandle")}})
	if err != nil {
		return err
	}
	if len(backendItems) != 1 {
		return errors.New("owned Longhorn volume identity is unavailable")
	}
	backendMeta, _ := metadata(backendItems[0])
	backend := Object{APIVersion: "longhorn.io/v1beta2", Kind: "Volume", Resource: "volumes",
		Namespace: stringField(backendMeta, "namespace"), Name: stringField(backendMeta, "name"), UID: stringField(backendMeta, "uid")}
	if backend.Name != stringField(csi, "volumeHandle") || !validName(backend.Namespace, 63) || !kubernetesUID.MatchString(backend.UID) {
		return ErrConflict
	}
	engine.Store.State.Volumes = append(engine.Store.State.Volumes, OwnedVolume{PersistentVolume: ref, ClaimUID: claimUID, Driver: "driver.longhorn.io", Handle: backend.Name, Backend: backend})
	return engine.Store.Save()
}

// Record the bound guest disk while its owner chain is still observable.
// A later namespace deletion must not erase our only copy of the PVC identity.
func (engine *Engine) recordGuestStorage(ctx context.Context) error {
	state := engine.Store.State
	var disk *OwnedObject
	for _, owned := range state.Objects {
		if owned.Kind == "DataVolume" && owned.Namespace == state.Profile.Target.Namespace && owned.Name == state.Profile.Target.VirtualMachine+"-root" && owned.UID != "" {
			copy := owned
			disk = &copy
		}
	}
	if disk == nil {
		return ErrConflict
	}
	ref := Object{APIVersion: "v1", Kind: "PersistentVolumeClaim", Resource: "persistentvolumeclaims", Namespace: disk.Namespace, Name: disk.Name}
	claim, err := engine.Client.get(ctx, ref)
	if err != nil {
		return err
	}
	meta, ok := metadata(claim)
	ref.UID = stringField(meta, "uid")
	owners, _ := meta["ownerReferences"].([]any)
	ownedByDisk := false
	for _, value := range owners {
		owner, _ := value.(map[string]any)
		if stringField(owner, "uid") == disk.UID && stringField(owner, "name") == disk.Name && stringField(owner, "kind") == disk.Kind && stringField(owner, "apiVersion") == disk.APIVersion {
			ownedByDisk = true
		}
	}
	if !ok || stringField(claim, "apiVersion") != ref.APIVersion || stringField(claim, "kind") != ref.Kind || stringField(meta, "name") != ref.Name ||
		stringField(meta, "namespace") != ref.Namespace || !kubernetesUID.MatchString(ref.UID) || !ownedByDisk ||
		stringField(nested(claim, "status"), "phase") != "Bound" || !validDNS(stringField(nested(claim, "spec"), "volumeName")) {
		return errors.New("bound development guest storage identity is unavailable")
	}
	return engine.recordInventory(ctx, []inventoryObject{{Ref: ref, Value: claim}})
}

func (engine *Engine) recordInventory(ctx context.Context, items []inventoryObject) error {
	refs, err := engine.classifyInventory(ctx, items)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, ref := range engine.Store.State.DerivedObjects {
		seen[ref.APIVersion+"/"+ref.Resource+"/"+ref.UID] = true
	}
	for _, ref := range refs {
		key := ref.APIVersion + "/" + ref.Resource + "/" + ref.UID
		if !seen[key] {
			engine.Store.State.DerivedObjects = append(engine.Store.State.DerivedObjects, ref)
			seen[key] = true
		}
	}
	if len(engine.Store.State.DerivedObjects) > 256 {
		return errors.New("owned development inventory exceeds bound")
	}
	if err := engine.Store.Save(); err != nil {
		return err
	}
	for _, item := range items {
		if item.Ref.APIVersion == "v1" && item.Ref.Kind == "PersistentVolumeClaim" {
			name := stringField(nested(item.Value, "spec"), "volumeName")
			if name == "" {
				continue
			}
			pv, err := engine.Client.get(ctx, Object{APIVersion: "v1", Kind: "PersistentVolume", Resource: "persistentvolumes", Name: name})
			if err != nil {
				return err
			}
			if err := engine.recordVolume(ctx, pv, item.Ref.UID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (engine *Engine) validateRecordedVolumes() error {
	claims := map[string]bool{}
	for _, ref := range engine.Store.State.DerivedObjects {
		if ref.APIVersion == "v1" && ref.Kind == "PersistentVolumeClaim" && ref.Namespace == engine.Store.State.Profile.Target.Namespace {
			claims[ref.UID] = true
		}
	}
	seen := map[string]bool{}
	for _, volume := range engine.Store.State.Volumes {
		pv, backend := volume.PersistentVolume, volume.Backend
		if pv.APIVersion != "v1" || pv.Kind != "PersistentVolume" || pv.Resource != "persistentvolumes" || pv.Namespace != "" || !validDNS(pv.Name) || !kubernetesUID.MatchString(pv.UID) ||
			!claims[volume.ClaimUID] || volume.Driver != "driver.longhorn.io" || volume.Handle != backend.Name || backend.APIVersion != "longhorn.io/v1beta2" || backend.Kind != "Volume" || backend.Resource != "volumes" ||
			!validName(backend.Namespace, 63) || !validName(backend.Name, 63) || !kubernetesUID.MatchString(backend.UID) || seen[pv.UID] {
			return ErrConflict
		}
		seen[pv.UID] = true
	}
	return nil
}

func (engine *Engine) deleteOwned(ctx context.Context, owned OwnedObject) error {
	object, err := engine.Client.get(ctx, owned.Object)
	if apiStatus(err, http.StatusNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	ref, version, err := readOwned(object, owned.Object, engine.Store.State)
	if err != nil {
		return err
	}
	if owned.UID == "" {
		for index, candidate := range engine.Store.State.Objects {
			if candidate.APIVersion == owned.APIVersion && candidate.Resource == owned.Resource && candidate.Name == owned.Name && candidate.Namespace == owned.Namespace {
				engine.Store.State.Objects[index].UID = ref.UID
				owned.UID = ref.UID
			}
		}
		if err := engine.Store.Save(); err != nil {
			return err
		}
	}
	if err := engine.Client.verifyCluster(ctx); err != nil {
		return err
	}
	if err := engine.Client.delete(ctx, ref.Object, version); err != nil && !apiStatus(err, http.StatusNotFound) {
		return err
	}
	return poll(ctx, 2*time.Second, func() (bool, error) {
		current, err := engine.Client.get(ctx, ref.Object)
		if apiStatus(err, http.StatusNotFound) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		meta, _ := metadata(current)
		if stringField(meta, "uid") != ref.UID {
			return false, ErrConflict
		}
		return false, nil
	})
}

// Destroy never clears finalizers or directly deletes CSI backend volumes.
// The normal controllers must finish foreground deletion and Longhorn reclaim.
func (engine *Engine) Destroy(ctx context.Context) (Report, error) {
	if err := engine.guard(); err != nil {
		return Report{}, err
	}
	if err := engine.validateRecordedVolumes(); err != nil {
		return engine.report(), err
	}
	if err := engine.Client.verifyCluster(ctx); err != nil {
		return engine.report(), err
	}
	var namespace *OwnedObject
	recovered := false
	for index := range engine.Store.State.Objects {
		owned := engine.Store.State.Objects[index]
		if owned.Kind == "Namespace" {
			namespace = &owned
		}
		object, err := engine.Client.get(ctx, owned.Object)
		if apiStatus(err, http.StatusNotFound) {
			continue
		}
		if err != nil {
			return engine.report(), err
		}
		observed, _, err := readOwned(object, owned.Object, engine.Store.State)
		if err != nil {
			return engine.report(), err
		}
		if owned.UID == "" {
			engine.Store.State.Objects[index].UID = observed.UID
			recovered = true
		}
	}
	if recovered {
		if err := engine.Store.Save(); err != nil {
			return engine.report(), err
		}
	}
	namespaceExists := false
	if namespace != nil {
		if _, err := engine.Client.get(ctx, namespace.Object); err == nil {
			namespaceExists = true
		} else if !apiStatus(err, http.StatusNotFound) {
			return engine.report(), err
		}
	}
	if !namespaceExists {
		attemptedDisk, recordedClaim := false, false
		for _, owned := range engine.Store.State.Objects {
			attemptedDisk = attemptedDisk || owned.Kind == "DataVolume"
		}
		for _, ref := range engine.Store.State.DerivedObjects {
			recordedClaim = recordedClaim || ref.APIVersion == "v1" && ref.Kind == "PersistentVolumeClaim" && ref.Namespace == engine.Store.State.Profile.Target.Namespace
		}
		if attemptedDisk && !recordedClaim {
			return engine.report(), errors.New("development namespace disappeared before storage identity was recorded; recovery journal preserved")
		}
	}
	if namespaceExists {
		items, err := engine.Client.namespaceInventory(ctx)
		if err != nil {
			return engine.report(), err
		}
		if err := engine.recordInventory(ctx, items); err != nil {
			return engine.report(), err
		}
	}
	engine.Store.State.Phase = "destroying"
	if err := engine.Store.Save(); err != nil {
		return engine.report(), err
	}
	if err := engine.progress("destroy-owned-objects"); err != nil {
		return engine.report(), err
	}
	// Remove the VM and disk first. Keep namespace policy and quota until
	// execution and storage stop, then remove the remaining explicit objects.
	for index := len(engine.Store.State.Objects) - 1; index >= 0; index-- {
		owned := engine.Store.State.Objects[index]
		if owned.Kind == "Namespace" || owned.Kind == "PriorityClass" {
			continue
		}
		if err := engine.deleteOwned(ctx, owned); err != nil {
			return engine.report(), err
		}
	}
	if namespaceExists {
		items, err := engine.Client.namespaceInventory(ctx)
		if err != nil {
			return engine.report(), err
		}
		if err := engine.recordInventory(ctx, items); err != nil {
			return engine.report(), err
		}
		if err := engine.deleteOwned(ctx, *namespace); err != nil {
			return engine.report(), err
		}
	}
	for _, owned := range engine.Store.State.Objects {
		if owned.Kind == "PriorityClass" {
			if err := engine.deleteOwned(ctx, owned); err != nil {
				return engine.report(), err
			}
		}
	}
	if err := engine.progress("verify-owned-storage-absence"); err != nil {
		return engine.report(), err
	}
	if err := engine.waitStorageAbsent(ctx); err != nil {
		return engine.report(), err
	}
	for _, owned := range engine.Store.State.Objects {
		if _, err := engine.Client.get(ctx, owned.Object); !apiStatus(err, http.StatusNotFound) {
			if err != nil {
				return engine.report(), err
			}
			return engine.report(), errors.New("owned development object residue remains")
		}
	}
	for _, ref := range engine.Store.State.DerivedObjects {
		if _, err := engine.Client.get(ctx, ref); !apiStatus(err, http.StatusNotFound) {
			if err != nil {
				return engine.report(), err
			}
			return engine.report(), errors.New("owned development derived object residue remains")
		}
	}
	report := engine.report()
	report.Phase = "destroyed"
	report.Ready = false
	if err := engine.Store.Remove(); err != nil {
		return report, err
	}
	report.ZeroOwnedResidue = true
	report.Checks = []Check{{Name: "explicit-objects-absent", Passed: true}, {Name: "derived-objects-absent", Passed: true}, {Name: "pvc-pv-and-longhorn-backend-absent", Passed: true}, {Name: "owned-local-state-absent", Passed: true}}
	return report, nil
}

func (engine *Engine) waitStorageAbsent(ctx context.Context) error {
	return poll(ctx, 3*time.Second, func() (bool, error) {
		claims := map[string]bool{}
		for _, ref := range engine.Store.State.DerivedObjects {
			if ref.APIVersion == "v1" && ref.Kind == "PersistentVolumeClaim" {
				claims[ref.UID] = true
			}
		}
		volumes, err := engine.Client.list(ctx, "/api/v1/persistentvolumes", nil)
		if err != nil {
			return false, err
		}
		remaining := false
		for _, pv := range volumes {
			claim := nested(pv, "spec", "claimRef")
			if stringField(claim, "namespace") != engine.Store.State.Profile.Target.Namespace {
				continue
			}
			if !claims[stringField(claim, "uid")] {
				return false, errors.New("development namespace volume has an unrecorded claim identity; preserved")
			}
			remaining = true
			if err := engine.recordVolume(ctx, pv, stringField(claim, "uid")); err != nil {
				return false, err
			}
		}
		if err := engine.validateRecordedVolumes(); err != nil {
			return false, err
		}
		for _, volume := range engine.Store.State.Volumes {
			for _, ref := range []Object{volume.PersistentVolume, volume.Backend} {
				object, err := engine.Client.get(ctx, ref)
				if apiStatus(err, http.StatusNotFound) {
					continue
				}
				if err != nil {
					return false, err
				}
				meta, _ := metadata(object)
				if stringField(meta, "uid") != ref.UID {
					return false, ErrConflict
				}
				remaining = true
			}
		}
		// A late provisioner may create a handle after its PVC disappeared.
		// Longhorn's CSI handles are derived from the immutable PVC UID.
		for claim := range claims {
			items, err := engine.Client.list(ctx, "/apis/longhorn.io/v1beta2/volumes", url.Values{"fieldSelector": {"metadata.name=pvc-" + claim}})
			if err != nil {
				return false, err
			}
			if len(items) != 0 {
				remaining = true
				known := false
				for _, volume := range engine.Store.State.Volumes {
					if volume.ClaimUID == claim && volume.Handle == "pvc-"+claim {
						known = true
					}
				}
				if !known {
					return false, errors.New("late owned Longhorn volume needs identity reconciliation; preserved")
				}
			}
		}
		return !remaining, nil
	})
}

// Reset is explicitly destructive for this one installation. It starts a new
// ownership identity only after the previous installation has a green receipt.
func (engine *Engine) Reset(ctx context.Context) (Report, error) {
	profile, path := engine.Store.State.Profile, engine.Store.Path
	if _, err := engine.Destroy(ctx); err != nil {
		return Report{}, err
	}
	if err := engine.Store.Close(); err != nil {
		return Report{}, err
	}
	store, err := OpenState(path, profile, true)
	if err != nil {
		return Report{}, err
	}
	engine.Store = store
	return engine.Create(ctx)
}
