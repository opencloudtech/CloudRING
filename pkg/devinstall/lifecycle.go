// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"
)

type Engine struct {
	Client   *Client
	Store    *StateStore
	Progress io.Writer
}

type Report struct {
	APIVersion       string               `json:"apiVersion"`
	InstallationID   string               `json:"installationID"`
	Profile          string               `json:"profile"`
	ProfileSHA256    string               `json:"profileSHA256"`
	SourceCommit     string               `json:"sourceCommit"`
	ProductionReady  bool                 `json:"productionReady"`
	ObservedAt       time.Time            `json:"observedAt"`
	Phase            string               `json:"phase"`
	Ready            bool                 `json:"ready"`
	TargetClusterUID string               `json:"targetClusterUID"`
	PublicOrigin     string               `json:"publicOrigin"`
	Objects          []Object             `json:"objects"`
	DerivedObjects   []Object             `json:"derivedObjects,omitempty"`
	Volumes          []OwnedVolume        `json:"volumes,omitempty"`
	Provider         *ProviderObservation `json:"provider,omitempty"`
	Checks           []Check              `json:"checks"`
	ZeroOwnedResidue bool                 `json:"zeroOwnedResidue"`
}

type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Code   string `json:"code,omitempty"`
}

func (engine *Engine) guard() error {
	if engine == nil || engine.Client == nil || engine.Store == nil || engine.Client.profile.InstallationID != engine.Store.State.InstallationID ||
		Fingerprint(engine.Client.profile) != engine.Store.State.ProfileSHA256 {
		return ErrConflict
	}
	if err := engine.Store.guard(); err != nil {
		return err
	}
	if err := engine.Store.validateState(engine.Client.profile); err != nil {
		return err
	}
	plan, err := BuildPlan(engine.Client.profile)
	if err != nil {
		return err
	}
	desired, err := renderObjects(engine.Store.State)
	if err != nil {
		return err
	}
	seen := map[Object]bool{}
	for _, owned := range engine.Store.State.Objects {
		ref := owned.Object
		ref.UID = ""
		if seen[ref] || !engine.Client.allowed(ref) || owned.UID != "" && !kubernetesUID.MatchString(owned.UID) {
			return ErrConflict
		}
		seen[ref] = true
		for index, candidate := range plan.Objects {
			if candidate == ref && owned.DesiredSHA256 != objectFingerprint(desired[index]) {
				return ErrConflict
			}
		}
	}
	return nil
}

func (engine *Engine) report() Report {
	state := engine.Store.State
	objects := make([]Object, 0, len(state.Objects))
	for _, owned := range state.Objects {
		objects = append(objects, owned.Object)
	}
	return Report{APIVersion: "cloudring.development-report/v1", InstallationID: state.InstallationID, Profile: Development,
		ProfileSHA256: state.ProfileSHA256, SourceCommit: state.Profile.Artifacts.SourceCommit, DerivedObjects: state.DerivedObjects, Volumes: state.Volumes,
		ObservedAt: time.Now().UTC(), Phase: state.Phase, TargetClusterUID: state.Profile.Target.KubeSystemUID, PublicOrigin: state.Profile.Network.PublicOrigin,
		Objects: objects, Checks: []Check{}}
}

func (engine *Engine) progress(phase string) error {
	if engine.Progress == nil {
		return nil
	}
	return json.NewEncoder(engine.Progress).Encode(map[string]string{"installationID": engine.Store.State.InstallationID, "phase": phase})
}

func (engine *Engine) pending(ref Object, desired apiObject) (int, error) {
	for index, owned := range engine.Store.State.Objects {
		comparison := owned.Object
		comparison.UID = ""
		if comparison == ref {
			return index, nil
		}
	}
	engine.Store.State.Objects = append(engine.Store.State.Objects, OwnedObject{Object: ref, DesiredSHA256: objectFingerprint(desired)})
	if err := engine.Store.Save(); err != nil {
		return 0, err
	}
	return len(engine.Store.State.Objects) - 1, nil
}

func (engine *Engine) reconcile(ctx context.Context, ref Object, desired apiObject) error {
	if err := engine.guard(); err != nil {
		return err
	}
	index, err := engine.pending(ref, desired)
	if err != nil {
		return err
	}
	expected := engine.Store.State.Objects[index]
	observed, err := engine.Client.get(ctx, ref)
	if apiStatus(err, http.StatusNotFound) {
		if expected.UID != "" {
			return errors.New("recorded development object disappeared; destroy/reset required")
		}
		if err := engine.Client.verifyCluster(ctx); err != nil {
			return err
		}
		if _, err := engine.Client.create(ctx, ref, desired, true); err != nil {
			return err
		}
		observed, err = engine.Client.create(ctx, ref, desired, false)
		if err != nil {
			return err
		} // The pending journal enables a safe retry after an uncertain response.
	} else if err != nil {
		return err
	}
	owned, _, err := readOwned(observed, expected.Object, engine.Store.State)
	if err != nil || !containsDesired(observed, desired) {
		return ErrConflict
	}
	owned.DesiredSHA256 = expected.DesiredSHA256
	engine.Store.State.Objects[index] = owned
	return engine.Store.Save()
}

// containsDesired permits API defaulted fields while rejecting changes to
// every submitted field and extra list entries such as disks or containers.
func containsDesired(observed, desired any) bool {
	switch value := desired.(type) {
	case localObjectReference:
		return containsDesired(observed, map[string]any{"name": value.Name})
	case apiObject:
		return containsDesired(observed, map[string]any(value))
	case map[string]any:
		actual, ok := observed.(map[string]any)
		if !ok {
			if converted, ok := observed.(apiObject); ok {
				actual = converted
			} else {
				return false
			}
		}
		for key, expected := range value {
			if !containsDesired(actual[key], expected) {
				return false
			}
		}
		return true
	case []any:
		actual, ok := observed.([]any)
		if !ok || len(actual) != len(value) {
			return false
		}
		for index, expected := range value {
			if !containsDesired(actual[index], expected) {
				return false
			}
		}
		return true
	case []string:
		actual, ok := observed.([]any)
		if !ok || len(actual) != len(value) {
			return false
		}
		for index, expected := range value {
			if actual[index] != expected {
				return false
			}
		}
		return true
	case int:
		actual, ok := observed.(float64)
		return ok && actual == float64(value)
	default:
		return reflect.DeepEqual(observed, desired)
	}
}

func (engine *Engine) Create(ctx context.Context) (Report, error) {
	if err := engine.guard(); err != nil {
		return Report{}, err
	}
	if engine.Store.State.Phase == "destroying" {
		return engine.report(), errors.New("development destruction must finish before creating again")
	}
	if err := engine.Client.verifyCluster(ctx); err != nil {
		return engine.report(), err
	}
	// A resumed guest already consumes its reservation; never demand capacity
	// for a duplicate guest. Verify its immutable journal before continuing.
	vmExists := false
	for _, owned := range engine.Store.State.Objects {
		if owned.Kind == "VirtualMachine" && owned.UID != "" {
			observed, err := engine.Client.get(ctx, owned.Object)
			if err != nil {
				return engine.report(), err
			}
			if _, _, err := readOwned(observed, owned.Object, engine.Store.State); err != nil {
				return engine.report(), err
			}
			vmExists = true
		}
	}
	if !vmExists {
		if _, err := engine.Client.CheckPrerequisites(ctx); err != nil {
			return engine.report(), err
		}
	}
	if err := engine.ensureInstaller(ctx); err != nil {
		return engine.report(), err
	}
	engine.Store.State.Phase = "creating"
	engine.Store.State.FailureCode = ""
	if err := engine.Store.Save(); err != nil {
		return engine.report(), err
	}
	plan, _ := BuildPlan(engine.Store.State.Profile)
	desired, err := renderObjects(engine.Store.State)
	if err != nil {
		return engine.report(), err
	}
	for index, ref := range plan.Objects {
		if err := engine.progress("reconcile-" + ref.Kind); err != nil {
			return engine.report(), err
		}
		if err := engine.reconcile(ctx, ref, desired[index]); err != nil {
			return engine.report(), err
		}
	}
	if err := engine.ensureGuestRunning(ctx); err != nil {
		return engine.report(), err
	}
	if err := engine.recordGuestStorage(ctx); err != nil {
		return engine.report(), err
	}
	if err := engine.progress("bootstrap-owned-guest"); err != nil {
		return engine.report(), err
	}
	guest, err := engine.waitGuest(ctx)
	if err != nil {
		return engine.report(), err
	}
	defer guest.Close()
	if err := engine.bootstrapGuest(ctx, guest); err != nil {
		return engine.report(), err
	}
	engine.Store.State.GuestBootstrapped = true
	if err := engine.Store.Save(); err != nil {
		return engine.report(), err
	}
	observation, err := engine.observeProvider(ctx, guest)
	if err != nil {
		return engine.report(), err
	}
	engine.Store.State.Phase = "ready"
	if err := engine.Store.Save(); err != nil {
		return engine.report(), err
	}
	if err := engine.Store.WriteCredentialFile("api-ca.pem", []byte(engine.Store.State.Credentials.CACertificate)); err != nil {
		return engine.report(), err
	}
	if err := engine.Store.WriteCredentialFile("operator-token", []byte(engine.Store.State.Credentials.OperatorToken)); err != nil {
		return engine.report(), err
	}
	report := engine.report()
	report.Ready = true
	report.Provider = &observation
	report.Checks = []Check{{Name: "guest-bootstrap", Passed: true}, {Name: "verified-provider-api", Passed: true}, {Name: "operator-denials", Passed: true}}
	return report, nil
}

func (engine *Engine) vm() (OwnedObject, error) {
	for _, owned := range engine.Store.State.Objects {
		if owned.Kind == "VirtualMachine" && owned.UID != "" {
			return owned, nil
		}
	}
	return OwnedObject{}, ErrNotFound
}

func (engine *Engine) verifyVMI(ctx context.Context) (apiObject, error) {
	vm, err := engine.vm()
	if err != nil {
		return nil, err
	}
	ref := Object{APIVersion: "kubevirt.io/v1", Kind: "VirtualMachineInstance", Resource: "virtualmachineinstances", Namespace: vm.Namespace, Name: vm.Name}
	object, err := engine.Client.get(ctx, ref)
	if err != nil {
		return nil, err
	}
	if _, _, err := readOwned(object, ref, engine.Store.State); err != nil {
		return nil, err
	}
	meta, _ := metadata(object)
	owners, _ := meta["ownerReferences"].([]any)
	for _, item := range owners {
		owner, _ := item.(map[string]any)
		if stringField(owner, "kind") == "VirtualMachine" && stringField(owner, "uid") == vm.UID && stringField(owner, "name") == vm.Name && owner["controller"] == true {
			return object, nil
		}
	}
	return nil, ErrConflict
}

func (engine *Engine) ensureGuestRunning(ctx context.Context) error {
	vm, err := engine.vm()
	if err != nil {
		return err
	}
	observed, err := engine.Client.get(ctx, vm.Object)
	if err != nil {
		return err
	}
	if _, _, err := readOwned(observed, vm.Object, engine.Store.State); err != nil {
		return err
	}
	if stringField(nested(observed, "spec"), "runStrategy") != "Always" {
		return ErrConflict
	}
	// Creation atomically starts only this owned VM. KubeVirt's start
	// subresource has no UID precondition, so it is deliberately not used.
	return poll(ctx, 2*time.Second, func() (bool, error) {
		object, err := engine.verifyVMI(ctx)
		if apiStatus(err, http.StatusNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		phase := stringField(nested(object, "status"), "phase")
		if phase == "Failed" || phase == "Succeeded" {
			return false, errors.New("owned guest is terminal")
		}
		return phase == "Running" && condition(object, "Ready", "True"), nil
	})
}

func poll(ctx context.Context, interval time.Duration, check func() (bool, error)) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		done, err := check()
		if err != nil || done {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (engine *Engine) waitGuest(ctx context.Context) (*guestClient, error) {
	var guest *guestClient
	err := poll(ctx, 3*time.Second, func() (bool, error) {
		if _, err := engine.verifyVMI(ctx); err != nil {
			return false, err
		}
		var err error
		guest, err = engine.Client.connectGuest(ctx, engine.Store.State)
		if err != nil {
			if errors.Is(err, ErrCredentials) || errors.Is(err, ErrConflict) || errors.Is(err, errGuestAuthentication) {
				return false, err
			}
			return false, nil
		}
		if err := engine.verifyGuestIdentity(ctx, guest); err != nil {
			_ = guest.Close()
			return false, err
		}
		return true, nil
	})
	return guest, err
}
