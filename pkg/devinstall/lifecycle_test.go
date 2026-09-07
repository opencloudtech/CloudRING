//go:build linux || darwin

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testEngine(t *testing.T, handler http.Handler) *Engine {
	t.Helper()
	client, profile, _ := testAPIClient(t, handler)
	store, err := OpenState(filepath.Join(t.TempDir(), "owned-installation"), profile, true)
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{Client: client, Store: store}
	t.Cleanup(func() { _ = engine.Store.Close() })
	return engine
}

func emitJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}

func normalizeObject(t *testing.T, value apiObject, uid string) apiObject {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result apiObject
	if json.Unmarshal(payload, &result) != nil {
		t.Fatal("normalize object")
	}
	meta, _ := metadata(result)
	meta["uid"] = uid
	meta["resourceVersion"] = "1"
	return result
}

func TestCreateRecoversUncertainAPIResponseWithoutDuplicateOrAdoption(t *testing.T) {
	var lock sync.Mutex
	var stored apiObject
	var realCreates atomic.Int32
	var engine *Engine
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		if request.URL.Path == "/api/v1/namespaces/kube-system" {
			emitJSON(writer, apiObject{"metadata": map[string]any{"uid": engine.Store.State.Profile.Target.KubeSystemUID}})
			return
		}
		switch request.Method {
		case http.MethodGet:
			if stored == nil {
				writer.WriteHeader(http.StatusNotFound)
			} else {
				emitJSON(writer, stored)
			}
		case http.MethodPost:
			var object apiObject
			if json.NewDecoder(request.Body).Decode(&object) != nil {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			meta, _ := metadata(object)
			meta["uid"] = "11111111-1111-4111-8111-111111111111"
			meta["resourceVersion"] = "1"
			if request.URL.Query().Get("dryRun") == "All" {
				emitJSON(writer, object)
				return
			}
			realCreates.Add(1)
			stored = object
			// The server committed the create, but the client cannot observe
			// the response. A restart must recover the same owned UID.
			connection, _, err := writer.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
		default:
			t.Error("unexpected API mutation")
			writer.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	engine = testEngine(t, handler)
	plan, _ := BuildPlan(engine.Store.State.Profile)
	desired, err := renderObjects(engine.Store.State)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.reconcile(context.Background(), plan.Objects[0], desired[0]); err == nil {
		t.Fatal("uncertain response was reported as success")
	}
	if len(engine.Store.State.Objects) != 1 || engine.Store.State.Objects[0].UID != "" {
		t.Fatal("uncertain create did not retain a pending journal")
	}
	path, profile, nonce := engine.Store.Path, engine.Store.State.Profile, engine.Store.State.OwnerNonce
	if err := engine.Store.Close(); err != nil {
		t.Fatal(err)
	}
	engine.Store, err = OpenState(path, profile, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.reconcile(context.Background(), plan.Objects[0], desired[0]); err != nil {
		t.Fatal(err)
	}
	if engine.Store.State.OwnerNonce != nonce || engine.Store.State.Objects[0].UID != "11111111-1111-4111-8111-111111111111" || realCreates.Load() != 1 {
		t.Fatal("retry duplicated or replaced ownership")
	}
	lock.Lock()
	meta, _ := metadata(stored)
	meta["uid"] = "22222222-2222-4222-8222-222222222222"
	lock.Unlock()
	if err := engine.reconcile(context.Background(), plan.Objects[0], desired[0]); !errors.Is(err, ErrConflict) {
		t.Fatal("replacement object adopted")
	}
	if realCreates.Load() != 1 {
		t.Fatal("conflict triggered another create")
	}
}

func TestDestroyRefusesForeignNamespaceContentBeforeAnyDeletion(t *testing.T) {
	var deletions atomic.Int32
	var engine *Engine
	var namespace apiObject
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodDelete {
			deletions.Add(1)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch request.URL.Path {
		case "/api/v1/namespaces/kube-system":
			emitJSON(writer, apiObject{"metadata": map[string]any{"uid": engine.Store.State.Profile.Target.KubeSystemUID}})
		case "/api/v1/namespaces/cloudring-dev-parser-test":
			emitJSON(writer, namespace)
		case "/apis":
			emitJSON(writer, apiObject{"groups": []any{}})
		case "/api/v1":
			emitJSON(writer, apiObject{"groupVersion": "v1", "resources": []any{map[string]any{"name": "configmaps", "kind": "ConfigMap", "namespaced": true, "verbs": []string{"get", "list", "delete"}}}})
		case "/api/v1/namespaces/cloudring-dev-parser-test/configmaps":
			emitJSON(writer, apiObject{"items": []any{map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "foreign-content", "namespace": "cloudring-dev-parser-test", "uid": "33333333-3333-4333-8333-333333333333"}, "data": map[string]any{"keep": "operator data"}}}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	})
	engine = testEngine(t, handler)
	plan, _ := BuildPlan(engine.Store.State.Profile)
	desired, _ := renderObjects(engine.Store.State)
	namespace = normalizeObject(t, desired[0], "11111111-1111-4111-8111-111111111111")
	ref := plan.Objects[0]
	ref.UID = "11111111-1111-4111-8111-111111111111"
	engine.Store.State.Objects = []OwnedObject{{Object: ref, DesiredSHA256: objectFingerprint(desired[0])}}
	if err := engine.Store.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Destroy(context.Background()); err == nil {
		t.Fatal("foreign namespace content deleted")
	}
	if deletions.Load() != 0 {
		t.Fatal("destruction began before foreign-content gate")
	}
	if _, err := os.Stat(filepath.Join(engine.Store.Path, "state.json")); err != nil {
		t.Fatal("ownership recovery journal removed")
	}
}

func TestDestroyProducesReceiptOnlyAfterAPIAndLocalAbsence(t *testing.T) {
	var engine *Engine
	var lock sync.Mutex
	var namespace apiObject
	var removed bool
	var deletions atomic.Int32
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		switch request.URL.Path {
		case "/api/v1/namespaces/kube-system":
			emitJSON(writer, apiObject{"metadata": map[string]any{"uid": engine.Store.State.Profile.Target.KubeSystemUID}})
		case "/api/v1/namespaces/cloudring-dev-parser-test":
			if removed {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			if request.Method == http.MethodDelete {
				var body apiObject
				_ = json.NewDecoder(request.Body).Decode(&body)
				if stringField(nested(body, "preconditions"), "uid") != "11111111-1111-4111-8111-111111111111" || stringField(nested(body, "preconditions"), "resourceVersion") != "1" {
					t.Error("missing deletion guards")
				}
				deletions.Add(1)
				removed = true
				emitJSON(writer, apiObject{"kind": "Status"})
			} else {
				emitJSON(writer, namespace)
			}
		case "/apis":
			emitJSON(writer, apiObject{"groups": []any{}})
		case "/api/v1":
			emitJSON(writer, apiObject{"groupVersion": "v1", "resources": []any{}})
		case "/api/v1/persistentvolumes":
			emitJSON(writer, apiObject{"items": []any{}})
		default:
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	})
	engine = testEngine(t, handler)
	plan, _ := BuildPlan(engine.Store.State.Profile)
	desired, _ := renderObjects(engine.Store.State)
	namespace = normalizeObject(t, desired[0], "11111111-1111-4111-8111-111111111111")
	// Pending UID exercises crash recovery before the destroy inventory.
	engine.Store.State.Objects = []OwnedObject{{Object: plan.Objects[0], DesiredSHA256: objectFingerprint(desired[0])}}
	if err := engine.Store.Save(); err != nil {
		t.Fatal(err)
	}
	path := engine.Store.Path
	report, err := engine.Destroy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !report.ZeroOwnedResidue || report.Phase != "destroyed" || report.ProductionReady || deletions.Load() != 1 {
		t.Fatal("invalid cleanup receipt")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("local owned residue remains")
	}
}

func TestLonghornCleanupWaitsForBackendUIDAndNeverForcesDeletion(t *testing.T) {
	var absent atomic.Bool
	var mutations atomic.Int32
	var engine *Engine
	claim := "44444444-4444-4444-8444-444444444444"
	backend := Object{APIVersion: "longhorn.io/v1beta2", Kind: "Volume", Resource: "volumes", Namespace: "longhorn-system", Name: "pvc-" + claim, UID: "55555555-5555-4555-8555-555555555555"}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			mutations.Add(1)
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch {
		case request.URL.Path == "/api/v1/persistentvolumes":
			emitJSON(writer, apiObject{"items": []any{}})
		case request.URL.Path == "/apis/longhorn.io/v1beta2/volumes":
			items := []any{}
			if !absent.Load() {
				items = append(items, map[string]any{"metadata": map[string]any{"name": backend.Name, "namespace": backend.Namespace, "uid": backend.UID}})
			}
			emitJSON(writer, apiObject{"items": items})
		case strings.Contains(request.URL.Path, "/namespaces/longhorn-system/volumes/") && !absent.Load():
			emitJSON(writer, apiObject{"metadata": map[string]any{"name": backend.Name, "namespace": backend.Namespace, "uid": backend.UID}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	})
	engine = testEngine(t, handler)
	engine.Store.State.DerivedObjects = []Object{{APIVersion: "v1", Kind: "PersistentVolumeClaim", Resource: "persistentvolumeclaims", Namespace: engine.Store.State.Profile.Target.Namespace, Name: "development-linux-root", UID: claim}}
	engine.Store.State.Volumes = []OwnedVolume{{PersistentVolume: Object{APIVersion: "v1", Kind: "PersistentVolume", Resource: "persistentvolumes", Name: "pvc-" + claim, UID: "66666666-6666-4666-8666-666666666666"}, ClaimUID: claim, Driver: "driver.longhorn.io", Handle: backend.Name, Backend: backend}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := engine.waitStorageAbsent(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("backend residue accepted: %v", err)
	}
	absent.Store(true)
	if err := engine.waitStorageAbsent(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mutations.Load() != 0 {
		t.Fatal("backend cleanup was forced")
	}
}

func TestReviewDestroyFindsForeignResourceOutsideGroupPreferredVersion(t *testing.T) {
	var deletions atomic.Int32
	var engine *Engine
	var namespace apiObject
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletions.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-system":
			emitJSON(w, apiObject{"metadata": map[string]any{"uid": engine.Store.State.Profile.Target.KubeSystemUID}})
		case "/api/v1/namespaces/cloudring-dev-parser-test":
			emitJSON(w, namespace)
		case "/apis":
			emitJSON(w, apiObject{"groups": []any{map[string]any{"name": "review.example.com", "preferredVersion": map[string]any{"groupVersion": "review.example.com/v1", "version": "v1"}, "versions": []any{map[string]any{"groupVersion": "review.example.com/v1", "version": "v1"}, map[string]any{"groupVersion": "review.example.com/v1alpha1", "version": "v1alpha1"}}}}})
		case "/api/v1":
			emitJSON(w, apiObject{"groupVersion": "v1", "resources": []any{}})
		case "/apis/review.example.com/v1":
			emitJSON(w, apiObject{"groupVersion": "review.example.com/v1", "resources": []any{}})
		case "/apis/review.example.com/v1alpha1":
			emitJSON(w, apiObject{"groupVersion": "review.example.com/v1alpha1", "resources": []any{map[string]any{"name": "widgets", "kind": "Widget", "namespaced": true, "verbs": []string{"get", "list", "delete"}}}})
		case "/apis/review.example.com/v1alpha1/namespaces/cloudring-dev-parser-test/widgets":
			emitJSON(w, apiObject{"items": []any{map[string]any{"apiVersion": "review.example.com/v1alpha1", "kind": "Widget", "metadata": map[string]any{"name": "foreign-widget", "namespace": "cloudring-dev-parser-test", "uid": "33333333-3333-4333-8333-333333333333"}, "spec": map[string]any{"keep": "operator data"}}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	engine = testEngine(t, handler)
	plan, _ := BuildPlan(engine.Store.State.Profile)
	desired, _ := renderObjects(engine.Store.State)
	namespace = normalizeObject(t, desired[0], "11111111-1111-4111-8111-111111111111")
	ref := plan.Objects[0]
	ref.UID = "11111111-1111-4111-8111-111111111111"
	engine.Store.State.Objects = []OwnedObject{{Object: ref, DesiredSHA256: objectFingerprint(desired[0])}}
	if err := engine.Store.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Destroy(context.Background()); err == nil {
		t.Fatal("foreign resource was not detected")
	}
	if deletions.Load() != 0 {
		t.Fatalf("namespace delete reached API while foreign nonpreferred-version resource exists: deletes=%d", deletions.Load())
	}
}

func TestReviewDestroyCannotClaimStorageAbsentAfterNamespaceDisappearsBeforeInventory(t *testing.T) {
	var engine *Engine
	var mutations atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutations.Add(1)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-system":
			emitJSON(w, apiObject{"metadata": map[string]any{"uid": engine.Store.State.Profile.Target.KubeSystemUID}})
		case "/api/v1/persistentvolumes":
			emitJSON(w, apiObject{"items": []any{map[string]any{"apiVersion": "v1", "kind": "PersistentVolume", "metadata": map[string]any{"name": "pvc-44444444-4444-4444-8444-444444444444", "uid": "55555555-5555-4555-8555-555555555555"}, "spec": map[string]any{"claimRef": map[string]any{"namespace": engine.Store.State.Profile.Target.Namespace, "name": engine.Store.State.Profile.Target.VirtualMachine + "-root", "uid": "44444444-4444-4444-8444-444444444444"}, "storageClassName": engine.Store.State.Profile.Target.StorageClass, "persistentVolumeReclaimPolicy": "Delete", "csi": map[string]any{"driver": "driver.longhorn.io", "volumeHandle": "pvc-44444444-4444-4444-8444-444444444444"}}}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	engine = testEngine(t, handler)
	plan, _ := BuildPlan(engine.Store.State.Profile)
	desired, _ := renderObjects(engine.Store.State)
	for i, ref := range plan.Objects {
		if ref.Kind != "Namespace" && ref.Kind != "DataVolume" {
			continue
		}
		ref.UID = "11111111-1111-4111-8111-111111111111"
		if ref.Kind == "DataVolume" {
			ref.UID = "22222222-2222-4222-8222-222222222222"
		}
		engine.Store.State.Objects = append(engine.Store.State.Objects, OwnedObject{Object: ref, DesiredSHA256: objectFingerprint(desired[i])})
	}
	engine.Store.State.Phase = "creating"
	if err := engine.Store.Save(); err != nil {
		t.Fatal(err)
	}
	report, err := engine.Destroy(context.Background())
	if err == nil || report.ZeroOwnedResidue {
		t.Fatalf("cleanup claimed success with a still-present namespace PV whose claim UID was never inventoried: error=%v zeroOwnedResidue=%v", err, report.ZeroOwnedResidue)
	}
	if mutations.Load() != 0 {
		t.Fatal("unexpected API mutation during missing-namespace reconciliation")
	}
	if _, err := os.Stat(filepath.Join(engine.Store.Path, "state.json")); err != nil {
		t.Fatal("storage ownership uncertainty discarded the recovery journal")
	}
}
