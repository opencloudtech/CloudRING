// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package velero118

import (
	"encoding/json"
	"testing"
)

func TestPVProofStateIgnoresControllerNoiseAndRejectsMaterialChange(t *testing.T) {
	t.Parallel()
	base := map[string]any{
		"apiVersion": "v1", "kind": "PersistentVolume",
		"metadata": map[string]any{"name": "source-pv", "namespace": "", "uid": "pv-uid", "resourceVersion": "10", "labels": map[string]any{"unrelated": "old"}},
		"spec": map[string]any{
			"claimRef": map[string]any{"namespace": "source", "name": "volume", "uid": "pvc-uid"},
			"csi":      map[string]any{"driver": "csi.example", "volumeHandle": "handle"},
		},
		"status": map[string]any{"phase": "Bound", "lastPhaseTransitionTime": "2026-07-01T00:00:00Z"},
	}
	assertProofNoiseAndChanges(t, "PersistentVolume", base, func(noisy map[string]any) {
		metadata := noisy["metadata"].(map[string]any)
		metadata["resourceVersion"] = "11"
		metadata["annotations"] = map[string]any{"controller.example/heartbeat": "new"}
		metadata["labels"] = map[string]any{"unrelated": "new"}
		noisy["status"].(map[string]any)["lastPhaseTransitionTime"] = "2026-07-02T00:00:00Z"
	}, map[string]func(map[string]any){
		"claim identity": func(changed map[string]any) {
			changed["spec"].(map[string]any)["claimRef"].(map[string]any)["uid"] = "other-pvc"
		},
		"CSI handle": func(changed map[string]any) {
			changed["spec"].(map[string]any)["csi"].(map[string]any)["volumeHandle"] = "other-handle"
		},
		"bound phase": func(changed map[string]any) { changed["status"].(map[string]any)["phase"] = "Released" },
	})
}

func TestDataDownloadProofStateIgnoresControllerNoiseAndRejectsLineageChange(t *testing.T) {
	t.Parallel()
	base := map[string]any{
		"apiVersion": "velero.io/v2alpha1", "kind": "DataDownload",
		"metadata": map[string]any{
			"name": "restore-volume", "namespace": "velero", "uid": "download-uid", "resourceVersion": "20",
			"labels": map[string]any{
				"velero.io/restore-name": "restore", "velero.io/restore-uid": "restore-uid", "velero.io/async-operation-id": "operation", "unrelated": "old",
			},
			"ownerReferences": []any{map[string]any{"apiVersion": "velero.io/v1", "kind": "Restore", "name": "restore", "uid": "restore-uid", "controller": true}},
		},
		"spec": map[string]any{
			"targetVolume": map[string]any{"pvc": "volume", "pv": "", "namespace": "target"},
			"snapshotID":   "snapshot", "backupStorageLocation": "offcell",
		},
		"status": map[string]any{
			"phase": "Completed", "startTimestamp": "2026-07-01T00:00:00Z", "completionTimestamp": "2026-07-01T00:01:00Z",
			"progress": map[string]any{"bytesDone": 4096, "totalBytes": 4096}, "controllerHeartbeat": "old",
		},
	}
	assertProofNoiseAndChanges(t, "DataDownload", base, func(noisy map[string]any) {
		metadata := noisy["metadata"].(map[string]any)
		metadata["resourceVersion"] = "21"
		metadata["annotations"] = map[string]any{"controller.example/heartbeat": "new"}
		metadata["labels"].(map[string]any)["unrelated"] = "new"
		noisy["status"].(map[string]any)["controllerHeartbeat"] = "new"
	}, map[string]func(map[string]any){
		"owner UID": func(changed map[string]any) {
			changed["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["uid"] = "other-restore"
		},
		"lineage label": func(changed map[string]any) {
			changed["metadata"].(map[string]any)["labels"].(map[string]any)["velero.io/restore-uid"] = "other-restore"
		},
		"snapshot":       func(changed map[string]any) { changed["spec"].(map[string]any)["snapshotID"] = "other-snapshot" },
		"terminal phase": func(changed map[string]any) { changed["status"].(map[string]any)["phase"] = "Failed" },
		"terminal time": func(changed map[string]any) {
			changed["status"].(map[string]any)["completionTimestamp"] = "2026-07-01T00:02:00Z"
		},
		"terminal progress": func(changed map[string]any) {
			changed["status"].(map[string]any)["progress"].(map[string]any)["bytesDone"] = float64(2048)
		},
	})
}

func assertProofNoiseAndChanges(t *testing.T, kind string, base map[string]any, mutateNoise func(map[string]any), changes map[string]func(map[string]any)) {
	t.Helper()
	baseDigest, err := proofRelevantKubernetesStateSHA256(base, kind)
	if err != nil {
		t.Fatal(err)
	}
	noisy := cloneProofState(t, base)
	mutateNoise(noisy)
	noisyDigest, err := proofRelevantKubernetesStateSHA256(noisy, kind)
	if err != nil || noisyDigest != baseDigest {
		t.Fatalf("%s controller noise changed proof digest: %s != %s, err=%v", kind, noisyDigest, baseDigest, err)
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			changed := cloneProofState(t, base)
			mutate(changed)
			digest, err := proofRelevantKubernetesStateSHA256(changed, kind)
			if err != nil {
				t.Fatal(err)
			}
			if digest == baseDigest {
				t.Fatalf("%s proof-relevant %s change was ignored", kind, name)
			}
		})
	}
}

func cloneProofState(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned map[string]any
	if err := json.Unmarshal(payload, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}
