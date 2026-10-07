// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

//go:build linux && etcdrecoveryintegration

package etcdrecovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRealSyntheticSnapshotRecovery consumes a source-safe snapshot generated
// by the CI job from a temporary loopback-only etcd. The worker itself receives
// only the completed file and invokes etcdutl offline.
func TestRealSyntheticSnapshotRecovery(t *testing.T) {
	archivePath := os.Getenv("CLOUDRING_TEST_ETCD_SNAPSHOT")
	toolPath := os.Getenv("CLOUDRING_TEST_ETCDUTL")
	if archivePath == "" || toolPath == "" {
		t.Fatal("real snapshot integration paths are required")
	}
	t.Cleanup(func() { _ = os.Chmod(archivePath, 0o600) })
	for _, test := range []struct {
		name string
		mode os.FileMode
	}{
		{name: "owner-read-write", mode: 0o600},
		{name: "owner-read-only", mode: 0o400},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Chmod(archivePath, test.mode); err != nil {
				t.Fatal(err)
			}
			runRealSyntheticSnapshotRecovery(t, archivePath, toolPath)
		})
	}
}

func runRealSyntheticSnapshotRecovery(t *testing.T, archivePath, toolPath string) {
	t.Helper()
	archive, err := openProtectedFile(archivePath, MaxArchiveBytes, exactOwnerOnly)
	if err != nil {
		t.Fatal(err)
	}
	archiveSHA, archiveBytes, err := archive.Digest()
	_ = archive.Close()
	if err != nil {
		t.Fatal(err)
	}
	tool, err := openProtectedFile(toolPath, maximumToolBytes, trustedExecutable)
	if err != nil {
		t.Fatal(err)
	}
	toolSHA, _, err := tool.Digest()
	_ = tool.Close()
	if err != nil {
		t.Fatal(err)
	}
	if toolSHA != ToolSHA256 {
		t.Fatalf("etcdutl digest = %s, want %s", toolSHA, ToolSHA256)
	}
	workerSHA, err := runningExecutableSHA256(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(root, "work")
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(inputs, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	inputSecretSHA, err := InputSecretProjectionSHA256(InputSecretProjection{
		SchemaVersion:       InputProjectionSchemaVersion,
		Namespace:           "kube-system",
		ProjectedObjectName: "cloudring-etcd-recovery-request",
		SecretKey:           "request.json",
		MountPath:           DefaultRequestPath,
		DefaultMode:         0o440,
		Optional:            false,
		ReadOnly:            true,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		SchemaVersion: RequestSchemaVersion, OperationID: "synthetic-integration", SnapshotID: "synthetic-snapshot",
		SnapshotChecksumSHA256: archiveSHA, SnapshotBytes: archiveBytes, SourceMode: "local-file",
		ClusterIdentitySHA256: strings.Repeat("1", 64), JobTemplateSHA256: strings.Repeat("2", 64),
		ExecutionProfileSHA256: strings.Repeat("3", 64), InputSecretSHA256: inputSecretSHA,
		WorkerExecutableSHA256: workerSHA, WorkerImageDigest: "sha256:" + strings.Repeat("5", 64),
		EtcdutlVersion: ToolVersion, EtcdutlSHA256: ToolSHA256,
		IssuedAt: canonicalTime(now.Add(-time.Minute)), ExpiresAt: canonicalTime(now.Add(10 * time.Minute)), TimeoutSeconds: 120,
	}
	request.ObjectIdentitySHA256 = ObjectIdentitySHA256(request)
	requestBytes, err := CanonicalRequest(request, now)
	if err != nil {
		t.Fatal(err)
	}
	requestRoot := filepath.Join(inputs, "request")
	writeProjectedMount(t, requestRoot, map[string]string{"request.json": string(requestBytes)})
	requestPath := filepath.Join(requestRoot, "request.json")
	receipt, err := Run(context.Background(), Paths{
		RequestPath: requestPath, ArchivePath: archivePath, ToolPath: toolPath,
		WorkspaceRoot: workspace, CredentialRoot: filepath.Join(root, "credentials"),
	})
	if err != nil || receipt.Status != "verified" || !receipt.OfflineMemberDatabaseVerified || !receipt.WorkspaceCleanupVerified {
		t.Fatalf("real snapshot receipt = %#v, %v", receipt, err)
	}
}
