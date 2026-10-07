// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package etcdrecovery

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeTool struct {
	identity     string
	restoreMode  string
	status       snapshotStatus
	restoredData []byte
	hashes       []snapshotKVHash
	hashCalls    int
}

func (tool *fakeTool) IdentitySHA256() string                      { return tool.identity }
func (tool *fakeTool) Close() error                                { return nil }
func (tool *fakeTool) VerifyVersion(context.Context, string) error { return nil }
func (tool *fakeTool) Status(ctx context.Context, _ *protectedFile, _ string) (snapshotStatus, error) {
	if tool.restoreMode == "cancel" {
		<-ctx.Done()
		return snapshotStatus{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return snapshotStatus{}, err
	}
	return tool.status, nil
}
func (tool *fakeTool) HashKV(ctx context.Context, _ *protectedFile, _ string) (snapshotKVHash, error) {
	if err := ctx.Err(); err != nil {
		return snapshotKVHash{}, err
	}
	index := tool.hashCalls
	tool.hashCalls++
	if len(tool.hashes) == 0 {
		return snapshotKVHash{Hash: 7, HashRevision: tool.status.Revision, CompactRevision: -1}, nil
	}
	if index >= len(tool.hashes) {
		index = len(tool.hashes) - 1
	}
	return tool.hashes[index], nil
}
func (tool *fakeTool) Restore(ctx context.Context, _ *protectedFile, dataDir string) error {
	if tool.restoreMode == "cancel" {
		<-ctx.Done()
		return ctx.Err()
	}
	if tool.restoreMode == "partial" {
		return nil
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "member", "snap"), 0o700); err != nil {
		return err
	}
	db := filepath.Join(dataDir, "member", "snap", "db")
	if tool.restoreMode == "symlink" {
		return os.Symlink(filepath.Join(filepath.Dir(dataDir), "outside"), db)
	}
	return os.WriteFile(db, tool.restoredData, 0o600)
}

func TestWorkerProducesSanitizedCanonicalReceiptAndCleansWorkspace(t *testing.T) {
	fixture := newWorkerFixture(t)
	receipt, err := run(context.Background(), fixture.paths, fixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "verified" || receipt.MemberHealthVerified || !receipt.OfflineMemberDatabaseVerified ||
		!receipt.LoopbackOnly || !receipt.WorkspaceCleanupVerified || receipt.EvidenceSHA256 == "" {
		t.Fatalf("receipt = %#v", receipt)
	}
	if receipt.EndpointSHA256 != EndpointSHA256(fixture.request) ||
		receipt.ObjectReferenceSHA256 != ObjectReferenceSHA256(fixture.request) {
		t.Fatalf("receipt binding helpers diverged: %#v", receipt)
	}
	payload, err := CanonicalReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{fixture.request.SnapshotID, fixture.request.ObjectKey, fixture.request.ObjectVersion, fixture.paths.ArchivePath} {
		if forbidden != "" && strings.Contains(string(payload), forbidden) {
			t.Fatalf("receipt leaked forbidden value %q: %s", forbidden, payload)
		}
	}
	entries, err := os.ReadDir(fixture.paths.WorkspaceRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("workspace residue = %v, %v", entries, err)
	}
}

func TestWorkerS3ModeUsesBoundedDisposableSourceHashCopy(t *testing.T) {
	fixture := newWorkerFixture(t)
	fixture.request.SourceMode = "s3"
	fixture.request.Endpoint = "https://objects.example.test"
	fixture.request.Region = "eu-west-1"
	fixture.request.Bucket = "synthetic-backup"
	fixture.request.ObjectKey = "snapshots/synthetic.db"
	fixture.request.ObjectVersion = "version-01"
	fixture.request.ObjectIdentitySHA256 = ObjectIdentitySHA256(fixture.request)
	fixture.writeRequest(t)
	archiveBytes, err := os.ReadFile(fixture.paths.ArchivePath) // #nosec G304 -- test-owned path.
	if err != nil {
		t.Fatal(err)
	}
	deps := fixture.dependencies()
	deps.fetchS3 = func(ctx context.Context, _ Request, _ string, workspace string, _ time.Time) (*protectedFile, error) {
		path := filepath.Join(workspace, "archive.db")
		// #nosec G703 -- workspace is an owner-only directory created and validated by the worker; archive.db is a fixed test filename.
		if err := os.WriteFile(path, archiveBytes, 0o600); err != nil {
			return nil, err
		}
		return openProtectedFile(path, MaxArchiveBytes, exactOwnerOnly)
	}
	receipt, err := run(context.Background(), fixture.paths, deps)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "verified" || receipt.SourceMode != "s3" ||
		!receipt.OfflineMemberDatabaseVerified || !receipt.WorkspaceCleanupVerified {
		t.Fatalf("S3 receipt = %#v", receipt)
	}
}

func TestWorkerRejectsWrongArchiveDigestSizeAndObjectIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Request)
	}{
		{"digest", func(r *Request) { r.SnapshotChecksumSHA256 = strings.Repeat("d", 64) }},
		{"size", func(r *Request) { r.SnapshotBytes++ }},
		{"object identity", func(r *Request) { r.ObjectIdentitySHA256 = strings.Repeat("e", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkerFixture(t)
			test.mutate(&fixture.request)
			fixture.writeRequest(t)
			if _, err := run(context.Background(), fixture.paths, fixture.dependencies()); err == nil {
				t.Fatal("worker accepted mismatched archive binding")
			}
		})
	}
}

func TestWorkerRejectsDuplicateUnknownAndNoncanonicalJSON(t *testing.T) {
	for _, payload := range []string{
		`{"schemaVersion":"cloudring.etcd-recovery.request/v1","schemaVersion":"cloudring.etcd-recovery.request/v1"}`,
		`{"unknown":true}`,
		`{ "schemaVersion": "cloudring.etcd-recovery.request/v1" }`,
	} {
		fixture := newWorkerFixture(t)
		fixture.writeRawRequest(t, []byte(payload))
		if _, err := run(context.Background(), fixture.paths, fixture.dependencies()); err == nil {
			t.Fatal("worker accepted invalid request JSON")
		}
	}
}

func TestMalformedRequestFailureBindsOnlyCanonicalInputBytes(t *testing.T) {
	fixture := newWorkerFixture(t)
	payload := []byte(`{"schemaVersion":"cloudring.etcd-recovery.request/v1"}`)
	fixture.writeRawRequest(t, payload)
	receipt, err := run(context.Background(), fixture.paths, fixture.dependencies())
	if err == nil {
		t.Fatal("worker accepted malformed request")
	}
	if receipt.RequestSHA256 != digestBytes(payload) || receipt.SourceMode != "" ||
		receipt.SnapshotIDSHA256 != "" || receipt.WorkerImageDigest != "" {
		t.Fatalf("malformed request receipt disclosed or invented decoded binding: %#v", receipt)
	}
	if _, err := CanonicalReceipt(receipt); err != nil {
		t.Fatalf("malformed request terminal receipt is invalid: %v", err)
	}
}

func TestWorkerRejectsSymlinkHardlinkTraversalAndOversizedInputs(t *testing.T) {
	t.Run("symlink request", func(t *testing.T) {
		fixture := newWorkerFixture(t)
		target := fixture.paths.RequestPath + ".target"
		if err := os.Rename(fixture.paths.RequestPath, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, fixture.paths.RequestPath); err != nil {
			t.Fatal(err)
		}
		if _, err := run(context.Background(), fixture.paths, fixture.dependencies()); err == nil {
			t.Fatal("worker accepted symlink input")
		}
	})
	t.Run("hardlink archive", func(t *testing.T) {
		fixture := newWorkerFixture(t)
		if err := os.Link(fixture.paths.ArchivePath, fixture.paths.ArchivePath+".link"); err != nil {
			t.Fatal(err)
		}
		if _, err := run(context.Background(), fixture.paths, fixture.dependencies()); err == nil {
			t.Fatal("worker accepted hardlinked archive")
		}
	})
	t.Run("path traversal", func(t *testing.T) {
		fixture := newWorkerFixture(t)
		directory := filepath.Dir(fixture.paths.ArchivePath)
		fixture.paths.ArchivePath = directory + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(directory) + string(filepath.Separator) + filepath.Base(fixture.paths.ArchivePath)
		if _, err := run(context.Background(), fixture.paths, fixture.dependencies()); err == nil {
			t.Fatal("worker accepted noncanonical traversal path")
		}
	})
	t.Run("oversized request", func(t *testing.T) {
		fixture := newWorkerFixture(t)
		fixture.writeRawRequest(t, []byte(strings.Repeat("x", MaxRequestBytes+1)))
		if _, err := run(context.Background(), fixture.paths, fixture.dependencies()); err == nil {
			t.Fatal("worker accepted oversized request")
		}
	})
	t.Run("oversized archive", func(t *testing.T) {
		fixture := newWorkerFixture(t)
		if err := os.Truncate(fixture.paths.ArchivePath, MaxArchiveBytes+1); err != nil {
			t.Fatal(err)
		}
		if _, err := run(context.Background(), fixture.paths, fixture.dependencies()); err == nil {
			t.Fatal("worker accepted oversized archive")
		}
	})
}

func TestWorkerCancellationToolSubstitutionAndPartialRestoreFailClosed(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		fixture := newWorkerFixture(t)
		fixture.tool.restoreMode = "cancel"
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		receipt, err := run(ctx, fixture.paths, fixture.dependencies())
		if err == nil {
			t.Fatal("worker accepted cancelled operation")
		}
		if receipt.Status != "cancelled" || receipt.ReasonCode != "operation_cancelled" || !receipt.WorkspaceCleanupVerified || receipt.EvidenceSHA256 == "" {
			t.Fatalf("cancelled receipt = %#v", receipt)
		}
	})
	t.Run("tool substitution", func(t *testing.T) {
		fixture := newWorkerFixture(t)
		fixture.tool.identity = strings.Repeat("f", 64)
		receipt, err := run(context.Background(), fixture.paths, fixture.dependencies())
		if err == nil {
			t.Fatal("worker accepted substituted tool")
		}
		if receipt.Tool != nil {
			t.Fatalf("failure receipt claimed unverified tool identity: %#v", receipt.Tool)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		fixture := newWorkerFixture(t)
		fixture.tool.restoreMode = "cancel"
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		receipt, err := run(ctx, fixture.paths, fixture.dependencies())
		if err == nil {
			t.Fatal("worker accepted timed-out operation")
		}
		if receipt.Status != "timeout" || receipt.ReasonCode != "operation_timed_out" || !receipt.WorkspaceCleanupVerified {
			t.Fatalf("timeout receipt = %#v", receipt)
		}
	})
	for _, mode := range []string{"partial", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newWorkerFixture(t)
			fixture.tool.restoreMode = mode
			receipt, err := run(context.Background(), fixture.paths, fixture.dependencies())
			if err == nil {
				t.Fatal("worker accepted incomplete or unsafe restore")
			}
			if receipt.Status != "failed" || !receipt.WorkspaceCleanupVerified || receipt.OfflineMemberDatabaseVerified || receipt.EvidenceSHA256 == "" {
				t.Fatalf("failed receipt = %#v", receipt)
			}
			for _, canary := range []string{fixture.request.ObjectKey, fixture.request.ObjectVersion} {
				if canary != "" && strings.Contains(err.Error(), canary) {
					t.Fatalf("error leaked private input: %v", err)
				}
			}
			entries, readErr := os.ReadDir(fixture.paths.WorkspaceRoot)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("failed operation left workspace residue: %v, %v", entries, readErr)
			}
		})
	}
}

func TestWorkerRejectsEqualStatusWithDifferentSemanticKVHash(t *testing.T) {
	fixture := newWorkerFixture(t)
	fixture.tool.hashes = []snapshotKVHash{
		{Hash: 1, HashRevision: fixture.tool.status.Revision, CompactRevision: -1},
		{Hash: 2, HashRevision: fixture.tool.status.Revision, CompactRevision: -1},
	}
	receipt, err := run(context.Background(), fixture.paths, fixture.dependencies())
	if err == nil {
		t.Fatal("worker accepted equal status metadata with different semantic KV content")
	}
	if receipt.Status != "failed" || receipt.OfflineMemberDatabaseVerified ||
		receipt.SourceKVHashSHA256 != "" || receipt.RestoredKVHashSHA256 != "" {
		t.Fatalf("semantic mismatch receipt = %#v", receipt)
	}
}

type workerFixture struct {
	paths   Paths
	request Request
	tool    *fakeTool
	now     time.Time
	selfSHA string
}

func newWorkerFixture(t *testing.T) *workerFixture {
	t.Helper()
	root := t.TempDir()
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	root = resolvedRoot
	workspace := filepath.Join(root, "work")
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(inputs, 0o700); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(inputs, "snapshot.db")
	archive := []byte("synthetic-etcd-snapshot-without-private-data")
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	selfSHA := strings.Repeat("a", 64)
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
		SchemaVersion: RequestSchemaVersion, OperationID: "operation-01", SnapshotID: "snapshot-01",
		SnapshotChecksumSHA256: digestBytes(archive), SnapshotBytes: int64(len(archive)),
		SourceMode:            "local-file",
		ClusterIdentitySHA256: strings.Repeat("1", 64), JobTemplateSHA256: strings.Repeat("2", 64),
		ExecutionProfileSHA256: strings.Repeat("3", 64), InputSecretSHA256: inputSecretSHA,
		WorkerExecutableSHA256: selfSHA, WorkerImageDigest: "sha256:" + strings.Repeat("c", 64),
		EtcdutlVersion: ToolVersion, EtcdutlSHA256: ToolSHA256,
		IssuedAt: canonicalTime(now.Add(-time.Minute)), ExpiresAt: canonicalTime(now.Add(10 * time.Minute)), TimeoutSeconds: 30,
	}
	request.ObjectIdentitySHA256 = ObjectIdentitySHA256(request)
	fixture := &workerFixture{
		paths: Paths{
			RequestPath: filepath.Join(inputs, "request", "request.json"), ArchivePath: archivePath,
			ToolPath: filepath.Join(inputs, "etcdutl"), WorkspaceRoot: workspace,
			CredentialRoot: filepath.Join(root, "credentials"),
		},
		request: request, now: now, selfSHA: selfSHA,
		tool: &fakeTool{identity: ToolSHA256, status: snapshotStatus{Hash: 1, Revision: 2, TotalKey: 3, TotalSize: 4096}, restoredData: []byte("restored-offline-database")},
	}
	fixture.writeRequest(t)
	return fixture
}

func (fixture *workerFixture) writeRequest(t *testing.T) {
	t.Helper()
	payload, err := json.Marshal(fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.writeRawRequest(t, payload)
}

func (fixture *workerFixture) writeRawRequest(t *testing.T, payload []byte) {
	t.Helper()
	root := filepath.Dir(fixture.paths.RequestPath)
	dataLink := filepath.Join(root, "..data")
	dataTarget, err := os.Readlink(dataLink)
	if errors.Is(err, os.ErrNotExist) {
		writeProjectedMount(t, root, map[string]string{filepath.Base(fixture.paths.RequestPath): string(payload)})
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, dataTarget, filepath.Base(fixture.paths.RequestPath))
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	// #nosec G306 -- reproduces the read-only group-readable Kubernetes projection mode.
	if err := os.WriteFile(target, payload, 0o440); err != nil {
		t.Fatal(err)
	}
}

func (fixture *workerFixture) dependencies() dependencies {
	return dependencies{
		now:            func() time.Time { return fixture.now },
		executableHash: func(context.Context) (string, error) { return fixture.selfSHA, nil },
		openTool:       func(context.Context, string, string, time.Duration) (toolRunner, error) { return fixture.tool, nil },
		fetchS3: func(context.Context, Request, string, string, time.Time) (*protectedFile, error) {
			return nil, errors.New("unexpected S3 fetch")
		},
		cleanup: cleanupWorkspaceContext,
	}
}

func TestCanonicalReceiptRejectsTampering(t *testing.T) {
	fixture := newWorkerFixture(t)
	receipt, err := run(context.Background(), fixture.paths, fixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	receipt.RestoredBytes++
	if _, err := CanonicalReceipt(receipt); !errors.Is(err, nil) {
		return
	}
	t.Fatal("tampered receipt was accepted")
}

func TestFailureReceiptIsCanonicalSanitizedAndWrittenOwnerOnly(t *testing.T) {
	fixture := newWorkerFixture(t)
	fixture.tool.restoreMode = "partial"
	receipt, runErr := run(context.Background(), fixture.paths, fixture.dependencies())
	if runErr == nil {
		t.Fatal("partial restore unexpectedly succeeded")
	}
	payload, err := CanonicalReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{fixture.request.ObjectKey, fixture.request.ObjectVersion, fixture.request.SnapshotID, fixture.paths.ArchivePath} {
		if canary != "" && strings.Contains(string(payload), canary) {
			t.Fatalf("failure receipt leaked %q: %s", canary, payload)
		}
	}
	outputRoot := filepath.Join(filepath.Dir(fixture.paths.WorkspaceRoot), "output-root")
	if err := os.Mkdir(outputRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(outputRoot, "private", "receipt.json")
	if err := WriteReceipt(path, receipt); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt output info = %#v, %v", info, err)
	}
	if err := WriteReceipt(path, receipt); err == nil {
		t.Fatal("receipt output was overwritten")
	}
}

func TestParseCanonicalReceiptAcceptsCompleteSuccessAndFailureReceipts(t *testing.T) {
	successFixture := newWorkerFixture(t)
	success, err := run(context.Background(), successFixture.paths, successFixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	successPayload, err := CanonicalReceipt(success)
	if err != nil {
		t.Fatal(err)
	}
	parsedSuccess, err := ParseCanonicalReceipt(successPayload)
	if err != nil || parsedSuccess.EvidenceSHA256 != success.EvidenceSHA256 {
		t.Fatalf("parsed success = %#v, %v", parsedSuccess, err)
	}

	failureFixture := newWorkerFixture(t)
	failureFixture.tool.restoreMode = "partial"
	failure, runErr := run(context.Background(), failureFixture.paths, failureFixture.dependencies())
	if runErr == nil {
		t.Fatal("expected terminal failure")
	}
	failurePayload, err := CanonicalReceipt(failure)
	if err != nil {
		t.Fatal(err)
	}
	parsedFailure, err := ParseCanonicalReceipt(failurePayload)
	if err != nil || parsedFailure.Status != "failed" {
		t.Fatalf("parsed failure = %#v, %v", parsedFailure, err)
	}
}

func TestParseCanonicalReceiptRejectsUnknownDuplicateNoncanonicalAndDigestMismatch(t *testing.T) {
	fixture := newWorkerFixture(t)
	receipt, err := run(context.Background(), fixture.paths, fixture.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := CanonicalReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), payload[:len(payload)-1]...), []byte(`,"unknown":true}`)...)
	duplicate := append(append([]byte(nil), payload[:len(payload)-1]...), []byte(`,"status":"verified"}`)...)
	noncanonical := append([]byte(" "), payload...)
	tampered := receipt
	tampered.EvidenceSHA256 = strings.Repeat("0", 64)
	digestMismatch, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"unknown": unknown, "duplicate": duplicate, "noncanonical": noncanonical, "digest": digestMismatch,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCanonicalReceipt(candidate); err == nil {
				t.Fatal("invalid receipt was accepted")
			}
		})
	}
}

func TestFailureReceiptValidationRejectsUnboundedFieldsAndInvalidTuples(t *testing.T) {
	fixture := newWorkerFixture(t)
	fixture.tool.restoreMode = "partial"
	receipt, err := run(context.Background(), fixture.paths, fixture.dependencies())
	if err == nil {
		t.Fatal("expected terminal failure")
	}
	for _, mutate := range []func(*Receipt){
		func(value *Receipt) { value.Stage = fixture.request.ObjectVersion + "private-stage" },
		func(value *Receipt) {
			value.Tool = &ToolIdentity{Name: "private-tool", Version: ToolVersion, ExecutableSHA256: ToolSHA256}
		},
		func(value *Receipt) { value.Status, value.ReasonCode = "timeout", "operation_cancelled" },
		func(value *Receipt) { value.SourceMode = "private-source" },
		func(value *Receipt) { value.RequestSHA256 = "" },
	} {
		candidate := receipt
		mutate(&candidate)
		candidate.EvidenceSHA256 = receiptDigest(candidate)
		if _, err := CanonicalReceipt(candidate); err == nil {
			t.Fatal("invalid failure receipt was accepted")
		}
	}
}

func TestCleanupFailureProducesCanonicalTerminalReceipt(t *testing.T) {
	fixture := newWorkerFixture(t)
	deps := fixture.dependencies()
	deps.cleanup = func(context.Context, string) error { return errors.New("synthetic cleanup failure") }
	receipt, err := run(context.Background(), fixture.paths, deps)
	if err == nil {
		t.Fatal("cleanup failure unexpectedly succeeded")
	}
	if receipt.Status != "failed" || receipt.ReasonCode != "workspace_cleanup_failed" ||
		receipt.Stage != "cleanup" || receipt.WorkspaceCleanupVerified {
		t.Fatalf("cleanup failure receipt = %#v", receipt)
	}
	if _, err := CanonicalReceipt(receipt); err != nil {
		t.Fatal(err)
	}
}
