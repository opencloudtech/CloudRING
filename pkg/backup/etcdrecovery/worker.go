// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package etcdrecovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

var (
	safeIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	hexPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Paths struct {
	RequestPath    string
	ArchivePath    string
	ToolPath       string
	WorkspaceRoot  string
	CredentialRoot string
}

func DefaultPaths() Paths {
	return Paths{
		RequestPath: DefaultRequestPath, ArchivePath: DefaultArchivePath, ToolPath: DefaultToolPath,
		WorkspaceRoot: DefaultWorkspace, CredentialRoot: DefaultAuthMountRoot,
	}
}

type dependencies struct {
	now            func() time.Time
	executableHash func(context.Context) (string, error)
	openTool       func(context.Context, string, string, time.Duration) (toolRunner, error)
	fetchS3        func(context.Context, Request, string, string, time.Time) (*protectedFile, error)
	cleanup        func(context.Context, string) error
}

type toolRunner interface {
	IdentitySHA256() string
	VerifyVersion(context.Context, string) error
	Status(context.Context, *protectedFile, string) (snapshotStatus, error)
	HashKV(context.Context, *protectedFile, string) (snapshotKVHash, error)
	Restore(context.Context, *protectedFile, string) error
	Close() error
}

type executionState struct {
	startedAt       time.Time
	request         *Request
	requestSHA256   string
	workerSHA256    string
	toolSHA256      string
	stage           string
	workspace       string
	cleanupPending  bool
	cleanupVerified bool
	runContext      context.Context
	parentContext   context.Context
}

func RunDefault(ctx context.Context) (Receipt, error) {
	return run(ctx, DefaultPaths(), dependencies{time.Now, runningExecutableSHA256, openPinnedTool, fetchS3Archive, cleanupWorkspaceContext})
}

func Run(ctx context.Context, paths Paths) (Receipt, error) {
	return run(ctx, paths, dependencies{time.Now, runningExecutableSHA256, openPinnedTool, fetchS3Archive, cleanupWorkspaceContext})
}

func run(ctx context.Context, paths Paths, deps dependencies) (result Receipt, resultErr error) {
	if ctx == nil || deps.now == nil || deps.executableHash == nil || deps.openTool == nil || deps.fetchS3 == nil || deps.cleanup == nil {
		return Receipt{}, errors.New("recovery worker configuration is invalid")
	}
	state := &executionState{startedAt: deps.now().UTC(), stage: "request", cleanupVerified: true, runContext: ctx, parentContext: ctx}
	defer func() {
		if state.cleanupPending {
			state.cleanupVerified = cleanupWithinLimit(deps.cleanup, state.workspace)
			state.cleanupPending = false
		}
		if resultErr != nil {
			result = failureReceipt(state, deps.now().UTC())
		}
	}()
	wallStarted := time.Now()
	maximumContext, maximumCancel := context.WithTimeout(ctx, MaximumRunTimeout)
	defer maximumCancel()
	state.runContext = maximumContext
	requestBytes, err := readProjectedBytesContext(
		maximumContext,
		filepath.Dir(paths.RequestPath),
		filepath.Base(paths.RequestPath),
		[]string{filepath.Base(paths.RequestPath)},
		MaxRequestBytes,
	)
	if err != nil {
		return Receipt{}, errors.New("recovery request is unavailable")
	}
	defer clear(requestBytes)
	requestSHA256 := digestBytes(requestBytes)
	state.requestSHA256 = requestSHA256
	request, err := decodeRequest(requestBytes, deps.now().UTC())
	if err != nil {
		return Receipt{}, err
	}
	state.request = &request

	timeout := time.Duration(request.TimeoutSeconds) * time.Second
	remaining := timeout - time.Since(wallStarted)
	if remaining <= 0 {
		expired, expiredCancel := context.WithDeadline(maximumContext, time.Now().Add(-time.Second))
		expiredCancel()
		state.runContext = expired
		return Receipt{}, errors.New("recovery operation timed out")
	}
	runContext, cancel := context.WithTimeout(maximumContext, remaining)
	defer cancel()
	state.runContext = runContext
	state.stage = "worker-identity"
	workerSHA256, err := deps.executableHash(runContext)
	if err != nil || workerSHA256 != request.WorkerExecutableSHA256 {
		return Receipt{}, errors.New("recovery worker executable identity is invalid")
	}
	state.workerSHA256 = workerSHA256
	state.stage = "workspace"
	workspace, err := newWorkspace(paths.WorkspaceRoot)
	if err != nil {
		return Receipt{}, errors.New("recovery workspace is unavailable")
	}
	state.workspace = workspace
	state.cleanupPending = true
	state.cleanupVerified = false
	state.stage = "archive"
	var archive *protectedFile
	if request.SourceMode == "local-file" {
		archive, err = openProtectedFile(paths.ArchivePath, MaxArchiveBytes, exactOwnerOnly)
	} else {
		archive, err = deps.fetchS3(runContext, request, paths.CredentialRoot, workspace, deps.now().UTC())
	}
	if err != nil {
		return Receipt{}, errors.New("recovery archive is unavailable")
	}
	defer archive.Close()
	archiveSHA256, archiveBytes, err := archive.DigestContext(runContext)
	if err != nil || archiveSHA256 != request.SnapshotChecksumSHA256 || archiveBytes != request.SnapshotBytes {
		return Receipt{}, errors.New("recovery archive identity is invalid")
	}

	state.stage = "tool-identity"
	tool, err := deps.openTool(runContext, paths.ToolPath, request.EtcdutlSHA256, timeout)
	if err != nil {
		return Receipt{}, errors.New("recovery tool identity is invalid")
	}
	defer tool.Close()
	if tool.IdentitySHA256() != request.EtcdutlSHA256 {
		return Receipt{}, errors.New("recovery tool identity is invalid")
	}
	if err := tool.VerifyVersion(runContext, workspace); err != nil {
		return Receipt{}, errors.New("recovery tool version is invalid")
	}
	state.toolSHA256 = tool.IdentitySHA256()

	startedAt := state.startedAt
	if runContext.Err() != nil {
		return Receipt{}, errors.New("recovery operation was cancelled")
	}

	state.stage = "source-status"
	sourceStatus, err := tool.Status(runContext, archive, workspace)
	if err != nil || !validStatus(sourceStatus) {
		return Receipt{}, errors.New("recovery snapshot status failed")
	}
	sourceKVHash, err := hashKVFromDisposableCopy(
		runContext,
		tool,
		archive,
		filepath.Join(workspace, "source-hash.db"),
		archiveSHA256,
		archiveBytes,
		workspace,
	)
	if err != nil || !validKVHash(sourceKVHash, sourceStatus) {
		return Receipt{}, errors.New("recovery snapshot KV hash failed")
	}
	restoreDir := filepath.Join(workspace, "restored.etcd")
	state.stage = "restore"
	if err := tool.Restore(runContext, archive, restoreDir); err != nil {
		return Receipt{}, errors.New("recovery snapshot restore failed")
	}
	if runContext.Err() != nil {
		return Receipt{}, errors.New("recovery operation was cancelled")
	}
	if err := validateWorkspaceLayout(runContext, workspace, request.SourceMode); err != nil {
		return Receipt{}, errors.New("recovery workspace result is invalid")
	}
	state.stage = "restored-status"
	restoredPath := filepath.Join(restoreDir, "member", "snap", "db")
	restored, err := openProtectedFile(restoredPath, MaxRestoredBytes, currentOrRootReadOnly)
	if err != nil {
		return Receipt{}, errors.New("recovery restored database is unavailable")
	}
	restoredKVHash, err := tool.HashKV(runContext, restored, workspace)
	if err != nil {
		_ = restored.Close()
		return Receipt{}, errors.New("recovery restored database KV hash failed")
	}
	if err := restored.Close(); err != nil {
		return Receipt{}, errors.New("close recovery restored database after KV hash")
	}
	restored, err = openProtectedFile(restoredPath, MaxRestoredBytes, currentOrRootReadOnly)
	if err != nil {
		return Receipt{}, errors.New("reopen recovery restored database")
	}
	restoredSHA256, restoredBytes, err := restored.DigestContext(runContext)
	if err != nil || restoredBytes <= 0 {
		_ = restored.Close()
		return Receipt{}, errors.New("recovery restored database is invalid")
	}
	restoredStatus, err := tool.Status(runContext, restored, workspace)
	if err != nil || !validStatus(restoredStatus) {
		_ = restored.Close()
		return Receipt{}, errors.New("recovery restored database status failed")
	}
	if !validKVHash(restoredKVHash, restoredStatus) {
		_ = restored.Close()
		return Receipt{}, errors.New("recovery restored database KV hash failed")
	}
	if sourceStatus.Revision != restoredStatus.Revision || sourceStatus.TotalKey != restoredStatus.TotalKey ||
		sourceStatus.Version != restoredStatus.Version || sourceKVHash != restoredKVHash {
		_ = restored.Close()
		return Receipt{}, errors.New("recovery restored database is not equivalent")
	}
	if err := archive.ValidateStable(); err != nil || restored.ValidateStable() != nil {
		_ = restored.Close()
		return Receipt{}, errors.New("recovery input changed during verification")
	}
	if err := restored.Close(); err != nil {
		return Receipt{}, errors.New("close recovery restored database")
	}
	if runContext.Err() != nil {
		return Receipt{}, errors.New("recovery operation was cancelled")
	}

	sourceStatusSHA256 := digestValue(sourceStatus)
	sourceKVHashSHA256 := digestValue(sourceKVHash)
	restoredStatusSHA256 := digestValue(restoredStatus)
	restoredKVHashSHA256 := digestValue(restoredKVHash)
	loopbackPeerURL := "http://" + "127.0." + "0.1:2380"
	sandboxSHA256 := digestValue(sandboxState{
		SchemaVersion: SandboxStateSchemaVersion, SourceStatusSHA256: sourceStatusSHA256,
		SourceKVHashSHA256: sourceKVHashSHA256, RestoredStatusSHA256: restoredStatusSHA256,
		RestoredKVHashSHA256: restoredKVHashSHA256, RestoredChecksumSHA256: restoredSHA256,
		RestoredBytes: restoredBytes, LoopbackPeerURL: loopbackPeerURL,
	})
	state.stage = "cleanup"
	state.cleanupVerified = cleanupWithinLimit(deps.cleanup, workspace)
	state.cleanupPending = false
	if !state.cleanupVerified {
		return Receipt{}, errors.New("recovery workspace cleanup failed")
	}
	if runContext.Err() != nil {
		return Receipt{}, errors.New("recovery operation was cancelled during cleanup")
	}
	completedAt := deps.now().UTC()
	if completedAt.Before(startedAt) {
		return Receipt{}, errors.New("recovery timeline is invalid")
	}
	receipt := Receipt{
		SchemaVersion: ReceiptSchemaVersion, Status: "verified", ReasonCode: "offline_restore_verified", Stage: "complete",
		SnapshotIDSHA256: digestString(request.SnapshotID), SnapshotChecksumSHA256: archiveSHA256,
		SnapshotBytes: archiveBytes, SourceMode: request.SourceMode,
		EndpointSHA256: endpointSHA256(request), ObjectReferenceSHA256: objectReferenceSHA256(request),
		ObjectIdentitySHA256:  request.ObjectIdentitySHA256,
		ClusterIdentitySHA256: request.ClusterIdentitySHA256, JobTemplateSHA256: request.JobTemplateSHA256,
		ExecutionProfileSHA256: request.ExecutionProfileSHA256, InputSecretSHA256: request.InputSecretSHA256,
		RequestSHA256: requestSHA256, WorkerExecutableSHA256: workerSHA256, WorkerImageDigest: request.WorkerImageDigest,
		Tool:               &ToolIdentity{Name: ToolName, Version: ToolVersion, ExecutableSHA256: tool.IdentitySHA256()},
		SourceStatusSHA256: sourceStatusSHA256, SourceKVHashSHA256: sourceKVHashSHA256,
		RestoredChecksumSHA256: restoredSHA256, RestoredBytes: restoredBytes,
		RestoredStatusSHA256: restoredStatusSHA256, RestoredKVHashSHA256: restoredKVHashSHA256,
		SandboxStateSHA256:   sandboxSHA256,
		MemberHealthVerified: false, OfflineMemberDatabaseVerified: true, LoopbackOnly: true, WorkspaceCleanupVerified: true,
		StartedAt: canonicalTime(startedAt), CompletedAt: canonicalTime(completedAt),
		ObservedDurationMilliseconds: completedAt.Sub(startedAt).Milliseconds(),
	}
	receipt.EvidenceSHA256 = receiptDigest(receipt)
	return receipt, nil
}

func hashKVFromDisposableCopy(
	ctx context.Context,
	tool toolRunner,
	original *protectedFile,
	scratchPath string,
	expectedSHA256 string,
	expectedBytes int64,
	workspace string,
) (snapshotKVHash, error) {
	if ctx == nil || tool == nil || original == nil {
		return snapshotKVHash{}, errors.New("recovery KV hash copy input is invalid")
	}
	scratch, err := copyProtectedFileContext(ctx, original, scratchPath, expectedSHA256, expectedBytes)
	if err != nil {
		return snapshotKVHash{}, errors.New("create recovery KV hash copy")
	}
	value, hashErr := tool.HashKV(ctx, scratch, workspace)
	discardErr := discardProtectedFile(scratch)
	if hashErr != nil || discardErr != nil || original.ValidateStable() != nil {
		return snapshotKVHash{}, errors.New("hash recovery KV copy")
	}
	return value, nil
}

func decodeRequest(data []byte, now time.Time) (Request, error) {
	var request Request
	if len(data) == 0 || len(data) > MaxRequestBytes || strictjson.DecodeExact(data, &request) != nil {
		return Request{}, errors.New("recovery request is invalid")
	}
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(canonical, data) {
		return Request{}, errors.New("recovery request is not canonical")
	}
	issuedAt, issuedErr := time.Parse(time.RFC3339Nano, request.IssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || request.IssuedAt != canonicalTime(issuedAt) || request.ExpiresAt != canonicalTime(expiresAt) ||
		expiresAt.Before(now) || issuedAt.After(now.Add(MaximumFutureSkew)) || now.Sub(issuedAt) > MaximumRequestAge ||
		!expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaximumRequestAge {
		return Request{}, errors.New("recovery request timeline is invalid")
	}
	if request.SchemaVersion != RequestSchemaVersion || !safeID(request.OperationID) || !safeID(request.SnapshotID) ||
		!validSHA256(request.SnapshotChecksumSHA256) || request.SnapshotBytes <= 0 || request.SnapshotBytes > MaxArchiveBytes ||
		!validSource(request) || !validSHA256(request.ObjectIdentitySHA256) ||
		!validSHA256(request.ClusterIdentitySHA256) || !validSHA256(request.JobTemplateSHA256) ||
		!validSHA256(request.ExecutionProfileSHA256) || !validSHA256(request.InputSecretSHA256) ||
		!validSHA256(request.WorkerExecutableSHA256) || !validImageDigest(request.WorkerImageDigest) || request.EtcdutlVersion != ToolVersion ||
		request.EtcdutlSHA256 != ToolSHA256 || request.TimeoutSeconds < 1 ||
		time.Duration(request.TimeoutSeconds)*time.Second > MaximumRunTimeout {
		return Request{}, errors.New("recovery request fields are invalid")
	}
	identity := requestObjectIdentity(request)
	if request.ObjectIdentitySHA256 != digestValue(identity) {
		return Request{}, errors.New("recovery object identity binding is invalid")
	}
	return request, nil
}

func CanonicalRequest(request Request, now time.Time) ([]byte, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return nil, errors.New("encode recovery request")
	}
	if _, err := decodeRequest(data, now.UTC()); err != nil {
		clear(data)
		return nil, err
	}
	return data, nil
}

func CanonicalReceipt(receipt Receipt) ([]byte, error) {
	if !validReceipt(receipt) || receipt.EvidenceSHA256 != receiptDigest(receipt) {
		return nil, errors.New("recovery receipt evidence binding is invalid")
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return nil, errors.New("encode recovery receipt")
	}
	return data, nil
}

// ParseCanonicalReceipt strictly decodes the complete public receipt. It
// rejects duplicate or unknown fields, non-canonical JSON bytes, invalid
// status/stage combinations, and an evidence digest mismatch.
func ParseCanonicalReceipt(data []byte) (Receipt, error) {
	var receipt Receipt
	if len(data) == 0 || len(data) > maximumReceiptBytes || strictjson.DecodeExact(data, &receipt) != nil {
		return Receipt{}, errors.New("recovery receipt is invalid")
	}
	canonical, err := json.Marshal(receipt)
	if err != nil {
		return Receipt{}, errors.New("encode recovery receipt")
	}
	defer clear(canonical)
	if !bytes.Equal(canonical, data) {
		return Receipt{}, errors.New("recovery receipt is not canonical")
	}
	if !validReceipt(receipt) || receipt.EvidenceSHA256 != receiptDigest(receipt) {
		return Receipt{}, errors.New("recovery receipt evidence binding is invalid")
	}
	return receipt, nil
}

func validReceipt(receipt Receipt) bool {
	started, startErr := time.Parse(time.RFC3339Nano, receipt.StartedAt)
	completed, completeErr := time.Parse(time.RFC3339Nano, receipt.CompletedAt)
	if receipt.SchemaVersion != ReceiptSchemaVersion || startErr != nil || completeErr != nil || completed.Before(started) ||
		receipt.StartedAt != canonicalTime(started) || receipt.CompletedAt != canonicalTime(completed) ||
		receipt.ObservedDurationMilliseconds != completed.Sub(started).Milliseconds() || !validSHA256(receipt.EvidenceSHA256) ||
		receipt.ObservedDurationMilliseconds < 0 ||
		receipt.ObservedDurationMilliseconds > MaximumReceiptDuration.Milliseconds() ||
		receipt.MemberHealthVerified || !receipt.LoopbackOnly || !validReceiptStage(receipt.Stage) ||
		!validOptionalSHA256(receipt.SnapshotIDSHA256) || !validOptionalSHA256(receipt.SnapshotChecksumSHA256) ||
		(receipt.SnapshotBytes < 0 || receipt.SnapshotBytes > MaxArchiveBytes) ||
		(receipt.SourceMode != "" && receipt.SourceMode != "local-file" && receipt.SourceMode != "s3") ||
		!validOptionalSHA256(receipt.EndpointSHA256) || !validOptionalSHA256(receipt.ObjectReferenceSHA256) ||
		!validOptionalSHA256(receipt.ObjectIdentitySHA256) || !validOptionalSHA256(receipt.ClusterIdentitySHA256) ||
		!validOptionalSHA256(receipt.JobTemplateSHA256) || !validOptionalSHA256(receipt.ExecutionProfileSHA256) ||
		!validOptionalSHA256(receipt.InputSecretSHA256) || !validOptionalSHA256(receipt.RequestSHA256) ||
		!validOptionalSHA256(receipt.WorkerExecutableSHA256) ||
		(receipt.WorkerImageDigest != "" && !validImageDigest(receipt.WorkerImageDigest)) ||
		!validOptionalSHA256(receipt.SourceStatusSHA256) || !validOptionalSHA256(receipt.SourceKVHashSHA256) ||
		!validOptionalSHA256(receipt.RestoredChecksumSHA256) ||
		(receipt.RestoredBytes < 0 || receipt.RestoredBytes > MaxRestoredBytes) ||
		!validOptionalSHA256(receipt.RestoredStatusSHA256) || !validOptionalSHA256(receipt.RestoredKVHashSHA256) ||
		!validOptionalSHA256(receipt.SandboxStateSHA256) ||
		!validOptionalTool(receipt.Tool) {
		return false
	}
	hasAnyRequestBinding := receipt.SourceMode != "" || receipt.SnapshotIDSHA256 != "" ||
		receipt.SnapshotChecksumSHA256 != "" || receipt.SnapshotBytes != 0 ||
		receipt.EndpointSHA256 != "" || receipt.ObjectReferenceSHA256 != "" ||
		receipt.ObjectIdentitySHA256 != "" || receipt.ClusterIdentitySHA256 != "" ||
		receipt.JobTemplateSHA256 != "" || receipt.ExecutionProfileSHA256 != "" ||
		receipt.InputSecretSHA256 != "" || receipt.WorkerImageDigest != ""
	hasCompleteRequestBinding := receipt.SourceMode != "" && validSHA256(receipt.SnapshotIDSHA256) &&
		validSHA256(receipt.SnapshotChecksumSHA256) && receipt.SnapshotBytes > 0 &&
		validSHA256(receipt.EndpointSHA256) && validSHA256(receipt.ObjectReferenceSHA256) &&
		validSHA256(receipt.ObjectIdentitySHA256) && validSHA256(receipt.ClusterIdentitySHA256) &&
		validSHA256(receipt.JobTemplateSHA256) && validSHA256(receipt.ExecutionProfileSHA256) &&
		validSHA256(receipt.InputSecretSHA256) && validSHA256(receipt.RequestSHA256) &&
		validImageDigest(receipt.WorkerImageDigest)
	if hasAnyRequestBinding != hasCompleteRequestBinding {
		return false
	}
	switch receipt.Status {
	case "verified":
		return receipt.ReasonCode == "offline_restore_verified" && receipt.Stage == "complete" && receipt.OfflineMemberDatabaseVerified && receipt.WorkspaceCleanupVerified &&
			validSHA256(receipt.SnapshotIDSHA256) && validSHA256(receipt.SnapshotChecksumSHA256) && receipt.SnapshotBytes > 0 &&
			(receipt.SourceMode == "local-file" || receipt.SourceMode == "s3") && validSHA256(receipt.EndpointSHA256) && validSHA256(receipt.ObjectReferenceSHA256) &&
			validSHA256(receipt.ObjectIdentitySHA256) && validSHA256(receipt.ClusterIdentitySHA256) && validSHA256(receipt.JobTemplateSHA256) &&
			validSHA256(receipt.ExecutionProfileSHA256) && validSHA256(receipt.InputSecretSHA256) && validSHA256(receipt.RequestSHA256) &&
			validSHA256(receipt.WorkerExecutableSHA256) && validImageDigest(receipt.WorkerImageDigest) && receipt.Tool != nil &&
			receipt.Tool.Name == ToolName && receipt.Tool.Version == ToolVersion && validSHA256(receipt.Tool.ExecutableSHA256) &&
			validSHA256(receipt.SourceStatusSHA256) && validSHA256(receipt.SourceKVHashSHA256) &&
			validSHA256(receipt.RestoredChecksumSHA256) && receipt.RestoredBytes > 0 &&
			validSHA256(receipt.RestoredStatusSHA256) && validSHA256(receipt.RestoredKVHashSHA256) &&
			receipt.SourceKVHashSHA256 == receipt.RestoredKVHashSHA256 && validSHA256(receipt.SandboxStateSHA256)
	case "failed":
		return !receipt.OfflineMemberDatabaseVerified && noOfflineSuccessFields(receipt) &&
			(receipt.ReasonCode == "operation_failed" && receipt.Stage != "complete" && receipt.WorkspaceCleanupVerified ||
				receipt.ReasonCode == "workspace_cleanup_failed" && receipt.Stage == "cleanup" && !receipt.WorkspaceCleanupVerified)
	case "cancelled":
		return !receipt.OfflineMemberDatabaseVerified && noOfflineSuccessFields(receipt) &&
			receipt.ReasonCode == "operation_cancelled" && receipt.Stage != "complete" && receipt.WorkspaceCleanupVerified
	case "timeout":
		return !receipt.OfflineMemberDatabaseVerified && noOfflineSuccessFields(receipt) &&
			receipt.ReasonCode == "operation_timed_out" && receipt.Stage != "complete" && receipt.WorkspaceCleanupVerified
	default:
		return false
	}
}

func validOptionalSHA256(value string) bool {
	return value == "" || validSHA256(value)
}

func validOptionalTool(tool *ToolIdentity) bool {
	return tool == nil || tool.Name == ToolName && tool.Version == ToolVersion && tool.ExecutableSHA256 == ToolSHA256
}

func noOfflineSuccessFields(receipt Receipt) bool {
	return receipt.SourceStatusSHA256 == "" && receipt.SourceKVHashSHA256 == "" &&
		receipt.RestoredChecksumSHA256 == "" && receipt.RestoredBytes == 0 &&
		receipt.RestoredStatusSHA256 == "" && receipt.RestoredKVHashSHA256 == "" &&
		receipt.SandboxStateSHA256 == ""
}

func validReceiptStage(stage string) bool {
	switch stage {
	case "initialization", "request", "worker-identity", "workspace", "archive", "tool-identity",
		"source-status", "restore", "restored-status", "cleanup", "complete":
		return true
	default:
		return false
	}
}

func ObjectIdentitySHA256(request Request) string {
	return digestValue(requestObjectIdentity(request))
}

// ObjectReferenceSHA256 returns the canonical source-safe binding carried in
// Receipt.ObjectReferenceSHA256.
func ObjectReferenceSHA256(request Request) string {
	return objectReferenceSHA256(request)
}

// EndpointSHA256 returns the canonical source-safe binding carried in
// Receipt.EndpointSHA256. Local-file mode binds the fixed mode literal rather
// than an external endpoint.
func EndpointSHA256(request Request) string {
	return endpointSHA256(request)
}

func requestObjectIdentity(request Request) objectIdentity {
	return objectIdentity{RequestSchemaVersion, request.SnapshotID, request.SourceMode, request.Endpoint, request.Region, request.Bucket, request.ObjectKey, request.ObjectVersion}
}

func objectReferenceSHA256(request Request) string {
	return digestValue(struct {
		Bucket  string `json:"bucket"`
		Key     string `json:"key"`
		Version string `json:"version"`
	}{request.Bucket, request.ObjectKey, request.ObjectVersion})
}

func endpointSHA256(request Request) string {
	if request.SourceMode == "local-file" {
		return digestString("local-file")
	}
	return digestString(request.Endpoint)
}

func receiptDigest(receipt Receipt) string {
	receipt.EvidenceSHA256 = ""
	return digestValue(receipt)
}

func failureReceipt(state *executionState, completedAt time.Time) Receipt {
	status := "failed"
	reason := "operation_failed"
	if state != nil && state.runContext != nil {
		switch {
		case errors.Is(state.runContext.Err(), context.DeadlineExceeded):
			status, reason = "timeout", "operation_timed_out"
		case state.parentContext != nil && errors.Is(state.parentContext.Err(), context.Canceled):
			status, reason = "cancelled", "operation_cancelled"
		}
	}
	if state == nil {
		state = &executionState{startedAt: completedAt, stage: "initialization", cleanupVerified: true}
	}
	if !state.cleanupVerified {
		status, reason, state.stage = "failed", "workspace_cleanup_failed", "cleanup"
	}
	if completedAt.Before(state.startedAt) {
		completedAt = state.startedAt
	}
	receipt := Receipt{
		SchemaVersion: ReceiptSchemaVersion, Status: status, ReasonCode: reason, Stage: state.stage,
		RequestSHA256: state.requestSHA256, WorkerExecutableSHA256: state.workerSHA256,
		MemberHealthVerified: false, OfflineMemberDatabaseVerified: false, LoopbackOnly: true,
		WorkspaceCleanupVerified: state.cleanupVerified,
		StartedAt:                canonicalTime(state.startedAt), CompletedAt: canonicalTime(completedAt),
		ObservedDurationMilliseconds: completedAt.Sub(state.startedAt).Milliseconds(),
	}
	if state.request != nil {
		request := state.request
		receipt.SnapshotIDSHA256 = digestString(request.SnapshotID)
		receipt.SnapshotChecksumSHA256 = request.SnapshotChecksumSHA256
		receipt.SnapshotBytes = request.SnapshotBytes
		receipt.SourceMode = request.SourceMode
		receipt.EndpointSHA256 = endpointSHA256(*request)
		receipt.ObjectReferenceSHA256 = objectReferenceSHA256(*request)
		receipt.ObjectIdentitySHA256 = request.ObjectIdentitySHA256
		receipt.ClusterIdentitySHA256 = request.ClusterIdentitySHA256
		receipt.JobTemplateSHA256 = request.JobTemplateSHA256
		receipt.ExecutionProfileSHA256 = request.ExecutionProfileSHA256
		receipt.InputSecretSHA256 = request.InputSecretSHA256
		receipt.WorkerImageDigest = request.WorkerImageDigest
	}
	if validSHA256(state.toolSHA256) {
		receipt.Tool = &ToolIdentity{Name: ToolName, Version: ToolVersion, ExecutableSHA256: state.toolSHA256}
	}
	receipt.EvidenceSHA256 = receiptDigest(receipt)
	return receipt
}

// InitializationFailureReceipt creates the only valid receipt available when
// the fixed worker invocation itself is invalid before a request can be read.
func InitializationFailureReceipt(now time.Time) Receipt {
	return failureReceipt(nil, now.UTC())
}

func digestValue(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	defer clear(data)
	return digestBytes(data)
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func digestString(value string) string { return digestBytes([]byte(value)) }

func validStatus(status snapshotStatus) bool {
	return status.Revision >= 0 && status.TotalKey >= 0 && status.TotalSize > 0
}

func validKVHash(value snapshotKVHash, status snapshotStatus) bool {
	return value.HashRevision == status.Revision && value.HashRevision >= 0 &&
		value.CompactRevision >= -1 && value.CompactRevision <= value.HashRevision
}

func canonicalTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
func validSHA256(value string) bool        { return hexPattern.MatchString(value) }
func validImageDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validSHA256(strings.TrimPrefix(value, "sha256:"))
}
func safeID(value string) bool {
	return value == strings.TrimSpace(value) && safeIDPattern.MatchString(value)
}

func safeOpaque(value string, maximum int) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func validObjectKey(value string) bool {
	if !safeOpaque(value, 2048) || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return false
	}
	clean := path.Clean(value)
	return clean == value && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func hashReader(reader io.Reader) (string, int64, error) {
	return hashReaderContext(context.Background(), reader)
}

func hashReaderContext(ctx context.Context, reader io.Reader) (string, int64, error) {
	if ctx == nil {
		return "", 0, errors.New("hash context is invalid")
	}
	hasher := sha256.New()
	buffer := make([]byte, 128<<10)
	defer clear(buffer)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return "", written, err
		}
		count, readErr := reader.Read(buffer)
		if count > 0 {
			_, _ = hasher.Write(buffer[:count])
			written += int64(count)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", written, readErr
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}
