// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package drill

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

var (
	idPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	namePattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$`)
	kindPattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.]{0,63}$`)
	shaPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gitSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,228}$`)
)

func ValidatePlan(plan Plan) error {
	issued, issuedErr := canonicalTime(plan.IssuedAt)
	expires, expiresErr := canonicalTime(plan.ExpiresAt)
	if plan.SchemaVersion != PlanSchemaVersion || !validID(plan.OperationID) || !validID(plan.ProofID) || !validID(plan.InstallationID) ||
		!gitSHAPattern.MatchString(plan.AcceptedPublicSHA) || !gitSHAPattern.MatchString(plan.AcceptedDownstreamSHA) || !validSHA(plan.ClusterIdentitySHA256) ||
		issuedErr != nil || expiresErr != nil || !expires.After(issued) || expires.Sub(issued) > 30*time.Minute || !validSHA(plan.RunNonceSHA256) {
		return errors.New("backup drill plan identity or validity window is invalid")
	}
	if !validName(plan.BackupStorageLocation.Name) || !validSHA(plan.BackupStorageLocation.UIDSHA256) || plan.BackupStorageLocation.Generation < 1 ||
		!validSHA(plan.BackupStorageLocation.ConfigSHA256) || !validPathToken(plan.ObjectStore.Prefix) || plan.ObjectStore.MinimumRetentionDays < 30 ||
		plan.ObjectStore.MinimumRetentionDays > 36500 || !slices.Contains([]string{"governance", "compliance"}, plan.ObjectStore.ObjectLockMode) {
		return errors.New("backup drill storage binding is invalid")
	}
	if plan.Tool.Name != "cloudring-backup" || !validSHA(plan.Tool.ExecutableSHA256) || !validID(plan.Adapter.Name) || !validSHA(plan.Adapter.ExecutableSHA256) {
		return errors.New("backup drill executable binding is invalid")
	}
	if plan.Backup.Kind != "Backup" || !validObject(plan.Backup) || plan.EtcdSandbox.Kind != "EtcdSandbox" || !validObject(plan.EtcdSandbox) {
		return errors.New("backup drill backup or etcd sandbox identity is invalid")
	}
	if len(plan.SourceBaselines) != len(TargetKinds) {
		return errors.New("backup drill requires exact source baselines")
	}
	for index, baseline := range plan.SourceBaselines {
		if baseline.Kind != TargetKinds[index] || !validSHA(baseline.IdentitySHA256) || !validSHA(baseline.StateSHA256) || !validSHA(baseline.DataSHA256) {
			return errors.New("backup drill source baselines are invalid or not canonical")
		}
	}
	restoreKinds := []string{"VirtualMachineClaim", "Volume", "Namespace", "KubernetesClusterClaim"}
	if len(plan.Restores) != len(restoreKinds) || len(plan.IsolatedNamespaces) != 5 {
		return errors.New("backup drill requires exact four restores and five isolated namespace mappings")
	}
	for index, restore := range plan.Restores {
		if restore.Kind != restoreKinds[index] || !validObject(restore) {
			return errors.New("backup drill restore identities are invalid or not canonical")
		}
	}
	mappingRestoreIndexes := []int{0, 1, 2, 2, 3}
	seenDestinations := make(map[string]bool, len(plan.IsolatedNamespaces))
	seenDestinationScopes := make(map[string]bool, len(plan.IsolatedNamespaces))
	seenMappings := make(map[string]bool, len(plan.IsolatedNamespaces))
	for index, mapping := range plan.IsolatedNamespaces {
		expectedRestoreIndex := mappingRestoreIndexes[index]
		if mapping.RestoreIndex != expectedRestoreIndex {
			return errors.New("backup drill isolated namespace mapping restore index is invalid")
		}
		restore := plan.Restores[expectedRestoreIndex]
		destination := mapping.Destination
		mappingIdentity := mapping.RestoreName + "/" + mapping.SourceNamespace
		if mapping.RestoreName != restore.Name || mapping.RestoreScopeSHA256 != restore.ScopeSHA256 || !validName(mapping.SourceNamespace) ||
			destination.Kind != "Namespace" || destination.Namespace != "" || !validObject(destination) || seenDestinations[destination.Name] ||
			seenDestinationScopes[destination.ScopeSHA256] || seenMappings[mappingIdentity] {
			return errors.New("backup drill isolated namespace mapping is invalid, duplicated, or misassigned")
		}
		if index == 2 && mapping.SourceNamespace != "platform-system" || index == 3 && mapping.SourceNamespace != "flux-system" {
			return errors.New("backup drill Namespace restore must map platform-system and flux-system")
		}
		seenDestinations[destination.Name] = true
		seenDestinationScopes[destination.ScopeSHA256] = true
		seenMappings[mappingIdentity] = true
	}
	if len(plan.CleanupTargets) != len(plan.IsolatedNamespaces)+1 {
		return errors.New("backup drill cleanup targets are incomplete")
	}
	seenCleanup := make(map[string]bool, len(plan.CleanupTargets))
	for index, target := range plan.CleanupTargets {
		identity := target.Kind + "/" + target.Namespace + "/" + target.Name
		if !kindPattern.MatchString(target.Kind) || !validName(target.Name) || target.Namespace != "" && !validName(target.Namespace) ||
			!validSHA(target.PreconditionIdentitySHA256) || seenCleanup[identity] || retainedKind(target.Kind) {
			return errors.New("backup drill cleanup target is unsafe or duplicated")
		}
		if index < len(plan.IsolatedNamespaces) && (target.Kind != "Namespace" || target.Namespace != "" || target.Name != plan.IsolatedNamespaces[index].Destination.Name) {
			return errors.New("backup drill cleanup targets are not exact isolated namespaces")
		}
		if index == len(plan.IsolatedNamespaces) && (target.Kind != "EtcdSandbox" || target.Namespace != "" || target.Name != plan.EtcdSandbox.Name) {
			return errors.New("backup drill cleanup target is not the exact etcd sandbox")
		}
		seenCleanup[identity] = true
	}
	if !validPathToken(plan.AggregateProofPathToken) {
		return errors.New("backup drill aggregate proof path token is invalid")
	}
	return nil
}

func ApprovalTuple(plan Plan, preflightBindingSHA256 string) string {
	issued, err := canonicalTime(plan.IssuedAt)
	if err != nil || !validSHA(preflightBindingSHA256) {
		return ""
	}
	return fmt.Sprintf("%s@%d@%s@%s@%s@%s", ApprovalTuplePrefix, issued.Unix(), plan.AcceptedDownstreamSHA, plan.RunNonceSHA256, ApprovalScopeSHA256(plan), preflightBindingSHA256)
}

func ValidateApproval(plan Plan, approval ApprovalReport, now time.Time) error {
	if err := validateApprovalBinding(plan, approval); err != nil {
		return err
	}
	issued, issuedErr := canonicalTime(approval.IssuedAt)
	expires, expiresErr := canonicalTime(approval.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || now.UTC().Before(issued) || !now.UTC().Before(expires) {
		return errors.New("backup drill approval is stale")
	}
	return nil
}

func validateApprovalBinding(plan Plan, approval ApprovalReport) error {
	if err := ValidatePlan(plan); err != nil {
		return err
	}
	preflightRequest := newAdapterRequest(plan, ApprovalReport{}, "preflight", "preflight", "")
	if approval.SchemaVersion != ApprovalSchemaVersion || approval.OperationID != plan.OperationID || approval.PlanSHA256 != PlanSHA256(plan) ||
		approval.ApprovalScopeSHA256 != ApprovalScopeSHA256(plan) || approval.AdapterExecutableSHA256 != plan.Adapter.ExecutableSHA256 ||
		approval.IssuedAt != plan.IssuedAt || approval.ExpiresAt != plan.ExpiresAt ||
		approval.PreflightRequestSHA256 != preflightRequest.RequestSHA256 || !validSHA(approval.PreflightResponseSHA256) ||
		!validEvidence(approval.PreflightEvidenceRef, approval.PreflightEvidenceSHA256) ||
		approval.PreflightBindingSHA256 != PreflightBindingSHA256(plan, approval.PreflightResponseSHA256, approval.PreflightEvidenceRef, approval.PreflightEvidenceSHA256) ||
		approval.ApprovalTuple != ApprovalTuple(plan, approval.PreflightBindingSHA256) || approval.ReportSHA256 != ApprovalReportSHA256(approval) {
		return errors.New("backup drill approval binding is invalid")
	}
	return nil
}

func ValidateAdapterResponse(request AdapterRequest, response AdapterResponse) error {
	if err := validateAdapterResponseBinding(request, response); err != nil {
		return err
	}
	switch request.Mode {
	case "preflight":
		if request.Step != "preflight" || response.Status != "ready" || response.Mutated {
			return errors.New("backup drill preflight attempted or reported mutation")
		}
	case "apply":
		mutationStep := slices.Contains([]string{"etcd-offcell-complete", "velero-backup-complete", "restore-watch-create-observe-complete", "etcd-sandbox-restored", "restore-validation-complete", "isolated-targets-deleted"}, request.Step)
		if response.Status != "completed" || response.Mutated != mutationStep {
			return errors.New("backup drill apply step is not complete")
		}
		if request.Step == "restore-watch-create-observe-complete" {
			if len(response.RestoreObservations) != len(request.Plan.IsolatedNamespaces) {
				return errors.New("backup drill combined restore observation evidence is incomplete")
			}
			for index, observation := range response.RestoreObservations {
				mapping := request.Plan.IsolatedNamespaces[index]
				if observation.RestoreName != mapping.RestoreName || observation.RestoreScopeSHA256 != mapping.RestoreScopeSHA256 ||
					observation.SourceNamespace != mapping.SourceNamespace || observation.DestinationNamespace != mapping.Destination.Name ||
					observation.DestinationScopeSHA256 != mapping.Destination.ScopeSHA256 || !validEvidence(observation.EvidenceRef, observation.EvidenceSHA256) {
					return errors.New("backup drill combined restore observation evidence is not plan-bound")
				}
			}
		} else if len(response.RestoreObservations) != 0 {
			return errors.New("backup drill restore observation evidence appeared in the wrong phase")
		}
	case "rollback":
		if request.Step == "rollback-safe-stop" {
			if response.Status != "safe-stopped" || response.Mutated {
				return errors.New("backup drill rollback did not safe-stop")
			}
		} else if response.Status != "completed" || !response.Mutated {
			return errors.New("backup drill rollback cleanup failed")
		}
	default:
		return errors.New("backup drill adapter mode is invalid")
	}
	return nil
}

func validateAdapterResponseBinding(request AdapterRequest, response AdapterResponse) error {
	if request.RequestSHA256 != AdapterRequestSHA256(request) || response.SchemaVersion != AdapterResponseVersion || response.ProtocolVersion != AdapterProtocolVersion ||
		response.OperationID != request.OperationID || response.Step != request.Step || response.RequestSHA256 != request.RequestSHA256 ||
		response.AdapterExecutableSHA256 != request.AdapterExecutableSHA256 || !validEvidence(response.Evidence.Ref, response.Evidence.SHA256) ||
		response.ResponseSHA256 != AdapterResponseSHA256(response) {
		return errors.New("backup drill adapter response binding is invalid")
	}
	return nil
}

func ValidateReceipt(plan Plan, approval ApprovalReport, receipt ExecutionReceipt, entries []JournalEntry) error {
	if err := ValidatePlan(plan); err != nil {
		return err
	}
	if err := validateApprovalBinding(plan, approval); err != nil {
		return err
	}
	if len(entries) != len(ApplySteps) || validateJournalEntries(entries) != nil || verifyJournalBinding(plan, approval, entries) != nil {
		return errors.New("backup drill receipt journal binding is invalid")
	}
	completed := entries[len(entries)-1]
	proofEntry := entries[len(entries)-2]
	if completed.Step != "completed" || proofEntry.Step != "proof-assembled" || proofEntry.Response == nil || validateProofResponse(plan, *proofEntry.Response) != nil {
		return errors.New("backup drill receipt proof journal entries are invalid")
	}
	proof := proofEntry.Response
	if receipt.SchemaVersion != ReceiptSchemaVersion || receipt.OperationID != plan.OperationID || receipt.ProofID != plan.ProofID ||
		receipt.InstallationID != plan.InstallationID || receipt.PlanSHA256 != PlanSHA256(plan) || receipt.ApprovalSHA256 != ApprovalSHA256(approval) ||
		receipt.ApprovalScopeSHA256 != ApprovalScopeSHA256(plan) || receipt.AdapterExecutableSHA256 != plan.Adapter.ExecutableSHA256 || receipt.Status != "completed" ||
		receipt.CompletedAt != completed.RecordedAt || receipt.JournalHeadSHA256 != completed.EntrySHA256 || receipt.ExecutionEvidenceResponseSHA256 != proof.ResponseSHA256 ||
		!slices.Equal(receipt.Targets, proof.Targets) || receipt.IsolationEvidence != *proof.IsolationEvidence || receipt.CleanupEvidence != *proof.CleanupEvidence ||
		receipt.ObjectLockDeleteDenialReceiptSHA256 != proof.ObjectLockDeleteDenialReceiptSHA256 || receipt.AggregateProofArtifactSHA256 != proof.AggregateProofArtifactSHA256 ||
		receipt.AggregateProofPathToken != proof.AggregateProofPathToken || receipt.ReceiptSHA256 != ExecutionReceiptSHA256(receipt) {
		return errors.New("backup drill execution receipt binding is invalid")
	}
	if _, err := canonicalTime(receipt.CompletedAt); err != nil || len(receipt.Targets) != len(TargetKinds) {
		return errors.New("backup drill execution receipt time or targets are invalid")
	}
	for index, target := range receipt.Targets {
		if target.Kind != TargetKinds[index] || target.SourceChecksumSHA256 != plan.SourceBaselines[index].DataSHA256 || target.SourceChecksumSHA256 != target.RestoredChecksumSHA256 ||
			!validEvidence(target.EvidenceRef, target.EvidenceSHA256) {
			return errors.New("backup drill target proof is invalid or not canonical")
		}
	}
	for index, entry := range entries {
		if entry.Step != ApplySteps[index] {
			return errors.New("backup drill receipt journal phases are incomplete")
		}
	}
	return nil
}

func validateProofResponse(plan Plan, response AdapterResponse) error {
	if response.Step != "proof-assembled" || len(response.Targets) != len(TargetKinds) || response.IsolationEvidence == nil || response.CleanupEvidence == nil ||
		!validEvidence(response.IsolationEvidence.Ref, response.IsolationEvidence.SHA256) || !validEvidence(response.CleanupEvidence.Ref, response.CleanupEvidence.SHA256) ||
		!validSHA(response.ObjectLockDeleteDenialReceiptSHA256) || !validSHA(response.AggregateProofArtifactSHA256) ||
		response.AggregateProofPathToken != plan.AggregateProofPathToken {
		return errors.New("backup drill proof response is incomplete")
	}
	for index, target := range response.Targets {
		if target.Kind != TargetKinds[index] || target.SourceChecksumSHA256 != plan.SourceBaselines[index].DataSHA256 || target.SourceChecksumSHA256 != target.RestoredChecksumSHA256 ||
			!validEvidence(target.EvidenceRef, target.EvidenceSHA256) {
			return errors.New("backup drill proof response target is invalid")
		}
	}
	return nil
}

func validObject(value ObjectIdentity) bool {
	return validName(value.Name) && (value.Namespace == "" || validName(value.Namespace)) && validSHA(value.ScopeSHA256)
}

func validID(value string) bool   { return idPattern.MatchString(value) }
func validName(value string) bool { return namePattern.MatchString(value) }
func validSHA(value string) bool {
	if !shaPattern.MatchString(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func validEvidence(ref, sha string) bool { return validPathToken(ref) && validSHA(sha) }
func validPathToken(value string) bool {
	return tokenPattern.MatchString(value) && !strings.Contains(value, "..") && !strings.HasPrefix(value, "/") && !strings.ContainsAny(value[len(value)-1:], ".-/")
}
func canonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("time is not canonical UTC RFC3339Nano")
	}
	return parsed, nil
}
func retainedKind(kind string) bool {
	return slices.Contains([]string{"Backup", "DataUpload", "ObjectStoreRecoveryPoint", "RestoreAuditCR"}, kind)
}
