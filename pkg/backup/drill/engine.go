// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package drill

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

type Clock func() time.Time

func SystemClock() time.Time { return time.Now().UTC() }

func Preflight(ctx context.Context, plan Plan, adapter *Adapter, now time.Time) (ApprovalReport, error) {
	if adapter == nil || adapter.IdentitySHA256() != plan.Adapter.ExecutableSHA256 {
		return ApprovalReport{}, errors.New("backup drill preflight input binding is invalid")
	}
	if err := ValidatePlan(plan); err != nil {
		return ApprovalReport{}, err
	}
	issued, _ := canonicalTime(plan.IssuedAt)
	expires, _ := canonicalTime(plan.ExpiresAt)
	if now.UTC().Before(issued) || !now.UTC().Before(expires) {
		return ApprovalReport{}, errors.New("backup drill preflight plan is not fresh")
	}
	request := newAdapterRequest(plan, ApprovalReport{}, "preflight", "preflight", "")
	response, err := adapter.invoke(ctx, request)
	if err != nil {
		return ApprovalReport{}, err
	}
	preflightBinding := PreflightBindingSHA256(plan, response.ResponseSHA256, response.Evidence.Ref, response.Evidence.SHA256)
	report := ApprovalReport{
		SchemaVersion: ApprovalSchemaVersion, OperationID: plan.OperationID, PlanSHA256: PlanSHA256(plan),
		ApprovalScopeSHA256: ApprovalScopeSHA256(plan), AdapterExecutableSHA256: adapter.IdentitySHA256(),
		IssuedAt: plan.IssuedAt, ExpiresAt: plan.ExpiresAt, ApprovalTuple: ApprovalTuple(plan, preflightBinding),
		PreflightRequestSHA256: request.RequestSHA256, PreflightResponseSHA256: response.ResponseSHA256,
		PreflightEvidenceRef: response.Evidence.Ref, PreflightEvidenceSHA256: response.Evidence.SHA256,
		PreflightBindingSHA256: preflightBinding,
	}
	report.ReportSHA256 = ApprovalReportSHA256(report)
	if err := ValidateApproval(plan, report, now); err != nil {
		return ApprovalReport{}, err
	}
	return report, nil
}

func Apply(ctx context.Context, plan Plan, approval ApprovalReport, confirmation, journalPath string, adapter *Adapter, clock Clock) (ExecutionReceipt, error) {
	clock = normalizedClock(clock)
	if err := validateExecutionInput(plan, approval, confirmation, adapter, clock(), true); err != nil {
		return ExecutionReceipt{}, err
	}
	if _, err := os.Lstat(journalPath); err == nil || !os.IsNotExist(err) {
		return ExecutionReceipt{}, errors.New("backup drill journal destination is unavailable")
	}
	firstRequest, firstResponse := approvalConsumedDigests(plan, approval)
	entry := newJournalEntry(clock(), 1, plan, approval, ApplySteps[0], firstRequest, firstResponse, "", nil)
	if err := CreateJournal(journalPath, entry); err != nil {
		return ExecutionReceipt{}, errors.New("create backup drill journal before mutation")
	}
	transaction, err := openJournalTransaction(journalPath)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	defer transaction.close()
	return runApply(ctx, plan, approval, transaction, adapter, clock)
}

func Recover(ctx context.Context, plan Plan, approval ApprovalReport, confirmation, journalPath string, adapter *Adapter, clock Clock) (ExecutionReceipt, error) {
	clock = normalizedClock(clock)
	if err := validateExecutionInput(plan, approval, confirmation, adapter, clock(), false); err != nil {
		return ExecutionReceipt{}, err
	}
	transaction, err := openJournalTransaction(journalPath)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	defer transaction.close()
	entries, _, err := transaction.load()
	if err != nil || len(entries) == 0 {
		return ExecutionReceipt{}, errors.New("backup drill recovery journal is unavailable")
	}
	if err := verifyJournalBinding(plan, approval, entries); err != nil {
		return ExecutionReceipt{}, err
	}
	if rollbackStarted(entries) {
		return ExecutionReceipt{}, errors.New("backup drill recovery rejects a rollback-started run")
	}
	return runApply(ctx, plan, approval, transaction, adapter, clock)
}

func Rollback(ctx context.Context, plan Plan, approval ApprovalReport, confirmation, journalPath string, adapter *Adapter, clock Clock) error {
	clock = normalizedClock(clock)
	if err := validateExecutionInput(plan, approval, confirmation, adapter, clock(), false); err != nil {
		return err
	}
	transaction, err := openJournalTransaction(journalPath)
	if err != nil {
		return err
	}
	defer transaction.close()
	entries, _, err := transaction.load()
	if err != nil || len(entries) == 0 {
		return errors.New("backup drill rollback journal is unavailable")
	}
	if err := verifyJournalBinding(plan, approval, entries); err != nil {
		return err
	}
	last := entries[len(entries)-1]
	switch last.Step {
	case "completed":
		return errors.New("backup drill rollback journal is already complete")
	case "rolled-back":
		return nil
	case "rollback-failed":
		return errors.New("backup drill rollback previously failed")
	case "rollback-safe-stop":
		if !rollbackResponseSucceeded(plan, approval, entries, len(entries)-1) {
			return appendRollbackTerminal(transaction, clock, plan, approval, entries, "rollback-failed")
		}
		return continueRollbackCleanup(ctx, transaction, clock, plan, approval, entries, adapter)
	case "rollback-cleanup-requested":
		terminal := "rollback-failed"
		if rollbackResponseSucceeded(plan, approval, entries, len(entries)-1) {
			terminal = "rolled-back"
		}
		return appendRollbackTerminal(transaction, clock, plan, approval, entries, terminal)
	}
	previous := entries[len(entries)-1]
	request := newRollbackRequest(plan, approval, "rollback-safe-stop", previous.EntrySHA256)
	response, err := adapter.invoke(ctx, request)
	responseSHA := response.ResponseSHA256
	var recordedResponse *AdapterResponse
	if validSHA(responseSHA) && validateAdapterResponseBinding(request, response) == nil {
		recordedResponse = &response
	} else {
		responseSHA = adapterFailureSHA256("safe-stop-failed")
	}
	stopEntry := newJournalEntry(clock(), len(entries)+1, plan, approval, request.Step, request.RequestSHA256, responseSHA, previous.EntrySHA256, recordedResponse)
	if appendErr := transaction.append(stopEntry); appendErr != nil {
		return errors.New("record backup drill rollback safe-stop")
	}
	entries = append(entries, stopEntry)
	if err != nil {
		return appendRollbackTerminal(transaction, clock, plan, approval, entries, "rollback-failed")
	}
	return continueRollbackCleanup(ctx, transaction, clock, plan, approval, entries, adapter)
}

func continueRollbackCleanup(ctx context.Context, transaction *journalTransaction, clock Clock, plan Plan, approval ApprovalReport, entries []JournalEntry, adapter *Adapter) error {
	previous := entries[len(entries)-1]
	request := newRollbackRequest(plan, approval, "rollback-cleanup-requested", previous.EntrySHA256)
	response, invokeErr := adapter.invoke(ctx, request)
	responseSHA := response.ResponseSHA256
	var recordedResponse *AdapterResponse
	if validSHA(responseSHA) && validateAdapterResponseBinding(request, response) == nil {
		recordedResponse = &response
	} else {
		responseSHA = adapterFailureSHA256("adapter-execution-failed")
	}
	cleanupEntry := newJournalEntry(clock(), len(entries)+1, plan, approval, request.Step, request.RequestSHA256, responseSHA, previous.EntrySHA256, recordedResponse)
	if appendErr := transaction.append(cleanupEntry); appendErr != nil {
		return errors.New("record backup drill rollback cleanup request")
	}
	entries = append(entries, cleanupEntry)
	terminalStep := "rolled-back"
	if invokeErr != nil {
		terminalStep = "rollback-failed"
	}
	return appendRollbackTerminal(transaction, clock, plan, approval, entries, terminalStep)
}

func appendRollbackTerminal(transaction *journalTransaction, clock Clock, plan Plan, approval ApprovalReport, entries []JournalEntry, step string) error {
	previous := entries[len(entries)-1]
	requestSHA, responseSHA := rollbackTerminalDigests(step, previous.EntrySHA256, previous.ResponseSHA256)
	terminal := newJournalEntry(clock(), len(entries)+1, plan, approval, step, requestSHA, responseSHA, previous.EntrySHA256, nil)
	if err := transaction.append(terminal); err != nil {
		return errors.New("record backup drill rollback outcome")
	}
	if step == "rollback-failed" {
		return errors.New("backup drill rollback cleanup failed")
	}
	return nil
}

func runApply(ctx context.Context, plan Plan, approval ApprovalReport, transaction *journalTransaction, adapter *Adapter, clock Clock) (ExecutionReceipt, error) {
	entries, _, err := transaction.load()
	if err != nil || verifyJournalBinding(plan, approval, entries) != nil {
		return ExecutionReceipt{}, errors.New("backup drill journal is not recoverable")
	}
	if rollbackStarted(entries) {
		return ExecutionReceipt{}, errors.New("backup drill apply cannot resume after rollback begins")
	}
	for len(entries) < len(ApplySteps)-1 {
		step := ApplySteps[len(entries)]
		previous := entries[len(entries)-1]
		if step == "mutation-started" {
			requestSHA, responseSHA := mutationStartedDigests(plan, previous.EntrySHA256)
			entry := newJournalEntry(clock(), len(entries)+1, plan, approval, step, requestSHA, responseSHA, previous.EntrySHA256, nil)
			if err := transaction.append(entry); err != nil {
				return ExecutionReceipt{}, errors.New("record backup drill mutation start")
			}
			entries = append(entries, entry)
			continue
		}
		request := newAdapterRequest(plan, approval, "apply", step, previous.EntrySHA256)
		response, err := adapter.invoke(ctx, request)
		if err != nil {
			return ExecutionReceipt{}, err
		}
		if step == "proof-assembled" {
			if err := validateProofResponse(plan, response); err != nil {
				return ExecutionReceipt{}, err
			}
		}
		entry := newJournalEntry(clock(), len(entries)+1, plan, approval, step, request.RequestSHA256, response.ResponseSHA256, previous.EntrySHA256, &response)
		if err := transaction.append(entry); err != nil {
			return ExecutionReceipt{}, errors.New("append backup drill execution journal")
		}
		entries = append(entries, entry)
	}
	proofIndex := len(entries) - 1
	if entries[proofIndex].Step == "completed" {
		proofIndex--
	}
	proof := entries[proofIndex].Response
	if proof == nil || validateProofResponse(plan, *proof) != nil {
		return ExecutionReceipt{}, errors.New("backup drill proof response is absent from journal")
	}
	if len(entries) == len(ApplySteps)-1 {
		previous := entries[len(entries)-1]
		requestSHA, responseSHA := completedDigests(proof.ResponseSHA256)
		entry := newJournalEntry(clock(), len(entries)+1, plan, approval, "completed", requestSHA, responseSHA, previous.EntrySHA256, nil)
		if err := transaction.append(entry); err != nil {
			return ExecutionReceipt{}, errors.New("record backup drill completion")
		}
		entries = append(entries, entry)
	}
	entries, _, err = transaction.load()
	if err != nil || verifyJournalBinding(plan, approval, entries) != nil || len(entries) != len(ApplySteps) {
		return ExecutionReceipt{}, errors.New("reload completed backup drill journal")
	}
	proof = entries[len(entries)-2].Response
	if proof == nil || validateProofResponse(plan, *proof) != nil {
		return ExecutionReceipt{}, errors.New("reloaded backup drill proof response is invalid")
	}
	receipt := ExecutionReceipt{
		SchemaVersion: ReceiptSchemaVersion, OperationID: plan.OperationID, ProofID: plan.ProofID, InstallationID: plan.InstallationID,
		PlanSHA256: PlanSHA256(plan), ApprovalSHA256: ApprovalSHA256(approval), ApprovalScopeSHA256: ApprovalScopeSHA256(plan),
		AdapterExecutableSHA256: plan.Adapter.ExecutableSHA256, Status: "completed", CompletedAt: entries[len(entries)-1].RecordedAt,
		JournalHeadSHA256: entries[len(entries)-1].EntrySHA256, ExecutionEvidenceResponseSHA256: proof.ResponseSHA256,
		Targets: append([]TargetResult(nil), proof.Targets...), IsolationEvidence: *proof.IsolationEvidence, CleanupEvidence: *proof.CleanupEvidence,
		ObjectLockDeleteDenialReceiptSHA256: proof.ObjectLockDeleteDenialReceiptSHA256,
		AggregateProofArtifactSHA256:        proof.AggregateProofArtifactSHA256, AggregateProofPathToken: proof.AggregateProofPathToken,
	}
	receipt.ReceiptSHA256 = ExecutionReceiptSHA256(receipt)
	if err := ValidateReceipt(plan, approval, receipt, entries); err != nil {
		return ExecutionReceipt{}, err
	}
	return receipt, nil
}

func validateExecutionInput(plan Plan, approval ApprovalReport, confirmation string, adapter *Adapter, now time.Time, requireFresh bool) error {
	if adapter == nil || adapter.IdentitySHA256() != plan.Adapter.ExecutableSHA256 {
		return errors.New("backup drill execution adapter binding is invalid")
	}
	approvalErr := validateApprovalBinding(plan, approval)
	if requireFresh {
		approvalErr = ValidateApproval(plan, approval, now)
	}
	if approvalErr != nil || confirmation != approval.ApprovalTuple {
		return errors.New("backup drill execution approval, confirmation, or adapter binding is invalid")
	}
	return nil
}

func verifyJournalBinding(plan Plan, approval ApprovalReport, entries []JournalEntry) error {
	if err := validateJournalEntries(entries); err != nil {
		return err
	}
	for index, entry := range entries {
		if entry.OperationID != plan.OperationID || entry.PlanSHA256 != PlanSHA256(plan) || entry.ApprovalSHA256 != ApprovalSHA256(approval) ||
			entry.ApprovalScopeSHA256 != ApprovalScopeSHA256(plan) || entry.AdapterExecutableSHA256 != plan.Adapter.ExecutableSHA256 {
			return errors.New("backup drill journal transaction binding changed")
		}
		switch entry.Step {
		case "approval-consumed":
			requestSHA, responseSHA := approvalConsumedDigests(plan, approval)
			if index != 0 || entry.Response != nil || entry.RequestSHA256 != requestSHA || entry.ResponseSHA256 != responseSHA {
				return errors.New("backup drill approval-consumed journal derivation is invalid")
			}
			continue
		case "mutation-started":
			if index != 1 {
				return errors.New("backup drill mutation-started journal position is invalid")
			}
			requestSHA, responseSHA := mutationStartedDigests(plan, entries[index-1].EntrySHA256)
			if entry.Response != nil || entry.RequestSHA256 != requestSHA || entry.ResponseSHA256 != responseSHA {
				return errors.New("backup drill mutation-started journal derivation is invalid")
			}
			continue
		case "completed":
			if index == 0 || entries[index-1].Step != "proof-assembled" || entries[index-1].Response == nil {
				return errors.New("backup drill completed journal predecessor is invalid")
			}
			requestSHA, responseSHA := completedDigests(entries[index-1].ResponseSHA256)
			if entry.Response != nil || entry.RequestSHA256 != requestSHA || entry.ResponseSHA256 != responseSHA {
				return errors.New("backup drill completed journal derivation is invalid")
			}
			continue
		case "rolled-back", "rollback-failed":
			if index == 0 {
				return errors.New("backup drill rollback terminal predecessor is absent")
			}
			requestSHA, responseSHA := rollbackTerminalDigests(entry.Step, entries[index-1].EntrySHA256, entries[index-1].ResponseSHA256)
			if entry.Response != nil || entry.RequestSHA256 != requestSHA || entry.ResponseSHA256 != responseSHA {
				return errors.New("backup drill rollback terminal derivation is invalid")
			}
			continue
		}
		if index == 0 {
			return errors.New("backup drill journal begins with an adapter step")
		}
		request := newAdapterRequest(plan, approval, "apply", entry.Step, entries[index-1].EntrySHA256)
		if strings.HasPrefix(entry.Step, "rollback-") {
			request = newRollbackRequest(plan, approval, entry.Step, entries[index-1].EntrySHA256)
		}
		if entry.RequestSHA256 != request.RequestSHA256 {
			return errors.New("backup drill journal adapter response is stale or conflicting")
		}
		failedTerminal := index+1 < len(entries) && entries[index+1].Step == "rollback-failed"
		incompleteRollbackFailure := index == len(entries)-1 && strings.HasPrefix(entry.Step, "rollback-")
		failureAllowed := failedTerminal || incompleteRollbackFailure
		if entry.Response == nil {
			expectedFailure := ""
			if entry.Step == "rollback-safe-stop" {
				expectedFailure = adapterFailureSHA256("safe-stop-failed")
			} else if entry.Step == "rollback-cleanup-requested" {
				expectedFailure = adapterFailureSHA256("adapter-execution-failed")
			}
			if !failureAllowed || entry.ResponseSHA256 != expectedFailure {
				return errors.New("backup drill journal adapter failure is not exact")
			}
			continue
		}
		if entry.ResponseSHA256 != entry.Response.ResponseSHA256 {
			return errors.New("backup drill journal adapter response digest conflicts")
		}
		if err := validateAdapterResponseBinding(request, *entry.Response); err != nil {
			return errors.New("backup drill journal adapter response binding is invalid")
		}
		if err := ValidateAdapterResponse(request, *entry.Response); err != nil && !failureAllowed {
			return errors.New("backup drill journal adapter response is invalid")
		}
	}
	return nil
}

func rollbackStarted(entries []JournalEntry) bool {
	return slices.ContainsFunc(entries, func(entry JournalEntry) bool {
		return strings.HasPrefix(entry.Step, "rollback-") || entry.Step == "rolled-back"
	})
}

func approvalConsumedDigests(plan Plan, approval ApprovalReport) (string, string) {
	return digest(struct {
		OperationID string `json:"operationId"`
		Tuple       string `json:"tuple"`
	}{plan.OperationID, approval.ApprovalTuple}), approval.PreflightResponseSHA256
}

func mutationStartedDigests(plan Plan, previous string) (string, string) {
	return digest(struct{ Step, Previous string }{"mutation-started", previous}),
		digest(struct{ Status, Scope string }{"mutation-authorized", ApprovalScopeSHA256(plan)})
}

func completedDigests(proofResponseSHA256 string) (string, string) {
	return digest(struct{ Step, Proof string }{"completed", proofResponseSHA256}), proofResponseSHA256
}

func rollbackTerminalDigests(step, previous, adapterResponseSHA256 string) (string, string) {
	return digest(struct{ Step, Previous string }{step, previous}),
		digest(struct{ Status, AdapterResponse string }{step, adapterResponseSHA256})
}

func adapterFailureSHA256(reason string) string {
	return digest(struct {
		Failure string `json:"failure"`
	}{reason})
}

func newAdapterRequest(plan Plan, approval ApprovalReport, mode, step, previous string) AdapterRequest {
	request := AdapterRequest{
		SchemaVersion: AdapterRequestVersion, ProtocolVersion: AdapterProtocolVersion, OperationID: plan.OperationID,
		PlanSHA256: PlanSHA256(plan), ApprovalScopeSHA256: ApprovalScopeSHA256(plan), AdapterExecutableSHA256: plan.Adapter.ExecutableSHA256,
		Mode: mode, Step: step, PreviousJournalSHA256: previous, Plan: plan,
	}
	if approval.SchemaVersion != "" {
		request.ApprovalSHA256 = ApprovalSHA256(approval)
	}
	request.RequestID = requestIdentity(request)
	request.RequestSHA256 = AdapterRequestSHA256(request)
	return request
}

func newRollbackRequest(plan Plan, approval ApprovalReport, step, previous string) AdapterRequest {
	request := newAdapterRequest(plan, approval, "rollback", step, previous)
	if step == "rollback-cleanup-requested" {
		request.RetainKinds = []string{"Backup", "DataUpload", "ObjectStoreRecoveryPoint", "RestoreAuditCR"}
		request.CleanupTargets = append([]CleanupTarget(nil), plan.CleanupTargets...)
		request.RequestID = requestIdentity(request)
		request.RequestSHA256 = AdapterRequestSHA256(request)
	}
	return request
}

func rollbackResponseSucceeded(plan Plan, approval ApprovalReport, entries []JournalEntry, index int) bool {
	if index < 1 || index >= len(entries) {
		return false
	}
	entry := entries[index]
	if entry.Step != "rollback-safe-stop" && entry.Step != "rollback-cleanup-requested" || entry.Response == nil {
		return false
	}
	request := newRollbackRequest(plan, approval, entry.Step, entries[index-1].EntrySHA256)
	return entry.RequestSHA256 == request.RequestSHA256 && ValidateAdapterResponse(request, *entry.Response) == nil
}

func requestIdentity(request AdapterRequest) string {
	return fmt.Sprintf("%s:%s", request.Mode, digest(struct {
		OperationID, PlanSHA256, ApprovalSHA256, Step, Previous string
	}{request.OperationID, request.PlanSHA256, request.ApprovalSHA256, request.Step, request.PreviousJournalSHA256})[:32])
}

func normalizedClock(clock Clock) Clock {
	if clock == nil {
		return SystemClock
	}
	return clock
}
