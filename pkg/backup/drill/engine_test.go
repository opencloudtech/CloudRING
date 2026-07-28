//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package drill

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/kubeconfigpipe"
)

type fakeAdapterRunner struct {
	identity          string
	requests          []AdapterRequest
	partialOnce       map[string]bool
	crashOnce         map[string]bool
	preflightMutation bool
	secretStep        string
	wrongDigestStep   string
	rollbackFailure   bool
	blockStep         string
	blockEntered      chan struct{}
	blockRelease      chan struct{}
	blockOnce         sync.Once
}

func (runner *fakeAdapterRunner) IdentitySHA256() string { return runner.identity }
func (runner *fakeAdapterRunner) Close() error           { return nil }

func (runner *fakeAdapterRunner) RunWithEnvironment(_ context.Context, arguments []string, input []byte, _, _ int64, environment []string, replay *kubeconfigpipe.Replay) ([]byte, []byte, error) {
	if len(arguments) != 1 || arguments[0] != "drill" || replay != nil || !slicesEqual(environment, []string{"LANG=C", "LC_ALL=C"}) {
		return nil, nil, errors.New("unsafe fake adapter invocation")
	}
	var request AdapterRequest
	if err := json.Unmarshal(input, &request); err != nil {
		return nil, nil, err
	}
	runner.requests = append(runner.requests, request)
	if request.Step == runner.blockStep && runner.blockRelease != nil {
		runner.blockOnce.Do(func() { close(runner.blockEntered) })
		<-runner.blockRelease
	}
	key := request.Mode + "/" + request.Step
	if runner.crashOnce[key] {
		delete(runner.crashOnce, key)
		return nil, nil, errors.New("injected process crash")
	}
	if request.Step == runner.secretStep {
		return []byte(`{"` + forbiddenCredentialField() + `":"synthetic-reference"}`), nil, nil
	}
	status := "completed"
	mutated := request.Mode == "apply" && slicesContains([]string{"etcd-offcell-complete", "velero-backup-complete", "restore-watch-create-observe-complete", "etcd-sandbox-restored", "restore-validation-complete", "isolated-targets-deleted"}, request.Step)
	if request.Mode == "preflight" {
		status = "ready"
		mutated = runner.preflightMutation
	}
	if request.Step == "rollback-safe-stop" {
		status = "safe-stopped"
		mutated = false
	}
	if request.Step == "rollback-cleanup-requested" {
		mutated = true
	}
	if runner.partialOnce[key] {
		delete(runner.partialOnce, key)
		status = "partial"
	}
	if runner.rollbackFailure && request.Step == "rollback-cleanup-requested" {
		status = "failed"
		mutated = false
	}
	response := AdapterResponse{
		SchemaVersion: AdapterResponseVersion, ProtocolVersion: AdapterProtocolVersion, OperationID: request.OperationID,
		Step: request.Step, RequestSHA256: request.RequestSHA256, AdapterExecutableSHA256: runner.identity,
		Status: status, Mutated: mutated, Evidence: Evidence{Ref: "evidence/" + request.Step, SHA256: testSHA(request.Step + "-evidence")},
	}
	if request.Step == runner.wrongDigestStep {
		response.AdapterExecutableSHA256 = strings.Repeat("f", 64)
	}
	if request.Step == "proof-assembled" {
		for index, kind := range TargetKinds {
			checksum := request.Plan.SourceBaselines[index].DataSHA256
			response.Targets = append(response.Targets, TargetResult{Kind: kind, SourceChecksumSHA256: checksum, RestoredChecksumSHA256: checksum,
				EvidenceRef: "evidence/target-" + strings.ToLower(kind), EvidenceSHA256: testSHA(kind + "-target")})
		}
		response.IsolationEvidence = &Evidence{Ref: "evidence/isolation", SHA256: testSHA("isolation")}
		response.CleanupEvidence = &Evidence{Ref: "evidence/cleanup", SHA256: testSHA("cleanup")}
		response.ObjectLockDeleteDenialReceiptSHA256 = testSHA("object-lock-delete-denial")
		response.AggregateProofArtifactSHA256 = testSHA("aggregate-proof")
		response.AggregateProofPathToken = request.Plan.AggregateProofPathToken
	}
	if request.Step == "restore-watch-create-observe-complete" {
		for _, mapping := range request.Plan.IsolatedNamespaces {
			response.RestoreObservations = append(response.RestoreObservations, RestoreObservation{
				RestoreName: mapping.RestoreName, RestoreScopeSHA256: mapping.RestoreScopeSHA256, SourceNamespace: mapping.SourceNamespace,
				DestinationNamespace: mapping.Destination.Name, DestinationScopeSHA256: mapping.Destination.ScopeSHA256,
				EvidenceRef: "evidence/observation-" + mapping.Destination.Name, EvidenceSHA256: testSHA(mapping.Destination.Name + "-observation"),
			})
		}
	}
	response.ResponseSHA256 = AdapterResponseSHA256(response)
	payload, err := json.Marshal(response)
	return payload, nil, err
}

func TestPreflightApplyAndRecoverCompletedReceipt(t *testing.T) {
	plan, now := validTestPlan()
	runner := newFakeRunner(plan)
	adapter := &Adapter{runner: runner}
	approval := mustPreflight(t, plan, adapter, now)
	journal := filepath.Join(t.TempDir(), "journal.jsonl")
	clock := advancingClock(now.Add(time.Second))
	receipt, err := Apply(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, clock)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := LoadJournal(journal)
	if err != nil || ValidateReceipt(plan, approval, receipt, entries) != nil {
		t.Fatalf("completed receipt or journal invalid: %v", err)
	}
	wrongReceipt := receipt
	wrongReceipt.Targets = append([]TargetResult(nil), receipt.Targets...)
	wrongReceipt.Targets[0].SourceChecksumSHA256 = testSHA("wrong-but-equal-target")
	wrongReceipt.Targets[0].RestoredChecksumSHA256 = wrongReceipt.Targets[0].SourceChecksumSHA256
	wrongReceipt.ReceiptSHA256 = ExecutionReceiptSHA256(wrongReceipt)
	if ValidateReceipt(plan, approval, wrongReceipt, entries) == nil {
		t.Fatal("receipt accepted arbitrary equal source/restored checksums")
	}
	wrongProof := *entries[len(entries)-2].Response
	wrongProof.Targets = append([]TargetResult(nil), wrongProof.Targets...)
	wrongProof.Targets[0].SourceChecksumSHA256 = testSHA("wrong-but-equal-proof")
	wrongProof.Targets[0].RestoredChecksumSHA256 = wrongProof.Targets[0].SourceChecksumSHA256
	if validateProofResponse(plan, wrongProof) == nil {
		t.Fatal("proof response accepted arbitrary equal source/restored checksums")
	}
	for name, mutate := range map[string]func(*ExecutionReceipt){
		"target evidence ref": func(candidate *ExecutionReceipt) {
			candidate.Targets = append([]TargetResult(nil), candidate.Targets...)
			candidate.Targets[0].EvidenceRef = "evidence/different-target"
		},
		"isolation evidence hash": func(candidate *ExecutionReceipt) {
			candidate.IsolationEvidence.SHA256 = testSHA("different-isolation")
		},
		"proof response hash": func(candidate *ExecutionReceipt) {
			candidate.ExecutionEvidenceResponseSHA256 = testSHA("different-proof-response")
		},
		"completed time": func(candidate *ExecutionReceipt) {
			candidate.CompletedAt = now.Add(9 * time.Minute).Format(time.RFC3339Nano)
		},
	} {
		t.Run("receipt rejects "+name, func(t *testing.T) {
			candidate := receipt
			mutate(&candidate)
			candidate.ReceiptSHA256 = ExecutionReceiptSHA256(candidate)
			if ValidateReceipt(plan, approval, candidate, entries) == nil {
				t.Fatal("receipt accepted data differing from stored proof response")
			}
		})
	}
	if len(entries) != len(ApplySteps) || entries[0].Step != "approval-consumed" || entries[1].Step != "mutation-started" || entries[len(entries)-1].Step != "completed" {
		t.Fatalf("journal steps = %#v", entries)
	}
	if runner.requests[0].Mode != "preflight" || runner.requests[1].Step != "etcd-offcell-complete" {
		t.Fatalf("engine-owned phases leaked to adapter: %#v", runner.requests)
	}
	combined := 0
	for _, request := range runner.requests {
		if request.Step == "restore-watch-ready" || request.Step == "restores-created" {
			t.Fatal("restore watch and create were split across adapter processes")
		}
		if request.Step == "restore-watch-create-observe-complete" {
			combined++
			if len(request.Plan.Restores) != 4 || len(request.Plan.IsolatedNamespaces) != 5 {
				t.Fatal("combined restore request did not carry exact four restores and five mappings")
			}
		}
	}
	if combined != 1 {
		t.Fatalf("combined watch/create/observe invocations = %d", combined)
	}
	combinedEntry := entries[4]
	if combinedEntry.Step != "restore-watch-create-observe-complete" || combinedEntry.Response == nil || len(combinedEntry.Response.RestoreObservations) != 5 {
		t.Fatal("combined restore phase did not durably journal five mapping observations")
	}
	for _, index := range []int{2, 3} {
		mapping := plan.IsolatedNamespaces[index]
		observation := combinedEntry.Response.RestoreObservations[index]
		if observation.SourceNamespace != mapping.SourceNamespace || observation.DestinationNamespace != mapping.Destination.Name ||
			observation.DestinationScopeSHA256 != mapping.Destination.ScopeSHA256 || plan.CleanupTargets[index].Name != mapping.Destination.Name {
			t.Fatalf("Namespace restore mapping %d is not observation- and cleanup-bound", index)
		}
	}
	tampered := *combinedEntry.Response
	tampered.RestoreObservations = append([]RestoreObservation(nil), combinedEntry.Response.RestoreObservations...)
	tampered.RestoreObservations[3].DestinationNamespace = tampered.RestoreObservations[2].DestinationNamespace
	tampered.ResponseSHA256 = AdapterResponseSHA256(tampered)
	request := newAdapterRequest(plan, approval, "apply", combinedEntry.Step, entries[3].EntrySHA256)
	if ValidateAdapterResponse(request, tampered) == nil {
		t.Fatal("combined observation accepted a duplicated Namespace destination")
	}
	recovered, err := Recover(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(2*time.Minute)))
	if err != nil || recovered.ReceiptSHA256 != receipt.ReceiptSHA256 {
		t.Fatalf("completed recovery = %#v, %v", recovered, err)
	}
}

func TestRecoverAfterPartialAndProcessCrash(t *testing.T) {
	for _, failure := range []string{"partial", "crash"} {
		t.Run(failure, func(t *testing.T) {
			plan, now := validTestPlan()
			runner := newFakeRunner(plan)
			adapter := &Adapter{runner: runner}
			approval := mustPreflight(t, plan, adapter, now)
			key := "apply/restore-watch-create-observe-complete"
			if failure == "partial" {
				runner.partialOnce[key] = true
			} else {
				runner.crashOnce[key] = true
			}
			journal := filepath.Join(t.TempDir(), "journal.jsonl")
			if _, err := Apply(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Second))); err == nil {
				t.Fatal("injected adapter failure unexpectedly completed")
			}
			receipt, err := Recover(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Minute)))
			if err != nil {
				t.Fatal(err)
			}
			entries, err := LoadJournal(journal)
			if err != nil || ValidateReceipt(plan, approval, receipt, entries) != nil {
				t.Fatalf("recovered receipt invalid: %v", err)
			}
		})
	}
}

func TestRecoverAndRollbackRemainAvailableAfterApprovalExpiry(t *testing.T) {
	t.Run("recover", func(t *testing.T) {
		plan, now := validTestPlan()
		runner := newFakeRunner(plan)
		adapter := &Adapter{runner: runner}
		approval := mustPreflight(t, plan, adapter, now)
		runner.crashOnce["apply/restore-watch-create-observe-complete"] = true
		journal := filepath.Join(t.TempDir(), "journal.jsonl")
		_, _ = Apply(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Second)))
		if _, err := Recover(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(24*time.Hour))); err != nil {
			t.Fatalf("recovery after approval expiry failed: %v", err)
		}
	})
	t.Run("rollback", func(t *testing.T) {
		plan, now := validTestPlan()
		runner := newFakeRunner(plan)
		adapter := &Adapter{runner: runner}
		approval := mustPreflight(t, plan, adapter, now)
		runner.crashOnce["apply/etcd-offcell-complete"] = true
		journal := filepath.Join(t.TempDir(), "journal.jsonl")
		_, _ = Apply(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Second)))
		if err := Rollback(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(24*time.Hour))); err != nil {
			t.Fatalf("rollback after approval expiry failed: %v", err)
		}
	})
}

func TestRollbackSuccessAndFailures(t *testing.T) {
	for _, failure := range []string{"", "cleanup-conflict", "adapter-crash"} {
		t.Run(failure, func(t *testing.T) {
			plan, now := validTestPlan()
			runner := newFakeRunner(plan)
			adapter := &Adapter{runner: runner}
			approval := mustPreflight(t, plan, adapter, now)
			runner.crashOnce["apply/etcd-offcell-complete"] = true
			journal := filepath.Join(t.TempDir(), "journal.jsonl")
			_, _ = Apply(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Second)))
			if failure == "cleanup-conflict" {
				runner.rollbackFailure = true
			}
			if failure == "adapter-crash" {
				runner.crashOnce["rollback/rollback-cleanup-requested"] = true
			}
			err := Rollback(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Minute)))
			entries, loadErr := LoadJournal(journal)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			last := entries[len(entries)-1].Step
			if failure == "" && (err != nil || last != "rolled-back") {
				t.Fatalf("rollback = %s, %v", last, err)
			}
			if failure != "" && (err == nil || last != "rollback-failed") {
				t.Fatalf("failed rollback = %s, %v", last, err)
			}
			cleanupRequest := runner.requests[len(runner.requests)-1]
			if len(cleanupRequest.RetainKinds) != 4 || len(cleanupRequest.CleanupTargets) != len(plan.CleanupTargets) {
				t.Fatal("rollback did not preserve retained recovery points or exact cleanup targets")
			}
			if _, err := Recover(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(2*time.Minute))); err == nil {
				t.Fatal("recover accepted rolled-back run")
			}
		})
	}
}

func TestScopeTuplePreflightAndAdapterFailuresFailClosed(t *testing.T) {
	plan, now := validTestPlan()
	tests := []struct {
		name string
		run  func(*testing.T, Plan, time.Time)
	}{
		{"wrong tuple", func(t *testing.T, plan Plan, now time.Time) {
			runner := newFakeRunner(plan)
			adapter := &Adapter{runner: runner}
			approval := mustPreflight(t, plan, adapter, now)
			if _, err := Apply(t.Context(), plan, approval, "wrong", filepath.Join(t.TempDir(), "journal"), adapter, advancingClock(now.Add(time.Second))); err == nil {
				t.Fatal("wrong tuple accepted")
			}
		}},
		{"stale tuple", func(t *testing.T, plan Plan, now time.Time) {
			runner := newFakeRunner(plan)
			adapter := &Adapter{runner: runner}
			approval := mustPreflight(t, plan, adapter, now)
			if _, err := Apply(t.Context(), plan, approval, approval.ApprovalTuple, filepath.Join(t.TempDir(), "journal"), adapter, advancingClock(now.Add(11*time.Minute))); err == nil {
				t.Fatal("stale approval accepted")
			}
		}},
		{"approval before issuance", func(t *testing.T, plan Plan, now time.Time) {
			runner := newFakeRunner(plan)
			adapter := &Adapter{runner: runner}
			approval := mustPreflight(t, plan, adapter, now)
			if ValidateApproval(plan, approval, now.Add(-time.Nanosecond)) == nil {
				t.Fatal("approval accepted before issuance")
			}
			if _, err := Apply(t.Context(), plan, approval, approval.ApprovalTuple, filepath.Join(t.TempDir(), "journal"), adapter, advancingClock(now.Add(-time.Nanosecond))); err == nil {
				t.Fatal("apply consumed approval before issuance")
			}
		}},
		{"changed scope", func(t *testing.T, plan Plan, now time.Time) {
			runner := newFakeRunner(plan)
			adapter := &Adapter{runner: runner}
			approval := mustPreflight(t, plan, adapter, now)
			plan.ObjectStore.Prefix = "goal01/changed"
			if _, err := Apply(t.Context(), plan, approval, approval.ApprovalTuple, filepath.Join(t.TempDir(), "journal"), adapter, advancingClock(now.Add(time.Second))); err == nil {
				t.Fatal("changed scope accepted")
			}
		}},
		{"preflight mutation", func(t *testing.T, plan Plan, now time.Time) {
			runner := newFakeRunner(plan)
			runner.preflightMutation = true
			if _, err := Preflight(t.Context(), plan, &Adapter{runner: runner}, now); err == nil {
				t.Fatal("mutating preflight accepted")
			}
		}},
		{"adapter digest mismatch", func(t *testing.T, plan Plan, now time.Time) {
			runner := newFakeRunner(plan)
			runner.wrongDigestStep = "preflight"
			if _, err := Preflight(t.Context(), plan, &Adapter{runner: runner}, now); err == nil {
				t.Fatal("wrong response adapter digest accepted")
			}
		}},
		{"secret response", func(t *testing.T, plan Plan, now time.Time) {
			runner := newFakeRunner(plan)
			runner.secretStep = "preflight"
			if _, err := Preflight(t.Context(), plan, &Adapter{runner: runner}, now); err == nil {
				t.Fatal("secret-looking response accepted")
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { test.run(t, plan, now) })
	}
}

func TestApprovalTupleBindsActualPreflightResponseAndEvidence(t *testing.T) {
	plan, now := validTestPlan()
	runner := newFakeRunner(plan)
	approval := mustPreflight(t, plan, &Adapter{runner: runner}, now)
	tamperedRequest := approval
	tamperedRequest.PreflightRequestSHA256 = testSHA("different-preflight-request")
	tamperedRequest.ReportSHA256 = ApprovalReportSHA256(tamperedRequest)
	if tamperedRequest.ApprovalTuple != approval.ApprovalTuple {
		t.Fatal("preflight request mutation unexpectedly changed the existing tuple")
	}
	if validateApprovalBinding(plan, tamperedRequest) == nil {
		t.Fatal("approval accepted a non-deterministic preflight request digest with recomputed report hash")
	}
	for _, mutate := range []func(*ApprovalReport){
		func(report *ApprovalReport) { report.PreflightResponseSHA256 = testSHA("different-preflight-response") },
		func(report *ApprovalReport) { report.PreflightEvidenceRef = "evidence/different-preflight" },
		func(report *ApprovalReport) { report.PreflightEvidenceSHA256 = testSHA("different-preflight-evidence") },
	} {
		tampered := approval
		mutate(&tampered)
		tampered.PreflightBindingSHA256 = PreflightBindingSHA256(plan, tampered.PreflightResponseSHA256, tampered.PreflightEvidenceRef, tampered.PreflightEvidenceSHA256)
		if nextTuple := ApprovalTuple(plan, tampered.PreflightBindingSHA256); nextTuple == approval.ApprovalTuple {
			t.Fatal("changed live preflight produced the same confirmation tuple")
		}
		tampered.ReportSHA256 = ApprovalReportSHA256(tampered)
		if validateApprovalBinding(plan, tampered) == nil {
			t.Fatal("changed live preflight accepted the previously confirmed tuple")
		}
	}
}

func TestPlanRejectsWeakOrUnknownObjectLockRetention(t *testing.T) {
	plan, _ := validTestPlan()
	plan.ObjectStore.MinimumRetentionDays = 29
	if ValidatePlan(plan) == nil {
		t.Fatal("Goal01 plan accepted retention below 30 days")
	}
	plan, _ = validTestPlan()
	plan.ObjectStore.ObjectLockMode = "disabled"
	if ValidatePlan(plan) == nil {
		t.Fatal("Goal01 plan accepted unknown object-lock mode")
	}
}

func TestPlanRequiresExactRestoreNamespaceMappingCardinality(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Plan)
	}{
		{"missing", func(plan *Plan) { plan.IsolatedNamespaces = plan.IsolatedNamespaces[:4] }},
		{"duplicate", func(plan *Plan) { plan.IsolatedNamespaces[3] = plan.IsolatedNamespaces[2] }},
		{"extra", func(plan *Plan) {
			plan.IsolatedNamespaces = append(plan.IsolatedNamespaces, plan.IsolatedNamespaces[4])
		}},
		{"misassigned", func(plan *Plan) {
			plan.IsolatedNamespaces[4].RestoreName = plan.Restores[0].Name
			plan.IsolatedNamespaces[4].RestoreScopeSHA256 = plan.Restores[0].ScopeSHA256
		}},
		{"wrong namespace source", func(plan *Plan) { plan.IsolatedNamespaces[3].SourceNamespace = "other-system" }},
		{"duplicate destination scope", func(plan *Plan) {
			plan.IsolatedNamespaces[3].Destination.ScopeSHA256 = plan.IsolatedNamespaces[2].Destination.ScopeSHA256
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, _ := validTestPlan()
			test.mutate(&plan)
			if ValidatePlan(plan) == nil {
				t.Fatal("invalid restore namespace mapping accepted")
			}
		})
	}
}

func TestPlatformAndFluxDestinationsAreExactCleanupTargets(t *testing.T) {
	plan, _ := validTestPlan()
	if ValidatePlan(plan) != nil {
		t.Fatal("valid five-namespace mapping was rejected")
	}
	for _, index := range []int{2, 3} {
		mapping := plan.IsolatedNamespaces[index]
		if mapping.SourceNamespace != []string{"platform-system", "flux-system"}[index-2] || plan.CleanupTargets[index].Name != mapping.Destination.Name {
			t.Fatalf("mapping %d is not exact cleanup target", index)
		}
	}
	plan.CleanupTargets[3] = plan.CleanupTargets[2]
	if ValidatePlan(plan) == nil {
		t.Fatal("plan accepted cleanup that omitted the flux-system destination")
	}
}

func TestJournalRejectsTruncationReorderTamperAndDuplicateStep(t *testing.T) {
	for _, mutation := range []string{"truncate", "reorder", "tamper", "duplicate"} {
		t.Run(mutation, func(t *testing.T) {
			plan, now := validTestPlan()
			runner := newFakeRunner(plan)
			adapter := &Adapter{runner: runner}
			approval := mustPreflight(t, plan, adapter, now)
			journal := filepath.Join(t.TempDir(), "journal.jsonl")
			if _, err := Apply(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Second))); err != nil {
				t.Fatal(err)
			}
			payload, err := os.ReadFile(journal) // #nosec G304 -- journal is the exact test-owned file created beneath this subtest's t.TempDir.
			if err != nil {
				t.Fatal(err)
			}
			lines := bytes.Split(payload[:len(payload)-1], []byte{'\n'})
			switch mutation {
			case "truncate":
				payload = payload[:len(payload)-1]
			case "reorder":
				lines[2], lines[3] = lines[3], lines[2]
				payload = append(bytes.Join(lines, []byte{'\n'}), '\n')
			case "tamper":
				payload = bytes.Replace(payload, []byte(`"sequence":3`), []byte(`"sequence":8`), 1)
			case "duplicate":
				lines = append(lines[:3], append([][]byte{lines[2]}, lines[3:]...)...)
				payload = append(bytes.Join(lines, []byte{'\n'}), '\n')
			}
			if err := os.WriteFile(journal, payload, 0o600); err != nil { // #nosec G703 -- journal is the exact test-owned file created beneath this subtest's t.TempDir.
				t.Fatal(err)
			}
			if _, err := LoadJournal(journal); err == nil {
				t.Fatalf("%s journal accepted", mutation)
			}
		})
	}
}

func TestJournalRejectsHardlinksWrongOwnerAndTimeRegression(t *testing.T) {
	plan, now := validTestPlan()
	runner := newFakeRunner(plan)
	adapter := &Adapter{runner: runner}
	approval := mustPreflight(t, plan, adapter, now)
	runner.crashOnce["apply/etcd-offcell-complete"] = true
	journal := filepath.Join(t.TempDir(), "journal.jsonl")
	_, _ = Apply(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Second)))
	alias := journal + ".hardlink"
	if err := os.Link(journal, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadJournal(journal); err == nil {
		t.Fatal("hard-linked journal accepted")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	entries, err := LoadJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	previous := entries[0]
	previous.RecordedAt = "2026-07-23T10:00:00.1Z"
	previous.EntrySHA256 = JournalEntrySHA256(previous)
	next := newJournalEntry(now, 2, plan, approval, "mutation-started", testSHA("request"), testSHA("response"), previous.EntrySHA256, nil)
	next.RecordedAt = "2026-07-23T10:00:00.09Z"
	next.EntrySHA256 = JournalEntrySHA256(next)
	if validateJournalEntry(next, &previous) == nil {
		t.Fatal("fractional RFC3339 time regression accepted")
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(journal, 65534, -1); err != nil {
			t.Fatal(err)
		}
		defer os.Chown(journal, 0, -1)
		if _, err := LoadJournal(journal); err == nil {
			t.Fatal("wrong-owner journal accepted")
		}
	}
}

func TestRecoverRequiresConfirmationAndExactEngineOwnedJournalEntries(t *testing.T) {
	plan, now := validTestPlan()
	runner := newFakeRunner(plan)
	adapter := &Adapter{runner: runner}
	approval := mustPreflight(t, plan, adapter, now)
	requestSHA, responseSHA := approvalConsumedDigests(plan, approval)

	journal := filepath.Join(t.TempDir(), "journal.jsonl")
	initial := newJournalEntry(now, 1, plan, approval, "approval-consumed", requestSHA, responseSHA, "", nil)
	if err := CreateJournal(journal, initial); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(t.Context(), plan, approval, "", journal, adapter, advancingClock(now.Add(24*time.Hour))); err == nil {
		t.Fatal("synthetic journal recovered after expiry without explicit confirmation")
	}

	wrongInitialPath := filepath.Join(t.TempDir(), "journal.jsonl")
	wrongInitial := newJournalEntry(now, 1, plan, approval, "approval-consumed", testSHA("fabricated-initial-request"), responseSHA, "", nil)
	if err := CreateJournal(wrongInitialPath, wrongInitial); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(t.Context(), plan, approval, approval.ApprovalTuple, wrongInitialPath, adapter, advancingClock(now.Add(24*time.Hour))); err == nil {
		t.Fatal("recovery accepted fabricated self-hashed approval-consumed entry")
	}

	wrongMutationPath := filepath.Join(t.TempDir(), "journal.jsonl")
	if err := CreateJournal(wrongMutationPath, initial); err != nil {
		t.Fatal(err)
	}
	mutation := newJournalEntry(now.Add(time.Second), 2, plan, approval, "mutation-started", testSHA("fabricated-mutation-request"), testSHA("fabricated-mutation-response"), initial.EntrySHA256, nil)
	if err := AppendJournal(wrongMutationPath, mutation); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(t.Context(), plan, approval, approval.ApprovalTuple, wrongMutationPath, adapter, advancingClock(now.Add(24*time.Hour))); err == nil {
		t.Fatal("recovery accepted fabricated self-hashed mutation-started entry")
	}
}

func TestConcurrentRecoverAndStaleAppendAreLinearizable(t *testing.T) {
	t.Run("two recoveries", func(t *testing.T) {
		plan, now := validTestPlan()
		runner := newFakeRunner(plan)
		adapter := &Adapter{runner: runner}
		approval := mustPreflight(t, plan, adapter, now)
		runner.crashOnce["apply/restore-watch-create-observe-complete"] = true
		journal := filepath.Join(t.TempDir(), "journal.jsonl")
		_, _ = Apply(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Second)))
		type result struct {
			receipt ExecutionReceipt
			err     error
		}
		results := make(chan result, 2)
		for range 2 {
			go func() {
				receipt, err := Recover(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Minute)))
				results <- result{receipt, err}
			}()
		}
		first, second := <-results, <-results
		if first.err != nil || second.err != nil || first.receipt.ReceiptSHA256 != second.receipt.ReceiptSHA256 {
			t.Fatalf("concurrent recoveries diverged: %v, %v", first.err, second.err)
		}
		entries, err := LoadJournal(journal)
		if err != nil || len(entries) != len(ApplySteps) || verifyJournalBinding(plan, approval, entries) != nil {
			t.Fatalf("concurrent recovery journal corrupted: %v", err)
		}
	})

	t.Run("stale append", func(t *testing.T) {
		plan, now := validTestPlan()
		runner := newFakeRunner(plan)
		adapter := &Adapter{runner: runner}
		approval := mustPreflight(t, plan, adapter, now)
		runner.crashOnce["apply/etcd-offcell-complete"] = true
		journal := filepath.Join(t.TempDir(), "journal.jsonl")
		_, _ = Apply(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Second)))
		entries, err := LoadJournal(journal)
		if err != nil {
			t.Fatal(err)
		}
		previous := entries[len(entries)-1]
		request := newAdapterRequest(plan, approval, "apply", "etcd-offcell-complete", previous.EntrySHA256)
		response, err := adapter.invoke(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		entry := newJournalEntry(now.Add(time.Minute), len(entries)+1, plan, approval, request.Step, request.RequestSHA256, response.ResponseSHA256, previous.EntrySHA256, &response)
		results := make(chan error, 2)
		go func() { results <- AppendJournal(journal, entry) }()
		go func() { results <- AppendJournal(journal, entry) }()
		first, second := <-results, <-results
		if (first == nil) == (second == nil) {
			t.Fatalf("stale appends did not linearize: %v, %v", first, second)
		}
		after, err := LoadJournal(journal)
		if err != nil || len(after) != len(entries)+1 || verifyJournalBinding(plan, approval, after) != nil {
			t.Fatalf("stale append corrupted journal: %v", err)
		}
	})
}

func TestConcurrentRecoveryExcludesRollbackFork(t *testing.T) {
	plan, now := validTestPlan()
	runner := newFakeRunner(plan)
	adapter := &Adapter{runner: runner}
	approval := mustPreflight(t, plan, adapter, now)
	runner.crashOnce["apply/restore-watch-create-observe-complete"] = true
	journal := filepath.Join(t.TempDir(), "journal.jsonl")
	_, _ = Apply(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Second)))
	runner.blockStep = "restore-watch-create-observe-complete"
	runner.blockEntered = make(chan struct{})
	runner.blockRelease = make(chan struct{})
	recoverResult := make(chan error, 1)
	go func() {
		_, err := Recover(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Minute)))
		recoverResult <- err
	}()
	select {
	case <-runner.blockEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery did not enter locked adapter phase")
	}
	rollbackResult := make(chan error, 1)
	go func() {
		rollbackResult <- Rollback(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(2*time.Minute)))
	}()
	close(runner.blockRelease)
	if err := <-recoverResult; err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	if err := <-rollbackResult; err == nil {
		t.Fatal("rollback forked after concurrent recovery completed")
	}
	entries, err := LoadJournal(journal)
	if err != nil || entries[len(entries)-1].Step != "completed" || verifyJournalBinding(plan, approval, entries) != nil {
		t.Fatalf("recovery/rollback race corrupted journal: %v", err)
	}
}

func TestRollbackResumesDurableSafeStopWithoutApplyOrDuplicateStop(t *testing.T) {
	plan, now := validTestPlan()
	runner := newFakeRunner(plan)
	adapter := &Adapter{runner: runner}
	approval := mustPreflight(t, plan, adapter, now)
	runner.crashOnce["apply/etcd-offcell-complete"] = true
	journal := filepath.Join(t.TempDir(), "journal.jsonl")
	_, _ = Apply(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Second)))
	appendRollbackAdapterEntry(t, journal, plan, approval, adapter, "rollback-safe-stop", now.Add(time.Minute))
	requestsBefore := countAdapterStep(runner.requests, "rollback-safe-stop")
	if _, err := Recover(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(2*time.Minute))); err == nil {
		t.Fatal("Recover resumed apply after durable rollback safe-stop")
	}
	if err := Rollback(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(3*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if countAdapterStep(runner.requests, "rollback-safe-stop") != requestsBefore || countAdapterStep(runner.requests, "rollback-cleanup-requested") != 1 {
		t.Fatal("rollback resume reissued safe-stop or omitted exact cleanup")
	}
	entries, err := LoadJournal(journal)
	if err != nil || entries[len(entries)-1].Step != "rolled-back" || verifyJournalBinding(plan, approval, entries) != nil {
		t.Fatalf("resumed safe-stop journal invalid: %v", err)
	}
}

func TestRollbackResumesDurableCleanupWithoutReissuingMutation(t *testing.T) {
	plan, now := validTestPlan()
	runner := newFakeRunner(plan)
	adapter := &Adapter{runner: runner}
	approval := mustPreflight(t, plan, adapter, now)
	runner.crashOnce["apply/etcd-offcell-complete"] = true
	journal := filepath.Join(t.TempDir(), "journal.jsonl")
	_, _ = Apply(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Second)))
	appendRollbackAdapterEntry(t, journal, plan, approval, adapter, "rollback-safe-stop", now.Add(time.Minute))
	appendRollbackAdapterEntry(t, journal, plan, approval, adapter, "rollback-cleanup-requested", now.Add(2*time.Minute))
	requestsBefore := len(runner.requests)
	if err := Rollback(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(3*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if len(runner.requests) != requestsBefore {
		t.Fatal("rollback resume reissued mutation after durable cleanup response")
	}
	entries, err := LoadJournal(journal)
	if err != nil || entries[len(entries)-1].Step != "rolled-back" || verifyJournalBinding(plan, approval, entries) != nil {
		t.Fatalf("resumed cleanup journal invalid: %v", err)
	}
}

func TestConcurrentRollbackResumeIsIdempotent(t *testing.T) {
	plan, now := validTestPlan()
	runner := newFakeRunner(plan)
	adapter := &Adapter{runner: runner}
	approval := mustPreflight(t, plan, adapter, now)
	runner.crashOnce["apply/etcd-offcell-complete"] = true
	journal := filepath.Join(t.TempDir(), "journal.jsonl")
	_, _ = Apply(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Second)))
	appendRollbackAdapterEntry(t, journal, plan, approval, adapter, "rollback-safe-stop", now.Add(time.Minute))
	results := make(chan error, 2)
	for range 2 {
		go func() {
			results <- Rollback(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(2*time.Minute)))
		}()
	}
	if first, second := <-results, <-results; first != nil || second != nil {
		t.Fatalf("concurrent rollback resume was not idempotent: %v, %v", first, second)
	}
	if countAdapterStep(runner.requests, "rollback-cleanup-requested") != 1 {
		t.Fatal("concurrent rollback issued duplicate cleanup")
	}
	entries, err := LoadJournal(journal)
	if err != nil || entries[len(entries)-1].Step != "rolled-back" || verifyJournalBinding(plan, approval, entries) != nil {
		t.Fatalf("concurrent rollback journal invalid: %v", err)
	}
}

func appendRollbackAdapterEntry(t *testing.T, journal string, plan Plan, approval ApprovalReport, adapter *Adapter, step string, at time.Time) {
	t.Helper()
	entries, err := LoadJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	previous := entries[len(entries)-1]
	request := newRollbackRequest(plan, approval, step, previous.EntrySHA256)
	response, err := adapter.invoke(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	entry := newJournalEntry(at, len(entries)+1, plan, approval, step, request.RequestSHA256, response.ResponseSHA256, previous.EntrySHA256, &response)
	if err := AppendJournal(journal, entry); err != nil {
		t.Fatal(err)
	}
}

func countAdapterStep(requests []AdapterRequest, step string) int {
	count := 0
	for _, request := range requests {
		if request.Step == step {
			count++
		}
	}
	return count
}

func TestReceiptCannotBeConstructedFromPlanAlone(t *testing.T) {
	plan, now := validTestPlan()
	runner := newFakeRunner(plan)
	approval := mustPreflight(t, plan, &Adapter{runner: runner}, now)
	receipt := ExecutionReceipt{SchemaVersion: ReceiptSchemaVersion, OperationID: plan.OperationID, PlanSHA256: PlanSHA256(plan)}
	receipt.ReceiptSHA256 = ExecutionReceiptSHA256(receipt)
	if ValidateReceipt(plan, approval, receipt, nil) == nil {
		t.Fatal("plan-only receipt accepted")
	}
}

func TestPinnedExternalFakeAdapterCompletesPortableProtocol(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "fakeadapter")
	command := exec.Command("go", "build", "-o", binary, "./testdata/fakeadapter") // #nosec G204 -- fixed test-only Go tool and package; binary is beneath this test's t.TempDir and no shell is used.
	command.Dir = "."
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build external fake adapter: %v: %s", err, output)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-ambient-value-must-not-be-inherited")
	replay := newTestReplay(t)
	defer replay.Close()
	adapter, err := PinAdapter(binary, 10*time.Second, replay)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	plan, now := validTestPlan()
	plan.Adapter.ExecutableSHA256 = adapter.IdentitySHA256()
	approval := mustPreflight(t, plan, adapter, now)
	journal := filepath.Join(directory, "journal.jsonl")
	receipt, err := Apply(t.Context(), plan, approval, approval.ApprovalTuple, journal, adapter, advancingClock(now.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := LoadJournal(journal)
	if err != nil || ValidateReceipt(plan, approval, receipt, entries) != nil {
		t.Fatalf("external protocol receipt invalid: %v", err)
	}
}

func TestPinAdapterRequiresPipeBackedKubeconfig(t *testing.T) {
	if _, err := PinAdapter(filepath.Join(t.TempDir(), "missing"), time.Second, nil); err == nil {
		t.Fatal("adapter without kubeconfig replay accepted")
	}
}

func newTestReplay(t *testing.T) *kubeconfigpipe.Replay {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := writer.Write([]byte("apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n"))
		closeErr := writer.Close()
		writeDone <- errors.Join(writeErr, closeErr)
	}()
	replay, err := kubeconfigpipe.NewFromFD(int(reader.Fd()))
	closeErr := reader.Close()
	writeErr := <-writeDone
	if err != nil || closeErr != nil || writeErr != nil {
		t.Fatalf("create test replay: %v", errors.Join(err, closeErr, writeErr))
	}
	return replay
}

func newFakeRunner(plan Plan) *fakeAdapterRunner {
	return &fakeAdapterRunner{identity: plan.Adapter.ExecutableSHA256, partialOnce: map[string]bool{}, crashOnce: map[string]bool{}}
}

func mustPreflight(t *testing.T, plan Plan, adapter *Adapter, now time.Time) ApprovalReport {
	t.Helper()
	approval, err := Preflight(t.Context(), plan, adapter, now)
	if err != nil {
		t.Fatal(err)
	}
	return approval
}

func validTestPlan() (Plan, time.Time) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	// #nosec G101 -- all identifiers and digests in this plan are synthetic test data, not credential material.
	plan := Plan{
		SchemaVersion: PlanSchemaVersion, OperationID: "goal01-op", ProofID: "goal01-proof", InstallationID: "installation-a",
		AcceptedPublicSHA: "72508dd243fb0ea88dbeea4d5a63f65a8ee71244", AcceptedDownstreamSHA: strings.Repeat("b", 40), ClusterIdentitySHA256: testSHA("cluster"),
		BackupStorageLocation: StorageLocation{Name: "offcell", UIDSHA256: testSHA("bsl-uid"), Generation: 7, ConfigSHA256: testSHA("bsl-config")},
		ObjectStore:           ObjectStore{Prefix: "goal01/operation-a", MinimumRetentionDays: 30, ObjectLockMode: "compliance"},
		Tool:                  ExecutableIdentity{Name: "cloudring-backup", ExecutableSHA256: testSHA("tool")}, Adapter: ExecutableIdentity{Name: "goal01-adapter", ExecutableSHA256: testSHA("adapter")},
		Backup:                  ObjectIdentity{Kind: "Backup", Namespace: "velero", Name: "goal01-backup", ScopeSHA256: testSHA("backup-scope")},
		EtcdSandbox:             ObjectIdentity{Kind: "EtcdSandbox", Name: "goal01-etcd-sandbox", ScopeSHA256: testSHA("etcd-sandbox")},
		AggregateProofPathToken: "proof/goal01/operation-a", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano), RunNonceSHA256: testSHA("nonce"),
	}
	for _, kind := range TargetKinds {
		plan.SourceBaselines = append(plan.SourceBaselines, Baseline{Kind: kind, IdentitySHA256: testSHA(kind + "-identity"), StateSHA256: testSHA(kind + "-state"), DataSHA256: testSHA(kind + "-data")})
	}
	for _, kind := range []string{"VirtualMachineClaim", "Volume", "Namespace", "KubernetesClusterClaim"} {
		name := strings.ToLower(kind) + "-restore"
		plan.Restores = append(plan.Restores, ObjectIdentity{Kind: kind, Namespace: "velero", Name: name, ScopeSHA256: testSHA(kind + "-restore-scope")})
	}
	for _, mapping := range []struct {
		restoreIndex int
		source       string
		destination  string
	}{
		{0, "vmc-source", "isolated-vmc"},
		{1, "volume-source", "isolated-volume"},
		{2, "platform-system", "isolated-platform"},
		{2, "flux-system", "isolated-flux"},
		{3, "cluster-source", "isolated-kcc"},
	} {
		restore := plan.Restores[mapping.restoreIndex]
		plan.IsolatedNamespaces = append(plan.IsolatedNamespaces, IsolatedNamespace{
			RestoreIndex: mapping.restoreIndex, RestoreName: restore.Name, RestoreScopeSHA256: restore.ScopeSHA256, SourceNamespace: mapping.source,
			Destination: ObjectIdentity{Kind: "Namespace", Name: mapping.destination, ScopeSHA256: testSHA(mapping.destination)},
		})
		plan.CleanupTargets = append(plan.CleanupTargets, CleanupTarget{Kind: "Namespace", Name: mapping.destination, PreconditionIdentitySHA256: testSHA(mapping.destination + "-uid")})
	}
	plan.CleanupTargets = append(plan.CleanupTargets, CleanupTarget{Kind: "EtcdSandbox", Name: plan.EtcdSandbox.Name, PreconditionIdentitySHA256: testSHA("etcd-sandbox-uid")})
	return plan, now
}

func testSHA(value string) string { return digest(struct{ Value string }{value}) }
func advancingClock(start time.Time) Clock {
	current := start.Add(-time.Second)
	return func() time.Time { current = current.Add(time.Second); return current }
}
func slicesContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func forbiddenCredentialField() string { return string([]byte{115, 101, 99, 114, 101, 116}) }
