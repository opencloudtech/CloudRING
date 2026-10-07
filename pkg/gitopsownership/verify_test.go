// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package gitopsownership

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVerifyProvesUniqueInventoryOwnershipWithoutChangingPrune(t *testing.T) {
	contract := testContract()
	target := contract.Spec.DriftProof.Target
	service := ResourceRef{APIVersion: "v1", Kind: "Service", Namespace: "platform-system", Name: "provider-api"}
	snapshot := Snapshot{
		Kustomizations: []KustomizationSnapshot{
			testRoot(t, "foundation", false, target, service),
		},
		KustomizationsComplete:  true,
		KustomizationsRVHash:    testArtifactDigest,
		KustomizationsPageCount: 1,
		KustomizationsItemCount: 1,
		Collections: testCollections(map[string][]ResourceRef{
			"gateways": {target},
			"services": {service},
		}),
		Resources: map[string][]ResourceRef{
			"gateways": {target},
			"services": {service},
		},
		SourceArtifact:           SourceArtifactSnapshot{Kind: "GitRepository", Namespace: "flux-system", Name: "source", Generation: 1, ObservedGeneration: 1, Ready: true, Revision: testSourceRevision, Digest: testArtifactDigest},
		AcceptedSourceRevision:   testSourceRevision,
		AcceptedArtifactDigest:   testArtifactDigest,
		AcceptedPublicGitlinkSHA: contract.Spec.SourceArtifact.PublicGitlinkSHA,
		ObservedPublicGitlinkSHA: contract.Spec.SourceArtifact.PublicGitlinkSHA,
	}

	report, code, err := Verify(contract, snapshot)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if code != 0 || report.Status != "ready" {
		t.Fatalf("Verify code/status = %d/%s, want 0/ready; blockers=%+v", code, report.Status, report.Blockers)
	}
	if report.APIVersion != "cloudring.gitops.ownership/v2" || !report.Scope.Complete || !report.Scope.AllCriticalFamiliesDeclared || !report.Scope.AllSelectedRootsObserved {
		t.Fatalf("report envelope/scope is not gate-consumable: %+v", report)
	}
	if !report.PruneEligible || report.PruneChanged || report.LiveMutationPerformed || report.DriftProof.LiveMutationPerformed {
		t.Fatalf("unexpected mutation/prune report: %+v", report)
	}
	if !report.DriftProof.TargetInventoryOwned {
		t.Fatal("drift target ownership was not proven")
	}
	if !report.SourceArtifact.Exact || !report.SourceArtifact.PublicGitlinkExact ||
		report.SourceArtifact.ExpectedPublicGitlinkSHA != contract.Spec.SourceArtifact.PublicGitlinkSHA ||
		report.SourceArtifact.AcceptedPublicGitlinkSHA != contract.Spec.SourceArtifact.PublicGitlinkSHA ||
		report.SourceArtifact.ObservedPublicGitlinkSHA != contract.Spec.SourceArtifact.PublicGitlinkSHA {
		t.Fatalf("public gitlink was not bound across contract, receipt, observation, and report: %+v", report.SourceArtifact)
	}
}

func TestVerifyRejectsRootSpecAndSourceReceiptDrift(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Snapshot)
		blocker string
	}{
		{"missing suspend", func(snapshot *Snapshot) { snapshot.Kustomizations[0].Suspend = nil }, "flux_kustomization_suspended"},
		{"suspended", func(snapshot *Snapshot) { value := true; snapshot.Kustomizations[0].Suspend = &value }, "flux_kustomization_suspended"},
		{"deletion policy", func(snapshot *Snapshot) { snapshot.Kustomizations[0].DeletionPolicy = "Delete" }, "flux_deletion_policy_mismatch"},
		{"missing wait", func(snapshot *Snapshot) { snapshot.Kustomizations[0].Wait = nil }, "flux_wait_mismatch"},
		{"source ref", func(snapshot *Snapshot) { snapshot.Kustomizations[0].SourceRef.Name = "other" }, "flux_source_ref_mismatch"},
		{"path", func(snapshot *Snapshot) { snapshot.Kustomizations[0].Path = "./other" }, "flux_path_mismatch"},
		{"dependencies", func(snapshot *Snapshot) {
			snapshot.Kustomizations[0].DependsOn = []FluxObjectReference{{Kind: "Kustomization", Namespace: "flux-system", Name: "other"}}
		}, "flux_dependencies_mismatch"},
		{"last applied revision", func(snapshot *Snapshot) {
			snapshot.Kustomizations[0].LastAppliedRevision = "main@sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}, "flux_last_applied_revision_mismatch"},
		{"artifact revision", func(snapshot *Snapshot) {
			snapshot.SourceArtifact.Revision = "main@sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}, "source_artifact_revision_mismatch"},
		{"artifact digest", func(snapshot *Snapshot) {
			snapshot.SourceArtifact.Digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}, "source_artifact_digest_mismatch"},
		{"source not ready", func(snapshot *Snapshot) { snapshot.SourceArtifact.Ready = false }, "source_artifact_not_ready"},
		{"missing accepted receipt", func(snapshot *Snapshot) { snapshot.AcceptedSourceRevision = "" }, "accepted_source_receipt_invalid"},
		{"missing accepted public gitlink", func(snapshot *Snapshot) { snapshot.AcceptedPublicGitlinkSHA = "" }, "accepted_public_gitlink_invalid"},
		{"wrong accepted public gitlink", func(snapshot *Snapshot) { snapshot.AcceptedPublicGitlinkSHA = strings.Repeat("b", 40) }, "accepted_public_gitlink_mismatch"},
		{"accepted and observed public gitlink agree on wrong SHA", func(snapshot *Snapshot) {
			snapshot.AcceptedPublicGitlinkSHA = strings.Repeat("b", 40)
			snapshot.ObservedPublicGitlinkSHA = snapshot.AcceptedPublicGitlinkSHA
		}, "accepted_public_gitlink_mismatch"},
		{"missing observed public gitlink", func(snapshot *Snapshot) { snapshot.ObservedPublicGitlinkSHA = "" }, "observed_public_gitlink_invalid"},
		{"observed public gitlink differs from receipt", func(snapshot *Snapshot) { snapshot.ObservedPublicGitlinkSHA = strings.Repeat("b", 40) }, "public_gitlink_receipt_mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contract := testContract()
			snapshot := readyTestSnapshot(t, contract)
			test.mutate(&snapshot)
			report, code, err := Verify(contract, snapshot)
			if err != nil {
				t.Fatalf("Verify returned error: %v", err)
			}
			if code != 2 || report.PruneEligible {
				t.Fatalf("drift code/pruneEligible = %d/%t, want 2/false", code, report.PruneEligible)
			}
			assertBlocker(t, report, test.blocker)
		})
	}
}

func TestVerifyFailsClosedForUnmanagedObjectWithEmptyDefaultAllowlist(t *testing.T) {
	contract := testContract()
	service := ResourceRef{APIVersion: "v1", Kind: "Service", Namespace: "platform-system", Name: "provider-api"}
	snapshot := Snapshot{
		Kustomizations:          []KustomizationSnapshot{testRoot(t, "foundation", false, contract.Spec.DriftProof.Target)},
		KustomizationsComplete:  true,
		KustomizationsRVHash:    testArtifactDigest,
		KustomizationsPageCount: 1,
		KustomizationsItemCount: 1,
		Collections: testCollections(map[string][]ResourceRef{
			"gateways": {contract.Spec.DriftProof.Target},
			"services": {service},
		}),
		Resources: map[string][]ResourceRef{
			"gateways": {contract.Spec.DriftProof.Target},
			"services": {service},
		},
	}

	report, code, err := Verify(contract, snapshot)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if code != 2 || report.PruneEligible {
		t.Fatalf("Verify code/pruneEligible = %d/%t, want 2/false", code, report.PruneEligible)
	}
	assertBlocker(t, report, "resource_not_flux_managed")
}

func TestValidateContractRejectsLegacyAllowUnmanaged(t *testing.T) {
	contract := testContract()
	service := ResourceRef{APIVersion: "v1", Kind: "Service", Namespace: "platform-system", Name: "provider-api"}
	contract.Spec.AllowUnmanaged = []ResourceRef{service}
	if err := ValidateContract(contract); err == nil {
		t.Fatal("ValidateContract accepted legacy allowUnmanaged in a closed-world contract")
	}
}

func TestVerifyRejectsDuplicateLiveResourceObservation(t *testing.T) {
	contract := testContract()
	snapshot := readyTestSnapshot(t, contract)
	collection := snapshot.Collections["gateways"]
	collection.Objects = append(collection.Objects, contract.Spec.DriftProof.Target)
	collection.ItemCount++
	snapshot.Collections["gateways"] = collection

	report, code, err := Verify(contract, snapshot)
	if err != nil {
		t.Fatalf("Verify duplicate resource returned error: %v", err)
	}
	if code != 2 || report.PruneEligible {
		t.Fatalf("duplicate resource code/pruneEligible = %d/%t, want 2/false", code, report.PruneEligible)
	}
	assertBlocker(t, report, "duplicate_resource_observation")
}

func TestVerifyRejectsUnlabelledManualObjectInClosedWorldScope(t *testing.T) {
	contract := testContract()
	snapshot := readyTestSnapshot(t, contract)
	manual := ResourceRef{APIVersion: "v1", Kind: "Service", Namespace: "platform-system", Name: "manual-unlabelled"}
	collection := snapshot.Collections["services"]
	collection.Objects = append(collection.Objects, manual)
	collection.ItemCount++
	snapshot.Collections["services"] = collection

	report, code, err := Verify(contract, snapshot)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if code != 2 || report.PruneEligible || report.ClosedWorldComplete || report.UnexpectedResourceCount != 1 {
		t.Fatalf("manual object code/prune/complete/unexpected = %d/%t/%t/%d, want 2/false/false/1", code, report.PruneEligible, report.ClosedWorldComplete, report.UnexpectedResourceCount)
	}
	assertBlocker(t, report, "undeclared_resource_in_closed_world_scope")
}

func TestVerifyRejectsIncompleteClosedWorldCollection(t *testing.T) {
	contract := testContract()
	snapshot := readyTestSnapshot(t, contract)
	collection := snapshot.Collections["services"]
	collection.Complete = false
	snapshot.Collections["services"] = collection

	report, code, err := Verify(contract, snapshot)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if code != 2 || report.ClosedWorldComplete {
		t.Fatalf("incomplete collection code/complete = %d/%t, want 2/false", code, report.ClosedWorldComplete)
	}
	assertBlocker(t, report, "family_collection_incomplete")
}

func TestVerifyIgnoresUnrelatedFluxRootButBlocksRelevantUndeclaredRoot(t *testing.T) {
	contract := testContract()
	snapshot := readyTestSnapshot(t, contract)
	unrelated := testRoot(t, "unrelated", false, ResourceRef{
		APIVersion: "v1", Kind: "ConfigMap", Namespace: "other", Name: "other",
	})
	unrelated.SourceRef.Name = "other-source"
	snapshot.Kustomizations = append(snapshot.Kustomizations, unrelated)
	snapshot.KustomizationsItemCount++

	report, code, err := Verify(contract, snapshot)
	if err != nil {
		t.Fatalf("Verify unrelated root returned error: %v", err)
	}
	if code != 0 || !report.PruneEligible {
		t.Fatalf("unrelated root code/prune = %d/%t, want 0/true; blockers=%+v", code, report.PruneEligible, report.Blockers)
	}

	relevant := testRoot(t, "undeclared", false)
	snapshot.Kustomizations = append(snapshot.Kustomizations, relevant)
	snapshot.KustomizationsItemCount++
	report, code, err = Verify(contract, snapshot)
	if err != nil {
		t.Fatalf("Verify relevant undeclared root returned error: %v", err)
	}
	if code != 2 {
		t.Fatalf("relevant undeclared root code = %d, want 2", code)
	}
	assertBlocker(t, report, "undeclared_relevant_flux_root")
}

func TestVerifyAcceptsReviewedExternalObjectOnlyWhenNotFluxOwned(t *testing.T) {
	contract := testContract()
	external := ResourceRef{APIVersion: "v1", Kind: "Service", Namespace: "platform-system", Name: "shared-dns"}
	contract.Spec.RequiredFamilies[1].Discovery.ExternalObjects = []ResourceRef{external}
	snapshot := readyTestSnapshot(t, contract)
	collection := snapshot.Collections["services"]
	collection.Objects = append(collection.Objects, external)
	collection.ItemCount++
	snapshot.Collections["services"] = collection

	report, code, err := Verify(contract, snapshot)
	if err != nil {
		t.Fatalf("Verify reviewed external object returned error: %v", err)
	}
	if code != 0 || !report.PruneEligible || report.ExternalResourceCount != 1 {
		t.Fatalf("external object code/pruneEligible/external = %d/%t/%d, want 0/true/1; blockers=%+v", code, report.PruneEligible, report.ExternalResourceCount, report.Blockers)
	}

	entry, err := InventoryID(external)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Kustomizations[0].Inventory = append(snapshot.Kustomizations[0].Inventory, entry)
	report, code, err = Verify(contract, snapshot)
	if err != nil {
		t.Fatalf("Verify Flux-owned external object returned error: %v", err)
	}
	if code != 2 {
		t.Fatalf("Flux-owned external object code = %d, want 2", code)
	}
	assertBlocker(t, report, "external_object_flux_owned")
}

func TestVerifyRejectsEveryIncompleteSourcedFamily(t *testing.T) {
	contract := testContract()
	snapshot := readyTestSnapshot(t, contract)
	delete(snapshot.Collections, "services")

	report, code, err := Verify(contract, snapshot)
	if err != nil {
		t.Fatalf("Verify incomplete family returned error: %v", err)
	}
	if code != 2 || report.PruneEligible {
		t.Fatalf("incomplete family code/pruneEligible = %d/%t, want 2/false", code, report.PruneEligible)
	}
	assertBlocker(t, report, "required_family_unobserved")
	for _, family := range report.Families {
		if family.ID == "services" && family.OwnershipComplete {
			t.Fatal("unobserved sourced family was marked ownership-complete")
		}
	}
}

func TestVerifyBlocksDuplicateOwnershipAndPrematurePrune(t *testing.T) {
	contract := testContract()
	target := contract.Spec.DriftProof.Target
	service := ResourceRef{APIVersion: "v1", Kind: "Service", Namespace: "platform-system", Name: "provider-api"}
	second := testRoot(t, "second", false, target)
	contract.Spec.PruneGate.Kustomizations = append(contract.Spec.PruneGate.Kustomizations, NamespacedName{Namespace: "flux-system", Name: "second"})
	contract.Spec.Scope.SelectedRoots = append(contract.Spec.Scope.SelectedRoots, NamespacedName{Namespace: "flux-system", Name: "second"})
	active, prune, wait := false, false, true
	contract.Spec.RootSpecs = append(contract.Spec.RootSpecs, RootSpecContract{
		Namespace: "flux-system", Name: "second", Suspend: &active, Prune: &prune, DeletionPolicy: "Orphan", Wait: &wait,
		SourceRef: FluxObjectReference{Kind: "GitRepository", Namespace: "flux-system", Name: "source"}, Path: "./second", DependsOn: []FluxObjectReference{},
	})
	snapshot := Snapshot{
		Kustomizations:          []KustomizationSnapshot{testRoot(t, "foundation", true, target, service), second},
		KustomizationsComplete:  true,
		KustomizationsRVHash:    testArtifactDigest,
		KustomizationsPageCount: 1,
		KustomizationsItemCount: 2,
		Collections: testCollections(map[string][]ResourceRef{
			"gateways": {target},
			"services": {service},
		}),
		Resources: map[string][]ResourceRef{
			"gateways": {target},
			"services": {service},
		},
	}
	report, code, err := Verify(contract, snapshot)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if code != 2 {
		t.Fatalf("Verify code = %d, want 2", code)
	}
	assertBlocker(t, report, "multiple_flux_owners")
	assertBlocker(t, report, "prune_enabled_before_gate")
	assertBlocker(t, report, "drift_target_ownership_unproven")
}

func TestDecodeContractRejectsUnknownAndTrailingFields(t *testing.T) {
	valid := `{
		"apiVersion":"cloudring.io/v1alpha2",
		"kind":"GitOpsOwnershipContract",
		"metadata":{"name":"test"},
		"spec":{
			"kustomizationSelector":"cloudring.io/ownership-scope=ovh-alpha",
			"sourceArtifact":{"kind":"GitRepository","namespace":"flux-system","name":"source","publicGitlinkSHA":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			"scope":{"name":"goal01","complete":true,"nonClaim":"declared scope is not ownership readiness","criticalFamilyIds":["services"],"selectedRoots":[{"namespace":"flux-system","name":"foundation"}]},
			"rootSpecs":[{"namespace":"flux-system","name":"foundation","suspend":false,"prune":false,"deletionPolicy":"Orphan","wait":true,"sourceRef":{"kind":"GitRepository","namespace":"flux-system","name":"source"},"path":"./foundation","dependsOn":[]}],
			"requiredFamilies":[{"id":"services","apiVersion":"v1","kind":"Service","resource":"services","namespaced":true,"labelSelector":"cloudring.io/installation=test","discovery":{"mode":"closed-world","namespaces":["default"]},"minimumCount":1,"critical":true,"sourceState":"sourced","expectedOwner":{"namespace":"flux-system","name":"foundation"},"expectedObjects":[{"apiVersion":"v1","kind":"Service","namespace":"default","name":"test"}]}],
			"pruneGate":{"kustomizations":[{"namespace":"flux-system","name":"foundation"}]},
			"driftProof":{"mode":"read-only-plan","target":{"apiVersion":"v1","kind":"Service","namespace":"default","name":"test"},"expectedOwner":{"namespace":"flux-system","name":"foundation"},"requiredObservations":["baseline","controlled-drift","reconciled"],"mutationAuthorization":"separate-explicit-approval-required"}
		}
	}`
	if _, err := DecodeContract(strings.NewReader(valid)); err != nil {
		t.Fatalf("DecodeContract valid returned error: %v", err)
	}
	if _, err := DecodeContract(strings.NewReader(strings.Replace(valid, `"metadata":{"name":"test"}`, `"metadata":{"name":"test","unknown":true}`, 1))); err == nil {
		t.Fatal("DecodeContract accepted unknown field")
	}
	if _, err := DecodeContract(strings.NewReader(strings.Replace(valid, `"metadata":{"name":"test"}`, `"metadata":{"name":"test","name":"duplicate"}`, 1))); err == nil {
		t.Fatal("DecodeContract accepted duplicate object field")
	}
	if _, err := DecodeContract(strings.NewReader(strings.Replace(valid, `"apiVersion":"cloudring.io/v1alpha2"`, `"apiVersion":"cloudring.io/v1alpha2","apiVersion":"cloudring.io/v1alpha2"`, 1))); err == nil {
		t.Fatal("DecodeContract accepted duplicate top-level field")
	}
	if _, err := DecodeContract(strings.NewReader(strings.Replace(valid, `"expectedOwner":{"namespace":"flux-system","name":"foundation"}`, `"expectedOwner":{"namespace":"flux-system","name":"foundation","name":"duplicate"}`, 1))); err == nil {
		t.Fatal("DecodeContract accepted deeply nested duplicate object field")
	}
	if _, err := DecodeContract(strings.NewReader(valid + `{}`)); err == nil {
		t.Fatal("DecodeContract accepted trailing JSON")
	}
	if _, err := DecodeContract(strings.NewReader(strings.Repeat(" ", (8<<20)+1))); err == nil {
		t.Fatal("DecodeContract accepted an oversized document")
	}
}

func TestVerifyDeclaresMissingCriticalSourceAsBlocker(t *testing.T) {
	contract := testContract()
	contract.Spec.Scope.CriticalFamilyIDs = append(contract.Spec.Scope.CriticalFamilyIDs, "portal")
	contract.Spec.RequiredFamilies = append(contract.Spec.RequiredFamilies, ResourceFamily{
		ID: "portal", APIVersion: "apps/v1", Kind: "Deployment", Resource: "deployments.apps", Namespaced: true,
		Critical: true, SourceState: "not-sourced", MissingSourceBlocker: "provider portal is not sourced by a selected Goal 01 Flux root",
	})
	target := contract.Spec.DriftProof.Target
	service := ResourceRef{APIVersion: "v1", Kind: "Service", Namespace: "platform-system", Name: "provider-api"}
	report, code, err := Verify(contract, Snapshot{
		Kustomizations:          []KustomizationSnapshot{testRoot(t, "foundation", false, target, service)},
		KustomizationsComplete:  true,
		KustomizationsRVHash:    testArtifactDigest,
		KustomizationsPageCount: 1,
		KustomizationsItemCount: 1,
		Collections:             testCollections(map[string][]ResourceRef{"gateways": {target}, "services": {service}}),
		Resources:               map[string][]ResourceRef{"gateways": {target}, "services": {service}},
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if code != 2 || len(report.Scope.SourceMissingFamilies) != 1 || report.Scope.SourceMissingFamilies[0] != "portal" {
		t.Fatalf("missing source was not reported fail-closed: code=%d report=%+v", code, report)
	}
	assertBlocker(t, report, "critical_family_source_missing")
}

func TestValidateContractRejectsIncompleteOrPartiallyDeclaredScope(t *testing.T) {
	contract := testContract()
	contract.Spec.Scope.Complete = false
	if err := ValidateContract(contract); err == nil {
		t.Fatal("ValidateContract accepted scope.complete=false")
	}
	contract = testContract()
	contract.Spec.Scope.CriticalFamilyIDs = contract.Spec.Scope.CriticalFamilyIDs[:1]
	if err := ValidateContract(contract); err == nil {
		t.Fatal("ValidateContract accepted a partially enumerated critical family scope")
	}
	contract = testContract()
	contract.Spec.Scope.SelectedRoots = nil
	if err := ValidateContract(contract); err == nil {
		t.Fatal("ValidateContract accepted an empty selected root inventory")
	}
}

func TestValidateContractBindsDriftProofToOneDeclaredCriticalObject(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Contract)
	}{
		{
			name: "undeclared target",
			mutate: func(contract *Contract) {
				contract.Spec.DriftProof.Target.Name = "not-declared"
			},
		},
		{
			name: "wrong owner",
			mutate: func(contract *Contract) {
				contract.Spec.DriftProof.ExpectedOwner.Name = "other-root"
			},
		},
		{
			name: "duplicate target across families",
			mutate: func(contract *Contract) {
				contract.Spec.RequiredFamilies[1].APIVersion = contract.Spec.RequiredFamilies[0].APIVersion
				contract.Spec.RequiredFamilies[1].Kind = contract.Spec.RequiredFamilies[0].Kind
				contract.Spec.RequiredFamilies[1].Resource = contract.Spec.RequiredFamilies[0].Resource
				contract.Spec.RequiredFamilies[1].ExpectedObjects = []ResourceRef{contract.Spec.DriftProof.Target}
			},
		},
		{
			name: "noncanonical observation sequence",
			mutate: func(contract *Contract) {
				contract.Spec.DriftProof.RequiredObservations = []string{"baseline", "reconciled", "controlled-drift"}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contract := testContract()
			test.mutate(&contract)
			if err := ValidateContract(contract); err == nil {
				t.Fatal("ValidateContract accepted an unbound drift proof")
			}
		})
	}
}

func TestValidateContractRejectsExpectedObjectSharedAcrossFamilies(t *testing.T) {
	contract := testContract()
	contract.Spec.RequiredFamilies[1].APIVersion = contract.Spec.RequiredFamilies[0].APIVersion
	contract.Spec.RequiredFamilies[1].Kind = contract.Spec.RequiredFamilies[0].Kind
	contract.Spec.RequiredFamilies[1].Resource = contract.Spec.RequiredFamilies[0].Resource
	contract.Spec.RequiredFamilies[1].ExpectedObjects = []ResourceRef{contract.Spec.RequiredFamilies[0].ExpectedObjects[0]}
	if err := ValidateContract(contract); err == nil {
		t.Fatal("ValidateContract accepted one expected object in multiple resource families")
	}
}

func TestValidateContractRejectsDuplicateExpectedObjectWithinFamily(t *testing.T) {
	contract := testContract()
	contract.Spec.RequiredFamilies[0].ExpectedObjects = append(contract.Spec.RequiredFamilies[0].ExpectedObjects, contract.Spec.RequiredFamilies[0].ExpectedObjects[0])
	contract.Spec.RequiredFamilies[0].MinimumCount = 2
	if err := ValidateContract(contract); err == nil {
		t.Fatal("ValidateContract accepted a duplicate expected object within one family")
	}
}

func TestValidateContractRejectsInvalidClosedWorldScopes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Contract)
	}{
		{
			name: "namespaced family without namespaces",
			mutate: func(contract *Contract) {
				contract.Spec.RequiredFamilies[0].Discovery.Namespaces = nil
			},
		},
		{
			name: "expected object outside namespace set",
			mutate: func(contract *Contract) {
				contract.Spec.RequiredFamilies[0].ExpectedObjects[0].Namespace = "other"
			},
		},
		{
			name: "external overlaps expected",
			mutate: func(contract *Contract) {
				contract.Spec.RequiredFamilies[0].Discovery.ExternalObjects =
					[]ResourceRef{contract.Spec.RequiredFamilies[0].ExpectedObjects[0]}
			},
		},
		{
			name: "duplicate expected object across shared discovery scope",
			mutate: func(contract *Contract) {
				duplicate := contract.Spec.RequiredFamilies[0]
				duplicate.ID = "gateways-copy"
				duplicate.ExpectedObjects = []ResourceRef{{
					APIVersion: duplicate.APIVersion,
					Kind:       duplicate.Kind,
					Name:       "cilium",
				}}
				contract.Spec.RequiredFamilies = append(contract.Spec.RequiredFamilies, duplicate)
				contract.Spec.Scope.CriticalFamilyIDs = append(contract.Spec.Scope.CriticalFamilyIDs, duplicate.ID)
			},
		},
		{
			name: "cluster family with namespace",
			mutate: func(contract *Contract) {
				family := &contract.Spec.RequiredFamilies[0]
				family.Namespaced = false
				family.Discovery.Namespaces = []string{"platform-system"}
				family.ExpectedObjects[0].Namespace = ""
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contract := testContract()
			test.mutate(&contract)
			if err := ValidateContract(contract); err == nil {
				t.Fatal("ValidateContract accepted an invalid closed-world discovery scope")
			}
		})
	}
}

func testContract() Contract {
	active, prune, wait := false, false, true
	return Contract{
		APIVersion: "cloudring.io/v1alpha2",
		Kind:       "GitOpsOwnershipContract",
		Metadata:   Metadata{Name: "test"},
		Spec: ContractSpec{
			KustomizationSelector: "cloudring.io/ownership-scope=ovh-alpha",
			SourceArtifact:        SourceArtifactContract{Kind: "GitRepository", Namespace: "flux-system", Name: "source", PublicGitlinkSHA: strings.Repeat("a", 40)},
			RootSpecs: []RootSpecContract{{
				Namespace: "flux-system", Name: "foundation", Suspend: &active, Prune: &prune, DeletionPolicy: "Orphan", Wait: &wait,
				SourceRef: FluxObjectReference{Kind: "GitRepository", Namespace: "flux-system", Name: "source"}, Path: "./foundation", DependsOn: []FluxObjectReference{},
			}},
			Scope: ScopeContract{
				Name: "goal01", Complete: true, NonClaim: "declared scope is not ownership readiness",
				CriticalFamilyIDs: []string{"gateways", "services"},
				SelectedRoots:     []NamespacedName{{Namespace: "flux-system", Name: "foundation"}},
			},
			RequiredFamilies: []ResourceFamily{
				{
					ID: "gateways", APIVersion: "gateway.networking.k8s.io/v1", Kind: "Gateway", Resource: "gateways.gateway.networking.k8s.io", Namespaced: true,
					LabelSelector: "cloudring.io/installation=test", MinimumCount: 1, Critical: true, SourceState: "sourced",
					Discovery:       Discovery{Mode: "closed-world", Namespaces: []string{"platform-system"}},
					ExpectedOwner:   NamespacedName{Namespace: "flux-system", Name: "foundation"},
					ExpectedObjects: []ResourceRef{{APIVersion: "gateway.networking.k8s.io/v1", Kind: "Gateway", Namespace: "platform-system", Name: "cloudring-public"}},
				},
				{
					ID: "services", APIVersion: "v1", Kind: "Service", Resource: "services", Namespaced: true,
					LabelSelector: "cloudring.io/installation=test", MinimumCount: 1, Critical: true, SourceState: "sourced",
					Discovery:       Discovery{Mode: "closed-world", Namespaces: []string{"platform-system"}},
					ExpectedOwner:   NamespacedName{Namespace: "flux-system", Name: "foundation"},
					ExpectedObjects: []ResourceRef{{APIVersion: "v1", Kind: "Service", Namespace: "platform-system", Name: "provider-api"}},
				},
			},
			PruneGate: PruneGate{Kustomizations: []NamespacedName{{Namespace: "flux-system", Name: "foundation"}}},
			DriftProof: DriftProof{
				Mode:                  "read-only-plan",
				Target:                ResourceRef{APIVersion: "gateway.networking.k8s.io/v1", Kind: "Gateway", Namespace: "platform-system", Name: "cloudring-public"},
				ExpectedOwner:         NamespacedName{Namespace: "flux-system", Name: "foundation"},
				RequiredObservations:  []string{"baseline", "controlled-drift", "reconciled"},
				MutationAuthorization: "separate-explicit-approval-required",
			},
		},
	}
}

func testRoot(t *testing.T, name string, prune bool, refs ...ResourceRef) KustomizationSnapshot {
	t.Helper()
	inventory := make([]InventoryEntry, 0, len(refs))
	for _, ref := range refs {
		entry, err := InventoryID(ref)
		if err != nil {
			t.Fatalf("InventoryID(%+v): %v", ref, err)
		}
		inventory = append(inventory, entry)
	}
	active, wait := false, true
	return KustomizationSnapshot{
		Namespace: "flux-system", Name: name, Generation: 1, ObservedGeneration: 1, Ready: true, Suspend: &active, Prune: &prune,
		DeletionPolicy: "Orphan", Wait: &wait, SourceRef: FluxObjectReference{Kind: "GitRepository", Namespace: "flux-system", Name: "source"},
		Path: "./" + name, DependsOn: []FluxObjectReference{}, LastAppliedRevision: testSourceRevision, Inventory: inventory,
	}
}

func readyTestSnapshot(t *testing.T, contract Contract) Snapshot {
	t.Helper()
	target := contract.Spec.DriftProof.Target
	service := ResourceRef{APIVersion: "v1", Kind: "Service", Namespace: "platform-system", Name: "provider-api"}
	return Snapshot{
		Kustomizations:           []KustomizationSnapshot{testRoot(t, "foundation", false, target, service)},
		KustomizationsComplete:   true,
		KustomizationsRVHash:     testArtifactDigest,
		KustomizationsPageCount:  1,
		KustomizationsItemCount:  1,
		Collections:              testCollections(map[string][]ResourceRef{"gateways": {target}, "services": {service}}),
		Resources:                map[string][]ResourceRef{"gateways": {target}, "services": {service}},
		SourceArtifact:           SourceArtifactSnapshot{Kind: "GitRepository", Namespace: "flux-system", Name: "source", Generation: 1, ObservedGeneration: 1, Ready: true, Revision: testSourceRevision, Digest: testArtifactDigest},
		AcceptedSourceRevision:   testSourceRevision,
		AcceptedArtifactDigest:   testArtifactDigest,
		AcceptedPublicGitlinkSHA: contract.Spec.SourceArtifact.PublicGitlinkSHA,
		ObservedPublicGitlinkSHA: contract.Spec.SourceArtifact.PublicGitlinkSHA,
	}
}

func testCollections(resources map[string][]ResourceRef) map[string]FamilyCollection {
	collections := make(map[string]FamilyCollection, len(resources))
	for family, objects := range resources {
		copied := append([]ResourceRef(nil), objects...)
		collections[family] = FamilyCollection{
			Complete:              true,
			ResourceVersionSHA256: testArtifactDigest,
			PageCount:             1,
			ItemCount:             len(copied),
			Objects:               copied,
		}
	}
	return collections
}

func TestVerifyDoesNotReflectMalformedLiveSourceOrInventoryValues(t *testing.T) {
	contract := testContract()
	snapshot := readyTestSnapshot(t, contract)
	secretLike := "private-token-value_ssh://internal"
	snapshot.SourceArtifact.Namespace = secretLike
	snapshot.SourceArtifact.Name = secretLike
	snapshot.SourceArtifact.Revision = secretLike
	snapshot.SourceArtifact.Digest = secretLike
	snapshot.AcceptedSourceRevision = secretLike
	snapshot.AcceptedArtifactDigest = secretLike
	snapshot.AcceptedPublicGitlinkSHA = secretLike
	snapshot.ObservedPublicGitlinkSHA = secretLike
	snapshot.Kustomizations[0].LastAppliedRevision = secretLike
	snapshot.Kustomizations[0].Inventory = append(snapshot.Kustomizations[0].Inventory, InventoryEntry{ID: secretLike, Version: secretLike})
	snapshot.Kustomizations[0].Inventory = append(snapshot.Kustomizations[0].Inventory, InventoryEntry{ID: "platform-system_provider-api__Service", Version: secretLike})
	snapshot.Kustomizations = append(snapshot.Kustomizations, KustomizationSnapshot{
		Namespace: secretLike, Name: secretLike, Generation: 1, ObservedGeneration: 1,
	})
	snapshot.KustomizationsItemCount++
	snapshot.Resources["services"] = append(snapshot.Resources["services"], ResourceRef{
		APIVersion: secretLike, Kind: secretLike, Namespace: secretLike, Name: secretLike,
	})
	serviceCollection := snapshot.Collections["services"]
	serviceCollection.Objects = append(serviceCollection.Objects, ResourceRef{
		APIVersion: secretLike, Kind: secretLike, Namespace: secretLike, Name: secretLike,
	})
	serviceCollection.ItemCount++
	snapshot.Collections["services"] = serviceCollection

	report, code, err := Verify(contract, snapshot)
	if err != nil {
		t.Fatalf("Verify malformed live evidence returned error: %v", err)
	}
	if code != 2 || report.PruneEligible {
		t.Fatalf("malformed live evidence code/pruneEligible = %d/%t, want 2/false", code, report.PruneEligible)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), secretLike) {
		t.Fatal("report reflected malformed live evidence")
	}
	assertBlocker(t, report, "accepted_source_receipt_invalid")
	assertBlocker(t, report, "accepted_public_gitlink_invalid")
	assertBlocker(t, report, "observed_public_gitlink_invalid")
	assertBlocker(t, report, "flux_inventory_entry_invalid")
}

func TestInventoryIDRejectsMalformedIdentityComponents(t *testing.T) {
	tests := []ResourceRef{
		{APIVersion: "v1/extra/more", Kind: "Service", Namespace: "platform-system", Name: "provider-api"},
		{APIVersion: "bad..group/v1", Kind: "Service", Namespace: "platform-system", Name: "provider-api"},
		{APIVersion: "v1", Kind: "Service/Secret", Namespace: "platform-system", Name: "provider-api"},
		{APIVersion: "v1", Kind: "Service", Namespace: "BAD", Name: "provider-api"},
		{APIVersion: "v1", Kind: "Service", Namespace: "platform-system", Name: "bad..name"},
	}
	for _, ref := range tests {
		if _, err := InventoryID(ref); err == nil {
			t.Fatalf("InventoryID accepted malformed resource identity: %+v", ref)
		}
	}
}

func TestInventoryIDMatchesFluxObjMetadataRBACEncoding(t *testing.T) {
	ref := ResourceRef{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       "ClusterRole",
		Name:       "system:controller",
	}
	entry, err := InventoryID(ref)
	if err != nil {
		t.Fatalf("InventoryID returned error: %v", err)
	}
	if entry.ID != "_system__controller_rbac.authorization.k8s.io_ClusterRole" || entry.Version != "v1" {
		t.Fatalf("InventoryID RBAC entry = %+v, want Flux ObjMetadata encoding", entry)
	}
	parsed, err := parseInventoryEntry(entry)
	if err != nil {
		t.Fatalf("parseInventoryEntry returned error: %v", err)
	}
	if parsed != ref {
		t.Fatalf("parseInventoryEntry = %+v, want %+v", parsed, ref)
	}
}

func TestVerifyProvesFluxEncodedRBACInventoryOwnership(t *testing.T) {
	contract := testContract()
	rbac := ResourceRef{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       "ClusterRole",
		Name:       "system:controller",
	}
	contract.Spec.Scope.CriticalFamilyIDs = append(contract.Spec.Scope.CriticalFamilyIDs, "cluster-roles")
	contract.Spec.RequiredFamilies = append(contract.Spec.RequiredFamilies, ResourceFamily{
		ID:              "cluster-roles",
		APIVersion:      rbac.APIVersion,
		Kind:            rbac.Kind,
		Resource:        "clusterroles.rbac.authorization.k8s.io",
		LabelSelector:   "cloudring.io/installation=test",
		Discovery:       Discovery{Mode: "closed-world"},
		MinimumCount:    1,
		Critical:        true,
		SourceState:     "sourced",
		ExpectedOwner:   NamespacedName{Namespace: "flux-system", Name: "foundation"},
		ExpectedObjects: []ResourceRef{rbac},
	})
	snapshot := readyTestSnapshot(t, contract)
	entry, err := InventoryID(rbac)
	if err != nil {
		t.Fatalf("InventoryID returned error: %v", err)
	}
	snapshot.Kustomizations[0].Inventory = append(snapshot.Kustomizations[0].Inventory, entry)
	snapshot.Resources["cluster-roles"] = []ResourceRef{rbac}
	snapshot.Collections["cluster-roles"] = FamilyCollection{
		Complete:              true,
		ResourceVersionSHA256: testArtifactDigest,
		PageCount:             1,
		ItemCount:             1,
		Objects:               []ResourceRef{rbac},
	}

	report, code, err := Verify(contract, snapshot)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if code != 0 || report.Status != statusReady || !report.PruneEligible {
		t.Fatalf("RBAC ownership code/status/pruneEligible = %d/%s/%t, want 0/ready/true; blockers=%+v", code, report.Status, report.PruneEligible, report.Blockers)
	}
}

func TestParseInventoryEntryUsesFluxFirstAndLastSeparators(t *testing.T) {
	entry := InventoryEntry{
		ID:      "test-namespace_system____leader_locking_rbac.authorization.k8s.io_Role",
		Version: "v1",
	}
	parsed, err := parseInventoryEntry(entry)
	if err != nil {
		t.Fatalf("parseInventoryEntry returned error: %v", err)
	}
	want := ResourceRef{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       "Role",
		Namespace:  "test-namespace",
		Name:       "system::leader_locking",
	}
	if parsed != want {
		t.Fatalf("parseInventoryEntry = %+v, want %+v", parsed, want)
	}
}

func TestAPIVersionUsesKubernetesDNS1035VersionSemantics(t *testing.T) {
	ref := ResourceRef{APIVersion: "example.io/v1-alpha1", Kind: "Widget", Namespace: "default", Name: "test"}
	entry, err := InventoryID(ref)
	if err != nil {
		t.Fatalf("InventoryID rejected DNS-1035 API version: %v", err)
	}
	if entry.Version != "v1-alpha1" {
		t.Fatalf("InventoryID version = %q, want v1-alpha1", entry.Version)
	}
	if parsed, err := parseInventoryEntry(entry); err != nil || parsed != ref {
		t.Fatalf("parseInventoryEntry(%+v) = %+v, %v; want %+v", entry, parsed, err, ref)
	}

	invalidVersions := []string{
		"1v",
		"V1",
		"v1_foo",
		"v1-",
		strings.Repeat("a", 64),
	}
	for _, version := range invalidVersions {
		entry := InventoryEntry{ID: "default_test_example.io_Widget", Version: version}
		if _, err := parseInventoryEntry(entry); err == nil {
			t.Fatalf("parseInventoryEntry accepted invalid API version %q", version)
		}
	}
}

func TestKindUsesMixedCaseDNS1035Semantics(t *testing.T) {
	ref := ResourceRef{APIVersion: "example.io/v1", Kind: "My-Widget", Namespace: "default", Name: "test"}
	entry, err := InventoryID(ref)
	if err != nil {
		t.Fatalf("InventoryID rejected mixed-case DNS-1035 Kind: %v", err)
	}
	if parsed, err := parseInventoryEntry(entry); err != nil || parsed != ref {
		t.Fatalf("parseInventoryEntry(%+v) = %+v, %v; want %+v", entry, parsed, err, ref)
	}

	invalidKinds := []string{
		"1Widget",
		"-Widget",
		"Widget-",
		"My_Widget",
		"My/Widget",
		strings.Repeat("W", 64),
	}
	for _, kind := range invalidKinds {
		invalid := ref
		invalid.Kind = kind
		if _, err := InventoryID(invalid); err == nil {
			t.Fatalf("InventoryID accepted invalid Kind %q", kind)
		}
	}
}

func TestParseInventoryEntryRejectsMalformedFluxMetadata(t *testing.T) {
	tests := []InventoryEntry{
		{ID: "missing-separators", Version: "v1"},
		{ID: "_name_group", Version: "v1"},
		{ID: "bad_namespace_name_group_Kind", Version: "v1"},
		{ID: "_bad%name_rbac.authorization.k8s.io_ClusterRole", Version: "v1"},
		{ID: "default_name_bad..group_Kind", Version: "v1"},
		{ID: "default_name_group_Bad/Kind", Version: "v1"},
	}
	for _, entry := range tests {
		if _, err := parseInventoryEntry(entry); err == nil {
			t.Fatalf("parseInventoryEntry accepted malformed entry %+v", entry)
		}
	}
}

const testSourceRevision = "main@sha1:0123456789abcdef0123456789abcdef01234567"
const testArtifactDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func assertBlocker(t *testing.T, report Report, id string) {
	t.Helper()
	for _, blocker := range report.Blockers {
		if blocker.ID == id {
			return
		}
	}
	t.Fatalf("blocker %q missing from %+v", id, report.Blockers)
}
