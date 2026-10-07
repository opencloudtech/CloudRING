// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package gitopsownership

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

var (
	acceptedSourceRevisionPattern = regexp.MustCompile(`^main@sha1:[0-9a-f]{40}$`)
	artifactDigestPattern         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	gitSHA1Pattern                = regexp.MustCompile(`^[0-9a-f]{40}$`)
	dns1035LabelPattern           = regexp.MustCompile(`^[a-z](?:[-a-z0-9]*[a-z0-9])?$`)
	dnsLabelPattern               = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	dnsSubdomainPattern           = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$`)
)

const (
	ContractAPIVersion       = "cloudring.io/v1alpha2"
	ContractKind             = "GitOpsOwnershipContract"
	ReportAPIVersion         = "cloudring.gitops.ownership/v2"
	DiscoveryModeClosedWorld = "closed-world"
	statusReady              = "ready"
	statusBlocked            = "blocked"
	driftMode                = "read-only-plan"
)

func DecodeContract(reader io.Reader) (Contract, error) {
	data, err := strictjson.Read(reader)
	if err != nil {
		return Contract{}, errors.New("decode GitOps ownership contract: invalid bounded JSON")
	}
	var contract Contract
	if err := strictjson.DecodeExact(data, &contract); err != nil {
		return Contract{}, errors.New("decode GitOps ownership contract: invalid closed schema")
	}
	if err := ValidateContract(contract); err != nil {
		return Contract{}, err
	}
	return contract, nil
}

func ValidateAcceptedSource(revision, digest string) error {
	if !acceptedSourceRevisionPattern.MatchString(revision) {
		return errors.New("accepted source revision must match main@sha1:<40 lowercase hex>")
	}
	if !artifactDigestPattern.MatchString(digest) {
		return errors.New("accepted artifact digest must match sha256:<64 lowercase hex>")
	}
	return nil
}

func ValidateContract(contract Contract) error {
	if contract.APIVersion != ContractAPIVersion || contract.Kind != ContractKind {
		return fmt.Errorf("GitOps ownership contract identity must be %s %s", ContractAPIVersion, ContractKind)
	}
	if strings.TrimSpace(contract.Metadata.Name) == "" {
		return errors.New("GitOps ownership contract metadata.name is required")
	}
	// v1alpha2 uses closed-world discovery; the legacy selector is retained only
	// as a migration diagnostic and is intentionally non-authoritative.
	if len(contract.Spec.RequiredFamilies) == 0 {
		return errors.New("GitOps ownership contract requires at least one resource family")
	}
	if !contract.Spec.Scope.Complete || strings.TrimSpace(contract.Spec.Scope.Name) == "" || strings.TrimSpace(contract.Spec.Scope.NonClaim) == "" {
		return errors.New("GitOps ownership contract scope.complete must be true and scope.name/nonClaim are required")
	}
	if len(contract.Spec.Scope.CriticalFamilyIDs) == 0 || len(contract.Spec.Scope.SelectedRoots) == 0 {
		return errors.New("GitOps ownership contract scope must enumerate criticalFamilyIds and selectedRoots")
	}
	if contract.Spec.SourceArtifact.Kind != "GitRepository" || contract.Spec.SourceArtifact.Namespace == "" || contract.Spec.SourceArtifact.Name == "" ||
		!gitSHA1Pattern.MatchString(contract.Spec.SourceArtifact.PublicGitlinkSHA) {
		return errors.New("sourceArtifact must bind one GitRepository namespace/name and an exact public gitlink SHA")
	}
	familyIDs := map[string]bool{}
	criticalIDs := map[string]bool{}
	expectedObjectFamilies := map[string]string{}
	discoveryScopes := map[string]string{}
	for _, id := range contract.Spec.Scope.CriticalFamilyIDs {
		if id == "" || criticalIDs[id] {
			return fmt.Errorf("scope critical family id %q must be non-empty and unique", id)
		}
		criticalIDs[id] = true
	}
	for _, family := range contract.Spec.RequiredFamilies {
		if family.ID == "" || familyIDs[family.ID] {
			return fmt.Errorf("resource family id %q must be non-empty and unique", family.ID)
		}
		familyIDs[family.ID] = true
		if family.APIVersion == "" || family.Kind == "" || family.Resource == "" {
			return fmt.Errorf("resource family %q must set apiVersion, kind, and resource", family.ID)
		}
		if !family.Critical || !criticalIDs[family.ID] {
			return fmt.Errorf("resource family %q must be critical and enumerated by scope.criticalFamilyIds", family.ID)
		}
		switch family.SourceState {
		case "sourced":
			if family.MinimumCount < 1 || len(family.ExpectedObjects) == 0 || family.MinimumCount != len(family.ExpectedObjects) {
				return fmt.Errorf("sourced resource family %q must set an exact expectedObjects/minimumCount inventory", family.ID)
			}
			if family.Discovery.Mode != DiscoveryModeClosedWorld {
				return fmt.Errorf("sourced resource family %q discovery.mode must be %q", family.ID, DiscoveryModeClosedWorld)
			}
			if family.Namespaced && len(family.Discovery.Namespaces) == 0 {
				return fmt.Errorf("namespaced sourced resource family %q requires exact discovery.namespaces", family.ID)
			}
			if !family.Namespaced && len(family.Discovery.Namespaces) != 0 {
				return fmt.Errorf("cluster-scoped sourced resource family %q must not set discovery.namespaces", family.ID)
			}
			if family.ExpectedOwner.Namespace == "" || family.ExpectedOwner.Name == "" {
				return fmt.Errorf("sourced resource family %q requires expectedOwner", family.ID)
			}
			namespaceSet := map[string]bool{}
			for _, namespace := range family.Discovery.Namespaces {
				if !validDNSLabel(namespace) || namespaceSet[namespace] {
					return fmt.Errorf("resource family %q discovery namespaces must be valid and unique", family.ID)
				}
				namespaceSet[namespace] = true
				// Several Flux roots may own different objects of the same Kubernetes
				// kind in one namespace. Collection is unfiltered; ownership is
				// resolved by the exact expected/external object inventory below.
				scopeKey := family.APIVersion + ":" + family.Resource + ":" + namespace
				if _, exists := discoveryScopes[scopeKey]; !exists {
					discoveryScopes[scopeKey] = family.ID
				}
			}
			if !family.Namespaced {
				scopeKey := family.APIVersion + ":" + family.Resource + ":<cluster>"
				if _, exists := discoveryScopes[scopeKey]; !exists {
					discoveryScopes[scopeKey] = family.ID
				}
			}
			seenExpected := map[string]bool{}
			for _, ref := range family.ExpectedObjects {
				if err := validateRef(ref); err != nil {
					return fmt.Errorf("resource family %q has invalid expected object: %w", family.ID, err)
				}
				if ref.APIVersion != family.APIVersion || ref.Kind != family.Kind ||
					(family.Namespaced && !namespaceSet[ref.Namespace]) || (!family.Namespaced && ref.Namespace != "") {
					return fmt.Errorf("resource family %q expected object does not match its identity and scope", family.ID)
				}
				key := refKey(ref)
				if seenExpected[key] {
					return fmt.Errorf("resource family %q contains duplicate expected object %s", family.ID, key)
				}
				if previousFamily, exists := expectedObjectFamilies[key]; exists {
					return fmt.Errorf("expected object %s occurs in both resource families %q and %q", key, previousFamily, family.ID)
				}
				seenExpected[key] = true
				expectedObjectFamilies[key] = family.ID
			}
			seenExternal := map[string]bool{}
			for _, ref := range family.Discovery.ExternalObjects {
				if err := validateRef(ref); err != nil {
					return fmt.Errorf("resource family %q has invalid external object: %w", family.ID, err)
				}
				if ref.APIVersion != family.APIVersion || ref.Kind != family.Kind ||
					(family.Namespaced && !namespaceSet[ref.Namespace]) || (!family.Namespaced && ref.Namespace != "") {
					return fmt.Errorf("resource family %q external object does not match its identity and scope", family.ID)
				}
				key := refKey(ref)
				if seenExternal[key] || seenExpected[key] {
					return fmt.Errorf("resource family %q external object %s must be unique and disjoint from expectedObjects", family.ID, key)
				}
				if previousFamily, exists := expectedObjectFamilies[key]; exists {
					return fmt.Errorf("external object %s overlaps expected inventory in resource family %q", key, previousFamily)
				}
				seenExternal[key] = true
			}
		case "not-sourced":
			if family.MissingSourceBlocker == "" || family.MinimumCount != 0 || len(family.ExpectedObjects) != 0 ||
				family.LabelSelector != "" || family.ExpectedOwner != (NamespacedName{}) ||
				family.Discovery.Mode != "" || len(family.Discovery.Namespaces) != 0 || len(family.Discovery.ExternalObjects) != 0 {
				return fmt.Errorf("not-sourced resource family %q must declare only missingSourceBlocker and zero inventory", family.ID)
			}
		default:
			return fmt.Errorf("resource family %q sourceState must be sourced or not-sourced", family.ID)
		}
	}
	if len(familyIDs) != len(criticalIDs) {
		return errors.New("scope.criticalFamilyIds must exactly enumerate requiredFamilies")
	}
	for id := range criticalIDs {
		if !familyIDs[id] {
			return fmt.Errorf("scope critical family %q is not declared in requiredFamilies", id)
		}
	}
	if len(contract.Spec.AllowUnmanaged) != 0 {
		return errors.New("closed-world ownership contracts require an empty allowUnmanaged list; declare reviewed non-CloudRING occupants as discovery.externalObjects")
	}
	if len(contract.Spec.PruneGate.Kustomizations) == 0 {
		return errors.New("GitOps ownership contract pruneGate.kustomizations must not be empty")
	}
	selectedRoots := map[string]bool{}
	for _, root := range contract.Spec.Scope.SelectedRoots {
		key := namespacedNameKey(root)
		if root.Namespace == "" || root.Name == "" || selectedRoots[key] {
			return fmt.Errorf("scope selected root %q must have namespace/name and be unique", key)
		}
		selectedRoots[key] = true
	}
	rootSpecs := map[string]bool{}
	for _, spec := range contract.Spec.RootSpecs {
		key := namespacedNameKey(NamespacedName{Namespace: spec.Namespace, Name: spec.Name})
		if spec.Namespace == "" || spec.Name == "" || rootSpecs[key] {
			return fmt.Errorf("root spec %q must have namespace/name and be unique", key)
		}
		rootSpecs[key] = true
		if !selectedRoots[key] {
			return fmt.Errorf("root spec %q is absent from scope.selectedRoots", key)
		}
		if spec.Suspend == nil || *spec.Suspend || spec.Prune == nil || *spec.Prune || spec.DeletionPolicy != "Orphan" || spec.Wait == nil || !*spec.Wait || !strings.HasPrefix(spec.Path, "./") || strings.Contains(spec.Path, "..") {
			return fmt.Errorf("root spec %q must require active, non-pruning, orphaning, wait-enabled exact-path readiness", key)
		}
		if spec.SourceRef.Kind != contract.Spec.SourceArtifact.Kind || spec.SourceRef.Name != contract.Spec.SourceArtifact.Name || spec.SourceRef.Namespace != contract.Spec.SourceArtifact.Namespace {
			return fmt.Errorf("root spec %q sourceRef must match sourceArtifact exactly", key)
		}
		dependencies := map[string]bool{}
		for _, dependency := range spec.DependsOn {
			dependencyKey := dependency.Namespace + "/" + dependency.Name
			if dependency.Kind != "Kustomization" || dependency.Namespace == "" || dependency.Name == "" || dependencies[dependencyKey] {
				return fmt.Errorf("root spec %q dependencies must be unique exact Kustomization references", key)
			}
			dependencies[dependencyKey] = true
			if !selectedRoots[dependencyKey] {
				return fmt.Errorf("root spec %q dependency %q is absent from scope.selectedRoots", key, dependencyKey)
			}
		}
	}
	if len(rootSpecs) != len(selectedRoots) {
		return errors.New("rootSpecs must exactly enumerate scope.selectedRoots")
	}
	pruneRoots := map[string]bool{}
	for _, root := range contract.Spec.PruneGate.Kustomizations {
		if root.Namespace == "" || root.Name == "" {
			return errors.New("prune gate Kustomizations require namespace and name")
		}
		key := namespacedNameKey(root)
		if pruneRoots[key] {
			return fmt.Errorf("duplicate prune gate Kustomization %s", key)
		}
		pruneRoots[key] = true
	}
	if len(selectedRoots) != len(pruneRoots) {
		return errors.New("pruneGate.kustomizations must exactly enumerate scope.selectedRoots")
	}
	for key := range selectedRoots {
		if !pruneRoots[key] {
			return fmt.Errorf("selected root %q is absent from pruneGate.kustomizations", key)
		}
	}
	for _, family := range contract.Spec.RequiredFamilies {
		if family.SourceState == "sourced" && !selectedRoots[namespacedNameKey(family.ExpectedOwner)] {
			return fmt.Errorf("resource family %q expectedOwner is absent from scope.selectedRoots", family.ID)
		}
	}
	if contract.Spec.DriftProof.Mode != driftMode {
		return fmt.Errorf("driftProof.mode must be %q", driftMode)
	}
	if err := validateRef(contract.Spec.DriftProof.Target); err != nil {
		return fmt.Errorf("invalid driftProof.target: %w", err)
	}
	if contract.Spec.DriftProof.ExpectedOwner.Namespace == "" || contract.Spec.DriftProof.ExpectedOwner.Name == "" {
		return errors.New("driftProof.expectedOwner requires namespace and name")
	}
	expectedDriftObservations := []string{"baseline", "controlled-drift", "reconciled"}
	if !reflect.DeepEqual(contract.Spec.DriftProof.RequiredObservations, expectedDriftObservations) {
		return errors.New("driftProof.requiredObservations must be exactly baseline, controlled-drift, reconciled")
	}
	if contract.Spec.DriftProof.MutationAuthorization != "separate-explicit-approval-required" {
		return errors.New("driftProof.mutationAuthorization must require separate explicit approval")
	}
	driftTargetKey := refKey(contract.Spec.DriftProof.Target)
	driftTargetMatches := 0
	for _, family := range contract.Spec.RequiredFamilies {
		if family.SourceState != "sourced" {
			continue
		}
		for _, expected := range family.ExpectedObjects {
			if refKey(expected) != driftTargetKey {
				continue
			}
			driftTargetMatches++
			if family.ExpectedOwner != contract.Spec.DriftProof.ExpectedOwner {
				return fmt.Errorf("driftProof.expectedOwner must match the declared owner of target %s", driftTargetKey)
			}
		}
	}
	if driftTargetMatches != 1 {
		return fmt.Errorf("driftProof.target must occur exactly once in the sourced critical inventory, found %d matches", driftTargetMatches)
	}
	return nil
}

func Verify(contract Contract, snapshot Snapshot) (Report, int, error) {
	if err := ValidateContract(contract); err != nil {
		return Report{}, 1, err
	}
	report := Report{
		APIVersion:               ReportAPIVersion,
		Kind:                     "GitOpsOwnershipReport",
		Contract:                 contract.Metadata.Name,
		Status:                   statusReady,
		RequiredFamilyCount:      len(contract.Spec.RequiredFamilies),
		PruneEligible:            true,
		PruneChanged:             false,
		LiveMutationPerformed:    false,
		AllowlistedResourceCount: 0,
		Scope: ScopeReport{
			Name:                        contract.Spec.Scope.Name,
			Complete:                    contract.Spec.Scope.Complete,
			AllCriticalFamiliesDeclared: true,
			AllSelectedRootsDeclared:    true,
			ClosedWorldComplete:         true,
			CriticalFamilyCount:         len(contract.Spec.Scope.CriticalFamilyIDs),
			DeclaredFamilyCount:         len(contract.Spec.RequiredFamilies),
			SelectedRootCount:           len(contract.Spec.Scope.SelectedRoots),
			NonClaim:                    contract.Spec.Scope.NonClaim,
		},
		NonClaims: []string{
			contract.Spec.Scope.NonClaim,
			"pruneEligible is a read-only pre-change review signal; this verifier never enables prune or mutates the live cluster",
		},
		DriftProof: DriftReport{
			Mode:                  contract.Spec.DriftProof.Mode,
			Target:                refKey(contract.Spec.DriftProof.Target),
			ExpectedOwner:         namespacedNameKey(contract.Spec.DriftProof.ExpectedOwner),
			LiveMutationPerformed: false,
			RequiredObservations:  append([]string(nil), contract.Spec.DriftProof.RequiredObservations...),
			NextAction:            "retain prune=false; execute the drift proof only after separate mutation approval",
		},
		SourceArtifact: SourceArtifactReport{
			Kind: contract.Spec.SourceArtifact.Kind, Namespace: contract.Spec.SourceArtifact.Namespace, Name: contract.Spec.SourceArtifact.Name,
			Ready:    snapshot.SourceArtifact.Ready,
			Revision: canonicalSourceRevision(snapshot.SourceArtifact.Revision), Digest: canonicalArtifactDigest(snapshot.SourceArtifact.Digest),
			AcceptedRevision: canonicalSourceRevision(snapshot.AcceptedSourceRevision), AcceptedDigest: canonicalArtifactDigest(snapshot.AcceptedArtifactDigest),
			ExpectedPublicGitlinkSHA: contract.Spec.SourceArtifact.PublicGitlinkSHA,
			AcceptedPublicGitlinkSHA: canonicalGitSHA1(snapshot.AcceptedPublicGitlinkSHA),
			ObservedPublicGitlinkSHA: canonicalGitSHA1(snapshot.ObservedPublicGitlinkSHA),
		},
	}
	acceptedInputsValid := ValidateAcceptedSource(snapshot.AcceptedSourceRevision, snapshot.AcceptedArtifactDigest) == nil
	if !acceptedInputsValid {
		block(&report, "accepted_source_receipt_invalid", "accepted source revision and artifact digest are mandatory exact canonical values", "", "")
	}
	sourceIdentityExact := snapshot.SourceArtifact.Kind == contract.Spec.SourceArtifact.Kind && snapshot.SourceArtifact.Namespace == contract.Spec.SourceArtifact.Namespace && snapshot.SourceArtifact.Name == contract.Spec.SourceArtifact.Name
	if !sourceIdentityExact {
		block(&report, "source_artifact_identity_mismatch", "live source artifact identity differs from the contracted GitRepository", "", "")
	}
	if snapshot.SourceArtifact.Generation < 1 || snapshot.SourceArtifact.ObservedGeneration != snapshot.SourceArtifact.Generation || !snapshot.SourceArtifact.Ready {
		block(&report, "source_artifact_not_ready", "live GitRepository must be Ready at its current observed generation", "", "")
	}
	if snapshot.SourceArtifact.Revision != snapshot.AcceptedSourceRevision {
		block(&report, "source_artifact_revision_mismatch", "live GitRepository artifact revision differs from the accepted Enterprise revision", "", "")
	}
	if snapshot.SourceArtifact.Digest != snapshot.AcceptedArtifactDigest {
		block(&report, "source_artifact_digest_mismatch", "live GitRepository artifact digest differs from the accepted artifact digest", "", "")
	}
	acceptedPublicGitlinkValid := gitSHA1Pattern.MatchString(snapshot.AcceptedPublicGitlinkSHA)
	if !acceptedPublicGitlinkValid {
		block(&report, "accepted_public_gitlink_invalid", "accepted public gitlink receipt must be one canonical lowercase SHA-1", "", "")
	} else if snapshot.AcceptedPublicGitlinkSHA != contract.Spec.SourceArtifact.PublicGitlinkSHA {
		block(&report, "accepted_public_gitlink_mismatch", "accepted public gitlink receipt differs from the contracted CloudRING revision", "", "")
	}
	observedPublicGitlinkValid := gitSHA1Pattern.MatchString(snapshot.ObservedPublicGitlinkSHA)
	if !observedPublicGitlinkValid {
		block(&report, "observed_public_gitlink_invalid", "observed public gitlink must be one canonical lowercase SHA-1", "", "")
	} else if acceptedPublicGitlinkValid && snapshot.ObservedPublicGitlinkSHA != snapshot.AcceptedPublicGitlinkSHA {
		block(&report, "public_gitlink_receipt_mismatch", "observed downstream public gitlink differs from the accepted public gitlink receipt", "", "")
	} else if acceptedPublicGitlinkValid && snapshot.ObservedPublicGitlinkSHA != contract.Spec.SourceArtifact.PublicGitlinkSHA {
		block(&report, "public_gitlink_mismatch", "observed downstream public gitlink differs from the contracted CloudRING revision", "", "")
	}
	report.SourceArtifact.PublicGitlinkExact = acceptedPublicGitlinkValid && observedPublicGitlinkValid &&
		snapshot.AcceptedPublicGitlinkSHA == contract.Spec.SourceArtifact.PublicGitlinkSHA &&
		snapshot.ObservedPublicGitlinkSHA == snapshot.AcceptedPublicGitlinkSHA
	report.SourceArtifact.Exact = acceptedInputsValid && sourceIdentityExact && snapshot.SourceArtifact.Generation > 0 && snapshot.SourceArtifact.ObservedGeneration == snapshot.SourceArtifact.Generation && snapshot.SourceArtifact.Ready && snapshot.SourceArtifact.Revision == snapshot.AcceptedSourceRevision && snapshot.SourceArtifact.Digest == snapshot.AcceptedArtifactDigest && report.SourceArtifact.PublicGitlinkExact

	rootSpecs := make(map[string]RootSpecContract, len(contract.Spec.RootSpecs))
	for _, spec := range contract.Spec.RootSpecs {
		rootSpecs[namespacedNameKey(NamespacedName{Namespace: spec.Namespace, Name: spec.Name})] = spec
	}
	declaredRoots := make(map[string]bool, len(contract.Spec.Scope.SelectedRoots))
	for _, root := range contract.Spec.Scope.SelectedRoots {
		declaredRoots[namespacedNameKey(root)] = true
	}
	if !snapshot.KustomizationsComplete ||
		!artifactDigestPattern.MatchString(snapshot.KustomizationsRVHash) ||
		snapshot.KustomizationsPageCount < 1 ||
		snapshot.KustomizationsPageCount > maxCollectionPages ||
		snapshot.KustomizationsItemCount != len(snapshot.Kustomizations) ||
		snapshot.KustomizationsItemCount > maxCollectionObjects ||
		hasDuplicateKustomizations(snapshot.Kustomizations) {
		report.Scope.ClosedWorldComplete = false
		block(&report, "flux_root_collection_incomplete", "unfiltered all-namespace Flux Kustomization collection is incomplete or internally inconsistent", "", "")
	}
	owners, roots := inventoryOwners(
		snapshot.Kustomizations,
		declaredRoots,
		contract.Spec.SourceArtifact,
		contract.Spec.RequiredFamilies,
		&report,
	)
	for key := range roots {
		if !declaredRoots[key] {
			evidenceRoot := ""
			namespace, name, ok := strings.Cut(key, "/")
			if ok && validDNSLabel(namespace) && validDNSLabel(name) {
				evidenceRoot = key
			}
			block(&report, "undeclared_relevant_flux_root", "an undeclared Flux root uses the accepted source or intersects a closed-world resource scope", "", evidenceRoot)
		}
	}
	for _, declared := range contract.Spec.Scope.SelectedRoots {
		key := namespacedNameKey(declared)
		root, observed := roots[key]
		rootReport := RootReport{Namespace: declared.Namespace, Name: declared.Name, Observed: observed}
		if observed {
			rootReport.Ready = root.Ready
			if root.Prune != nil {
				rootReport.Prune = *root.Prune
			}
			if root.Suspend != nil {
				rootReport.Suspend = *root.Suspend
			}
			rootReport.LastAppliedRevision = canonicalSourceRevision(root.LastAppliedRevision)
			rootReport.SpecSHA256 = rootSpecSHA256(root)
			rootReport.InventoryCount = len(root.Inventory)
			report.Scope.ObservedRootCount++
			expected := rootSpecs[key]
			if !equalBoolPointer(root.Suspend, expected.Suspend) {
				block(&report, "flux_kustomization_suspended", "selected Flux Kustomization suspend state differs from the active readiness contract", "", key)
			}
			if !equalBoolPointer(root.Prune, expected.Prune) {
				block(&report, "flux_prune_mismatch", "selected Flux Kustomization prune state differs from contract", "", key)
			}
			if root.DeletionPolicy != expected.DeletionPolicy {
				block(&report, "flux_deletion_policy_mismatch", "selected Flux Kustomization deletionPolicy differs from contract", "", key)
			}
			if !equalBoolPointer(root.Wait, expected.Wait) {
				block(&report, "flux_wait_mismatch", "selected Flux Kustomization wait behavior differs from contract", "", key)
			}
			if !reflect.DeepEqual(root.SourceRef, expected.SourceRef) {
				block(&report, "flux_source_ref_mismatch", "selected Flux Kustomization sourceRef differs from contract", "", key)
			}
			if root.Path != expected.Path {
				block(&report, "flux_path_mismatch", "selected Flux Kustomization path differs from contract", "", key)
			}
			if !reflect.DeepEqual(root.DependsOn, expected.DependsOn) {
				block(&report, "flux_dependencies_mismatch", "selected Flux Kustomization dependsOn order differs from contract", "", key)
			}
			if root.LastAppliedRevision != snapshot.AcceptedSourceRevision {
				block(&report, "flux_last_applied_revision_mismatch", "selected Flux Kustomization lastAppliedRevision differs from the accepted Enterprise revision", "", key)
			}
			rootReport.SpecExact = equalBoolPointer(root.Suspend, expected.Suspend) && equalBoolPointer(root.Prune, expected.Prune) && root.DeletionPolicy == expected.DeletionPolicy && equalBoolPointer(root.Wait, expected.Wait) &&
				reflect.DeepEqual(root.SourceRef, expected.SourceRef) && root.Path == expected.Path && reflect.DeepEqual(root.DependsOn, expected.DependsOn)
		} else {
			block(&report, "selected_flux_root_missing", "scope-selected Flux root was not returned by the live query", "", key)
		}
		report.Roots = append(report.Roots, rootReport)
	}
	report.Scope.AllSelectedRootsObserved = report.Scope.ObservedRootCount == report.Scope.SelectedRootCount
	for _, family := range contract.Spec.RequiredFamilies {
		familyReport := FamilyReport{
			ID: family.ID, Critical: family.Critical, SourceState: family.SourceState,
			ExpectedCount: len(family.ExpectedObjects), ExpectedOwner: namespacedNameKey(family.ExpectedOwner),
			DiscoveryMode:   family.Discovery.Mode,
			DiscoveryScopes: len(family.Discovery.Namespaces),
		}
		if !family.Namespaced && family.SourceState == "sourced" {
			familyReport.DiscoveryScopes = 1
		}
		if family.SourceState == "not-sourced" {
			familyReport.ClosedWorldComplete = false
			report.Scope.ClosedWorldComplete = false
			report.Scope.SourceMissingFamilies = append(report.Scope.SourceMissingFamilies, family.ID)
			block(&report, "critical_family_source_missing", family.MissingSourceBlocker, family.ID, "")
			report.Families = append(report.Families, familyReport)
			continue
		}
		collection, ok := snapshot.Collections[family.ID]
		if !ok {
			report.Scope.ClosedWorldComplete = false
			block(&report, "required_family_unobserved", "closed-world collection did not return this required resource family", family.ID, "")
			report.Families = append(report.Families, familyReport)
			continue
		}
		familyReport.CollectionComplete = collection.Complete
		familyReport.ResourceVersionSHA256 = canonicalArtifactDigest(collection.ResourceVersionSHA256)
		familyReport.PageCount = collection.PageCount
		familyReport.ItemCount = collection.ItemCount
		collectionMetaValid := collection.Complete &&
			artifactDigestPattern.MatchString(collection.ResourceVersionSHA256) &&
			collection.PageCount >= familyReport.DiscoveryScopes &&
			collection.PageCount <= maxCollectionPages &&
			collection.ItemCount == len(collection.Objects) &&
			collection.ItemCount <= maxCollectionObjects
		if !collectionMetaValid {
			report.Scope.ClosedWorldComplete = false
			block(&report, "family_collection_incomplete", "closed-world family collection is incomplete or internally inconsistent", family.ID, "")
		}
		resources := collection.Objects
		expected := make(map[string]bool, len(family.ExpectedObjects))
		external := make(map[string]bool, len(family.Discovery.ExternalObjects))
		observed := make(map[string]bool, len(resources))
		for _, ref := range family.ExpectedObjects {
			expected[refKey(ref)] = true
		}
		for _, ref := range family.Discovery.ExternalObjects {
			external[refKey(ref)] = true
		}
		for _, ref := range resources {
			key := refKey(ref)
			evidenceObject := ""
			if expected[key] || external[key] {
				evidenceObject = key
			}
			if observed[key] {
				block(&report, "duplicate_resource_observation", "live collection returned the same critical resource more than once", family.ID, evidenceObject)
				continue
			}
			observed[key] = true
			familyReport.ObservedCount++
			report.ObservedResourceCount++
			if !refInFamilyScope(ref, family) {
				block(&report, "resource_family_identity_mismatch", "observed object does not match the contracted family identity and scope", family.ID, evidenceObject)
				continue
			}
			if external[key] {
				familyReport.ExternalCount++
				report.ExternalResourceCount++
				if len(owners[key]) != 0 {
					familyReport.UnmanagedCount++
					report.UnmanagedResourceCount++
					block(&report, "external_object_flux_owned", "reviewed external object must not be inventory-owned by a selected or relevant Flux root", family.ID, key)
				}
				continue
			}
			if !expected[key] {
				familyReport.UnexpectedCount++
				report.UnexpectedResourceCount++
				block(&report, "undeclared_resource_in_closed_world_scope", "unfiltered live collection returned an object absent from expectedObjects and externalObjects", family.ID, "")
				continue
			}
			objectOwners := owners[key]
			switch {
			case len(objectOwners) == 1 && objectOwners[0] != namespacedNameKey(family.ExpectedOwner):
				block(&report, "resource_wrong_flux_owner", "required live object is inventory-owned by a different selected Flux root", family.ID, key)
			case len(objectOwners) == 1:
				familyReport.ManagedCount++
				report.ManagedResourceCount++
			case len(objectOwners) > 1:
				block(&report, "multiple_flux_owners", "object occurs in more than one Flux inventory", family.ID, key)
			default:
				familyReport.UnmanagedCount++
				report.UnmanagedResourceCount++
				block(&report, "resource_not_flux_managed", "required live object is absent from selected Flux status.inventory entries", family.ID, key)
			}
		}
		for _, ref := range family.ExpectedObjects {
			key := refKey(ref)
			if !observed[key] {
				block(&report, "declared_resource_missing", "declared critical resource was not returned by the live family query", family.ID, key)
			}
		}
		for _, ref := range family.Discovery.ExternalObjects {
			key := refKey(ref)
			if !observed[key] {
				block(&report, "declared_external_resource_missing", "reviewed external object was not returned by the closed-world live query", family.ID, key)
			}
		}
		if familyReport.ObservedCount < family.MinimumCount+len(family.Discovery.ExternalObjects) {
			block(&report, "required_family_below_minimum", fmt.Sprintf("observed %d objects, requires exactly %d expected plus %d reviewed external objects", familyReport.ObservedCount, family.MinimumCount, len(family.Discovery.ExternalObjects)), family.ID, "")
		}
		if familyReport.ManagedCount == 0 {
			block(&report, "required_family_has_no_managed_objects", "at least one object in every required family must be Flux inventory-owned", family.ID, "")
		}
		familyReport.ClosedWorldComplete = collectionMetaValid &&
			familyReport.UnexpectedCount == 0 &&
			familyReport.UnmanagedCount == 0 &&
			familyReport.ObservedCount == familyReport.ExpectedCount+familyReport.ExternalCount
		if !familyReport.ClosedWorldComplete {
			report.Scope.ClosedWorldComplete = false
		}
		familyReport.OwnershipComplete = familyReport.ClosedWorldComplete &&
			familyReport.ManagedCount == familyReport.ExpectedCount &&
			familyReport.ExternalCount == len(family.Discovery.ExternalObjects)
		if !familyReport.OwnershipComplete {
			block(&report, "critical_family_ownership_incomplete", "closed-world scope must contain exactly the declared expected and external objects, with every expected object uniquely owned by its contracted Flux root", family.ID, "")
		}
		report.Families = append(report.Families, familyReport)
	}
	report.ClosedWorldComplete = report.Scope.ClosedWorldComplete &&
		snapshot.KustomizationsComplete &&
		report.UnexpectedResourceCount == 0 &&
		report.UnmanagedResourceCount == 0 &&
		report.AllowlistedResourceCount == 0

	for _, gated := range contract.Spec.PruneGate.Kustomizations {
		_, ok := roots[namespacedNameKey(gated)]
		if !ok {
			block(&report, "prune_gate_kustomization_missing", "prune gate Kustomization was not returned by the selected live query", "", namespacedNameKey(gated))
		}
	}

	driftOwners := owners[refKey(contract.Spec.DriftProof.Target)]
	expectedOwner := namespacedNameKey(contract.Spec.DriftProof.ExpectedOwner)
	report.DriftProof.TargetInventoryOwned = len(driftOwners) == 1 && driftOwners[0] == expectedOwner
	if !report.DriftProof.TargetInventoryOwned {
		block(&report, "drift_target_ownership_unproven", "drift target is not uniquely present in the expected Flux inventory", "", refKey(contract.Spec.DriftProof.Target))
	}

	if len(report.Blockers) != 0 {
		report.Status = statusBlocked
		report.PruneEligible = false
		report.DriftProof.NextAction = "resolve ownership blockers and rerun this read-only verifier; keep prune=false"
	}
	sort.Strings(report.Scope.SourceMissingFamilies)
	sort.Slice(report.Blockers, func(i, j int) bool {
		left := report.Blockers[i].ID + report.Blockers[i].Family + report.Blockers[i].Object
		right := report.Blockers[j].ID + report.Blockers[j].Family + report.Blockers[j].Object
		return left < right
	})
	if report.Status == statusBlocked {
		return report, 2, nil
	}
	return report, 0, nil
}

func hasDuplicateKustomizations(kustomizations []KustomizationSnapshot) bool {
	seen := make(map[string]bool, len(kustomizations))
	for _, root := range kustomizations {
		key := namespacedNameKey(NamespacedName{Namespace: root.Namespace, Name: root.Name})
		if seen[key] {
			return true
		}
		seen[key] = true
	}
	return false
}

func inventoryOwners(
	kustomizations []KustomizationSnapshot,
	declaredRoots map[string]bool,
	source SourceArtifactContract,
	families []ResourceFamily,
	report *Report,
) (map[string][]string, map[string]KustomizationSnapshot) {
	owners := map[string][]string{}
	roots := map[string]KustomizationSnapshot{}
	for _, root := range kustomizations {
		rootKey := namespacedNameKey(NamespacedName{Namespace: root.Namespace, Name: root.Name})
		validRootIdentity := validDNSLabel(root.Namespace) && validDNSLabel(root.Name)
		parsedInventory := make([]ResourceRef, 0, len(root.Inventory))
		inventoryInvalid := false
		intersectsClosedWorld := false
		for _, entry := range root.Inventory {
			ref, err := parseInventoryEntry(entry)
			if err != nil {
				inventoryInvalid = true
				continue
			}
			parsedInventory = append(parsedInventory, ref)
			if refInAnyFamilyScope(ref, families) {
				intersectsClosedWorld = true
			}
		}
		sourceMatches := root.SourceRef.Kind == source.Kind &&
			root.SourceRef.Namespace == source.Namespace &&
			root.SourceRef.Name == source.Name
		relevant := declaredRoots[rootKey] || sourceMatches || intersectsClosedWorld || inventoryInvalid
		if !relevant {
			continue
		}
		evidenceRoot := ""
		if validRootIdentity {
			evidenceRoot = rootKey
		}
		if !validRootIdentity {
			block(report, "flux_kustomization_identity_invalid", "relevant Flux Kustomization namespace/name is invalid", "", "")
		}
		if inventoryInvalid {
			block(report, "flux_inventory_entry_invalid", "relevant Flux inventory contains an invalid entry, so closed-world intersection cannot be excluded", "", evidenceRoot)
		}
		if _, exists := roots[rootKey]; exists {
			block(report, "flux_kustomization_duplicate", "selected Flux query returned the same Kustomization more than once", "", evidenceRoot)
		}
		roots[rootKey] = root
		if root.Generation < 1 || root.ObservedGeneration != root.Generation {
			block(report, "flux_generation_not_observed", "Flux Kustomization has not observed its current generation", "", evidenceRoot)
		}
		if !root.Ready {
			block(report, "flux_kustomization_not_ready", "Flux Kustomization Ready condition is not True", "", evidenceRoot)
		}
		if root.Suspend == nil || *root.Suspend {
			block(report, "flux_kustomization_suspended", "selected Flux Kustomization is suspended and cannot satisfy readiness", "", evidenceRoot)
		}
		if len(root.Inventory) == 0 {
			block(report, "flux_inventory_empty", "Flux Kustomization status.inventory is empty", "", evidenceRoot)
		}
		if root.Prune == nil || *root.Prune {
			block(report, "prune_enabled_before_gate", "all selected ownership roots must retain prune=false until a ready report and separate reviewed change", "", evidenceRoot)
		}
		for _, ref := range parsedInventory {
			key := refKey(ref)
			owners[key] = append(owners[key], rootKey)
		}
	}
	for key := range owners {
		sort.Strings(owners[key])
	}
	return owners, roots
}

func refInAnyFamilyScope(ref ResourceRef, families []ResourceFamily) bool {
	for _, family := range families {
		if family.SourceState == "sourced" && refInFamilyScope(ref, family) {
			return true
		}
	}
	return false
}

func refInFamilyScope(ref ResourceRef, family ResourceFamily) bool {
	if ref.APIVersion != family.APIVersion || ref.Kind != family.Kind {
		return false
	}
	if !family.Namespaced {
		return ref.Namespace == ""
	}
	for _, namespace := range family.Discovery.Namespaces {
		if ref.Namespace == namespace {
			return true
		}
	}
	return false
}

func equalBoolPointer(left, right *bool) bool {
	return left != nil && right != nil && *left == *right
}

func rootSpecSHA256(root KustomizationSnapshot) string {
	spec := RootSpecContract{
		Namespace: root.Namespace, Name: root.Name, Suspend: root.Suspend, Prune: root.Prune, DeletionPolicy: root.DeletionPolicy,
		Wait: root.Wait, SourceRef: root.SourceRef, Path: root.Path, DependsOn: root.DependsOn,
	}
	data, err := json.Marshal(spec)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", digest)
}

func parseInventoryEntry(entry InventoryEntry) (ResourceRef, error) {
	if !validDNS1035Label(entry.Version) {
		return ResourceRef{}, errors.New("Flux inventory entry id/version is invalid")
	}
	namespaceEnd := strings.Index(entry.ID, "_")
	if namespaceEnd < 0 {
		return ResourceRef{}, errors.New("Flux inventory entry id/version is invalid")
	}
	namespace := entry.ID[:namespaceEnd]
	remainder := entry.ID[namespaceEnd+1:]
	kindStart := strings.LastIndex(remainder, "_")
	if kindStart < 0 {
		return ResourceRef{}, errors.New("Flux inventory entry id/version is invalid")
	}
	kind := remainder[kindStart+1:]
	remainder = remainder[:kindStart]
	groupStart := strings.LastIndex(remainder, "_")
	if groupStart < 0 {
		return ResourceRef{}, errors.New("Flux inventory entry id/version is invalid")
	}
	group := remainder[groupStart+1:]
	name := strings.ReplaceAll(remainder[:groupStart], "__", ":")
	ref := ResourceRef{Namespace: namespace, Name: name, Kind: kind}
	if group == "" {
		ref.APIVersion = entry.Version
	} else {
		ref.APIVersion = group + "/" + entry.Version
	}
	if err := validateRef(ref); err != nil {
		return ResourceRef{}, err
	}
	return ref, nil
}

func canonicalSourceRevision(value string) string {
	if acceptedSourceRevisionPattern.MatchString(value) {
		return value
	}
	return ""
}

func canonicalArtifactDigest(value string) string {
	if artifactDigestPattern.MatchString(value) {
		return value
	}
	return ""
}

func canonicalGitSHA1(value string) string {
	if gitSHA1Pattern.MatchString(value) {
		return value
	}
	return ""
}

func InventoryID(ref ResourceRef) (InventoryEntry, error) {
	if err := validateRef(ref); err != nil {
		return InventoryEntry{}, err
	}
	group, version, ok := strings.Cut(ref.APIVersion, "/")
	if !ok {
		version = group
		group = ""
	}
	name := ref.Name
	if isRBACResource(group, ref.Kind) {
		name = strings.ReplaceAll(name, ":", "__")
	}
	return InventoryEntry{ID: strings.Join([]string{ref.Namespace, name, group, ref.Kind}, "_"), Version: version}, nil
}

func validateRef(ref ResourceRef) error {
	group, _, _ := strings.Cut(ref.APIVersion, "/")
	if !validAPIVersion(ref.APIVersion) || !validKind(ref.Kind) || !validResourceName(group, ref.Kind, ref.Name) {
		return errors.New("resource reference requires apiVersion, kind, and name")
	}
	if ref.Namespace != "" && !validDNSLabel(ref.Namespace) {
		return errors.New("resource namespace must be a Kubernetes DNS label")
	}
	return nil
}

func validDNSLabel(value string) bool {
	return len(value) <= 63 && dnsLabelPattern.MatchString(value)
}

func validDNSSubdomain(value string) bool {
	if len(value) == 0 || len(value) > 253 || !dnsSubdomainPattern.MatchString(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

func validAPIVersion(value string) bool {
	group, version, grouped := strings.Cut(value, "/")
	if !grouped {
		return validDNS1035Label(group)
	}
	return !strings.Contains(version, "/") && validDNSSubdomain(group) && validDNS1035Label(version)
}

func validDNS1035Label(value string) bool {
	return len(value) <= 63 && dns1035LabelPattern.MatchString(value)
}

func validKind(value string) bool {
	return validDNS1035Label(strings.ToLower(value))
}

func validResourceName(group, kind, name string) bool {
	if !isRBACResource(group, kind) {
		return validDNSSubdomain(name)
	}
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/%")
}

func isRBACResource(group, kind string) bool {
	if group != "rbac.authorization.k8s.io" {
		return false
	}
	switch kind {
	case "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding":
		return true
	default:
		return false
	}
}

func refKey(ref ResourceRef) string {
	location := ref.Name
	if ref.Namespace != "" {
		location = ref.Namespace + "/" + ref.Name
	}
	return ref.APIVersion + ":" + ref.Kind + ":" + location
}

func namespacedNameKey(value NamespacedName) string {
	return value.Namespace + "/" + value.Name
}

func block(report *Report, id, message, family, object string) {
	report.Blockers = append(report.Blockers, Blocker{ID: id, Message: message, Family: family, Object: object})
}
