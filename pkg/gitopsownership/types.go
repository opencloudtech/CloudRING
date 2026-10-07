// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package gitopsownership

// Contract defines the exact live resource families that must be owned by the
// selected Flux Kustomizations before prune may be considered for a later,
// separately approved change.
type Contract struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	Metadata   Metadata     `json:"metadata"`
	Spec       ContractSpec `json:"spec"`
}

type Metadata struct {
	Name string `json:"name"`
}

type ContractSpec struct {
	// KustomizationSelector is retained as non-authoritative diagnostic
	// metadata for v1 contracts. Closed-world collection never uses it.
	KustomizationSelector string                 `json:"kustomizationSelector"`
	Scope                 ScopeContract          `json:"scope"`
	SourceArtifact        SourceArtifactContract `json:"sourceArtifact"`
	RootSpecs             []RootSpecContract     `json:"rootSpecs"`
	RequiredFamilies      []ResourceFamily       `json:"requiredFamilies"`
	AllowUnmanaged        []ResourceRef          `json:"allowUnmanaged,omitempty"`
	PruneGate             PruneGate              `json:"pruneGate"`
	DriftProof            DriftProof             `json:"driftProof"`
}

type SourceArtifactContract struct {
	Kind             string `json:"kind"`
	Namespace        string `json:"namespace"`
	Name             string `json:"name"`
	PublicGitlinkSHA string `json:"publicGitlinkSHA"`
}

type FluxObjectReference struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

type RootSpecContract struct {
	Namespace      string                `json:"namespace"`
	Name           string                `json:"name"`
	Suspend        *bool                 `json:"suspend"`
	Prune          *bool                 `json:"prune"`
	DeletionPolicy string                `json:"deletionPolicy"`
	Wait           *bool                 `json:"wait"`
	SourceRef      FluxObjectReference   `json:"sourceRef"`
	Path           string                `json:"path"`
	DependsOn      []FluxObjectReference `json:"dependsOn"`
}

type ScopeContract struct {
	Name              string           `json:"name"`
	Complete          bool             `json:"complete"`
	NonClaim          string           `json:"nonClaim"`
	CriticalFamilyIDs []string         `json:"criticalFamilyIds"`
	SelectedRoots     []NamespacedName `json:"selectedRoots"`
}

type ResourceFamily struct {
	ID         string `json:"id"`
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Resource   string `json:"resource"`
	Namespaced bool   `json:"namespaced"`
	// LabelSelector is retained as non-authoritative diagnostic metadata for
	// installations migrating from v1. Closed-world collection never uses it.
	LabelSelector        string         `json:"labelSelector,omitempty"`
	Discovery            Discovery      `json:"discovery"`
	MinimumCount         int            `json:"minimumCount"`
	Critical             bool           `json:"critical"`
	SourceState          string         `json:"sourceState"`
	ExpectedOwner        NamespacedName `json:"expectedOwner"`
	ExpectedObjects      []ResourceRef  `json:"expectedObjects,omitempty"`
	MissingSourceBlocker string         `json:"missingSourceBlocker,omitempty"`
}

// Discovery declares the exact Kubernetes collection scopes that must be read
// without label selectors. ExternalObjects are reviewed occupants of a shared
// scope; they are not unmanaged CloudRING resources.
type Discovery struct {
	Mode            string        `json:"mode"`
	Namespaces      []string      `json:"namespaces,omitempty"`
	ExternalObjects []ResourceRef `json:"externalObjects,omitempty"`
}

type ResourceRef struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

type PruneGate struct {
	Kustomizations []NamespacedName `json:"kustomizations"`
}

type NamespacedName struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type DriftProof struct {
	Mode                  string         `json:"mode"`
	Target                ResourceRef    `json:"target"`
	ExpectedOwner         NamespacedName `json:"expectedOwner"`
	RequiredObservations  []string       `json:"requiredObservations"`
	MutationAuthorization string         `json:"mutationAuthorization"`
}

type KustomizationSnapshot struct {
	Namespace           string                `json:"namespace"`
	Name                string                `json:"name"`
	Generation          int64                 `json:"generation"`
	ObservedGeneration  int64                 `json:"observedGeneration"`
	Ready               bool                  `json:"ready"`
	Suspend             *bool                 `json:"suspend"`
	Prune               *bool                 `json:"prune"`
	DeletionPolicy      string                `json:"deletionPolicy"`
	Wait                *bool                 `json:"wait"`
	SourceRef           FluxObjectReference   `json:"sourceRef"`
	Path                string                `json:"path"`
	DependsOn           []FluxObjectReference `json:"dependsOn"`
	LastAppliedRevision string                `json:"lastAppliedRevision"`
	Inventory           []InventoryEntry      `json:"inventory"`
}

// KustomizationCollection is the canonical result of one complete, unfiltered
// all-namespace Flux Kustomization List. ResourceVersionSHA256 binds the opaque
// Kubernetes snapshot without exposing resourceVersion itself.
type KustomizationCollection struct {
	Complete              bool                    `json:"complete"`
	ResourceVersionSHA256 string                  `json:"resourceVersionSHA256"`
	PageCount             int                     `json:"pageCount"`
	ItemCount             int                     `json:"itemCount"`
	Kustomizations        []KustomizationSnapshot `json:"kustomizations"`
}

type InventoryEntry struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type Snapshot struct {
	Kustomizations          []KustomizationSnapshot     `json:"kustomizations"`
	KustomizationsComplete  bool                        `json:"kustomizationsComplete"`
	KustomizationsRVHash    string                      `json:"kustomizationsResourceVersionSHA256"`
	KustomizationsPageCount int                         `json:"kustomizationsPageCount"`
	KustomizationsItemCount int                         `json:"kustomizationsItemCount"`
	Collections             map[string]FamilyCollection `json:"collections"`
	// Resources is retained only so a v1 producer fails closed instead of
	// failing to decode. Verify never uses selector-derived resources.
	Resources                map[string][]ResourceRef `json:"resources,omitempty"`
	SourceArtifact           SourceArtifactSnapshot   `json:"sourceArtifact"`
	AcceptedSourceRevision   string                   `json:"acceptedSourceRevision"`
	AcceptedArtifactDigest   string                   `json:"acceptedArtifactDigest"`
	AcceptedPublicGitlinkSHA string                   `json:"acceptedPublicGitlinkSHA"`
	ObservedPublicGitlinkSHA string                   `json:"observedPublicGitlinkSHA"`
}

// FamilyCollection is a complete, unfiltered list result for one contracted
// resource family. ResourceVersionSHA256 is a domain-separated digest of the
// Kubernetes resourceVersion values and never exposes those opaque values.
type FamilyCollection struct {
	Complete              bool          `json:"complete"`
	ResourceVersionSHA256 string        `json:"resourceVersionSHA256"`
	PageCount             int           `json:"pageCount"`
	ItemCount             int           `json:"itemCount"`
	Objects               []ResourceRef `json:"objects"`
}

type SourceArtifactSnapshot struct {
	Kind               string `json:"kind"`
	Namespace          string `json:"namespace"`
	Name               string `json:"name"`
	Generation         int64  `json:"generation"`
	ObservedGeneration int64  `json:"observedGeneration"`
	Ready              bool   `json:"ready"`
	Revision           string `json:"revision"`
	Digest             string `json:"digest"`
}

type Report struct {
	APIVersion               string               `json:"apiVersion"`
	Kind                     string               `json:"kind"`
	Contract                 string               `json:"contract"`
	Status                   string               `json:"status"`
	RequiredFamilyCount      int                  `json:"requiredFamilyCount"`
	ObservedResourceCount    int                  `json:"observedResourceCount"`
	ManagedResourceCount     int                  `json:"managedResourceCount"`
	AllowlistedResourceCount int                  `json:"allowlistedResourceCount"`
	ExternalResourceCount    int                  `json:"externalResourceCount"`
	UnexpectedResourceCount  int                  `json:"unexpectedResourceCount"`
	UnmanagedResourceCount   int                  `json:"unmanagedResourceCount"`
	ClosedWorldComplete      bool                 `json:"closedWorldComplete"`
	PruneEligible            bool                 `json:"pruneEligible"`
	PruneChanged             bool                 `json:"pruneChanged"`
	LiveMutationPerformed    bool                 `json:"liveMutationPerformed"`
	Families                 []FamilyReport       `json:"families"`
	DriftProof               DriftReport          `json:"driftProof"`
	Blockers                 []Blocker            `json:"blockers,omitempty"`
	Scope                    ScopeReport          `json:"scope"`
	Roots                    []RootReport         `json:"roots"`
	NonClaims                []string             `json:"nonClaims"`
	SourceArtifact           SourceArtifactReport `json:"sourceArtifact"`
}

type SourceArtifactReport struct {
	Kind                     string `json:"kind"`
	Namespace                string `json:"namespace"`
	Name                     string `json:"name"`
	Ready                    bool   `json:"ready"`
	Revision                 string `json:"revision"`
	Digest                   string `json:"digest"`
	AcceptedRevision         string `json:"acceptedRevision"`
	AcceptedDigest           string `json:"acceptedDigest"`
	ExpectedPublicGitlinkSHA string `json:"expectedPublicGitlinkSHA"`
	AcceptedPublicGitlinkSHA string `json:"acceptedPublicGitlinkSHA"`
	ObservedPublicGitlinkSHA string `json:"observedPublicGitlinkSHA"`
	PublicGitlinkExact       bool   `json:"publicGitlinkExact"`
	Exact                    bool   `json:"exact"`
}

type ScopeReport struct {
	Name                        string   `json:"name"`
	Complete                    bool     `json:"complete"`
	AllCriticalFamiliesDeclared bool     `json:"allCriticalFamiliesDeclared"`
	AllSelectedRootsDeclared    bool     `json:"allSelectedRootsDeclared"`
	CriticalFamilyCount         int      `json:"criticalFamilyCount"`
	DeclaredFamilyCount         int      `json:"declaredFamilyCount"`
	SelectedRootCount           int      `json:"selectedRootCount"`
	ObservedRootCount           int      `json:"observedRootCount"`
	AllSelectedRootsObserved    bool     `json:"allSelectedRootsObserved"`
	ClosedWorldComplete         bool     `json:"closedWorldComplete"`
	NonClaim                    string   `json:"nonClaim"`
	SourceMissingFamilies       []string `json:"sourceMissingFamilies,omitempty"`
}

type RootReport struct {
	Namespace           string `json:"namespace"`
	Name                string `json:"name"`
	Observed            bool   `json:"observed"`
	Ready               bool   `json:"ready"`
	Prune               bool   `json:"prune"`
	Suspend             bool   `json:"suspend"`
	LastAppliedRevision string `json:"lastAppliedRevision"`
	SpecSHA256          string `json:"specSHA256"`
	SpecExact           bool   `json:"specExact"`
	InventoryCount      int    `json:"inventoryCount"`
}

type FamilyReport struct {
	ID                    string `json:"id"`
	Critical              bool   `json:"critical"`
	SourceState           string `json:"sourceState"`
	ExpectedCount         int    `json:"expectedCount"`
	ExpectedOwner         string `json:"expectedOwner"`
	ObservedCount         int    `json:"observedCount"`
	ManagedCount          int    `json:"managedCount"`
	AllowlistedCount      int    `json:"allowlistedCount"`
	ExternalCount         int    `json:"externalCount"`
	UnexpectedCount       int    `json:"unexpectedCount"`
	UnmanagedCount        int    `json:"unmanagedCount"`
	DiscoveryMode         string `json:"discoveryMode"`
	DiscoveryScopes       int    `json:"discoveryScopes"`
	CollectionComplete    bool   `json:"collectionComplete"`
	ResourceVersionSHA256 string `json:"resourceVersionSHA256"`
	PageCount             int    `json:"pageCount"`
	ItemCount             int    `json:"itemCount"`
	ClosedWorldComplete   bool   `json:"closedWorldComplete"`
	OwnershipComplete     bool   `json:"ownershipComplete"`
}

type DriftReport struct {
	Mode                  string   `json:"mode"`
	Target                string   `json:"target"`
	ExpectedOwner         string   `json:"expectedOwner"`
	TargetInventoryOwned  bool     `json:"targetInventoryOwned"`
	LiveMutationPerformed bool     `json:"liveMutationPerformed"`
	RequiredObservations  []string `json:"requiredObservations"`
	NextAction            string   `json:"nextAction"`
}

type Blocker struct {
	ID      string `json:"id"`
	Message string `json:"message"`
	Family  string `json:"family,omitempty"`
	Object  string `json:"object,omitempty"`
}
