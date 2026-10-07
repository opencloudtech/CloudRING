// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package gitopsownership

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	CollectionPageLimit       = 500
	FluxKustomizationVersion  = "kustomize.toolkit.fluxcd.io/v1"
	FluxKustomizationKind     = "Kustomization"
	FluxKustomizationResource = "kustomizations"
	maxCollectionPages        = 100
	maxCollectionObjects      = 100_000
	maxCollectionPageBytes    = 16 << 20
	maxCollectionRestarts     = 3
	maxCollectionContinueSize = 4 << 10
)

// CollectionRequest describes one read-only Kubernetes List request. The first
// request in each scope always has ResourceVersion "0" and no Continue token.
// Follow-up requests use only the opaque Continue token returned by the API.
type CollectionRequest struct {
	APIVersion      string
	Resource        string
	Namespace       string
	AllNamespaces   bool
	Limit           int
	ResourceVersion string
	Continue        string
}

// CollectionPageReader is implemented downstream using a read-only Kubernetes
// API client. It must not add label or field selectors.
type CollectionPageReader interface {
	ReadCollectionPage(context.Context, CollectionRequest) ([]byte, error)
}

// CollectionStatusError lets a downstream reader preserve an HTTP status
// without exposing response bodies. HTTP 410 triggers a clean full restart of
// the affected collection scope.
type CollectionStatusError struct {
	Code int
	Err  error
}

func (err CollectionStatusError) Error() string {
	if err.Err == nil {
		return fmt.Sprintf("collection request failed with status %d", err.Code)
	}
	return fmt.Sprintf("collection request failed with status %d: %v", err.Code, err.Err)
}

func (err CollectionStatusError) Unwrap() error {
	return err.Err
}

func (err CollectionStatusError) StatusCode() int {
	return err.Code
}

type collectionStatusCoder interface {
	StatusCode() int
}

type rawListPage struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		ResourceVersion string `json:"resourceVersion"`
		Continue        string `json:"continue"`
	} `json:"metadata"`
	Items []struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"metadata"`
	} `json:"items"`
}

type collectedScope struct {
	namespace       string
	resourceVersion string
	pageCount       int
	objects         []ResourceRef
}

type rawKustomizationListPage struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		ResourceVersion string `json:"resourceVersion"`
		Continue        string `json:"continue"`
	} `json:"metadata"`
	Items []json.RawMessage `json:"items"`
}

type rawKustomization struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		Generation int64  `json:"generation"`
	} `json:"metadata"`
	Spec struct {
		Suspend        *bool  `json:"suspend"`
		Prune          *bool  `json:"prune"`
		DeletionPolicy string `json:"deletionPolicy"`
		Wait           *bool  `json:"wait"`
		SourceRef      struct {
			Kind      string `json:"kind"`
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"sourceRef"`
		Path      string `json:"path"`
		DependsOn []struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"dependsOn"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration  int64  `json:"observedGeneration"`
		LastAppliedRevision string `json:"lastAppliedRevision"`
		Conditions          []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
		Inventory struct {
			Entries []struct {
				ID      string `json:"id"`
				Version string `json:"v"`
			} `json:"entries"`
		} `json:"inventory"`
	} `json:"status"`
}

// CollectKustomizations performs the canonical bounded, unfiltered,
// all-namespace Flux Kustomization List used by Verify. A 410 response discards
// every page and restarts at resourceVersion=0; no label or field selector is
// representable in CollectionRequest.
func CollectKustomizations(ctx context.Context, reader CollectionPageReader) (KustomizationCollection, error) {
	if reader == nil {
		return KustomizationCollection{}, errors.New("Flux Kustomization collection reader is required")
	}
	for restart := 0; restart <= maxCollectionRestarts; restart++ {
		collection := KustomizationCollection{}
		continueToken := ""
		resourceVersion := ""
		seenContinue := map[string]bool{}
		seenObjects := map[string]bool{}
		restartRequired := false
		for {
			request := CollectionRequest{
				APIVersion:    FluxKustomizationVersion,
				Resource:      FluxKustomizationResource,
				AllNamespaces: true,
				Limit:         CollectionPageLimit,
				Continue:      continueToken,
			}
			if continueToken == "" {
				request.ResourceVersion = "0"
			}
			payload, err := reader.ReadCollectionPage(ctx, request)
			if err != nil {
				if collectionStatusCode(err) == 410 {
					restartRequired = true
					break
				}
				return KustomizationCollection{}, errors.New("all-namespace Flux Kustomization collection request failed")
			}
			if len(payload) == 0 || len(payload) > maxCollectionPageBytes {
				return KustomizationCollection{}, errors.New("all-namespace Flux Kustomization collection page is empty or oversized")
			}
			var page rawKustomizationListPage
			if err := json.Unmarshal(payload, &page); err != nil {
				return KustomizationCollection{}, errors.New("all-namespace Flux Kustomization collection page is invalid JSON")
			}
			if page.APIVersion != FluxKustomizationVersion || page.Kind != FluxKustomizationKind+"List" {
				return KustomizationCollection{}, errors.New("all-namespace Flux Kustomization list identity is invalid")
			}
			if strings.TrimSpace(page.Metadata.ResourceVersion) == "" {
				return KustomizationCollection{}, errors.New("all-namespace Flux Kustomization collection page lacks resourceVersion")
			}
			if resourceVersion == "" {
				resourceVersion = page.Metadata.ResourceVersion
			} else if resourceVersion != page.Metadata.ResourceVersion {
				return KustomizationCollection{}, errors.New("all-namespace Flux Kustomization resourceVersion changed between pages")
			}
			collection.PageCount++
			if collection.PageCount > maxCollectionPages {
				return KustomizationCollection{}, errors.New("all-namespace Flux Kustomization collection exceeded page bound")
			}
			for _, raw := range page.Items {
				root, err := decodeKustomization(raw)
				if err != nil {
					return KustomizationCollection{}, err
				}
				key := namespacedNameKey(NamespacedName{Namespace: root.Namespace, Name: root.Name})
				if seenObjects[key] {
					return KustomizationCollection{}, errors.New("all-namespace Flux Kustomization collection returned a duplicate object")
				}
				seenObjects[key] = true
				collection.Kustomizations = append(collection.Kustomizations, root)
				if len(collection.Kustomizations) > maxCollectionObjects {
					return KustomizationCollection{}, errors.New("all-namespace Flux Kustomization collection exceeded object bound")
				}
			}
			next := page.Metadata.Continue
			if len(next) > maxCollectionContinueSize {
				return KustomizationCollection{}, errors.New("all-namespace Flux Kustomization continue token is oversized")
			}
			if next == "" {
				sort.Slice(collection.Kustomizations, func(i, j int) bool {
					left := NamespacedName{Namespace: collection.Kustomizations[i].Namespace, Name: collection.Kustomizations[i].Name}
					right := NamespacedName{Namespace: collection.Kustomizations[j].Namespace, Name: collection.Kustomizations[j].Name}
					return namespacedNameKey(left) < namespacedNameKey(right)
				})
				collection.Complete = true
				collection.ItemCount = len(collection.Kustomizations)
				collection.ResourceVersionSHA256 = opaqueResourceVersionDigest(
					"cloudring.gitopsownership.kustomization-resource-version/v2",
					resourceVersion,
				)
				return collection, nil
			}
			if next == continueToken || seenContinue[next] {
				return KustomizationCollection{}, errors.New("all-namespace Flux Kustomization collection repeated a continue token")
			}
			seenContinue[next] = true
			continueToken = next
		}
		if !restartRequired {
			return KustomizationCollection{}, errors.New("all-namespace Flux Kustomization collection ended without a complete page")
		}
	}
	return KustomizationCollection{}, errors.New("all-namespace Flux Kustomization collection repeatedly expired")
}

func decodeKustomization(data []byte) (KustomizationSnapshot, error) {
	var raw rawKustomization
	if err := json.Unmarshal(data, &raw); err != nil {
		return KustomizationSnapshot{}, errors.New("Flux Kustomization item is invalid JSON")
	}
	if raw.APIVersion != FluxKustomizationVersion || raw.Kind != FluxKustomizationKind ||
		!validDNSLabel(raw.Metadata.Namespace) || !validDNSLabel(raw.Metadata.Name) {
		return KustomizationSnapshot{}, errors.New("Flux Kustomization item identity is invalid")
	}
	ready := false
	readySeen := false
	for _, condition := range raw.Status.Conditions {
		if condition.Type != "Ready" {
			continue
		}
		if readySeen || (condition.Status != "True" && condition.Status != "False" && condition.Status != "Unknown") {
			return KustomizationSnapshot{}, errors.New("Flux Kustomization Ready condition is ambiguous")
		}
		readySeen = true
		ready = condition.Status == "True"
	}
	sourceNamespace := raw.Spec.SourceRef.Namespace
	if sourceNamespace == "" {
		sourceNamespace = raw.Metadata.Namespace
	}
	root := KustomizationSnapshot{
		Namespace:          raw.Metadata.Namespace,
		Name:               raw.Metadata.Name,
		Generation:         raw.Metadata.Generation,
		ObservedGeneration: raw.Status.ObservedGeneration,
		Ready:              ready,
		Suspend:            raw.Spec.Suspend,
		Prune:              raw.Spec.Prune,
		DeletionPolicy:     raw.Spec.DeletionPolicy,
		Wait:               raw.Spec.Wait,
		SourceRef: FluxObjectReference{
			Kind:      raw.Spec.SourceRef.Kind,
			Namespace: sourceNamespace,
			Name:      raw.Spec.SourceRef.Name,
		},
		Path:                raw.Spec.Path,
		LastAppliedRevision: raw.Status.LastAppliedRevision,
		DependsOn:           make([]FluxObjectReference, 0, len(raw.Spec.DependsOn)),
		Inventory:           make([]InventoryEntry, 0, len(raw.Status.Inventory.Entries)),
	}
	for _, dependency := range raw.Spec.DependsOn {
		namespace := dependency.Namespace
		if namespace == "" {
			namespace = raw.Metadata.Namespace
		}
		root.DependsOn = append(root.DependsOn, FluxObjectReference{
			Kind:      FluxKustomizationKind,
			Namespace: namespace,
			Name:      dependency.Name,
		})
	}
	for _, entry := range raw.Status.Inventory.Entries {
		root.Inventory = append(root.Inventory, InventoryEntry{ID: entry.ID, Version: entry.Version})
	}
	return root, nil
}

// CollectFamily performs a bounded, unfiltered, closed-world List over every
// namespace declared by a sourced family (or once for a cluster-scoped family).
// A 410 response discards all pages from that scope and restarts from page one.
func CollectFamily(ctx context.Context, family ResourceFamily, reader CollectionPageReader) (FamilyCollection, error) {
	if reader == nil {
		return FamilyCollection{}, errors.New("closed-world collection reader is required")
	}
	if family.SourceState != "sourced" || family.Discovery.Mode != DiscoveryModeClosedWorld {
		return FamilyCollection{}, errors.New("closed-world collection requires a sourced family with discovery.mode=closed-world")
	}
	namespaces := append([]string(nil), family.Discovery.Namespaces...)
	if !family.Namespaced {
		namespaces = []string{""}
	}
	if family.Namespaced && len(namespaces) == 0 {
		return FamilyCollection{}, errors.New("namespaced closed-world collection requires at least one namespace")
	}
	sort.Strings(namespaces)
	seenNamespace := map[string]bool{}
	scopes := make([]collectedScope, 0, len(namespaces))
	totalPages := 0
	totalObjects := 0
	seenObjects := map[string]bool{}
	for _, namespace := range namespaces {
		if seenNamespace[namespace] {
			return FamilyCollection{}, errors.New("closed-world collection namespaces must be unique")
		}
		seenNamespace[namespace] = true
		scope, err := collectScope(ctx, family, namespace, reader)
		if err != nil {
			return FamilyCollection{}, err
		}
		totalPages += scope.pageCount
		totalObjects += len(scope.objects)
		if totalPages > maxCollectionPages || totalObjects > maxCollectionObjects {
			return FamilyCollection{}, errors.New("closed-world family collection exceeded global bounds")
		}
		for _, ref := range scope.objects {
			key := refKey(ref)
			if seenObjects[key] {
				return FamilyCollection{}, errors.New("closed-world family collection returned a duplicate object")
			}
			seenObjects[key] = true
		}
		scopes = append(scopes, scope)
	}
	objects := make([]ResourceRef, 0, totalObjects)
	for _, scope := range scopes {
		objects = append(objects, scope.objects...)
	}
	sort.Slice(objects, func(i, j int) bool { return refKey(objects[i]) < refKey(objects[j]) })
	return FamilyCollection{
		Complete:              true,
		ResourceVersionSHA256: collectionResourceVersionDigest(family, scopes),
		PageCount:             totalPages,
		ItemCount:             len(objects),
		Objects:               objects,
	}, nil
}

func collectScope(ctx context.Context, family ResourceFamily, namespace string, reader CollectionPageReader) (collectedScope, error) {
	for restart := 0; restart <= maxCollectionRestarts; restart++ {
		scope := collectedScope{namespace: namespace}
		continueToken := ""
		seenContinue := map[string]bool{}
		seenObjects := map[string]bool{}
		restartRequired := false
		for {
			request := CollectionRequest{
				APIVersion: family.APIVersion,
				Resource:   family.Resource,
				Namespace:  namespace,
				Limit:      CollectionPageLimit,
				Continue:   continueToken,
			}
			if continueToken == "" {
				request.ResourceVersion = "0"
			}
			payload, err := reader.ReadCollectionPage(ctx, request)
			if err != nil {
				if collectionStatusCode(err) == 410 {
					restartRequired = true
					break
				}
				return collectedScope{}, errors.New("closed-world Kubernetes collection request failed")
			}
			if len(payload) == 0 || len(payload) > maxCollectionPageBytes {
				return collectedScope{}, errors.New("closed-world Kubernetes collection page is empty or oversized")
			}
			var page rawListPage
			if err := json.Unmarshal(payload, &page); err != nil {
				return collectedScope{}, errors.New("closed-world Kubernetes collection page is invalid JSON")
			}
			if page.APIVersion != family.APIVersion || page.Kind != family.Kind+"List" {
				return collectedScope{}, errors.New("closed-world Kubernetes collection list identity does not match the contracted family")
			}
			if strings.TrimSpace(page.Metadata.ResourceVersion) == "" {
				return collectedScope{}, errors.New("closed-world Kubernetes collection page lacks resourceVersion")
			}
			if scope.resourceVersion == "" {
				scope.resourceVersion = page.Metadata.ResourceVersion
			} else if scope.resourceVersion != page.Metadata.ResourceVersion {
				return collectedScope{}, errors.New("closed-world Kubernetes collection resourceVersion changed between pages")
			}
			scope.pageCount++
			if scope.pageCount > maxCollectionPages {
				return collectedScope{}, errors.New("closed-world Kubernetes collection exceeded page bound")
			}
			for _, item := range page.Items {
				ref := ResourceRef{
					APIVersion: item.APIVersion,
					Kind:       item.Kind,
					Namespace:  item.Metadata.Namespace,
					Name:       item.Metadata.Name,
				}
				if !refInFamilyScope(ref, family) || (family.Namespaced && ref.Namespace != namespace) {
					return collectedScope{}, errors.New("closed-world Kubernetes collection item is outside the requested family scope")
				}
				if err := validateRef(ref); err != nil {
					return collectedScope{}, errors.New("closed-world Kubernetes collection item identity is invalid")
				}
				key := refKey(ref)
				if seenObjects[key] {
					return collectedScope{}, errors.New("closed-world Kubernetes collection returned a duplicate object")
				}
				seenObjects[key] = true
				scope.objects = append(scope.objects, ref)
				if len(scope.objects) > maxCollectionObjects {
					return collectedScope{}, errors.New("closed-world Kubernetes collection exceeded object bound")
				}
			}
			next := page.Metadata.Continue
			if len(next) > maxCollectionContinueSize {
				return collectedScope{}, errors.New("closed-world Kubernetes collection continue token is oversized")
			}
			if next == "" {
				sort.Slice(scope.objects, func(i, j int) bool {
					return refKey(scope.objects[i]) < refKey(scope.objects[j])
				})
				return scope, nil
			}
			if next == continueToken || seenContinue[next] {
				return collectedScope{}, errors.New("closed-world Kubernetes collection repeated a continue token")
			}
			seenContinue[next] = true
			continueToken = next
		}
		if !restartRequired {
			return scope, nil
		}
	}
	return collectedScope{}, errors.New("closed-world Kubernetes collection repeatedly expired")
}

func collectionStatusCode(err error) int {
	var status collectionStatusCoder
	if errors.As(err, &status) {
		return status.StatusCode()
	}
	return 0
}

func collectionResourceVersionDigest(family ResourceFamily, scopes []collectedScope) string {
	hash := sha256.New()
	hash.Write([]byte("cloudring.gitopsownership.collection-resource-version/v2\x00"))
	hash.Write([]byte(family.APIVersion))
	hash.Write([]byte{0})
	hash.Write([]byte(family.Resource))
	hash.Write([]byte{0})
	for _, scope := range scopes {
		hash.Write([]byte(scope.namespace))
		hash.Write([]byte{0})
		hash.Write([]byte(scope.resourceVersion))
		hash.Write([]byte{0})
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}

func opaqueResourceVersionDigest(domain, resourceVersion string) string {
	hash := sha256.New()
	hash.Write([]byte(domain))
	hash.Write([]byte{0})
	hash.Write([]byte(resourceVersion))
	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}
