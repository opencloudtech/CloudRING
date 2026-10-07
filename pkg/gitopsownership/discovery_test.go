// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package gitopsownership

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type scriptedCollectionResult struct {
	payload []byte
	err     error
}

type scriptedCollectionReader struct {
	t        *testing.T
	results  []scriptedCollectionResult
	requests []CollectionRequest
}

func (reader *scriptedCollectionReader) ReadCollectionPage(_ context.Context, request CollectionRequest) ([]byte, error) {
	reader.t.Helper()
	reader.requests = append(reader.requests, request)
	if len(reader.results) == 0 {
		reader.t.Fatal("unexpected collection request")
	}
	result := reader.results[0]
	reader.results = reader.results[1:]
	return result.payload, result.err
}

func TestCollectFamilyPaginatesWithoutSelectors(t *testing.T) {
	family := discoveryTestFamily()
	first := ResourceRef{APIVersion: family.APIVersion, Kind: family.Kind, Namespace: "platform-system", Name: "api"}
	second := ResourceRef{APIVersion: family.APIVersion, Kind: family.Kind, Namespace: "platform-system", Name: "portal"}
	reader := &scriptedCollectionReader{t: t, results: []scriptedCollectionResult{
		{payload: collectionPage(t, family, "101", "opaque-next", first)},
		{payload: collectionPage(t, family, "101", "", second)},
	}}

	collection, err := CollectFamily(context.Background(), family, reader)
	if err != nil {
		t.Fatalf("CollectFamily returned error: %v", err)
	}
	if !collection.Complete || collection.PageCount != 2 || collection.ItemCount != 2 ||
		!artifactDigestPattern.MatchString(collection.ResourceVersionSHA256) {
		t.Fatalf("collection is not a complete bounded receipt: %+v", collection)
	}
	if len(reader.requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(reader.requests))
	}
	if request := reader.requests[0]; request.Limit != CollectionPageLimit || request.ResourceVersion != "0" || request.Continue != "" {
		t.Fatalf("first request = %+v, want limit=500 resourceVersion=0 and no continue", request)
	}
	if request := reader.requests[1]; request.Limit != CollectionPageLimit || request.ResourceVersion != "" || request.Continue != "opaque-next" {
		t.Fatalf("follow-up request = %+v, want only opaque continue token", request)
	}
}

func TestCollectFamilyDiscardsExpiredPaginationBeforeRestart(t *testing.T) {
	family := discoveryTestFamily()
	stale := ResourceRef{APIVersion: family.APIVersion, Kind: family.Kind, Namespace: "platform-system", Name: "stale"}
	current := ResourceRef{APIVersion: family.APIVersion, Kind: family.Kind, Namespace: "platform-system", Name: "current"}
	reader := &scriptedCollectionReader{t: t, results: []scriptedCollectionResult{
		{payload: collectionPage(t, family, "old", "next", stale)},
		{err: CollectionStatusError{Code: 410}},
		{payload: collectionPage(t, family, "new", "", current)},
	}}

	collection, err := CollectFamily(context.Background(), family, reader)
	if err != nil {
		t.Fatalf("CollectFamily returned error: %v", err)
	}
	if collection.ItemCount != 1 || len(collection.Objects) != 1 || collection.Objects[0] != current {
		t.Fatalf("expired snapshot was spliced into restarted collection: %+v", collection)
	}
	if len(reader.requests) != 3 || reader.requests[2].ResourceVersion != "0" || reader.requests[2].Continue != "" {
		t.Fatalf("410 did not restart at page one: %+v", reader.requests)
	}
}

func TestCollectFamilyRejectsInconsistentOrAmbiguousPages(t *testing.T) {
	family := discoveryTestFamily()
	object := ResourceRef{APIVersion: family.APIVersion, Kind: family.Kind, Namespace: "platform-system", Name: "api"}
	tests := []struct {
		name    string
		results []scriptedCollectionResult
	}{
		{
			name: "resource version changed",
			results: []scriptedCollectionResult{
				{payload: collectionPage(t, family, "101", "next", object)},
				{payload: collectionPage(t, family, "102", "")},
			},
		},
		{
			name: "duplicate object across pages",
			results: []scriptedCollectionResult{
				{payload: collectionPage(t, family, "101", "next", object)},
				{payload: collectionPage(t, family, "101", "", object)},
			},
		},
		{
			name: "continue loop",
			results: []scriptedCollectionResult{
				{payload: collectionPage(t, family, "101", "next")},
				{payload: collectionPage(t, family, "101", "next")},
			},
		},
		{
			name: "wrong list kind",
			results: []scriptedCollectionResult{
				{payload: []byte(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"101"},"items":[]}`)},
			},
		},
		{
			name: "item outside namespace",
			results: []scriptedCollectionResult{
				{payload: collectionPage(t, family, "101", "", ResourceRef{
					APIVersion: family.APIVersion, Kind: family.Kind, Namespace: "other", Name: "api",
				})},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &scriptedCollectionReader{t: t, results: test.results}
			if _, err := CollectFamily(context.Background(), family, reader); err == nil {
				t.Fatal("CollectFamily accepted an inconsistent collection")
			}
		})
	}
}

func TestCollectFamilyFailsClosedAfterRepeatedExpiration(t *testing.T) {
	family := discoveryTestFamily()
	results := make([]scriptedCollectionResult, maxCollectionRestarts+1)
	for index := range results {
		results[index].err = CollectionStatusError{Code: 410, Err: errors.New("expired")}
	}
	reader := &scriptedCollectionReader{t: t, results: results}
	if _, err := CollectFamily(context.Background(), family, reader); err == nil {
		t.Fatal("CollectFamily accepted repeatedly expired pagination")
	}
}

func TestCollectKustomizationsPaginatesAllNamespacesWithoutSelectors(t *testing.T) {
	revision := "main@sha1:" + strings.Repeat("a", 40)
	reader := &scriptedCollectionReader{t: t, results: []scriptedCollectionResult{
		{payload: kustomizationPage(t, "101", "opaque-next", makeTestKustomization("flux-system", "foundation", revision))},
		{payload: kustomizationPage(t, "101", "", makeTestKustomization("flux-system", "portal", revision))},
	}}
	collection, err := CollectKustomizations(context.Background(), reader)
	if err != nil {
		t.Fatalf("CollectKustomizations returned error: %v", err)
	}
	if !collection.Complete || collection.PageCount != 2 || collection.ItemCount != 2 || !artifactDigestPattern.MatchString(collection.ResourceVersionSHA256) {
		t.Fatalf("collection is not a complete bounded receipt: %+v", collection)
	}
	if len(reader.requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(reader.requests))
	}
	if request := reader.requests[0]; request.APIVersion != FluxKustomizationVersion || request.Resource != FluxKustomizationResource || !request.AllNamespaces || request.Limit != CollectionPageLimit || request.ResourceVersion != "0" || request.Continue != "" {
		t.Fatalf("first request = %+v, want unfiltered all-namespace resourceVersion=0", request)
	}
	if request := reader.requests[1]; request.ResourceVersion != "" || request.Continue != "opaque-next" || !request.AllNamespaces {
		t.Fatalf("follow-up request = %+v, want only opaque continue token", request)
	}
	if collection.Kustomizations[0].Name != "foundation" || collection.Kustomizations[1].Name != "portal" {
		t.Fatalf("kustomizations were not canonicalized: %+v", collection.Kustomizations)
	}
}

func TestCollectKustomizationsDiscardsExpiredPagesBeforeRestart(t *testing.T) {
	revision := "main@sha1:" + strings.Repeat("a", 40)
	reader := &scriptedCollectionReader{t: t, results: []scriptedCollectionResult{
		{payload: kustomizationPage(t, "old", "next", makeTestKustomization("flux-system", "stale", revision))},
		{err: CollectionStatusError{Code: 410}},
		{payload: kustomizationPage(t, "new", "", makeTestKustomization("flux-system", "current", revision))},
	}}
	collection, err := CollectKustomizations(context.Background(), reader)
	if err != nil {
		t.Fatalf("CollectKustomizations returned error: %v", err)
	}
	if collection.ItemCount != 1 || len(collection.Kustomizations) != 1 || collection.Kustomizations[0].Name != "current" {
		t.Fatalf("expired snapshot was spliced into restarted collection: %+v", collection)
	}
	if len(reader.requests) != 3 || reader.requests[2].ResourceVersion != "0" || reader.requests[2].Continue != "" {
		t.Fatalf("410 did not restart at page one: %+v", reader.requests)
	}
}

func TestCollectKustomizationsRejectsAmbiguousReadyAndDuplicates(t *testing.T) {
	revision := "main@sha1:" + strings.Repeat("a", 40)
	ambiguous := makeTestKustomization("flux-system", "foundation", revision)
	ambiguous.Status.Conditions = append(ambiguous.Status.Conditions, struct {
		Type   string `json:"type"`
		Status string `json:"status"`
	}{Type: "Ready", Status: "False"})
	for _, test := range []struct {
		name    string
		results []scriptedCollectionResult
	}{
		{name: "ambiguous ready", results: []scriptedCollectionResult{{payload: kustomizationPage(t, "101", "", ambiguous)}}},
		{name: "duplicate object", results: []scriptedCollectionResult{{payload: kustomizationPage(t, "101", "", makeTestKustomization("flux-system", "foundation", revision), makeTestKustomization("flux-system", "foundation", revision))}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &scriptedCollectionReader{t: t, results: test.results}
			if _, err := CollectKustomizations(context.Background(), reader); err == nil {
				t.Fatal("accepted an invalid all-namespace Kustomization collection")
			}
		})
	}
}

func discoveryTestFamily() ResourceFamily {
	return ResourceFamily{
		ID:          "services",
		APIVersion:  "v1",
		Kind:        "Service",
		Resource:    "services",
		Namespaced:  true,
		SourceState: "sourced",
		Discovery:   Discovery{Mode: DiscoveryModeClosedWorld, Namespaces: []string{"platform-system"}},
	}
}

type testKustomizationItem struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		Generation int64  `json:"generation"`
	} `json:"metadata"`
	Spec struct {
		Suspend   *bool `json:"suspend"`
		Prune     *bool `json:"prune"`
		Wait      *bool `json:"wait"`
		SourceRef struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"sourceRef"`
		Path string `json:"path"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration  int64  `json:"observedGeneration"`
		LastAppliedRevision string `json:"lastAppliedRevision"`
		Conditions          []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
	} `json:"status"`
}

func makeTestKustomization(namespace, name, revision string) testKustomizationItem {
	active := false
	prune := false
	wait := true
	item := testKustomizationItem{APIVersion: FluxKustomizationVersion, Kind: FluxKustomizationKind}
	item.Metadata.Namespace, item.Metadata.Name, item.Metadata.Generation = namespace, name, 1
	item.Spec.Suspend, item.Spec.Prune, item.Spec.Wait = &active, &prune, &wait
	item.Spec.SourceRef.Kind, item.Spec.SourceRef.Name = "GitRepository", "cloudring"
	item.Spec.Path = "./" + name
	item.Status.ObservedGeneration, item.Status.LastAppliedRevision = 1, revision
	item.Status.Conditions = []struct {
		Type   string `json:"type"`
		Status string `json:"status"`
	}{{Type: "Ready", Status: "True"}}
	return item
}

func kustomizationPage(t *testing.T, resourceVersion, next string, objects ...testKustomizationItem) []byte {
	t.Helper()
	payload := struct {
		APIVersion string                  `json:"apiVersion"`
		Kind       string                  `json:"kind"`
		Metadata   map[string]string       `json:"metadata"`
		Items      []testKustomizationItem `json:"items"`
	}{APIVersion: FluxKustomizationVersion, Kind: FluxKustomizationKind + "List", Metadata: map[string]string{"resourceVersion": resourceVersion}, Items: objects}
	if next != "" {
		payload.Metadata["continue"] = next
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func collectionPage(t *testing.T, family ResourceFamily, resourceVersion, next string, objects ...ResourceRef) []byte {
	t.Helper()
	type item struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Namespace string `json:"namespace,omitempty"`
			Name      string `json:"name"`
		} `json:"metadata"`
	}
	items := make([]item, 0, len(objects))
	for _, object := range objects {
		value := item{APIVersion: object.APIVersion, Kind: object.Kind}
		value.Metadata.Namespace = object.Namespace
		value.Metadata.Name = object.Name
		items = append(items, value)
	}
	payload := struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			ResourceVersion string `json:"resourceVersion"`
			Continue        string `json:"continue,omitempty"`
		} `json:"metadata"`
		Items []item `json:"items"`
	}{APIVersion: family.APIVersion, Kind: family.Kind + "List", Items: items}
	payload.Metadata.ResourceVersion = resourceVersion
	payload.Metadata.Continue = next
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
