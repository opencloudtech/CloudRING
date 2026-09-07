// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

type inventoryObject struct {
	Ref   Object
	Value apiObject
}

func (client *Client) list(ctx context.Context, path string, query url.Values) ([]apiObject, error) {
	if query == nil {
		query = url.Values{}
	}
	query.Set("limit", "500")
	result := []apiObject{}
	seen := map[string]bool{}
	for {
		var page struct {
			Items    []apiObject `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		if err := client.request(ctx, http.MethodGet, path, query, nil, &page); err != nil {
			return nil, err
		}
		if len(page.Items) > 500 || len(result)+len(page.Items) > 10000 {
			return nil, errors.New("development API inventory exceeds bound")
		}
		result = append(result, page.Items...)
		if page.Metadata.Continue == "" {
			return result, nil
		}
		if seen[page.Metadata.Continue] || len(page.Metadata.Continue) > 16384 {
			return nil, errors.New("development API pagination is invalid")
		}
		seen[page.Metadata.Continue] = true
		query.Set("continue", page.Metadata.Continue)
	}
}

// Namespace inventory uses served discovery rather than a hand-picked list of
// familiar workloads. An unreadable API or an unknown object prevents delete.
func (client *Client) namespaceInventory(ctx context.Context) ([]inventoryObject, error) {
	type servedVersion struct {
		GroupVersion string `json:"groupVersion"`
		Version      string `json:"version"`
	}
	versions := []string{"v1"}
	var discovery struct {
		Groups []struct {
			Name             string          `json:"name"`
			PreferredVersion servedVersion   `json:"preferredVersion"`
			Versions         []servedVersion `json:"versions"`
		} `json:"groups"`
	}
	if err := client.request(ctx, http.MethodGet, "/apis", nil, nil, &discovery); err != nil {
		return nil, err
	}
	if len(discovery.Groups) > 256 {
		return nil, errors.New("development API discovery exceeds bound")
	}
	seenGroups := map[string]bool{}
	for _, group := range discovery.Groups {
		if !validDNS(group.Name) || seenGroups[group.Name] || len(group.Versions) == 0 || len(group.Versions) > 32 {
			return nil, errors.New("development API group discovery is invalid")
		}
		seenGroups[group.Name] = true
		seenVersions := map[string]bool{}
		for _, version := range group.Versions {
			if !validName(version.Version, 32) || version.GroupVersion != group.Name+"/"+version.Version || seenVersions[version.GroupVersion] {
				return nil, errors.New("development API version discovery is invalid")
			}
			seenVersions[version.GroupVersion] = true
		}
		preferred := group.PreferredVersion
		if !seenVersions[preferred.GroupVersion] || preferred.GroupVersion != group.Name+"/"+preferred.Version {
			return nil, errors.New("development preferred API version is not served")
		}
		// Prefer one representation when a resource serves multiple versions,
		// but discover every version: a resource may exist only outside the
		// group's preferred version (as is valid for multi-version CRDs).
		versions = append(versions, preferred.GroupVersion)
		for _, version := range group.Versions {
			if version.GroupVersion != preferred.GroupVersion {
				versions = append(versions, version.GroupVersion)
			}
		}
		if len(versions) > 1024 {
			return nil, errors.New("development API version count exceeds bound")
		}
	}
	results := []inventoryObject{}
	seenResources := map[string]bool{}
	selectedResources := map[string]string{}
	for _, version := range versions {
		path, apiGroup := "/api/v1", ""
		if version != "v1" {
			group, apiVersion, ok := strings.Cut(version, "/")
			if !ok || !validDNS(group) || !validName(apiVersion, 32) {
				return nil, errors.New("development API discovery is invalid")
			}
			path = "/apis/" + version
			apiGroup = group
		}
		var resources struct {
			GroupVersion string `json:"groupVersion"`
			Resources    []struct {
				Name       string   `json:"name"`
				Kind       string   `json:"kind"`
				Namespaced bool     `json:"namespaced"`
				Verbs      []string `json:"verbs"`
			} `json:"resources"`
		}
		if err := client.request(ctx, http.MethodGet, path, nil, nil, &resources); err != nil {
			return nil, err
		}
		if resources.GroupVersion != version || len(resources.Resources) > 1000 {
			return nil, errors.New("development API discovery version mismatch")
		}
		for _, resource := range resources.Resources {
			if !resource.Namespaced || strings.Contains(resource.Name, "/") || !slices.Contains(resource.Verbs, "delete") && !slices.Contains(resource.Verbs, "deletecollection") {
				continue
			}
			if !slices.Contains(resource.Verbs, "list") {
				return nil, errors.New("deletable development namespace resource cannot be inventoried")
			}
			if !validName(resource.Name, 63) || resource.Kind == "" || len(resource.Kind) > 128 {
				return nil, errors.New("development API resource discovery is invalid")
			}
			if seenResources[version+"/"+resource.Name] {
				return nil, errors.New("duplicate development API resource")
			}
			seenResources[version+"/"+resource.Name] = true
			logicalResource := apiGroup + "/" + resource.Name
			if selectedKind, exists := selectedResources[logicalResource]; exists {
				if selectedKind != resource.Kind {
					return nil, errors.New("development API resource kind differs across versions")
				}
				continue
			}
			selectedResources[logicalResource] = resource.Kind
			objects, err := client.list(ctx, path+"/namespaces/"+client.profile.Target.Namespace+"/"+resource.Name, nil)
			if err != nil {
				return nil, err
			}
			for _, object := range objects {
				meta, ok := metadata(object)
				ref := Object{APIVersion: version, Kind: resource.Kind, Resource: resource.Name, Namespace: client.profile.Target.Namespace, Name: stringField(meta, "name"), UID: stringField(meta, "uid")}
				if !ok || stringField(object, "apiVersion") != version || stringField(object, "kind") != resource.Kind || stringField(meta, "namespace") != ref.Namespace || !validDNS(ref.Name) || !kubernetesUID.MatchString(ref.UID) {
					return nil, errors.New("development namespace inventory identity is invalid")
				}
				results = append(results, inventoryObject{Ref: ref, Value: object})
				if len(results) > 256 {
					return nil, errors.New("development namespace inventory exceeds ownership bound")
				}
			}
		}
	}
	return results, nil
}

func (engine *Engine) classifyInventory(ctx context.Context, items []inventoryObject) ([]Object, error) {
	state := engine.Store.State
	owned := map[string]bool{}
	for _, ref := range state.Objects {
		if ref.UID != "" {
			owned[ref.UID] = true
		}
	}
	for _, ref := range state.DerivedObjects {
		if ref.Namespace != state.Profile.Target.Namespace || !kubernetesUID.MatchString(ref.UID) {
			return nil, ErrConflict
		}
		owned[ref.UID] = true
	}
	// This controller-generated ConfigMap is compared to the exact cluster's
	// kube-system copy; arbitrary similarly named user data is preserved.
	var rootCA apiObject
	for _, item := range items {
		if item.Ref.APIVersion == "v1" && item.Ref.Kind == "ConfigMap" && item.Ref.Name == "kube-root-ca.crt" {
			object, err := engine.Client.get(ctx, Object{APIVersion: "v1", Kind: "ConfigMap", Resource: "configmaps", Namespace: "kube-system", Name: "kube-root-ca.crt"})
			if err != nil {
				return nil, err
			}
			rootCA = nested(object, "data")
		}
	}
	for _, item := range items {
		if owned[item.Ref.UID] {
			continue
		}
		if item.Ref.APIVersion == "v1" && item.Ref.Kind == "ServiceAccount" && item.Ref.Name == "default" {
			secrets, _ := item.Value["secrets"].([]any)
			pull, _ := item.Value["imagePullSecrets"].([]any)
			meta, _ := metadata(item.Value)
			owners, _ := meta["ownerReferences"].([]any)
			if len(secrets) == 0 && len(pull) == 0 && len(owners) == 0 {
				owned[item.Ref.UID] = true
			}
		}
		if item.Ref.APIVersion == "v1" && item.Ref.Kind == "ConfigMap" && item.Ref.Name == "kube-root-ca.crt" && len(rootCA) == 1 && len(nested(item.Value, "data")) == 1 &&
			stringField(rootCA, "ca.crt") != "" && stringField(nested(item.Value, "data"), "ca.crt") == stringField(rootCA, "ca.crt") {
			owned[item.Ref.UID] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, item := range items {
			if owned[item.Ref.UID] {
				continue
			}
			meta, _ := metadata(item.Value)
			references, _ := meta["ownerReferences"].([]any)
			allOwned := len(references) > 0
			for _, value := range references {
				owner, _ := value.(map[string]any)
				if !owned[stringField(owner, "uid")] {
					allOwned = false
				}
			}
			if allOwned {
				owned[item.Ref.UID] = true
				changed = true
				continue
			}
			if item.Ref.Kind == "Event" {
				uid := stringField(nested(item.Value, "involvedObject"), "uid")
				if uid == "" {
					uid = stringField(nested(item.Value, "regarding"), "uid")
				}
				if owned[uid] {
					owned[item.Ref.UID] = true
					changed = true
				}
			}
		}
	}
	refs := []Object{}
	for _, item := range items {
		if !owned[item.Ref.UID] {
			return nil, errors.New("foreign namespace content prevents development destruction")
		}
		refs = append(refs, item.Ref)
	}
	return refs, nil
}
