// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maximumAPIBytes = 8 << 20

type Client struct {
	profile   Profile
	http      *http.Client
	transport *http.Transport
	bearer    string
}

// APIError exposes only a status code. API bodies can include Secret contents
// or broad cluster information and are never returned as diagnostic strings.
type APIError struct{ StatusCode int }

func (err *APIError) Error() string {
	return fmt.Sprintf("development substrate API returned HTTP %d", err.StatusCode)
}
func apiStatus(err error, status int) bool {
	var result *APIError
	return errors.As(err, &result) && result.StatusCode == status
}

func (client *Client) Close() error {
	if client != nil && client.transport != nil {
		client.transport.CloseIdleConnections()
		client.bearer = ""
	}
	return nil
}

func (client *Client) request(ctx context.Context, method, path string, query url.Values, payload any, result any) error {
	if client == nil || client.http == nil || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\\") {
		return errors.New("invalid development API request")
	}
	requestCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil || len(body) > maximumAPIBytes {
			return errors.New("development API payload exceeds bound")
		}
		defer clear(body)
	}
	location := strings.TrimSuffix(client.profile.Target.APIServer, "/") + path
	if len(query) > 0 {
		location += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(requestCtx, method, location, bytes.NewReader(body))
	if err != nil {
		return errors.New("construct development API request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "cloudring-development/1")
	if client.bearer != "" {
		request.Header.Set("Authorization", "Bearer "+client.bearer)
	}
	response, err := client.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("development substrate API transport failed")
	}
	defer response.Body.Close()
	if err := requestCtx.Err(); err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &APIError{StatusCode: response.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maximumAPIBytes+1))
	defer clear(data)
	if err := requestCtx.Err(); err != nil {
		return err
	}
	if err != nil || len(data) > maximumAPIBytes {
		return errors.New("development API response exceeds bound")
	}
	if result != nil && json.Unmarshal(data, result) != nil {
		return errors.New("development API returned invalid JSON")
	}
	return nil
}

func objectPath(ref Object, collection bool) (string, error) {
	if !validDNS(ref.Name) || !validName(ref.Resource, 63) || ref.Namespace != "" && !validName(ref.Namespace, 63) {
		return "", ErrConflict
	}
	var path string
	if ref.APIVersion == "v1" {
		path = "/api/v1"
	} else {
		group, version, ok := strings.Cut(ref.APIVersion, "/")
		if !ok || !validDNS(group) || !validName(version, 32) {
			return "", ErrConflict
		}
		path = "/apis/" + group + "/" + version
	}
	if ref.Namespace != "" {
		path += "/namespaces/" + ref.Namespace
	}
	path += "/" + ref.Resource
	if !collection {
		path += "/" + ref.Name
	}
	return path, nil
}

func (client *Client) get(ctx context.Context, ref Object) (apiObject, error) {
	path, err := objectPath(ref, false)
	if err != nil {
		return nil, err
	}
	var object apiObject
	if err := client.request(ctx, http.MethodGet, path, nil, nil, &object); err != nil {
		return nil, err
	}
	return object, nil
}

func (client *Client) create(ctx context.Context, ref Object, object apiObject, dryRun bool) (apiObject, error) {
	meta, ok := metadata(object)
	if !client.allowed(ref) || !ok || stringField(meta, "name") != ref.Name || stringField(meta, "namespace") != ref.Namespace ||
		stringField(object, "apiVersion") != ref.APIVersion || stringField(object, "kind") != ref.Kind ||
		stringField(nested(meta, "labels"), OwnerLabel) != client.profile.InstallationID ||
		stringField(nested(meta, "annotations"), ProfileAnnotation) != Fingerprint(client.profile) ||
		!hexDigest.MatchString(stringField(nested(meta, "annotations"), OwnerAnnotation)) {
		return nil, ErrConflict
	}
	path, err := objectPath(ref, true)
	if err != nil {
		return nil, err
	}
	query := url.Values{"fieldValidation": {"Strict"}, "fieldManager": {"cloudring-development"}}
	if dryRun {
		query.Set("dryRun", "All")
	}
	var result apiObject
	if err := client.request(ctx, http.MethodPost, path, query, object, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (client *Client) delete(ctx context.Context, ref Object, resourceVersion string) error {
	if !client.allowed(ref) || !kubernetesUID.MatchString(ref.UID) || resourceVersion == "" || len(resourceVersion) > 128 {
		return ErrConflict
	}
	path, err := objectPath(ref, false)
	if err != nil {
		return err
	}
	return client.request(ctx, http.MethodDelete, path, nil, apiObject{"apiVersion": "v1", "kind": "DeleteOptions",
		"propagationPolicy": "Foreground", "preconditions": map[string]string{"uid": ref.UID, "resourceVersion": resourceVersion}}, nil)
}

func (client *Client) allowed(ref Object) bool {
	plan, err := BuildPlan(client.profile)
	if err != nil {
		return false
	}
	ref.UID = ""
	for _, candidate := range plan.Objects {
		if candidate == ref {
			return true
		}
	}
	return false
}

func metadata(object apiObject) (apiObject, bool) {
	value, ok := object["metadata"].(map[string]any)
	return apiObject(value), ok
}

func stringField(object apiObject, key string) string { value, _ := object[key].(string); return value }
func nested(object apiObject, keys ...string) apiObject {
	current := object
	for _, key := range keys {
		value, ok := current[key].(map[string]any)
		if !ok {
			return nil
		}
		current = value
	}
	return current
}

func readOwned(object apiObject, expected Object, state State) (OwnedObject, string, error) {
	meta, ok := metadata(object)
	uid, version := stringField(meta, "uid"), stringField(meta, "resourceVersion")
	if !ok || stringField(object, "apiVersion") != expected.APIVersion || stringField(object, "kind") != expected.Kind ||
		stringField(meta, "name") != expected.Name || stringField(meta, "namespace") != expected.Namespace ||
		!kubernetesUID.MatchString(uid) || version == "" || expected.UID != "" && uid != expected.UID ||
		stringField(nested(meta, "labels"), OwnerLabel) != state.InstallationID ||
		stringField(nested(meta, "annotations"), OwnerAnnotation) != state.OwnerNonce ||
		stringField(nested(meta, "annotations"), ProfileAnnotation) != state.ProfileSHA256 {
		return OwnedObject{}, "", ErrConflict
	}
	expected.UID = uid
	return OwnedObject{Object: expected}, version, nil
}
