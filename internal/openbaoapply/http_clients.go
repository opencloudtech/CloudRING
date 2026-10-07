// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package openbaoapply

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxResponseBytes = 2 * 1024 * 1024

const supportedOpenBaoVersion = "2.5.5"

const rfc3339Micro = "2006-01-02T15:04:05.000000Z07:00"

var (
	errAPIUnavailable     = errors.New("required API operation unavailable")
	errMutationAmbiguous  = errors.New("mutation outcome is ambiguous")
	errDefinitelyRejected = errors.New("mutation was definitely rejected")
	errForbidden          = errors.New("operation was forbidden")
	kubernetesMicroTime   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}(?:Z|[+-][0-9]{2}:[0-9]{2})$`)
)

type restClient struct {
	base          *url.URL
	http          *http.Client
	headerName    string
	defaultBearer string
}

func newRESTClient(connection Connection, headerName string) (*restClient, error) {
	parsed, err := url.Parse(connection.Address)
	if err != nil {
		return nil, errAPIUnavailable
	}
	caPEM, err := base64.StdEncoding.Strict().DecodeString(connection.CACertificateBase64)
	if err != nil {
		return nil, errAPIUnavailable
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errAPIUnavailable
	}
	defaultBearer := ""
	if connection.BearerTokenBase64 != "" {
		decoded, err := base64.StdEncoding.Strict().DecodeString(connection.BearerTokenBase64)
		if err != nil {
			return nil, errAPIUnavailable
		}
		defaultBearer = string(decoded)
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DisableCompression:    true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			ServerName: connection.ServerName,
		},
	}
	return &restClient{
		base: parsed,
		http: &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		headerName:    headerName,
		defaultBearer: defaultBearer,
	}, nil
}

func (client *restClient) do(ctx context.Context, method, path, bearer string, body any) (int, map[string]any, error) {
	return client.doWithHeaders(ctx, method, path, bearer, body, nil)
}

func (client *restClient) doWithHeaders(ctx context.Context, method, path, bearer string, body any, extraHeaders map[string]string) (int, map[string]any, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?\x00\r\n") {
		return 0, nil, errAPIUnavailable
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, errAPIUnavailable
		}
		reader = bytes.NewReader(encoded)
	}
	target := *client.base
	target.Path = strings.TrimSuffix(client.base.Path, "/") + path
	target.RawPath, target.RawQuery, target.Fragment = "", "", ""
	request, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return 0, nil, errAPIUnavailable
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Vault-Request", "true")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range extraHeaders {
		if name != "X-Vault-Wrap-TTL" || value != "60s" {
			return 0, nil, errAPIUnavailable
		}
		request.Header.Set(name, value)
	}
	if bearer == "" {
		bearer = client.defaultBearer
	}
	if client.headerName != "" && bearer != "" {
		if client.headerName == "Authorization" {
			request.Header.Set(client.headerName, "Bearer "+bearer)
		} else {
			request.Header.Set(client.headerName, bearer)
		}
	}
	response, err := client.http.Do(request)
	if err != nil {
		return 0, nil, errAPIUnavailable
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(payload) > maxResponseBytes {
		return 0, nil, errAPIUnavailable
	}
	if len(bytes.TrimSpace(payload)) == 0 {
		return response.StatusCode, map[string]any{}, nil
	}
	if duplicate, duplicateErr := inspectJSONFields(payload); duplicateErr != nil || duplicate {
		return 0, nil, errAPIUnavailable
	}
	var decoded map[string]any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil || decoded == nil || decoder.Decode(&struct{}{}) != io.EOF {
		return 0, nil, errAPIUnavailable
	}
	return response.StatusCode, decoded, nil
}

type kubeRESTClient struct{ rest *restClient }

func NewKubernetesClient(connection Connection) (KubernetesClient, error) {
	rest, err := newRESTClient(connection, "Authorization")
	if err != nil {
		return nil, err
	}
	return &kubeRESTClient{rest: rest}, nil
}

func (client *kubeRESTClient) GetLease(ctx context.Context, target LeaseTarget) (Lease, error) {
	path := "/apis/coordination.k8s.io/v1/namespaces/" + target.Namespace + "/leases/" + target.Name
	status, payload, err := client.rest.do(ctx, http.MethodGet, path, "", nil)
	if err != nil || status != http.StatusOK {
		return Lease{}, errAPIUnavailable
	}
	lease, err := leaseFromPayload(payload)
	if err != nil || lease.Name != target.Name || lease.Namespace != target.Namespace {
		return Lease{}, errAPIUnavailable
	}
	return lease, nil
}

func leaseFromPayload(payload map[string]any) (Lease, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Lease{}, errAPIUnavailable
	}
	metadata, ok := object(payload, "metadata")
	if !ok || metadata["deletionTimestamp"] != nil {
		return Lease{}, errAPIUnavailable
	}
	spec, ok := object(payload, "spec")
	if !ok || spec["strategy"] != nil || spec["preferredHolder"] != nil {
		return Lease{}, errAPIUnavailable
	}
	lease := Lease{Name: textValue(metadata, "name"), Namespace: textValue(metadata, "namespace"), UID: textValue(metadata, "uid"), ResourceVersion: textValue(metadata, "resourceVersion"), Raw: raw}
	if holder, ok := optionalString(spec, "holderIdentity"); ok {
		lease.HolderIdentity = holder
	} else {
		return Lease{}, errAPIUnavailable
	}
	if value, present, valid := optionalNumber(spec, "leaseDurationSeconds"); !valid {
		return Lease{}, errAPIUnavailable
	} else if present {
		parsed, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return Lease{}, errAPIUnavailable
		}
		lease.LeaseDurationSec = int32(parsed)
	}
	acquireTime, ok := optionalString(spec, "acquireTime")
	if !ok {
		return Lease{}, errAPIUnavailable
	}
	lease.AcquireTime, err = parseKubernetesMicroTime(acquireTime)
	if err != nil {
		return Lease{}, errAPIUnavailable
	}
	renewTime, ok := optionalString(spec, "renewTime")
	if !ok {
		return Lease{}, errAPIUnavailable
	}
	lease.RenewTime, err = parseKubernetesMicroTime(renewTime)
	if err != nil {
		return Lease{}, errAPIUnavailable
	}
	if lease.Name == "" || lease.Namespace == "" || lease.UID == "" || lease.ResourceVersion == "" {
		return Lease{}, errAPIUnavailable
	}
	return lease, nil
}

func (client *kubeRESTClient) UpdateLease(ctx context.Context, target LeaseTarget, lease Lease) (Lease, error) {
	var payload map[string]any
	decoder := json.NewDecoder(bytes.NewReader(lease.Raw))
	decoder.UseNumber()
	if len(lease.Raw) == 0 || decoder.Decode(&payload) != nil || payload == nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Lease{}, errAPIUnavailable
	}
	metadata, ok := object(payload, "metadata")
	if !ok || textValue(metadata, "name") != target.Name || textValue(metadata, "namespace") != target.Namespace || textValue(metadata, "uid") != lease.UID || lease.Name != target.Name || lease.Namespace != target.Namespace {
		return Lease{}, errAPIUnavailable
	}
	metadata["resourceVersion"] = lease.ResourceVersion
	spec, ok := object(payload, "spec")
	if !ok {
		return Lease{}, errAPIUnavailable
	}
	spec["holderIdentity"] = lease.HolderIdentity
	spec["leaseDurationSeconds"] = lease.LeaseDurationSec
	if !lease.AcquireTime.IsZero() {
		spec["acquireTime"] = lease.AcquireTime.UTC().Truncate(time.Microsecond).Format(rfc3339Micro)
	}
	if !lease.RenewTime.IsZero() {
		spec["renewTime"] = lease.RenewTime.UTC().Truncate(time.Microsecond).Format(rfc3339Micro)
	}
	path := "/apis/coordination.k8s.io/v1/namespaces/" + target.Namespace + "/leases/" + target.Name
	status, response, err := client.rest.do(ctx, http.MethodPut, path, "", payload)
	if err != nil {
		return Lease{}, errMutationAmbiguous
	}
	if status != http.StatusOK {
		return Lease{}, mutationStatusError(status)
	}
	updated, err := leaseFromPayload(response)
	if err != nil || updated.Name != target.Name || updated.Namespace != target.Namespace {
		return Lease{}, errAPIUnavailable
	}
	return updated, nil
}

func optionalString(values map[string]any, key string) (string, bool) {
	raw, exists := values[key]
	if !exists || raw == nil {
		return "", true
	}
	value, ok := raw.(string)
	return value, ok
}

func optionalNumber(values map[string]any, key string) (string, bool, bool) {
	raw, exists := values[key]
	if !exists || raw == nil {
		return "", false, true
	}
	value, ok := numberValue(values, key)
	return value, true, ok
}

func optionalBool(values map[string]any, key string) (bool, bool, bool) {
	raw, exists := values[key]
	if !exists || raw == nil {
		return false, false, true
	}
	value, ok := raw.(bool)
	return value, true, ok
}

func parseKubernetesMicroTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(rfc3339Micro, value)
	if err != nil || !kubernetesMicroTime.MatchString(value) {
		return time.Time{}, errAPIUnavailable
	}
	return parsed.UTC(), nil
}

func (client *kubeRESTClient) ReviewSelf(ctx context.Context) (SubjectFacts, error) {
	body := map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview", "spec": map[string]any{}}
	status, payload, err := client.rest.do(ctx, http.MethodPost, "/apis/authentication.k8s.io/v1/selfsubjectreviews", "", body)
	if err != nil || status != http.StatusCreated {
		return SubjectFacts{}, errAPIUnavailable
	}
	statusObject, ok := object(payload, "status")
	if !ok {
		return SubjectFacts{}, errAPIUnavailable
	}
	userInfo, ok := object(statusObject, "userInfo")
	groups, groupsOK := stringSlice(userInfo, "groups")
	if !ok || !groupsOK || textValue(userInfo, "username") == "" || textValue(userInfo, "uid") == "" {
		return SubjectFacts{}, errAPIUnavailable
	}
	return SubjectFacts{Username: textValue(userInfo, "username"), UID: textValue(userInfo, "uid"), Groups: groups}, nil
}

func (client *kubeRESTClient) ReviewAccess(ctx context.Context, access ResourceAccess) (bool, error) {
	attributes := map[string]any{
		"verb": access.Verb, "group": access.Group, "resource": access.Resource,
		"namespace": access.Namespace, "name": access.Name,
	}
	if access.Subresource != "" {
		attributes["subresource"] = access.Subresource
	}
	body := map[string]any{
		"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
		"spec": map[string]any{"resourceAttributes": attributes},
	}
	status, payload, err := client.rest.do(ctx, http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "", body)
	if err != nil || status != http.StatusCreated {
		return false, errAPIUnavailable
	}
	result, ok := object(payload, "status")
	evaluationError, evaluationOK := optionalString(result, "evaluationError")
	if !ok || !evaluationOK || evaluationError != "" {
		return false, errAPIUnavailable
	}
	allowed, allowedOK := result["allowed"].(bool)
	denied, deniedPresent, deniedOK := optionalBool(result, "denied")
	if !allowedOK || !deniedOK || (deniedPresent && allowed && denied) {
		return false, errAPIUnavailable
	}
	return allowed, nil
}

func (client *kubeRESTClient) GetServiceAccount(ctx context.Context, namespace, serviceAccount string) (ServiceAccountFacts, error) {
	path := "/api/v1/namespaces/" + namespace + "/serviceaccounts/" + serviceAccount
	status, payload, err := client.rest.do(ctx, http.MethodGet, path, "", nil)
	if err != nil || status != http.StatusOK {
		return ServiceAccountFacts{}, errAPIUnavailable
	}
	metadata, ok := object(payload, "metadata")
	if !ok || textValue(metadata, "name") != serviceAccount || textValue(metadata, "namespace") != namespace || textValue(metadata, "uid") == "" || metadata["deletionTimestamp"] != nil {
		return ServiceAccountFacts{}, errAPIUnavailable
	}
	return ServiceAccountFacts{UID: textValue(metadata, "uid")}, nil
}

func (client *kubeRESTClient) RequestServiceAccountToken(ctx context.Context, namespace, serviceAccount, audience string, expirationSeconds int64) (ServiceAccountToken, error) {
	path := "/api/v1/namespaces/" + namespace + "/serviceaccounts/" + serviceAccount + "/token"
	body := map[string]any{
		"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
		"spec": map[string]any{"audiences": []string{audience}, "expirationSeconds": expirationSeconds},
	}
	status, payload, err := client.rest.do(ctx, http.MethodPost, path, "", body)
	if err != nil || status != http.StatusCreated {
		return ServiceAccountToken{}, errAPIUnavailable
	}
	result, ok := object(payload, "status")
	if !ok {
		return ServiceAccountToken{}, errAPIUnavailable
	}
	jwt := textValue(result, "token")
	if len(jwt) < 8 || len(jwt) > 64*1024 {
		return ServiceAccountToken{}, errAPIUnavailable
	}
	expires, err := time.Parse(time.RFC3339, textValue(result, "expirationTimestamp"))
	if err != nil {
		return ServiceAccountToken{}, errAPIUnavailable
	}
	return ServiceAccountToken{JWT: jwt, ExpirationTimestamp: expires.UTC()}, nil
}

type openBaoRESTClient struct{ rest *restClient }

type supervisorOpenBaoRESTClient struct{ *openBaoRESTClient }

func NewOpenBaoClient(connection Connection) (OpenBaoClient, error) {
	rest, err := newRESTClient(connection, "X-Vault-Token")
	if err != nil {
		return nil, err
	}
	return &openBaoRESTClient{rest: rest}, nil
}

func newSupervisorOpenBaoClient(connection Connection) (SupervisorOpenBaoClient, error) {
	client, err := NewOpenBaoClient(connection)
	if err != nil {
		return nil, err
	}
	concrete, ok := client.(*openBaoRESTClient)
	if !ok {
		return nil, errAPIUnavailable
	}
	return &supervisorOpenBaoRESTClient{openBaoRESTClient: concrete}, nil
}

func (client *supervisorOpenBaoRESTClient) ApplyClient() OpenBaoClient {
	return client.openBaoRESTClient
}

func (client *supervisorOpenBaoRESTClient) LookupInitialRoot(ctx context.Context, rootBearer string) (TokenFacts, error) {
	return client.LookupSelf(ctx, rootBearer)
}

func (client *supervisorOpenBaoRESTClient) ReadTemporaryPolicy(ctx context.Context, rootBearer, policyName string) (ReadResult, error) {
	return client.Read(ctx, rootBearer, "sys/policies/acl/"+policyName)
}

func (client *supervisorOpenBaoRESTClient) CreateTemporaryPolicy(ctx context.Context, rootBearer, policyName, body string) error {
	_, err := client.Write(ctx, rootBearer, "sys/policies/acl/"+policyName, map[string]any{"policy": body, "cas": -1, "cas_required": false})
	return err
}

func (client *supervisorOpenBaoRESTClient) DeleteTemporaryPolicy(ctx context.Context, rootBearer, policyName string) error {
	return client.Delete(ctx, rootBearer, "sys/policies/acl/"+policyName)
}

func (client *supervisorOpenBaoRESTClient) CreateWrappedManagementToken(ctx context.Context, rootBearer, rootAccessor, policyName string) (WrappedToken, error) {
	body := map[string]any{
		"policies": []string{policyName}, "no_parent": true, "no_default_policy": true,
		"renewable": false, "type": "service", "ttl": "10m", "explicit_max_ttl": "15m", "num_uses": 0,
	}
	status, payload, err := client.rest.doWithHeaders(ctx, http.MethodPost, "/v1/auth/token/create", rootBearer, body, map[string]string{"X-Vault-Wrap-TTL": "60s"})
	if err != nil {
		return WrappedToken{}, errMutationAmbiguous
	}
	if status != http.StatusOK {
		return WrappedToken{}, mutationStatusError(status)
	}
	wrapInfo, ok := object(payload, "wrap_info")
	leaseDuration, leaseOK := integer(payload, "lease_duration")
	renewable, renewableOK := payload["renewable"].(bool)
	// OpenBao 2.5.5 builds a wrapped HTTP response from WrapInfo alone, so the
	// serialized request_id field is present and empty.
	if !ok || len(payload) != 8 || len(wrapInfo) != 6 || textValue(payload, "request_id") != "" || textValue(payload, "lease_id") != "" ||
		!leaseOK || leaseDuration != 0 || !renewableOK || renewable || payload["data"] != nil || payload["warnings"] != nil || payload["auth"] != nil {
		return WrappedToken{}, errMutationAmbiguous
	}
	ttl, ttlOK := integer(wrapInfo, "ttl")
	wrapped := WrappedToken{
		Value: textValue(wrapInfo, "token"), Accessor: textValue(wrapInfo, "accessor"),
		WrappedAccessor: textValue(wrapInfo, "wrapped_accessor"), CreationPath: textValue(wrapInfo, "creation_path"),
	}
	createdAt, creationErr := time.Parse(time.RFC3339Nano, textValue(wrapInfo, "creation_time"))
	age := time.Since(createdAt)
	if !ttlOK || ttl != 60 || wrapped.CreationPath != "auth/token/create" || !safeOpaque(wrapped.Value, 8, 64*1024) || !safeOpaque(wrapped.Accessor, 8, 512) || !safeOpaque(wrapped.WrappedAccessor, 8, 512) ||
		wrapped.Accessor == wrapped.WrappedAccessor || wrapped.Accessor == rootAccessor || wrapped.WrappedAccessor == rootAccessor || creationErr != nil || age < -30*time.Second || age > 2*time.Minute {
		return WrappedToken{}, errMutationAmbiguous
	}
	return wrapped, nil
}

func (client *supervisorOpenBaoRESTClient) RevokeAccessorAndProve(ctx context.Context, rootBearer, accessor string) bool {
	if accessor == "" || ctx.Err() != nil {
		return false
	}
	present, err := client.accessorPresent(ctx, rootBearer, accessor)
	if err != nil {
		return false
	}
	if present {
		status, _, revokeErr := client.rest.do(ctx, http.MethodPost, "/v1/auth/token/revoke-accessor", rootBearer, map[string]any{"accessor": accessor})
		if revokeErr != nil || (status != http.StatusOK && status != http.StatusNoContent) {
			present, lookupErr := client.accessorPresent(ctx, rootBearer, accessor)
			return lookupErr == nil && !present
		}
	}
	present, err = client.accessorPresent(ctx, rootBearer, accessor)
	return err == nil && !present
}

func safeOpaque(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func (client *supervisorOpenBaoRESTClient) accessorPresent(ctx context.Context, rootBearer, accessor string) (bool, error) {
	status, payload, err := client.rest.do(ctx, http.MethodPost, "/v1/auth/token/lookup-accessor", rootBearer, map[string]any{"accessor": accessor})
	if err != nil {
		return false, errAPIUnavailable
	}
	if status == http.StatusBadRequest {
		return false, nil
	}
	if status != http.StatusOK {
		return false, errAPIUnavailable
	}
	data, ok := object(payload, "data")
	if !ok || textValue(data, "accessor") != accessor {
		return false, errAPIUnavailable
	}
	return true, nil
}

func (client *openBaoRESTClient) Unwrap(ctx context.Context, wrappingToken string) (string, error) {
	status, payload, err := client.rest.do(ctx, http.MethodPost, "/v1/sys/wrapping/unwrap", wrappingToken, map[string]any{})
	if err != nil {
		return "", errMutationAmbiguous
	}
	if status != http.StatusOK {
		return "", mutationStatusError(status)
	}
	auth, ok := object(payload, "auth")
	if !ok {
		return "", errAPIUnavailable
	}
	unwrappedCredential := textValue(auth, "client_token")
	if !safeOpaque(unwrappedCredential, 8, 64*1024) {
		return "", errMutationAmbiguous
	}
	return unwrappedCredential, nil
}

func (client *openBaoRESTClient) LookupSelf(ctx context.Context, token string) (TokenFacts, error) {
	status, payload, err := client.rest.do(ctx, http.MethodGet, "/v1/auth/token/lookup-self", token, nil)
	if err != nil || status != http.StatusOK {
		return TokenFacts{}, errAPIUnavailable
	}
	data, ok := object(payload, "data")
	if !ok {
		return TokenFacts{}, errAPIUnavailable
	}
	policies, ok := stringSlice(data, "policies")
	if !ok {
		return TokenFacts{}, errAPIUnavailable
	}
	ttl, ok := integer(data, "ttl")
	if !ok {
		return TokenFacts{}, errAPIUnavailable
	}
	renewable := false
	renewableKnown := false
	if raw, exists := data["renewable"]; exists {
		var renewableOK bool
		renewable, renewableOK = raw.(bool)
		if !renewableOK {
			return TokenFacts{}, errAPIUnavailable
		}
		renewableKnown = true
	}
	identityPolicies := []string{}
	if _, exists := data["identity_policies"]; exists {
		identityPolicies, ok = stringSlice(data, "identity_policies")
		if !ok {
			return TokenFacts{}, errAPIUnavailable
		}
	}
	externalPolicyCount := 0
	if raw, exists := data["external_namespace_policies"]; exists {
		external, ok := raw.(map[string]any)
		if !ok {
			return TokenFacts{}, errAPIUnavailable
		}
		externalPolicyCount = len(external)
	}
	explicitMaxTTL, ok := integer(data, "explicit_max_ttl")
	if !ok {
		return TokenFacts{}, errAPIUnavailable
	}
	numUses, ok := integer(data, "num_uses")
	if !ok {
		return TokenFacts{}, errAPIUnavailable
	}
	orphan, ok := data["orphan"].(bool)
	if !ok {
		return TokenFacts{}, errAPIUnavailable
	}
	metadataEntries := 0
	if raw, exists := data["meta"]; exists {
		if raw != nil {
			metadata, ok := raw.(map[string]any)
			if !ok {
				return TokenFacts{}, errAPIUnavailable
			}
			metadataEntries = len(metadata)
		}
	}
	return TokenFacts{
		Policies: policies, Accessor: textValue(data, "accessor"), IdentityPolicies: identityPolicies,
		ExternalNamespacePolicies: externalPolicyCount, EntityID: textValue(data, "entity_id"),
		Path: textValue(data, "path"), TTL: ttl, ExplicitMaxTTL: explicitMaxTTL,
		NumUses: numUses, MetadataEntries: metadataEntries,
		Renewable: renewable, RenewableKnown: renewableKnown, Orphan: orphan, TokenType: textValue(data, "type"),
	}, nil
}

func (client *openBaoRESTClient) CapabilitiesSelf(ctx context.Context, token string, paths []string) (map[string][]string, error) {
	status, payload, err := client.rest.do(ctx, http.MethodPost, "/v1/sys/capabilities-self", token, map[string]any{"paths": paths})
	if err != nil || status != http.StatusOK {
		return nil, errAPIUnavailable
	}
	data, ok := object(payload, "data")
	if !ok || len(data) != len(paths) {
		return nil, errAPIUnavailable
	}
	result := make(map[string][]string, len(paths))
	for _, path := range paths {
		values, ok := stringSlice(data, path)
		if !ok {
			return nil, errAPIUnavailable
		}
		result[path] = values
	}
	return result, nil
}

func (client *openBaoRESTClient) Read(ctx context.Context, token, path string) (ReadResult, error) {
	return client.read(ctx, http.MethodGet, token, path)
}

func (client *openBaoRESTClient) List(ctx context.Context, token, path string) (ReadResult, error) {
	return client.read(ctx, "LIST", token, path)
}

func (client *openBaoRESTClient) read(ctx context.Context, method, token, path string) (ReadResult, error) {
	status, payload, err := client.rest.do(ctx, method, "/v1/"+path, token, nil)
	if err != nil {
		return ReadResult{}, errAPIUnavailable
	}
	if status == http.StatusNotFound {
		return ReadResult{Found: false}, nil
	}
	// OpenBao 2.5.5 reports a missing auth mount through the read-specific
	// logical error contract rather than HTTP 404. Accept only its exact,
	// mount-bound envelope; every other 400 remains an API failure.
	if status == http.StatusBadRequest && exactMissingAuthMountRead(path, payload) {
		return ReadResult{Found: false}, nil
	}
	// OpenBao 2.5.5 uses the same read-specific HTTP 400 pattern for an
	// absent secret-engine mount. Accept only the exact mount-bound envelope so
	// the state machine can authorize create-only KV-v2 initialization.
	if status == http.StatusBadRequest && exactMissingSecretMountRead(path, payload) {
		return ReadResult{Found: false}, nil
	}
	if status != http.StatusOK {
		return ReadResult{}, errAPIUnavailable
	}
	data, _ := object(payload, "data")
	auth, _ := object(payload, "auth")
	return ReadResult{Found: true, Data: data, Auth: auth}, nil
}

func exactMissingAuthMountRead(path string, payload map[string]any) bool {
	const prefix = "sys/auth/"
	mount := strings.TrimPrefix(path, prefix)
	if mount == path || !dnsLabel.MatchString(mount) || len(payload) != 1 {
		return false
	}
	errors, ok := stringSlice(payload, "errors")
	return ok && len(errors) == 1 && errors[0] == "No auth engine at "+mount+"/"
}

func exactMissingSecretMountRead(path string, payload map[string]any) bool {
	const prefix = "sys/mounts/"
	mount := strings.TrimPrefix(path, prefix)
	if mount == path || !dnsLabel.MatchString(mount) || len(payload) != 1 {
		return false
	}
	errors, ok := stringSlice(payload, "errors")
	return ok && len(errors) == 1 && errors[0] == "No secret engine mount at "+mount+"/"
}

func (client *openBaoRESTClient) Write(ctx context.Context, token, path string, body any) (ReadResult, error) {
	status, payload, err := client.rest.do(ctx, http.MethodPost, "/v1/"+path, token, body)
	if err != nil {
		return ReadResult{}, errMutationAmbiguous
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return ReadResult{}, mutationStatusError(status)
	}
	if strings.HasSuffix(path, "/login") && !exactLoginEnvelope(payload) {
		return ReadResult{}, errMutationAmbiguous
	}
	data, _ := object(payload, "data")
	auth, _ := object(payload, "auth")
	return ReadResult{Found: true, Data: data, Auth: auth}, nil
}

func exactLoginEnvelope(payload map[string]any) bool {
	if len(payload) != 8 || textValue(payload, "request_id") == "" || textValue(payload, "lease_id") != "" || payload["data"] != nil || payload["wrap_info"] != nil || payload["warnings"] != nil {
		return false
	}
	renewable, renewableOK := payload["renewable"].(bool)
	leaseDuration, leaseOK := integer(payload, "lease_duration")
	_, authOK := object(payload, "auth")
	return renewableOK && !renewable && leaseOK && leaseDuration == 0 && authOK
}

func (client *openBaoRESTClient) Delete(ctx context.Context, token, path string) error {
	status, _, err := client.rest.do(ctx, http.MethodDelete, "/v1/"+path, token, nil)
	if err != nil {
		return errMutationAmbiguous
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return mutationStatusError(status)
	}
	return nil
}

func mutationStatusError(status int) error {
	if status == http.StatusForbidden {
		return errForbidden
	}
	if status >= 400 && status < 500 {
		return errDefinitelyRejected
	}
	return errMutationAmbiguous
}

func (client *openBaoRESTClient) Health(ctx context.Context) error {
	status, payload, err := client.rest.do(ctx, http.MethodGet, "/v1/sys/health", "", nil)
	if err != nil || status != http.StatusOK || len(payload) != 10 {
		return errAPIUnavailable
	}
	if initialized, ok := payload["initialized"].(bool); !ok || !initialized {
		return errAPIUnavailable
	}
	if sealed, ok := payload["sealed"].(bool); !ok || sealed {
		return errAPIUnavailable
	}
	if standby, ok := payload["standby"].(bool); !ok || standby {
		return errAPIUnavailable
	}
	if textValue(payload, "version") != supportedOpenBaoVersion {
		return errAPIUnavailable
	}
	performanceStandby, performanceOK := payload["performance_standby"].(bool)
	serverTime, serverTimeOK := integer(payload, "server_time_utc")
	performanceMode := textValue(payload, "replication_performance_mode")
	if !performanceOK || performanceStandby || !serverTimeOK || deltaSeconds(time.Now().Unix(), serverTime) > 300 ||
		(performanceMode != "disabled" && performanceMode != "primary") || textValue(payload, "replication_dr_mode") != "disabled" ||
		textValue(payload, "cluster_name") == "" || textValue(payload, "cluster_id") == "" {
		return errAPIUnavailable
	}
	return nil
}

func deltaSeconds(left, right int64) int64 {
	if left < right {
		return right - left
	}
	return left - right
}

func (client *openBaoRESTClient) ExpectForbidden(ctx context.Context, method, token, path string, body any) error {
	status, _, err := client.rest.do(ctx, method, "/v1/"+path, token, body)
	if err != nil || status != http.StatusForbidden {
		return errAPIUnavailable
	}
	return nil
}

func object(value map[string]any, key string) (map[string]any, bool) {
	result, ok := value[key].(map[string]any)
	return result, ok
}

func textValue(value map[string]any, key string) string {
	result, _ := value[key].(string)
	return result
}

func numberValue(value map[string]any, key string) (string, bool) {
	switch typed := value[key].(type) {
	case json.Number:
		return typed.String(), true
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64), true
	default:
		return "", false
	}
}

func integer(value map[string]any, key string) (int64, bool) {
	raw, ok := numberValue(value, key)
	if !ok {
		return 0, false
	}
	result, err := strconv.ParseInt(raw, 10, 64)
	return result, err == nil
}

func stringSlice(value map[string]any, key string) ([]string, bool) {
	raw, ok := value[key].([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		result = append(result, text)
	}
	return result, true
}
