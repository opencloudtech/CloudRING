// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package openbaoapply

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/opencloudtech/CloudRING/pkg/openbaoauth"
)

var (
	errInputUnavailable = errors.New("OpenBao apply input unavailable")
	dnsLabel            = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	secretKey           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// Parse reads and strictly validates one request. It returns only fixed error
// codes so credentials and provider identifiers cannot enter evidence.
func Parse(reader io.Reader) (Request, string, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxInputBytes+1))
	if err != nil {
		return Request{}, "input-unavailable", errInputUnavailable
	}
	if len(data) > MaxInputBytes {
		return Request{}, "input-too-large", nil
	}
	if len(data) == 0 || !json.Valid(data) {
		return Request{}, "invalid-json", nil
	}
	duplicate, err := inspectJSONFields(data)
	if err != nil {
		return Request{}, "invalid-json", nil
	}
	if duplicate {
		return Request{}, "duplicate-field", nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, "invalid-contract", nil
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Request{}, "trailing-json", nil
	}
	if gate := validateRequest(&request); gate != "" {
		return Request{}, gate, nil
	}
	return request, "", nil
}

func validateRequest(request *Request) string {
	if request.SchemaVersion != SchemaVersion {
		return "schema-version"
	}
	if problems := openbaoauth.Validate(request.Contract); len(problems) != 0 {
		return "planner-contract"
	}
	if validateConnection(request.OpenBao, false) != "" || validateConnection(request.Kubernetes, true) != "" {
		return "secure-connection-contract"
	}
	if !dnsLabel.MatchString(request.Lease.Namespace) || !dnsLabel.MatchString(request.Lease.Name) ||
		request.Lease.HolderIdentity == "" || len(request.Lease.HolderIdentity) > 128 || strings.ContainsAny(request.Lease.HolderIdentity, "\x00\r\n\t ") {
		return "lease-contract"
	}
	if !dnsLabel.MatchString(request.ExecutorIdentity.Namespace) || !dnsLabel.MatchString(request.ExecutorIdentity.ServiceAccount) {
		return "executor-identity-contract"
	}
	executorUID, ok := validateExecutorBearer(request.Kubernetes.BearerTokenBase64, request.ExecutorIdentity)
	if !ok {
		return "executor-token-contract"
	}
	request.ExecutorServiceAccountUID = executorUID
	if !dnsLabel.MatchString(request.ManagementPolicyName) || request.ManagementPolicyName == "root" || request.ManagementPolicyName == "default" || request.ManagementPolicyName == "response-wrapping" || request.ManagementPolicyName == request.Contract.PolicyName {
		return "management-policy-contract"
	}
	if !safeOpaque(request.ManagementAccessor, 8, 512) {
		return "management-accessor-contract"
	}
	wrappingToken, err := base64.StdEncoding.Strict().DecodeString(request.WrappingTokenBase64)
	if err != nil || len(wrappingToken) < 8 || len(wrappingToken) > 16*1024 {
		return "wrapping-token-contract"
	}
	if !validRelativePath(request.Seed.RelativePath) || len(request.Seed.Entries) == 0 || len(request.Seed.Entries) > 64 {
		return "seed-contract"
	}
	seen := make(map[string]bool, len(request.Seed.Entries))
	for _, entry := range request.Seed.Entries {
		if !secretKey.MatchString(entry.Key) || seen[entry.Key] {
			return "seed-contract"
		}
		seen[entry.Key] = true
		value, err := base64.StdEncoding.Strict().DecodeString(entry.ValueBase64)
		if err != nil || len(value) == 0 || len(value) > 256*1024 || !utf8.Valid(value) {
			return "seed-contract"
		}
	}
	wrongSA := request.NegativeIdentities.WrongServiceAccount
	wrongNS := request.NegativeIdentities.WrongNamespace
	if !dnsLabel.MatchString(wrongSA.Namespace) || !dnsLabel.MatchString(wrongSA.ServiceAccount) ||
		!dnsLabel.MatchString(wrongNS.Namespace) || !dnsLabel.MatchString(wrongNS.ServiceAccount) ||
		wrongSA.Namespace != request.Contract.WorkloadIdentity.Namespace ||
		wrongSA.ServiceAccount == request.Contract.WorkloadIdentity.ServiceAccount ||
		wrongNS.Namespace == request.Contract.WorkloadIdentity.Namespace ||
		wrongNS.ServiceAccount != request.Contract.WorkloadIdentity.ServiceAccount {
		return "negative-identity-contract"
	}
	executor := request.ExecutorIdentity
	positive := WorkloadIdentity{Namespace: request.Contract.WorkloadIdentity.Namespace, ServiceAccount: request.Contract.WorkloadIdentity.ServiceAccount}
	if sameIdentity(executor, positive) || sameIdentity(executor, wrongSA) || sameIdentity(executor, wrongNS) {
		return "executor-identity-separation"
	}
	if !request.Approval.ChangeAuthorized || len(request.Approval.BindingSHA256) != sha256.Size*2 {
		return "approval-binding"
	}
	if _, err := hex.DecodeString(request.Approval.BindingSHA256); err != nil {
		return "approval-binding"
	}
	want, err := BindingSHA256(*request)
	if err != nil || !strings.EqualFold(request.Approval.BindingSHA256, want) {
		return "approval-binding"
	}
	return ""
}

func validateExecutorBearer(encoded string, identity WorkloadIdentity) (string, bool) {
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return "", false
	}
	parts := strings.Split(string(raw), ".")
	zeroBytes(raw)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", false
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || !json.Valid(payload) {
		return "", false
	}
	if duplicate, inspectErr := inspectJSONFields(payload); inspectErr != nil || duplicate {
		zeroBytes(payload)
		return "", false
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var claims map[string]any
	if decoder.Decode(&claims) != nil {
		zeroBytes(payload)
		return "", false
	}
	zeroBytes(payload)
	expiration, expOK := integer(claims, "exp")
	remaining := time.Until(time.Unix(expiration, 0))
	if !expOK || remaining < 5*time.Minute || remaining > 15*time.Minute || textValue(claims, "sub") != "system:serviceaccount:"+identity.Namespace+":"+identity.ServiceAccount || !nonemptyAudience(claims["aud"]) {
		return "", false
	}
	kubernetesClaims, ok := object(claims, "kubernetes.io")
	if !ok || textValue(kubernetesClaims, "namespace") != identity.Namespace {
		return "", false
	}
	serviceAccount, ok := object(kubernetesClaims, "serviceaccount")
	if !ok || textValue(serviceAccount, "name") != identity.ServiceAccount || textValue(serviceAccount, "uid") == "" {
		return "", false
	}
	return textValue(serviceAccount, "uid"), true
}

func nonemptyAudience(value any) bool {
	switch typed := value.(type) {
	case string:
		return typed != ""
	case []any:
		if len(typed) == 0 {
			return false
		}
		for _, item := range typed {
			if text, ok := item.(string); !ok || text == "" {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func sameIdentity(left, right WorkloadIdentity) bool {
	return left.Namespace == right.Namespace && left.ServiceAccount == right.ServiceAccount
}

func validateConnection(connection Connection, bearerRequired bool) string {
	parsed, err := url.Parse(connection.Address)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" ||
		connection.ServerName == "" || strings.ContainsAny(connection.ServerName, "\x00\r\n\t /:@") {
		return "invalid"
	}
	ca, err := base64.StdEncoding.Strict().DecodeString(connection.CACertificateBase64)
	if err != nil || len(ca) == 0 || len(ca) > 256*1024 {
		return "invalid"
	}
	if bearerRequired {
		token, err := base64.StdEncoding.Strict().DecodeString(connection.BearerTokenBase64)
		if err != nil || len(token) < 8 || len(token) > 64*1024 {
			return "invalid"
		}
	} else if connection.BearerTokenBase64 != "" {
		return "invalid"
	}
	return ""
}

func validRelativePath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.ContainsAny(value, "*+\\\x00\r\n\t ") {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) > 8 {
		return false
	}
	for _, part := range parts {
		if part == "." || part == ".." || !dnsLabel.MatchString(part) {
			return false
		}
	}
	return true
}

// BindingSHA256 binds non-secret target identity and seed content without ever
// emitting that fingerprint in Report. Callers use it only inside the request.
func BindingSHA256(request Request) (string, error) {
	entries := append([]SecretEntry(nil), request.Seed.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	canonical := struct {
		SchemaVersion        string                                                    `json:"schemaVersion"`
		Contract             openbaoauth.Contract                                      `json:"contract"`
		OpenBao              struct{ Address, ServerName, CACertificateSHA256 string } `json:"openBao"`
		Kubernetes           struct{ Address, ServerName, CACertificateSHA256 string } `json:"kubernetes"`
		Lease                LeaseTarget                                               `json:"lease"`
		ExecutorIdentity     WorkloadIdentity                                          `json:"executorIdentity"`
		ManagementPolicyName string                                                    `json:"managementPolicyName"`
		ManagementAccessor   string                                                    `json:"managementAccessor"`
		Seed                 Seed                                                      `json:"seed"`
		NegativeIdentities   NegativeIdentities                                        `json:"negativeIdentities"`
	}{SchemaVersion: request.SchemaVersion, Contract: request.Contract, Lease: request.Lease, ExecutorIdentity: request.ExecutorIdentity, ManagementPolicyName: request.ManagementPolicyName, ManagementAccessor: request.ManagementAccessor, Seed: Seed{RelativePath: request.Seed.RelativePath, Entries: entries}, NegativeIdentities: request.NegativeIdentities}
	canonical.OpenBao.Address, canonical.OpenBao.ServerName = request.OpenBao.Address, request.OpenBao.ServerName
	canonical.Kubernetes.Address, canonical.Kubernetes.ServerName = request.Kubernetes.Address, request.Kubernetes.ServerName
	openBaoCA, err := base64.StdEncoding.Strict().DecodeString(request.OpenBao.CACertificateBase64)
	if err != nil {
		return "", err
	}
	kubernetesCA, err := base64.StdEncoding.Strict().DecodeString(request.Kubernetes.CACertificateBase64)
	if err != nil {
		return "", err
	}
	openBaoCADigest, kubernetesCADigest := sha256.Sum256(openBaoCA), sha256.Sum256(kubernetesCA)
	canonical.OpenBao.CACertificateSHA256 = hex.EncodeToString(openBaoCADigest[:])
	canonical.Kubernetes.CACertificateSHA256 = hex.EncodeToString(kubernetesCADigest[:])
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func inspectJSONFields(data []byte) (bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	duplicate, err := inspectJSONValue(decoder, 0)
	if err != nil || duplicate {
		return duplicate, err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return false, errors.New("trailing JSON value")
	}
	return false, nil
}

func inspectJSONValue(decoder *json.Decoder, depth int) (bool, error) {
	if depth > 32 {
		return false, errors.New("JSON nesting limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return false, nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return false, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return false, errors.New("invalid JSON key")
			}
			if seen[key] {
				return true, nil
			}
			seen[key] = true
			duplicate, err := inspectJSONValue(decoder, depth+1)
			if err != nil || duplicate {
				return duplicate, err
			}
		}
		_, err = decoder.Token()
		return false, err
	case '[':
		for decoder.More() {
			duplicate, err := inspectJSONValue(decoder, depth+1)
			if err != nil || duplicate {
				return duplicate, err
			}
		}
		_, err = decoder.Token()
		return false, err
	default:
		return false, errors.New("invalid JSON delimiter")
	}
}
