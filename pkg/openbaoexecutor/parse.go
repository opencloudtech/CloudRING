// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package openbaoexecutor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/opencloudtech/CloudRING/pkg/openbaoauth"
)

var (
	errInputUnavailable = errors.New("OpenBao executor profile input unavailable")
	dnsLabel            = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
)

// Decode reads one bounded profile and rejects duplicate, unknown, trailing,
// or structurally invalid JSON without reflecting input values.
func Decode(reader io.Reader) (Profile, []Problem, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxInputBytes+1))
	if err != nil {
		return Profile{}, nil, errInputUnavailable
	}
	if len(data) > MaxInputBytes {
		return Profile{}, []Problem{{Path: "$", Code: "input_too_large"}}, nil
	}
	profile, problems := Parse(data)
	return profile, problems, nil
}

// Parse strictly decodes and validates one in-memory profile.
func Parse(data []byte) (Profile, []Problem) {
	if len(data) == 0 || !json.Valid(data) {
		return Profile{}, []Problem{{Path: "$", Code: "invalid_json"}}
	}
	duplicate, err := inspectJSONFields(data)
	if err != nil {
		return Profile{}, []Problem{{Path: "$", Code: "invalid_json_contract"}}
	}
	if duplicate {
		return Profile{}, []Problem{{Path: "$", Code: "duplicate_field"}}
	}
	if problems := validateExactProfileFields(data); len(problems) != 0 {
		return Profile{}, problems
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var profile Profile
	if decoder.Decode(&profile) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Profile{}, []Problem{{Path: "$", Code: "invalid_json_contract"}}
	}
	return profile, Validate(profile)
}

func validateExactProfileFields(data []byte) []Problem {
	top, problem := exactJSONObject(data, "$", "schemaVersion", "contract", "executorIdentity", "lease", "negativeIdentities")
	if problem != nil {
		return []Problem{*problem}
	}
	if raw, found := top["contract"]; found {
		_, contractProblems := openbaoauth.Parse(raw)
		if len(contractProblems) != 0 {
			problems := make([]Problem, 0, len(contractProblems))
			for _, item := range contractProblems {
				problems = append(problems, Problem{Path: "$.contract" + strings.TrimPrefix(item.Path, "$"), Code: item.Code})
			}
			return problems
		}
	}
	for _, field := range []struct {
		name string
		path string
	}{
		{"executorIdentity", "$.executorIdentity"},
		{"lease", "$.lease"},
	} {
		if raw, found := top[field.name]; found {
			allowed := []string{"namespace", "serviceAccount"}
			if field.name == "lease" {
				allowed = []string{"namespace", "name"}
			}
			if _, problem := exactJSONObject(raw, field.path, allowed...); problem != nil {
				return []Problem{*problem}
			}
		}
	}
	if raw, found := top["negativeIdentities"]; found {
		negative, problem := exactJSONObject(raw, "$.negativeIdentities", "wrongServiceAccount", "wrongNamespace")
		if problem != nil {
			return []Problem{*problem}
		}
		for _, name := range []string{"wrongServiceAccount", "wrongNamespace"} {
			if identityRaw, found := negative[name]; found {
				if _, problem := exactJSONObject(identityRaw, "$.negativeIdentities."+name, "namespace", "serviceAccount"); problem != nil {
					return []Problem{*problem}
				}
			}
		}
	}
	return nil
}

func exactJSONObject(data []byte, path string, allowed ...string) (map[string]json.RawMessage, *Problem) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return nil, &Problem{Path: path, Code: "invalid_object"}
	}
	allowedFields := make(map[string]bool, len(allowed))
	for _, field := range allowed {
		allowedFields[field] = true
	}
	for field := range object {
		if !allowedFields[field] {
			return nil, &Problem{Path: path, Code: "unknown_field"}
		}
	}
	return object, nil
}

// Validate enforces the exact identity relationships assumed by the executor
// state machine and renderer.
func Validate(profile Profile) []Problem {
	problems := make([]Problem, 0)
	if profile.SchemaVersion != SchemaVersion {
		problems = append(problems, Problem{Path: "$.schemaVersion", Code: "unsupported_value"})
	}
	for _, problem := range openbaoauth.Validate(profile.Contract) {
		problems = append(problems, Problem{Path: "$.contract" + strings.TrimPrefix(problem.Path, "$"), Code: problem.Code})
	}
	positive := profile.Contract.WorkloadIdentity
	for _, field := range []struct {
		path  string
		value string
	}{
		{"$.executorIdentity.namespace", profile.ExecutorIdentity.Namespace},
		{"$.executorIdentity.serviceAccount", profile.ExecutorIdentity.ServiceAccount},
		{"$.lease.namespace", profile.Lease.Namespace},
		{"$.lease.name", profile.Lease.Name},
		{"$.negativeIdentities.wrongServiceAccount.namespace", profile.NegativeIdentities.WrongServiceAccount.Namespace},
		{"$.negativeIdentities.wrongServiceAccount.serviceAccount", profile.NegativeIdentities.WrongServiceAccount.ServiceAccount},
		{"$.negativeIdentities.wrongNamespace.namespace", profile.NegativeIdentities.WrongNamespace.Namespace},
		{"$.negativeIdentities.wrongNamespace.serviceAccount", profile.NegativeIdentities.WrongNamespace.ServiceAccount},
	} {
		if !dnsLabel.MatchString(field.value) {
			problems = append(problems, Problem{Path: field.path, Code: "invalid_dns_label"})
		}
	}
	if profile.ExecutorIdentity.Namespace != positive.Namespace {
		problems = append(problems, Problem{Path: "$.executorIdentity.namespace", Code: "must_equal_workload_namespace"})
	}
	if profile.ExecutorIdentity.ServiceAccount == positive.ServiceAccount {
		problems = append(problems, Problem{Path: "$.executorIdentity.serviceAccount", Code: "must_differ_from_workload_identity"})
	}
	if profile.Lease.Namespace != profile.ExecutorIdentity.Namespace {
		problems = append(problems, Problem{Path: "$.lease.namespace", Code: "must_equal_executor_namespace"})
	}
	executorScopeName := ExecutorScopeName(profile.ExecutorIdentity)
	if profile.Lease.Name != executorScopeName {
		problems = append(problems, Problem{Path: "$.lease.name", Code: "must_equal_executor_identity_scope"})
	}
	wrongServiceAccount := profile.NegativeIdentities.WrongServiceAccount
	if wrongServiceAccount.Namespace != positive.Namespace {
		problems = append(problems, Problem{Path: "$.negativeIdentities.wrongServiceAccount.namespace", Code: "must_equal_workload_namespace"})
	}
	if wrongServiceAccount.ServiceAccount == positive.ServiceAccount || wrongServiceAccount.ServiceAccount == profile.ExecutorIdentity.ServiceAccount {
		problems = append(problems, Problem{Path: "$.negativeIdentities.wrongServiceAccount.serviceAccount", Code: "must_be_distinct"})
	}
	wrongNamespace := profile.NegativeIdentities.WrongNamespace
	if wrongNamespace.Namespace == positive.Namespace {
		problems = append(problems, Problem{Path: "$.negativeIdentities.wrongNamespace.namespace", Code: "must_differ_from_workload_namespace"})
	}
	if wrongNamespace.ServiceAccount != positive.ServiceAccount {
		problems = append(problems, Problem{Path: "$.negativeIdentities.wrongNamespace.serviceAccount", Code: "must_equal_workload_service_account"})
	}
	sort.SliceStable(problems, func(left, right int) bool {
		if problems[left].Path == problems[right].Path {
			return problems[left].Code < problems[right].Code
		}
		return problems[left].Path < problems[right].Path
	})
	return problems
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
		return false, errors.New("JSON nesting exceeds profile limit")
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
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return false, keyErr
			}
			key, keyOK := keyToken.(string)
			if !keyOK {
				return false, errors.New("invalid JSON object key")
			}
			if seen[key] {
				return true, nil
			}
			seen[key] = true
			duplicate, valueErr := inspectJSONValue(decoder, depth+1)
			if valueErr != nil || duplicate {
				return duplicate, valueErr
			}
		}
		_, err = decoder.Token()
		return false, err
	case '[':
		for decoder.More() {
			duplicate, valueErr := inspectJSONValue(decoder, depth+1)
			if valueErr != nil || duplicate {
				return duplicate, valueErr
			}
		}
		_, err = decoder.Token()
		return false, err
	default:
		return false, errors.New("unexpected JSON delimiter")
	}
}
