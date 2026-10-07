// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package openbaoauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
)

var errInputUnavailable = errors.New("OpenBao plan input unavailable")

// Evaluate reads one bounded JSON contract and returns a sanitized plan report.
func Evaluate(reader io.Reader) (Report, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxInputBytes+1))
	if err != nil {
		return Report{}, errInputUnavailable
	}
	if len(data) > MaxInputBytes {
		return blockedReport([]Problem{{Path: "$", Code: "input_too_large"}}), nil
	}
	contract, problems := Parse(data)
	if len(problems) != 0 {
		return blockedReport(problems), nil
	}
	plan, problems := Build(contract)
	if len(problems) != 0 {
		return blockedReport(problems), nil
	}
	return buildReport(plan), nil
}

// Parse strictly decodes one contract. It rejects duplicate, unknown, and
// trailing JSON without reflecting decoder messages or input values.
func Parse(data []byte) (Contract, []Problem) {
	if len(data) == 0 || !json.Valid(data) {
		return Contract{}, []Problem{{Path: "$", Code: "invalid_json"}}
	}
	duplicate, structureErr := inspectJSONFields(data)
	if structureErr != nil {
		return Contract{}, []Problem{{Path: "$", Code: "invalid_json_contract"}}
	}
	if duplicate {
		return Contract{}, []Problem{{Path: "$", Code: "duplicate_field"}}
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return Contract{}, []Problem{{Path: "$", Code: "invalid_json_contract"}}
	}
	known := map[string]bool{
		"schemaVersion": true, "authMount": true, "authMountOwnership": true, "kvV2Mount": true,
		"dataPrefix": true, "policyName": true, "roleName": true,
		"workloadIdentity": true, "audience": true, "aliasNameSource": true,
		"tokenTTL": true, "tokenMaxTTL": true, "tokenNoDefaultPolicy": true,
	}
	for field := range top {
		if !known[field] {
			return Contract{}, []Problem{{Path: "$", Code: "unknown_field"}}
		}
	}
	if raw, ok := top["workloadIdentity"]; ok {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(raw, &nested); err != nil || nested == nil {
			return Contract{}, []Problem{{Path: "$.workloadIdentity", Code: "invalid_object"}}
		}
		for field := range nested {
			if field != "namespace" && field != "serviceAccount" {
				return Contract{}, []Problem{{Path: "$.workloadIdentity", Code: "unknown_field"}}
			}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var contract Contract
	if err := decoder.Decode(&contract); err != nil {
		return Contract{}, []Problem{{Path: "$", Code: "invalid_json_contract"}}
	}
	problems := Validate(contract)
	sort.SliceStable(problems, func(left, right int) bool {
		if problems[left].Path == problems[right].Path {
			return problems[left].Code < problems[right].Code
		}
		return problems[left].Path < problems[right].Path
	})
	return contract, problems
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
		return false, errors.New("JSON nesting exceeds contract limit")
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
