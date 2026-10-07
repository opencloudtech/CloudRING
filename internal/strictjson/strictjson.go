// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Package strictjson provides bounded structural validation for untrusted JSON.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	// MaxDocumentBytes bounds a single Kubernetes or adapter response.
	MaxDocumentBytes = 8 << 20
	maxDepth         = 64
)

var (
	ErrInvalid   = errors.New("invalid JSON document")
	ErrDuplicate = errors.New("duplicate JSON object field")
	ErrTooLarge  = errors.New("JSON document exceeds size limit")
)

// Read validates and returns exactly one bounded JSON document. Error text
// never reflects the untrusted input.
func Read(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxDocumentBytes+1))
	if err != nil {
		return nil, ErrInvalid
	}
	if len(data) > MaxDocumentBytes {
		return nil, ErrTooLarge
	}
	if err := Validate(data); err != nil {
		return nil, err
	}
	return data, nil
}

// Validate rejects malformed, duplicate-key, deeply nested, and trailing JSON.
func Validate(data []byte) error {
	if len(data) == 0 || len(data) > MaxDocumentBytes || !json.Valid(data) {
		if len(data) > MaxDocumentBytes {
			return ErrTooLarge
		}
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	duplicate, err := inspectValue(decoder, 0)
	if err != nil {
		return ErrInvalid
	}
	if duplicate {
		return ErrDuplicate
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return ErrInvalid
	}
	return nil
}

// Decode validates one document and then decodes it while retaining integer
// precision when the destination contains interface values.
func Decode(data []byte, destination any) error {
	if err := Validate(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalid
	}
	return nil
}

// DecodeExact validates one document and rejects fields that are not present
// in the destination type. Use it for closed external protocols whose JSON
// Schema declares additionalProperties=false. Kubernetes objects intentionally
// use Decode so forward-compatible fields remain covered by the state digest.
func DecodeExact(data []byte, destination any) error {
	if err := Validate(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalid
	}
	return nil
}

func inspectValue(decoder *json.Decoder, depth int) (bool, error) {
	if depth > maxDepth {
		return false, ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return false, nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return false, keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return false, ErrInvalid
			}
			if _, exists := seen[key]; exists {
				return true, nil
			}
			seen[key] = struct{}{}
			duplicate, valueErr := inspectValue(decoder, depth+1)
			if duplicate || valueErr != nil {
				return duplicate, valueErr
			}
		}
		_, err = decoder.Token()
		return false, err
	case '[':
		for decoder.More() {
			duplicate, valueErr := inspectValue(decoder, depth+1)
			if duplicate || valueErr != nil {
				return duplicate, valueErr
			}
		}
		_, err = decoder.Token()
		return false, err
	default:
		return false, ErrInvalid
	}
}
