// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package safepush

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Verification errors contain fixed categories, never input values or CI logs.
// When several defects are present, VerifyChecks returns the first applicable
// category in this declaration order, independent of slice ordering.
var (
	ErrInvalidHeadSHA         = errors.New("safepush: invalid head SHA")
	ErrNoRequiredChecks       = errors.New("safepush: no required checks")
	ErrInvalidRequiredCheck   = errors.New("safepush: invalid required check identity")
	ErrDuplicateRequiredCheck = errors.New("safepush: duplicate required check identity")
	ErrInvalidObservation     = errors.New("safepush: invalid observation identity")
	ErrHeadMismatch           = errors.New("safepush: observation head does not match candidate")
	ErrDuplicateObservation   = errors.New("safepush: duplicate observation identity")
	ErrUnexpectedCheck        = errors.New("safepush: unexpected check identity")
	ErrMissingCheck           = errors.New("safepush: missing required check")
	ErrCheckNotSuccessful     = errors.New("safepush: check did not complete successfully")
)

// CheckIdentity identifies one job in an adapter-verified immutable workflow.
// Source binds the workflow path and its trusted revision or content, rather
// than a display name. The adapter must establish that binding using native API
// records; setting Source alone is not evidence of authenticity.
//
// Both fields are compared exactly, without case folding, trimming, or Unicode
// normalization. They must be nonblank valid UTF-8 without control characters.
type CheckIdentity struct {
	Source string `json:"source"`
	Job    string `json:"job"`
}

// CheckObservation is one native CI job result for the selected run attempt.
// Status and Conclusion use the canonical pair "completed" and "success" only
// when the provider reports actual successful completion. The adapter must not
// translate skipped, neutral, allowed-failure, or absent results to that pair.
type CheckObservation struct {
	Check      CheckIdentity `json:"check"`
	HeadSHA    string        `json:"headSHA"`
	Status     string        `json:"status"`
	Conclusion string        `json:"conclusion"`
}

// VerifyChecks requires exactly one successful observation for every required
// identity and no other observations. The required set must not be empty.
// Every observation must match the exact candidate headSHA, which must be a
// nonzero 40- or 64-character lowercase hexadecimal Git object ID.
//
// Only Status == "completed" and Conclusion == "success" passes. Duplicate
// observations are ambiguous even when they agree; the adapter must select the
// authoritative run attempt before calling this function. Inputs are not
// modified, and nil means only that these consistency checks passed. See the
// package documentation for the adapter's remaining authorization obligations.
func VerifyChecks(headSHA string, required []CheckIdentity, observations []CheckObservation) error {
	if !validHeadSHA(headSHA) {
		return ErrInvalidHeadSHA
	}
	if len(required) == 0 {
		return ErrNoRequiredChecks
	}

	requiredSet := make(map[CheckIdentity]struct{}, len(required))
	var invalidRequired, duplicateRequired bool
	for _, check := range required {
		if !validCheckIdentity(check) {
			invalidRequired = true
		}
		if _, exists := requiredSet[check]; exists {
			duplicateRequired = true
		}
		requiredSet[check] = struct{}{}
	}
	if invalidRequired {
		return ErrInvalidRequiredCheck
	}
	if duplicateRequired {
		return ErrDuplicateRequiredCheck
	}

	observedSet := make(map[CheckIdentity]struct{}, len(observations))
	var invalidObservation, headMismatch, duplicateObservation, unexpected, notSuccessful bool
	for _, observation := range observations {
		if !validCheckIdentity(observation.Check) {
			invalidObservation = true
		}
		if observation.HeadSHA != headSHA {
			headMismatch = true
		}
		if _, exists := observedSet[observation.Check]; exists {
			duplicateObservation = true
		}
		observedSet[observation.Check] = struct{}{}
		if _, exists := requiredSet[observation.Check]; !exists {
			unexpected = true
		}
		if observation.Status != "completed" || observation.Conclusion != "success" {
			notSuccessful = true
		}
	}

	switch {
	case invalidObservation:
		return ErrInvalidObservation
	case headMismatch:
		return ErrHeadMismatch
	case duplicateObservation:
		return ErrDuplicateObservation
	case unexpected:
		return ErrUnexpectedCheck
	case len(observedSet) != len(requiredSet):
		return ErrMissingCheck
	case notSuccessful:
		return ErrCheckNotSuccessful
	default:
		return nil
	}
}

func validHeadSHA(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	var nonzero bool
	for _, char := range []byte(value) {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
		if char != '0' {
			nonzero = true
		}
	}
	return nonzero
}

func validCheckIdentity(identity CheckIdentity) bool {
	return validIdentityPart(identity.Source) && validIdentityPart(identity.Job)
}

func validIdentityPart(value string) bool {
	if !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}
