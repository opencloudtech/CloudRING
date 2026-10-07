// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package sourcecheck

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

func identifyPath(raw string) PathIdentity {
	digest := sha256.Sum256([]byte(raw))
	hexDigest := hex.EncodeToString(digest[:])
	identity := PathIdentity{
		SHA256:    hexDigest,
		Base64URL: base64.RawURLEncoding.EncodeToString(digest[:]),
	}
	if safePathDisplay(raw) {
		identity.Display = raw
	} else {
		identity.Display = "<redacted-path:" + hexDigest[:12] + ">"
	}
	return identity
}

func safePathDisplay(raw string) bool {
	if raw == "" || len(raw) > 240 || !utf8.ValidString(raw) {
		return false
	}
	for _, character := range raw {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._-/", character)) {
			return false
		}
	}
	lower := strings.ToLower(raw)
	for _, marker := range []string{
		"g" + "hp_",
		"github_" + "pat_",
		"a" + "kia",
		"authori" + "zation", "bear" + "er", "pass" + "word", "pass" + "wd",
		"to" + "ken", "se" + "cret", "credential", "api" + "key", "private" + "key",
	} {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return false
		}
	}
	for _, segment := range strings.Split(raw, "/") {
		if segment == "" || len(segment) > 64 || suspiciousAlnumRun(segment) {
			return false
		}
	}
	return !localFilesystemPath(raw) && !privateTreeReference(raw)
}

func suspiciousAlnumRun(value string) bool {
	start := -1
	check := func(end int) bool {
		if start < 0 || end-start < 12 {
			return false
		}
		var lower, upper, digit bool
		for _, character := range value[start:end] {
			switch {
			case character >= 'a' && character <= 'z':
				lower = true
			case character >= 'A' && character <= 'Z':
				upper = true
			case character >= '0' && character <= '9':
				digit = true
			}
		}
		categories := 0
		for _, present := range []bool{lower, upper, digit} {
			if present {
				categories++
			}
		}
		return end-start >= 24 || categories >= 2
	}
	for index, character := range value {
		alnum := (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')
		if alnum && start < 0 {
			start = index
		}
		if !alnum {
			if check(index) {
				return true
			}
			start = -1
		}
	}
	return check(len(value))
}

func safePath(raw string) string {
	return identifyPath(raw).Display
}

func safeError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s failed", operation)
}

func canonicalPolicyPath(raw string) (string, error) {
	if raw == "" || strings.IndexByte(raw, 0) >= 0 {
		return "", fmt.Errorf("policy path is invalid")
	}
	normalized := strings.ReplaceAll(raw, `\`, "/")
	if strings.HasPrefix(normalized, "/") || strings.HasPrefix(normalized, "//") || drivePrefixedPath(normalized) {
		return "", fmt.Errorf("policy path must be repository-relative")
	}
	parts := strings.Split(normalized, "/")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			return "", fmt.Errorf("policy path escapes the repository")
		default:
			clean = append(clean, part)
		}
	}
	if len(clean) == 0 {
		return "", fmt.Errorf("policy path is empty")
	}
	return strings.Join(clean, "/"), nil
}

func drivePrefixedPath(value string) bool {
	return len(value) >= 2 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':'
}
