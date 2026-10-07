// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package httpsecurity

import (
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var directiveNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

func evaluateHeaders(header http.Header, surface Surface, mode Mode) map[string]bool {
	results := make(map[string]bool)
	evaluateHSTS(header, mode, results)
	evaluateCSP(header, surface, results)
	evaluateExactHeader(header, "X-Frame-Options", "header.x-frame-options", "x-frame-options.deny", "DENY", results)
	evaluateExactHeader(header, "X-Content-Type-Options", "header.x-content-type-options", "x-content-type-options.nosniff", "nosniff", results)
	evaluateExactHeader(header, "Referrer-Policy", "header.referrer-policy", "referrer-policy.no-referrer", "no-referrer", results)
	evaluatePermissionsPolicy(header, results)
	evaluateExactHeader(header, "Cross-Origin-Opener-Policy", "header.coop", "coop.same-origin", "same-origin", results)
	evaluateExactHeader(header, "Cross-Origin-Resource-Policy", "header.corp", "corp.same-origin", "same-origin", results)
	return results
}

func evaluateHSTS(header http.Header, mode Mode, results map[string]bool) {
	value, present, noConflict := uniqueHeader(header, "Strict-Transport-Security")
	results["header.hsts.present"] = present
	results["header.hsts.no-conflict"] = noConflict
	results["hsts.syntax"] = false
	results["hsts.max-age"] = false
	results["hsts.include-subdomains.absent"] = false
	results["hsts.preload.absent"] = false
	if !present || !noConflict {
		return
	}
	directives, maxAge, valid := parseHSTS(value)
	results["hsts.syntax"] = valid
	if !valid {
		return
	}
	if mode == ModeCanary {
		results["hsts.max-age"] = maxAge == CanaryMaxAgeSeconds
	} else {
		results["hsts.max-age"] = maxAge >= SteadyMinAgeSeconds
	}
	_, includesSubdomains := directives["includesubdomains"]
	_, preload := directives["preload"]
	results["hsts.include-subdomains.absent"] = !includesSubdomains
	results["hsts.preload.absent"] = !preload
}

func parseHSTS(value string) (map[string]string, uint64, bool) {
	if !validASCIIFieldValue(value) {
		return nil, 0, false
	}
	directives := make(map[string]string)
	for _, raw := range strings.Split(value, ";") {
		raw = trimOWS(raw)
		if raw == "" {
			continue
		}
		name, directiveValue, hasValue := strings.Cut(raw, "=")
		name = trimOWS(name)
		if !directiveNamePattern.MatchString(name) {
			return nil, 0, false
		}
		name = asciiLower(name)
		if _, exists := directives[name]; exists {
			return nil, 0, false
		}
		if hasValue {
			directiveValue = trimOWS(directiveValue)
			if directiveValue == "" || strings.Contains(directiveValue, "=") {
				return nil, 0, false
			}
		} else {
			directiveValue = ""
		}
		switch name {
		case "max-age":
			if !hasValue {
				return nil, 0, false
			}
		case "includesubdomains", "preload":
			if hasValue {
				return nil, 0, false
			}
		default:
			return nil, 0, false
		}
		directives[name] = directiveValue
	}
	maxAgeValue, exists := directives["max-age"]
	if !exists {
		return nil, 0, false
	}
	if maxAgeValue == "" {
		return nil, 0, false
	}
	for _, character := range maxAgeValue {
		if character < '0' || character > '9' {
			return nil, 0, false
		}
	}
	maxAge, err := strconv.ParseUint(maxAgeValue, 10, 64)
	if err != nil {
		return nil, 0, false
	}
	return directives, maxAge, true
}

func evaluateCSP(header http.Header, surface Surface, results map[string]bool) {
	value, present, noConflict := uniqueHeader(header, "Content-Security-Policy")
	results["header.csp.present"] = present
	results["header.csp.no-conflict"] = noConflict
	results["csp.syntax"] = false
	results["csp.default-src"] = false
	results["csp.object-src-none"] = false
	results["csp.base-uri-none"] = false
	results["csp.frame-ancestors-none"] = false
	if surface == SurfaceAPI {
		results["csp.api.sandbox"] = false
	} else {
		results["csp.script.no-unsafe-inline"] = false
		results["csp.script.no-unsafe-eval"] = false
	}
	if !present || !noConflict {
		return
	}
	directives, valid := parseCSP(value)
	results["csp.syntax"] = valid
	if !valid {
		return
	}
	defaultSources := directives["default-src"]
	if surface == SurfaceAPI {
		results["csp.default-src"] = exactTokens(defaultSources, "'none'")
		values, sandboxExists := directives["sandbox"]
		results["csp.api.sandbox"] = sandboxExists && len(values) == 0
	} else {
		results["csp.default-src"] = exactTokens(defaultSources, "'self'") || exactTokens(defaultSources, "'none'")
		results["csp.script.no-unsafe-inline"] = scriptDirectivesOmit(directives, "'unsafe-inline'")
		results["csp.script.no-unsafe-eval"] = scriptDirectivesOmit(directives, "'unsafe-eval'")
	}
	results["csp.object-src-none"] = exactTokens(directives["object-src"], "'none'")
	results["csp.base-uri-none"] = exactTokens(directives["base-uri"], "'none'")
	results["csp.frame-ancestors-none"] = exactTokens(directives["frame-ancestors"], "'none'")
}

func scriptDirectivesOmit(directives map[string][]string, forbidden string) bool {
	for _, name := range []string{"default-src", "script-src", "script-src-elem", "script-src-attr"} {
		for _, value := range directives[name] {
			if asciiEqualFold(value, forbidden) {
				return false
			}
		}
	}
	return true
}

func parseCSP(value string) (map[string][]string, bool) {
	if !validASCIIFieldValue(value) {
		return nil, false
	}
	directives := make(map[string][]string)
	for _, raw := range strings.Split(value, ";") {
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		name := asciiLower(fields[0])
		if !directiveNamePattern.MatchString(name) {
			return nil, false
		}
		if _, exists := directives[name]; exists {
			return nil, false
		}
		directives[name] = append([]string{}, fields[1:]...)
	}
	return directives, len(directives) > 0
}

func evaluatePermissionsPolicy(header http.Header, results map[string]bool) {
	value, present, noConflict := uniqueHeader(header, "Permissions-Policy")
	results["header.permissions-policy.present"] = present
	results["header.permissions-policy.no-conflict"] = noConflict
	results["permissions-policy.syntax"] = false
	results["permissions-policy.camera-disabled"] = false
	results["permissions-policy.microphone-disabled"] = false
	results["permissions-policy.geolocation-disabled"] = false
	results["permissions-policy.payment-disabled"] = false
	results["permissions-policy.usb-disabled"] = false
	if !present || !noConflict {
		return
	}
	directives, valid := parsePermissionsPolicy(value)
	results["permissions-policy.syntax"] = valid
	if !valid {
		return
	}
	results["permissions-policy.camera-disabled"] = directives["camera"] == "()"
	results["permissions-policy.microphone-disabled"] = directives["microphone"] == "()"
	results["permissions-policy.geolocation-disabled"] = directives["geolocation"] == "()"
	results["permissions-policy.payment-disabled"] = directives["payment"] == "()"
	results["permissions-policy.usb-disabled"] = directives["usb"] == "()"
}

func parsePermissionsPolicy(value string) (map[string]string, bool) {
	if !validASCIIFieldValue(value) {
		return nil, false
	}
	directives := make(map[string]string)
	for _, raw := range strings.Split(value, ",") {
		member := trimOWS(raw)
		name, allowlist, found := strings.Cut(member, "=")
		if !found || name == "" || name != trimOWS(name) || allowlist != trimOWS(allowlist) {
			return nil, false
		}
		if name != asciiLower(name) || !directiveNamePattern.MatchString(name) || !requiredPermission(name) || allowlist != "()" {
			return nil, false
		}
		if _, exists := directives[name]; exists {
			return nil, false
		}
		directives[name] = allowlist
	}
	return directives, len(directives) == 5
}

func evaluateExactHeader(header http.Header, headerName, prefix, policyRule, expected string, results map[string]bool) {
	value, present, noConflict := uniqueHeader(header, headerName)
	results[prefix+".present"] = present
	results[prefix+".no-conflict"] = noConflict
	results[policyRule] = present && noConflict && asciiEqualFold(trimOWS(value), expected)
}

func uniqueHeader(header http.Header, name string) (string, bool, bool) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", false, true
	}
	if !validASCIIFieldValue(values[0]) {
		return "", true, false
	}
	first := trimOWS(values[0])
	for _, value := range values[1:] {
		if !validASCIIFieldValue(value) || first != trimOWS(value) {
			return "", true, false
		}
	}
	return first, true, true
}

func exactTokens(actual []string, expected ...string) bool {
	if len(actual) != len(expected) {
		return false
	}
	return slices.Equal(normalizeASCII(actual), normalizeASCII(expected))
}

func normalizeASCII(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		normalized = append(normalized, asciiLower(value))
	}
	return normalized
}

func requiredPermission(name string) bool {
	switch name {
	case "camera", "microphone", "geolocation", "payment", "usb":
		return true
	default:
		return false
	}
}

func validASCIIFieldValue(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '\t' || (character >= 0x20 && character <= 0x7e) {
			continue
		}
		return false
	}
	return true
}

func trimOWS(value string) string {
	return strings.Trim(value, " \t")
}

func asciiLower(value string) string {
	lowered := []byte(value)
	for index, character := range lowered {
		if character >= 'A' && character <= 'Z' {
			lowered[index] = character + ('a' - 'A')
		}
	}
	return string(lowered)
}

func asciiEqualFold(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := 0; index < len(left); index++ {
		leftCharacter := left[index]
		rightCharacter := right[index]
		if leftCharacter >= 'A' && leftCharacter <= 'Z' {
			leftCharacter += 'a' - 'A'
		}
		if rightCharacter >= 'A' && rightCharacter <= 'Z' {
			rightCharacter += 'a' - 'A'
		}
		if leftCharacter != rightCharacter {
			return false
		}
	}
	return true
}
