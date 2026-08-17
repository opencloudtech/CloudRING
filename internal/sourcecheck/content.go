// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package sourcecheck

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
)

type contentRule struct {
	id      string
	class   string
	message string
	pattern *regexp.Regexp
}

var directContentRules = []contentRule{
	{id: "github_classic_token", class: "secret", message: "GitHub token-like value", pattern: regexp.MustCompile(`\b` + "g" + `hp_[A-Za-z0-9_]{20,}\b`)},
	{id: "github_fine_grained_token", class: "secret", message: "GitHub fine-grained token-like value", pattern: regexp.MustCompile(`\b` + "github_" + `pat_[A-Za-z0-9_]{20,}\b`)},
	{id: "cloud_access_key", class: "secret", message: "cloud access-key identifier", pattern: regexp.MustCompile(`\b(?:A` + `KIA|A` + `SIA)[A-Z0-9]{16}\b`)},
	{id: "private_key_block", class: "private_key", message: "private key material", pattern: regexp.MustCompile(`B` + `EGIN [A-Z0-9 ]*PRIVATE KEY`)},
	{id: "authorization_bearer", class: "secret", message: "serialized authorization credential", pattern: regexp.MustCompile(`(?i)Authori` + `zation\s*:\s*Bearer\s+[-._~+/A-Za-z0-9]+=*`)},
	{id: "compact_jwt", class: "secret", message: "compact JWT-like credential", pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{id: "kubeconfig_key_data", class: "kubeconfig", message: "embedded kubeconfig credential material", pattern: regexp.MustCompile(`(?i)client-` + `key-data\s*:`)},
	{id: "kubeconfig_certificate_data", class: "kubeconfig", message: "embedded kubeconfig credential material", pattern: regexp.MustCompile(`(?i)(?:client-` + `certificate-data|certificate-` + `authority-data)\s*:`)},
	{id: "kubeconfig_context", class: "kubeconfig", message: "serialized kubeconfig context", pattern: regexp.MustCompile(`(?i)current-` + `context\s*:`)},
}

var (
	credentialKeyPattern        = regexp.MustCompile(`(?i)(?:^|[\s,{])["']?([a-z][a-z0-9_.-]*)["']?\s*([:=])`)
	xmlCredentialPattern        = regexp.MustCompile(`(?i)<\s*([a-z][a-z0-9_.:-]*)\s*>\s*([^<\r\n]+?)\s*</`)
	urlCredentialPattern        = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]{1,31}://[^/\s:@]+:([^@\s/]+)@[^/\s]+`)
	environmentReferencePattern = regexp.MustCompile(`^(?:\$\{[A-Z_][A-Z0-9_]*\}|(?:os[.])?(?:Getenv|LookupEnv)[(]["'][A-Z_][A-Z0-9_]*["'][)])$`)
	environmentNamePattern      = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	dnsReferencePattern         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	structuredReferencePattern  = regexp.MustCompile(`^(?:secretref|secretstore|credentialref)[.][a-z0-9](?:[a-z0-9._:/-]*[a-z0-9])?$`)
	goTemplateReferencePattern  = regexp.MustCompile(`^{{-?\s*\.[A-Za-z][A-Za-z0-9_.]*\s*-?}}$`)
	ipv4TokenPattern            = regexp.MustCompile(`\b(?:[0-9]{1,3}[.]){3}[0-9]{1,3}\b`)
	ipv6TokenPattern            = regexp.MustCompile(`\[?[0-9A-Fa-f:]*:[0-9A-Fa-f:]+\]?`)
	privateHostnamePattern      = regexp.MustCompile(`(?i)(?:https?://|ssh://|git@)(?:[a-z0-9-]+[.])+(?:in` + `ternal|lo` + `cal|co` + `rp|la` + `n|intra` + `net|ho` + `me|local` + `domain)(?::[0-9]+)?`)
	barePrivateHostnamePattern  = regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+[.])+(?:in` + `ternal|lo` + `cal|co` + `rp|la` + `n|intra` + `net|ho` + `me|local` + `domain)(?::[0-9]+)?\b`)
	unixUserPathPattern         = regexp.MustCompile(`(?i)/(?:Us` + `ers|ho` + `me)/[^\s"']+`)
	windowsUserPathPattern      = regexp.MustCompile(`(?i)[a-z]:[\\/](?:Us` + `ers|Documents and Settings)[\\/][^\s"']+`)
	referenceCredentialKeys     = exactStringSet(
		"access"+"keyref", "api"+"keyref", "client"+"secretref", "credential"+"ref", "pass"+"wordref",
		"private"+"keyref", "secret"+"keyref", "secret"+"name", "secret"+"namespace", "secret"+"ref", "secret"+"storeref", "token"+"env",
	)
	baseCredentialKeys = exactStringSet(
		"access"+"key", "access"+"keyid", "access"+"token", "api"+"key", "api"+"token", "auth"+"token",
		"client"+"secret", "credential", "pass"+"word", "pass"+"wd", "private"+"key", "refresh"+"token",
		"se"+"cret", "secret"+"value", "signing"+"key", "to"+"ken",
	)
	nonCredentialConfigKeys = exactStringSet(
		"id"+"token",
		"automount"+"serviceaccounttoken",
		"create"+"secret",
		"credential"+"class",
		"contains"+"credentials",
		"contains"+"secrets",
		"password"+"encryption",
		"persist"+"credentials",
		"token"+"ttl",
		"token"+"maxttl",
		"token"+"nodefaultpolicy",
		"serviceaccount"+"tokencreate",
		"enable"+"tokencache",
		"secret"+"key",
		"image"+"pull"+"secrets",
		"aggregate"+"proof"+"path"+"token",
	)
)

func scanContent(path string, content string) []Finding {
	budget := newFindingBudget(nil)
	findings, _ := scanContentWithBudget(path, "", "text", content, budget)
	return findings
}

func scanContentWithBudget(path string, sourceVariant string, inputKind string, content string, budget *findingBudget) ([]Finding, error) {
	var findings []Finding
	pendingCredentialLine := 0
	lineNumber := 1
	previousLine := ""
	reviewedVendoredDocumentation := reviewedVendoredPrivateKeyDocumentation(path, sourceVariant, inputKind, content)
	for start := 0; start <= len(content); {
		end := strings.IndexByte(content[start:], '\n')
		if end < 0 {
			end = len(content)
		} else {
			end += start
		}
		line := content[start:end]
		if err := budget.consumeLine(); err != nil {
			return nil, err
		}
		if pendingCredentialLine != 0 {
			if value, resolved := multilineCredentialScalar(line); resolved {
				if value != "" && !structuralCredentialReference(value) {
					if err := budget.add(&findings, Finding{Rule: "credential_assignment", Class: "secret", Line: pendingCredentialLine, Message: "credential-like assignment contains a value instead of a reference"}); err != nil {
						return nil, err
					}
				}
				pendingCredentialLine = 0
			}
		}
		for _, rule := range directContentRules {
			if rule.pattern.FindStringIndex(line) != nil && !(rule.id == "private_key_block" && reviewedVendoredDocumentation && exactVendoredPrivateKeyDocumentationLine(previousLine, line)) {
				if err := budget.add(&findings, Finding{Rule: rule.id, Class: rule.class, Line: lineNumber, Message: rule.message}); err != nil {
					return nil, err
				}
			}
		}
		if credentialAssignmentForPath(path, line) {
			if err := budget.add(&findings, Finding{Rule: "credential_assignment", Class: "secret", Line: lineNumber, Message: "credential-like assignment contains a value instead of a reference"}); err != nil {
				return nil, err
			}
		}
		if xmlCredentialAssignment(line) {
			if err := budget.add(&findings, Finding{Rule: "credential_xml", Class: "secret", Line: lineNumber, Message: "credential-like XML element contains a value instead of a reference"}); err != nil {
				return nil, err
			}
		}
		if urlCredentialAssignment(line) {
			if err := budget.add(&findings, Finding{Rule: "credential_url", Class: "secret", Line: lineNumber, Message: "URL contains embedded credential userinfo"}); err != nil {
				return nil, err
			}
		}
		if pendingCredentialLine == 0 && credentialAssignmentAwaitsValue(path, line) {
			pendingCredentialLine = lineNumber
		}
		if privateEndpoint(line) {
			if err := budget.add(&findings, Finding{Rule: "private_endpoint", Class: "private_endpoint", Line: lineNumber, Message: "private or host-local endpoint value"}); err != nil {
				return nil, err
			}
		}
		if localFilesystemPath(line) {
			if err := budget.add(&findings, Finding{Rule: "local_user_path", Class: "local_path", Line: lineNumber, Message: "local user-profile path"}); err != nil {
				return nil, err
			}
		}
		if privateTreeReference(line) {
			if err := budget.add(&findings, Finding{Rule: "private_tree_reference", Class: "private_source", Line: lineNumber, Message: "private source-tree or evidence reference"}); err != nil {
				return nil, err
			}
		}
		if privateSourceAttribution(line) {
			if err := budget.add(&findings, Finding{Rule: "private_source_attribution", Class: "private_source", Line: lineNumber, Message: "attribution to copied private or proprietary source"}); err != nil {
				return nil, err
			}
		}
		if end == len(content) {
			break
		}
		previousLine = line
		start = end + 1
		lineNumber++
	}
	readiness, err := readinessFindingsWithBudget(path, content, budget)
	if err != nil {
		return nil, err
	}
	return append(findings, readiness...), nil
}

func credentialAssignment(line string) bool {
	return credentialAssignmentForPath("synthetic-config.yaml", line)
}

func credentialAssignmentForPath(path string, line string) bool {
	if strings.HasPrefix(strings.TrimSpace(line), "type ") {
		return false
	}
	extendedKeys := credentialConfigPath(path)
	for _, match := range credentialKeyPattern.FindAllStringSubmatchIndex(line, -1) {
		if len(match) != 6 {
			continue
		}
		separatorStart := match[4]
		valueStart := match[1]
		separator := line[separatorStart]
		if separator == '=' && valueStart < len(line) && line[valueStart] == '=' {
			continue
		}
		if separator == ':' && valueStart < len(line) && line[valueStart] == '=' {
			valueStart++
		}
		key := normalizeCredentialKey(line[match[2]:match[3]])
		value := credentialScalar(line[valueStart:])
		// An empty YAML sensitive-field mapping followed by indented structural
		// fields contains no credential scalar. Nested lines are scanned
		// independently, so treating the parent mapping as safe cannot hide an
		// assigned credential value.
		if value == "" {
			continue
		}
		if referenceKind, ok := referenceCredentialKind(key, extendedKeys); ok {
			if !validReferenceCredentialValue(referenceKind, value) {
				return true
			}
			continue
		}
		if !credentialKey(key, extendedKeys) {
			continue
		}
		if !credentialContainer(value) && !structuralCredentialReference(value) {
			return true
		}
	}
	return false
}

func credentialAssignmentAwaitsValue(path string, line string) bool {
	if strings.Contains(line, "{{") || strings.Contains(line, "}}") {
		return false
	}
	if !credentialConfigPath(path) || strings.HasPrefix(strings.TrimSpace(line), "type ") {
		return false
	}
	extendedKeys := credentialConfigPath(path)
	for _, match := range credentialKeyPattern.FindAllStringSubmatchIndex(line, -1) {
		if len(match) != 6 {
			continue
		}
		key := normalizeCredentialKey(line[match[2]:match[3]])
		if _, ok := referenceCredentialKind(key, extendedKeys); ok || !credentialKey(key, extendedKeys) {
			continue
		}
		if credentialScalar(line[match[1]:]) == "" {
			return true
		}
	}
	return false
}

func multilineCredentialScalar(line string) (string, bool) {
	value := strings.TrimSpace(line)
	if value == "" || strings.HasPrefix(value, "#") || strings.HasPrefix(value, "//") {
		return "", false
	}
	if credentialContainer(value) {
		return "", true
	}
	if value == "}" || value == "}," || value == "]" || value == "]," {
		return "", true
	}
	// A following mapping entry is independently scanned. Only a standalone
	// scalar resolves a pending sensitive JSON/YAML key.
	if credentialKeyPattern.FindStringIndex(value) != nil {
		return "", true
	}
	value = strings.TrimSuffix(value, ",")
	if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
		return value, true
	}
	return value, true
}

func xmlCredentialAssignment(line string) bool {
	for _, match := range xmlCredentialPattern.FindAllStringSubmatchIndex(line, -1) {
		if len(match) != 6 {
			continue
		}
		key := normalizeCredentialKey(line[match[2]:match[3]])
		if _, ok := referenceCredentialKind(key, true); ok || !credentialKey(key, true) {
			continue
		}
		if value := strings.TrimSpace(line[match[4]:match[5]]); value != "" && !structuralCredentialReference(value) {
			return true
		}
	}
	return false
}

func urlCredentialAssignment(line string) bool {
	for _, match := range urlCredentialPattern.FindAllStringSubmatchIndex(line, -1) {
		if len(match) != 4 {
			continue
		}
		value := line[match[2]:match[3]]
		if value != "" && !structuralCredentialReference(value) {
			return true
		}
	}
	return false
}

func credentialScalar(remainder string) string {
	value := strings.TrimLeft(remainder, " \t")
	if value == "" {
		return ""
	}
	parenDepth, braceDepth, bracketDepth := 0, 0, 0
	var quote byte
	escaped := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if quote != 0 {
			switch {
			case escaped:
				escaped = false
			case character == '\\':
				escaped = true
			case character == quote:
				quote = 0
			}
			continue
		}
		switch character {
		case '"', '\'':
			quote = character
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth == 0 && parenDepth == 0 && bracketDepth == 0 {
				return strings.TrimSpace(value[:index])
			}
			braceDepth--
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth == 0 && parenDepth == 0 && braceDepth == 0 {
				return strings.TrimSpace(value[:index])
			}
			bracketDepth--
		case ',':
			if parenDepth == 0 && braceDepth == 0 && bracketDepth == 0 {
				return strings.TrimSpace(value[:index])
			}
		case '#':
			if parenDepth == 0 && braceDepth == 0 && bracketDepth == 0 && (index == 0 || value[index-1] == ' ' || value[index-1] == '\t') {
				return strings.TrimSpace(value[:index])
			}
		}
	}
	return strings.TrimSpace(value)
}

func normalizeCredentialKey(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if character != '_' && character != '-' && character != '.' && character != ':' {
			builder.WriteRune(unicode.ToLower(character))
		}
	}
	return builder.String()
}

func credentialKey(key string, extended bool) bool {
	if _, ok := baseCredentialKeys[key]; ok {
		return true
	}
	if !extended {
		return false
	}
	if _, ok := nonCredentialConfigKeys[key]; ok {
		return false
	}
	for _, marker := range []string{
		"pass" + "word",
		"pass" + "wd",
		"se" + "cret",
		"to" + "ken",
		"private" + "key",
		"api" + "key",
		"credential",
	} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return strings.Contains(key, "access"+"key") ||
		strings.HasSuffix(key, "signing"+"key") ||
		strings.HasSuffix(key, "signing"+"keyid")
}

func credentialConfigPath(path string) bool {
	lower := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	base := lower[strings.LastIndex(lower, "/")+1:]
	if strings.HasSuffix(base, ".schema.json") {
		return false
	}
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}
	for _, suffix := range []string{".conf", ".config", ".ini", ".json", ".properties", ".toml", ".xml", ".yaml", ".yml"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

func referenceCredentialKind(key string, qualified bool) (string, bool) {
	if _, ok := referenceCredentialKeys[key]; ok {
		return key, true
	}
	if !qualified {
		return "", false
	}
	for _, suffix := range []string{
		"access" + "keyref",
		"api" + "keyref",
		"client" + "secretref",
		"credential" + "ref",
		"pass" + "wordref",
		"private" + "keyref",
		"secret" + "keyref",
		"secret" + "name",
		"secret" + "namespace",
		"secret" + "ref",
		"secret" + "storeref",
		"token" + "env",
	} {
		if strings.HasSuffix(key, suffix) {
			return suffix, true
		}
	}
	for _, suffix := range []string{
		"credential" + "secret",
		"registry" + "secret",
		"tls" + "secret",
	} {
		if strings.HasSuffix(key, suffix) {
			return "secret" + "name", true
		}
	}
	return "", false
}

func exactStringSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func structuralCredentialReference(raw string) bool {
	if nullCredentialScalar(raw) {
		return true
	}
	value := unquoteScalar(raw)
	if environmentReferencePattern.MatchString(value) || structuredReferencePattern.MatchString(value) || goTemplateReferencePattern.MatchString(value) {
		return true
	}
	switch strings.ToLower(value) {
	case "<redacted>", "***redacted***", "<placeholder>", "<password>", "<passwd>", "<pswd>", "<secret>", "<token>":
		return true
	default:
		return false
	}
}

func nullCredentialScalar(raw string) bool {
	value := strings.TrimSpace(raw)
	return value == "~" || strings.EqualFold(value, "null")
}

func credentialContainer(raw string) bool {
	switch strings.TrimSpace(raw) {
	case "{", "}", "[", "]", "{}", "[]":
		return true
	default:
		return false
	}
}

const reviewedVendoredPrivateKeyDocumentationPath = "deploy/kubernetes/storage/longhorn-three-node/vendor/longhorn/values.yaml"

func reviewedVendoredPrivateKeyDocumentation(path, sourceVariant, inputKind, content string) bool {
	if inputKind != "text" || !exactReviewedVendoredPrivateKeyDocumentationPath(path, sourceVariant) {
		return false
	}
	digest := sha256.Sum256([]byte(content))
	return hex.EncodeToString(digest[:]) == "70b801c79e6d54ac281dda702cd078249d9aa0bbdf13edaf1aced8e866c02876"
}

func exactReviewedVendoredPrivateKeyDocumentationPath(path, sourceVariant string) bool {
	if strings.Contains(path, `\`) {
		return false
	}
	canonical, err := canonicalPolicyPath(path)
	if err != nil || canonical != path {
		return false
	}
	if path == reviewedVendoredPrivateKeyDocumentationPath {
		return !strings.HasPrefix(sourceVariant, "gitlink/")
	}
	if sourceVariant != "gitlink/index" && sourceVariant != "gitlink/worktree" {
		return false
	}
	prefix, childPath, ok := strings.Cut(path, "/")
	return ok && prefix != "" && childPath == reviewedVendoredPrivateKeyDocumentationPath
}

func exactVendoredPrivateKeyDocumentationLine(previousLine, line string) bool {
	return previousLine == "  ## key and certificate should start with -----BEGIN CERTIFICATE----- or" &&
		line == "  ## -----B"+"EGIN RSA PRIVATE KEY-----"
}

func validReferenceCredentialValue(key string, raw string) bool {
	if nullCredentialScalar(raw) {
		return true
	}
	value := unquoteScalar(raw)
	if value == "" {
		return true
	}
	if environmentReferencePattern.MatchString(value) || goTemplateReferencePattern.MatchString(value) {
		return true
	}
	switch key {
	case "token" + "env":
		return environmentNamePattern.MatchString(value)
	case "secret" + "name", "secret" + "namespace":
		return dnsReferencePattern.MatchString(value)
	case "secret" + "ref", "secret" + "keyref", "secret" + "storeref", "credential" + "ref", "password" + "ref", "apikey" + "ref", "accesskey" + "ref", "clientsecret" + "ref", "privatekey" + "ref":
		return structuredReferencePattern.MatchString(value)
	default:
		return false
	}
}

func unquoteScalar(raw string) string {
	value := strings.TrimSpace(raw)
	if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
		return value[1 : len(value)-1]
	}
	return value
}

func privateEndpoint(line string) bool {
	if privateHostnamePattern.FindStringIndex(line) != nil {
		return true
	}
	lower := strings.ToLower(line)
	endpointContext := strings.Contains(lower, "endpoint") || strings.Contains(lower, "url") || strings.Contains(lower, "host:") || strings.Contains(lower, "host=")
	if endpointContext && barePrivateHostnamePattern.FindStringIndex(line) != nil {
		return true
	}
	for offset := 0; offset < len(line); {
		match := ipv4TokenPattern.FindStringIndex(line[offset:])
		if match == nil {
			break
		}
		addressText := line[offset+match[0] : offset+match[1]]
		offset += match[1]
		address, err := netip.ParseAddr(addressText)
		if err != nil || !address.Is4() {
			continue
		}
		sharedAddressSpace := netip.MustParsePrefix("100." + "64.0.0/10")
		if address.IsPrivate() || sharedAddressSpace.Contains(address) || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
			return true
		}
	}
	for offset := 0; offset < len(line); {
		match := ipv6TokenPattern.FindStringIndex(line[offset:])
		if match == nil {
			break
		}
		addressText := line[offset+match[0] : offset+match[1]]
		offset += match[1]
		candidate := strings.Trim(addressText, "[]")
		if candidate == "::" {
			if endpointContext {
				return true
			}
			continue
		}
		address, err := netip.ParseAddr(candidate)
		if err != nil || !address.Is6() {
			continue
		}
		if address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
			return true
		}
	}
	return false
}

func localFilesystemPath(line string) bool {
	return unixUserPathPattern.FindStringIndex(line) != nil || windowsUserPathPattern.FindStringIndex(line) != nil
}

func privateTreeReference(line string) bool {
	lower := strings.ToLower(line)
	privateModule := "cloudring" + ".local/" + "platform"
	privateEvidence := "." + "omo/"
	privateRequirements := "require" + "ments/"
	return strings.Contains(lower, privateModule) || strings.Contains(lower, privateEvidence) || strings.Contains(lower, privateRequirements)
}

func privateSourceAttribution(line string) bool {
	lower := strings.ToLower(strings.Join(strings.Fields(line), " "))
	phrases := []string{
		"copied " + "from private " + "source",
		"copied " + "from proprietary " + "source",
		"copied " + "from internal " + "repository",
		"ported " + "from private " + "repository",
	}
	for _, phrase := range phrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}
