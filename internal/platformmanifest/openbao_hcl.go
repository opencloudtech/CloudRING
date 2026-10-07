// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package platformmanifest

import (
	"errors"
	"strconv"
	"unicode"
)

type hclToken struct {
	kind  byte
	value string
}

type hclParser struct {
	tokens []hclToken
	index  int
}

func parseOpenBaoHCL(source string) (openBaoHCL, error) {
	tokens, err := lexOpenBaoHCL(source)
	if err != nil {
		return openBaoHCL{}, err
	}
	parser := hclParser{tokens: tokens}
	var result openBaoHCL
	seen := map[string]bool{}
	for !parser.done() {
		name, err := parser.identifier()
		if err != nil {
			return openBaoHCL{}, err
		}
		if seen[name] && name != "listener" && name != "storage" && name != "audit" && name != "service_registration" {
			return openBaoHCL{}, errors.New("duplicate top-level HCL attribute")
		}
		seen[name] = true
		switch name {
		case "ui":
			result.UI, err = parser.booleanAssignment()
		case "listener":
			var listener openBaoListener
			listener, err = parser.listenerBlock()
			result.Listeners = append(result.Listeners, listener)
		case "storage":
			var storage openBaoStorage
			storage, err = parser.storageBlock()
			result.Storage = append(result.Storage, storage)
		case "audit":
			var audit openBaoAudit
			audit, err = parser.auditBlock()
			result.Audits = append(result.Audits, audit)
		case "service_registration":
			var registry openBaoServiceRegistry
			registry, err = parser.serviceRegistryBlock()
			result.ServiceRegistrations = append(result.ServiceRegistrations, registry)
		default:
			return openBaoHCL{}, errors.New("unknown top-level HCL item")
		}
		if err != nil {
			return openBaoHCL{}, err
		}
	}
	if !seen["ui"] {
		return openBaoHCL{}, errors.New("required top-level HCL attribute is missing")
	}
	return result, nil
}

func lexOpenBaoHCL(source string) ([]hclToken, error) {
	var tokens []hclToken
	for index := 0; index < len(source); {
		r := rune(source[index])
		if unicode.IsSpace(r) {
			index++
			continue
		}
		if source[index] == '#' {
			for index < len(source) && source[index] != '\n' {
				index++
			}
			continue
		}
		switch source[index] {
		case '{', '}', '=':
			tokens = append(tokens, hclToken{kind: source[index], value: source[index : index+1]})
			index++
			continue
		case '"':
			start := index
			index++
			escaped := false
			for index < len(source) {
				character := source[index]
				index++
				if escaped {
					escaped = false
					continue
				}
				if character == '\\' {
					escaped = true
					continue
				}
				if character == '"' {
					decoded, err := strconv.Unquote(source[start:index])
					if err != nil {
						return nil, errors.New("invalid HCL string")
					}
					tokens = append(tokens, hclToken{kind: 's', value: decoded})
					break
				}
			}
			if len(tokens) == 0 || tokens[len(tokens)-1].kind != 's' || source[index-1] != '"' {
				return nil, errors.New("unterminated HCL string")
			}
			continue
		}
		if unicode.IsLetter(r) || source[index] == '_' {
			start := index
			for index < len(source) {
				current := rune(source[index])
				if !unicode.IsLetter(current) && !unicode.IsDigit(current) && source[index] != '_' {
					break
				}
				index++
			}
			tokens = append(tokens, hclToken{kind: 'i', value: source[start:index]})
			continue
		}
		if unicode.IsDigit(r) {
			start := index
			for index < len(source) && unicode.IsDigit(rune(source[index])) {
				index++
			}
			tokens = append(tokens, hclToken{kind: 'n', value: source[start:index]})
			continue
		}
		return nil, errors.New("unsupported HCL token")
	}
	return tokens, nil
}

func (parser *hclParser) listenerBlock() (openBaoListener, error) {
	label, err := parser.stringToken()
	if err != nil || parser.consume('{') != nil {
		return openBaoListener{}, errors.New("invalid listener block")
	}
	result := openBaoListener{Type: label}
	seen := map[string]bool{}
	for !parser.peek('}') {
		name, err := parser.uniqueIdentifier(seen)
		if err != nil {
			return openBaoListener{}, err
		}
		switch name {
		case "address":
			result.Address, err = parser.stringAssignment()
		case "cluster_address":
			result.ClusterAddress, err = parser.stringAssignment()
		case "tls_disable":
			result.TLSDisable, err = parser.integerAssignment()
		case "tls_cert_file":
			result.TLSCertFile, err = parser.stringAssignment()
		case "tls_key_file":
			result.TLSKeyFile, err = parser.stringAssignment()
		case "tls_client_ca_file":
			result.TLSClientCAFile, err = parser.stringAssignment()
		default:
			return openBaoListener{}, errors.New("unknown listener attribute")
		}
		if err != nil {
			return openBaoListener{}, err
		}
	}
	for _, required := range []string{"address", "cluster_address", "tls_disable", "tls_cert_file", "tls_key_file", "tls_client_ca_file"} {
		if !seen[required] {
			return openBaoListener{}, errors.New("required listener attribute is missing")
		}
	}
	return result, parser.consume('}')
}

func (parser *hclParser) storageBlock() (openBaoStorage, error) {
	label, err := parser.stringToken()
	if err != nil || parser.consume('{') != nil {
		return openBaoStorage{}, errors.New("invalid storage block")
	}
	result := openBaoStorage{Type: label}
	seen := map[string]bool{}
	for !parser.peek('}') {
		name, err := parser.identifier()
		if err != nil {
			return openBaoStorage{}, err
		}
		if name == "retry_join" {
			join, err := parser.retryJoinBlock()
			if err != nil {
				return openBaoStorage{}, err
			}
			result.RetryJoin = append(result.RetryJoin, join)
			continue
		}
		if name != "path" || seen[name] {
			return openBaoStorage{}, errors.New("unknown or duplicate storage attribute")
		}
		seen[name] = true
		result.Path, err = parser.stringAssignment()
		if err != nil {
			return openBaoStorage{}, err
		}
	}
	return result, parser.consume('}')
}

func (parser *hclParser) retryJoinBlock() (openBaoRetryJoin, error) {
	if err := parser.consume('{'); err != nil {
		return openBaoRetryJoin{}, err
	}
	result := openBaoRetryJoin{}
	seen := map[string]bool{}
	for !parser.peek('}') {
		name, err := parser.uniqueIdentifier(seen)
		if err != nil {
			return openBaoRetryJoin{}, err
		}
		var target *string
		switch name {
		case "leader_api_addr":
			target = &result.LeaderAPIAddress
		case "leader_ca_cert_file":
			target = &result.LeaderCACertFile
		case "leader_client_cert_file":
			target = &result.LeaderClientCertFile
		case "leader_client_key_file":
			target = &result.LeaderClientKeyFile
		case "leader_tls_servername":
			target = &result.LeaderTLSServerName
		default:
			return openBaoRetryJoin{}, errors.New("unknown retry-join attribute")
		}
		*target, err = parser.stringAssignment()
		if err != nil {
			return openBaoRetryJoin{}, err
		}
	}
	return result, parser.consume('}')
}

func (parser *hclParser) serviceRegistryBlock() (openBaoServiceRegistry, error) {
	label, err := parser.stringToken()
	if err != nil || parser.consume('{') != nil || parser.consume('}') != nil {
		return openBaoServiceRegistry{}, errors.New("invalid service-registration block")
	}
	return openBaoServiceRegistry{Type: label}, nil
}

func (parser *hclParser) auditBlock() (openBaoAudit, error) {
	auditType, err := parser.stringToken()
	if err != nil {
		return openBaoAudit{}, errors.New("invalid audit block")
	}
	name, err := parser.stringToken()
	if err != nil || parser.consume('{') != nil {
		return openBaoAudit{}, errors.New("invalid audit block")
	}
	result := openBaoAudit{Type: auditType, Name: name}
	seen := map[string]bool{}
	for !parser.peek('}') {
		attribute, err := parser.uniqueIdentifier(seen)
		if err != nil {
			return openBaoAudit{}, err
		}
		switch attribute {
		case "description":
			result.Description, err = parser.stringAssignment()
		case "options":
			result.Options, err = parser.auditOptionsBlock()
		default:
			return openBaoAudit{}, errors.New("unknown audit attribute")
		}
		if err != nil {
			return openBaoAudit{}, err
		}
	}
	if !seen["description"] || !seen["options"] {
		return openBaoAudit{}, errors.New("required audit attribute is missing")
	}
	return result, parser.consume('}')
}

func (parser *hclParser) auditOptionsBlock() (openBaoAuditOptions, error) {
	if err := parser.consume('{'); err != nil {
		return openBaoAuditOptions{}, errors.New("invalid audit options block")
	}
	result := openBaoAuditOptions{}
	seen := map[string]bool{}
	for !parser.peek('}') {
		name, err := parser.uniqueIdentifier(seen)
		if err != nil {
			return openBaoAuditOptions{}, err
		}
		var target *string
		switch name {
		case "file_path":
			target = &result.FilePath
		case "mode":
			target = &result.Mode
		case "log_raw":
			target = &result.LogRaw
		default:
			return openBaoAuditOptions{}, errors.New("unknown audit option")
		}
		*target, err = parser.stringAssignment()
		if err != nil {
			return openBaoAuditOptions{}, err
		}
	}
	for _, required := range []string{"file_path", "mode", "log_raw"} {
		if !seen[required] {
			return openBaoAuditOptions{}, errors.New("required audit option is missing")
		}
	}
	return result, parser.consume('}')
}

func (parser *hclParser) uniqueIdentifier(seen map[string]bool) (string, error) {
	name, err := parser.identifier()
	if err != nil || seen[name] {
		return "", errors.New("duplicate or invalid HCL attribute")
	}
	seen[name] = true
	return name, nil
}

func (parser *hclParser) identifier() (string, error) {
	if parser.done() || parser.tokens[parser.index].kind != 'i' {
		return "", errors.New("expected HCL identifier")
	}
	value := parser.tokens[parser.index].value
	parser.index++
	return value, nil
}

func (parser *hclParser) stringAssignment() (string, error) {
	if err := parser.consume('='); err != nil {
		return "", err
	}
	return parser.stringToken()
}

func (parser *hclParser) stringToken() (string, error) {
	if parser.done() || parser.tokens[parser.index].kind != 's' {
		return "", errors.New("expected HCL string")
	}
	value := parser.tokens[parser.index].value
	parser.index++
	return value, nil
}

func (parser *hclParser) booleanAssignment() (bool, error) {
	if err := parser.consume('='); err != nil {
		return false, err
	}
	value, err := parser.identifier()
	if err != nil || (value != "true" && value != "false") {
		return false, errors.New("expected HCL boolean")
	}
	return value == "true", nil
}

func (parser *hclParser) integerAssignment() (int, error) {
	if err := parser.consume('='); err != nil || parser.done() || parser.tokens[parser.index].kind != 'n' {
		return 0, errors.New("expected HCL integer")
	}
	value, err := strconv.Atoi(parser.tokens[parser.index].value)
	parser.index++
	return value, err
}

func (parser *hclParser) consume(kind byte) error {
	if parser.done() || parser.tokens[parser.index].kind != kind {
		return errors.New("unexpected HCL token")
	}
	parser.index++
	return nil
}

func (parser *hclParser) peek(kind byte) bool {
	return !parser.done() && parser.tokens[parser.index].kind == kind
}

func (parser *hclParser) done() bool {
	return parser.index == len(parser.tokens)
}
