// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package sourcecheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanContent_detects_sensitive_classes(t *testing.T) {
	tests := []struct {
		name string
		path string
		text string
		rule string
	}{
		{name: "github classic", path: "config.txt", text: "g" + "hp_" + strings.Repeat("A", 24), rule: "github_classic_token"},
		{name: "github fine grained", path: "config.txt", text: "github_" + "pat_" + strings.Repeat("B", 24), rule: "github_fine_grained_token"},
		{name: "cloud key", path: "config.txt", text: "A" + "KIA" + strings.Repeat("C", 16), rule: "cloud_access_key"},
		{name: "private key", path: "key.txt", text: "-----B" + "EGIN PRIVATE KEY-----", rule: "private_key_block"},
		{name: "authorization", path: "request.txt", text: "Authori" + "zation: Bearer " + strings.Repeat("d", 30), rule: "authorization_bearer"},
		{name: "jwt", path: "token.txt", text: "eyJ" + strings.Repeat("a", 12) + "." + strings.Repeat("b", 12) + "." + strings.Repeat("c", 12), rule: "compact_jwt"},
		{name: "credential assignment", path: "config.yaml", text: "pass" + "word: " + strings.Repeat("q", 18), rule: "credential_assignment"},
		{name: "kube key", path: "cluster.yaml", text: "client-" + "key-data: abc", rule: "kubeconfig_key_data"},
		{name: "kube certificate", path: "cluster.yaml", text: "client-" + "certificate-data: abc", rule: "kubeconfig_certificate_data"},
		{name: "kube context", path: "cluster.yaml", text: "current-" + "context: tenant", rule: "kubeconfig_context"},
		{name: "private ipv4", path: "config.yaml", text: "https://10." + "20.30.40:8443", rule: "private_endpoint"},
		{name: "private hostname", path: "config.yaml", text: "https://api." + "internal:8443", rule: "private_endpoint"},
		{name: "unix user path", path: "notes.txt", text: "/" + "Users/synthetic/work", rule: "local_user_path"},
		{name: "windows user path", path: "notes.txt", text: "C:" + `\Users\synthetic\work`, rule: "local_user_path"},
		{name: "private module", path: "go.mod", text: "cloudring" + ".local/" + "platform", rule: "private_tree_reference"},
		{name: "private evidence", path: "notes.txt", text: "." + "omo/receipt.json", rule: "private_tree_reference"},
		{name: "private requirements", path: "notes.txt", text: "require" + "ments/private.md", rule: "private_tree_reference"},
		{name: "private attribution", path: "notes.txt", text: "copied " + "from private " + "source", rule: "private_source_attribution"},
		{name: "readiness", path: "README.md", text: "The package is production " + "ready.", rule: "readiness_overclaim"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := scanContent(test.path, test.text)
			if !containsRule(findings, test.rule) {
				t.Fatalf("expected rule %q, got %+v", test.rule, findings)
			}
		})
	}
}

func TestScanContent_allows_references_and_explicit_non_claims(t *testing.T) {
	content := strings.Join([]string{
		"secretRef" + ": secretref.synthetic.access",
		"tokenEnv" + ": CLOUDRING_SYNTHETIC_TOKEN_ENV",
		"endpoint: https://service.example",
		"test endpoints: 192.0.2.10 198.51.100.20 203.0.113.30",
		"secret" + "Name: {{ .Values.ingress.tlsSecret }}",
		strings.Join([]string{"backupTargetCredentialSecret", ": ~"}, ""),
		strings.Join([]string{"registryPasswd", ": null"}, ""),
		strings.Join([]string{"registrySecret", ": registry.synthetic"}, ""),
		strings.Join([]string{"tlsSecret", ": longhorn.example-tls"}, ""),
		"This does not claim live production readiness.",
	}, "\n")
	if findings := scanContent("README.md", content); len(findings) != 0 {
		t.Fatalf("safe public references were rejected: %+v", findings)
	}
}

func TestScanContent_stillDetectsCommentedPrivateKeyMaterial(t *testing.T) {
	content := strings.Join([]string{
		"# -----B" + "EGIN RSA PRIVATE KEY-----",
		"# c3ludGhldGljLWxlYWtlZC1rZXktbWF0ZXJpYWw=",
		"# -----END RSA PRIVATE KEY-----",
	}, "\n")
	if findings := scanContent("values.yaml", content); !containsRule(findings, "private_key_block") {
		t.Fatalf("commented private key material was accepted: %+v", findings)
	}
}

func TestScanContent_allowsOnlyExactReviewedVendoredPrivateKeyDocumentation(t *testing.T) {
	repositoryPath := filepath.Join("..", "..", "deploy", "kubernetes", "storage", "longhorn-three-node", "vendor", "longhorn", "values.yaml")
	// #nosec G304 -- this test reads one fixed repository fixture path assembled for platform portability.
	data, err := os.ReadFile(repositoryPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	path := "deploy/kubernetes/storage/longhorn-three-node/vendor/longhorn/values.yaml"
	if findings := scanContent(path, content); len(findings) != 0 {
		t.Fatalf("exact reviewed vendored documentation was rejected: %+v", findings)
	}
	if findings := scanContent("other/values.yaml", content); !containsRule(findings, "private_key_block") {
		t.Fatalf("same documentation bytes outside the reviewed path were accepted: %+v", findings)
	}
	leaked := content + strings.Join([]string{
		"\n# -----B" + "EGIN RSA PRIVATE KEY-----",
		"# c3ludGhldGljLWxlYWtlZC1rZXktbWF0ZXJpYWw=",
		"# -----END RSA PRIVATE KEY-----\n",
	}, "\n")
	if findings := scanContent(path, leaked); !containsRule(findings, "private_key_block") {
		t.Fatalf("fully commented leaked PEM in the reviewed vendored path was accepted: %+v", findings)
	}
}

func TestReviewedVendoredPrivateKeyDocumentation_requiresExactPathDigestAndGitlinkProvenance(t *testing.T) {
	repositoryPath := filepath.Join("..", "..", filepath.FromSlash(reviewedVendoredPrivateKeyDocumentationPath))
	// #nosec G304 -- this test reads one fixed repository fixture path assembled for platform portability.
	data, err := os.ReadFile(repositoryPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	tests := []struct {
		name    string
		path    string
		variant string
		kind    string
		content string
		want    bool
	}{
		{name: "root index", path: reviewedVendoredPrivateKeyDocumentationPath, variant: "index", content: content, want: true},
		{name: "root worktree", path: reviewedVendoredPrivateKeyDocumentationPath, variant: "worktree", content: content, want: true},
		{name: "one gitlink index prefix", path: "cloudring_core/" + reviewedVendoredPrivateKeyDocumentationPath, variant: "gitlink/index", content: content, want: true},
		{name: "one gitlink worktree prefix", path: "cloudring_core/" + reviewedVendoredPrivateKeyDocumentationPath, variant: "gitlink/worktree", content: content, want: true},
		{name: "prefixed without recursive provenance", path: "cloudring_core/" + reviewedVendoredPrivateKeyDocumentationPath, variant: "index", content: content},
		{name: "root path with recursive provenance", path: reviewedVendoredPrivateKeyDocumentationPath, variant: "gitlink/index", content: content},
		{name: "nested path prefix", path: "provider/cloudring_core/" + reviewedVendoredPrivateKeyDocumentationPath, variant: "gitlink/index", content: content},
		{name: "nested recursive provenance", path: "provider/" + reviewedVendoredPrivateKeyDocumentationPath, variant: "gitlink/gitlink/index", content: content},
		{name: "extra child prefix", path: "cloudring_core/extra/" + reviewedVendoredPrivateKeyDocumentationPath, variant: "gitlink/index", content: content},
		{name: "near directory", path: "cloudring_core/deploy/kubernetes/storage/longhorn-three-node/vendor/longhorn-copy/values.yaml", variant: "gitlink/index", content: content},
		{name: "near filename", path: "cloudring_core/" + reviewedVendoredPrivateKeyDocumentationPath + ".bak", variant: "gitlink/index", content: content},
		{name: "dot traversal", path: "cloudring_core/../" + reviewedVendoredPrivateKeyDocumentationPath, variant: "gitlink/index", content: content},
		{name: "parent traversal", path: "../cloudring_core/" + reviewedVendoredPrivateKeyDocumentationPath, variant: "gitlink/index", content: content},
		{name: "empty segment", path: "cloudring_core//" + reviewedVendoredPrivateKeyDocumentationPath, variant: "gitlink/index", content: content},
		{name: "backslash path", path: `cloudring_core\` + strings.ReplaceAll(reviewedVendoredPrivateKeyDocumentationPath, "/", `\`), variant: "gitlink/index", content: content},
		{name: "absolute path", path: "/cloudring_core/" + reviewedVendoredPrivateKeyDocumentationPath, variant: "gitlink/index", content: content},
		{name: "nul path", path: "cloudring_core/" + reviewedVendoredPrivateKeyDocumentationPath + "\x00", variant: "gitlink/index", content: content},
		{name: "wrong whole file digest", path: "cloudring_core/" + reviewedVendoredPrivateKeyDocumentationPath, variant: "gitlink/index", content: content + "\n"},
		{name: "symlink input kind", path: "cloudring_core/" + reviewedVendoredPrivateKeyDocumentationPath, variant: "gitlink/worktree", kind: "symlink", content: content},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kind := test.kind
			if kind == "" {
				kind = "text"
			}
			if got := reviewedVendoredPrivateKeyDocumentation(test.path, test.variant, kind, test.content); got != test.want {
				t.Fatalf("reviewedVendoredPrivateKeyDocumentation() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestReadinessOverclaim_non_claim_does_not_mask_later_claim(t *testing.T) {
	text := "This does not claim production readiness. The module is production " + "ready."
	findings := scanContent("README.md", text)
	if !containsRule(findings, "readiness_overclaim") {
		t.Fatalf("later readiness claim was masked by a non-claim: %+v", findings)
	}
}

func TestCredentialAssignment_uses_substring_markers_and_structural_references(t *testing.T) {
	unsafe := []string{
		"pass" + "word: x",
		"pass" + "word: p@()[]!",
		"pass" + "word: example-reference!",
		"pass" + "word: ${lower_case}",
		"pass" + "word: ${CLOUDRING_PASSWORD_ENV}literal",
		"pass" + "word: ${CLOUDRING_PASSWORD_ENV} literal",
		"pass" + "word: prefix${CLOUDRING_PASSWORD_ENV}",
		"pass" + "word: $CLOUDRING_PASSWORD_ENV",
		"pass" + `word: os.Getenv("CLOUDRING_PASSWORD_ENV")+"literal"`,
		"pass" + `word: "${CLOUDRING_PASSWORD_ENV}"suffix`,
		"pass" + `word = "${CLOUDRING_PASSWORD_ENV}" + "literal"`,
		"pass" + `word := "literal"`,
		"pass" + "word: <redacted>suffix",
		"secret" + "Ref: literal-value",
		"token" + "Env: lower_case",
		strings.Join([]string{"registryPasswd", ": literal"}, ""),
	}
	for _, line := range unsafe {
		if !credentialAssignment(line) {
			t.Fatalf("credential literal bypassed exact structural validation: %q", line)
		}
	}
	for _, line := range []string{
		"password_encryption: scram-sha-256",
		"persist-credentials: false",
		"credentialClass: interactive_session",
		"containsCredentials: false",
		"containsSecrets: false",
		"tokenTTL: 10m",
		"tokenMaxTTL: 30m",
		"tokenNoDefaultPolicy: true",
		"serviceAccountTokenCreate: false",
		"enableTokenCache: false",
		"private" + "Key:",
		"sec" + "ret:",
		"sec" + "retRef:",
		"pass" + "word: ${CLOUDRING_PASSWORD_ENV}",
		"pass" + `word: os.Getenv("CLOUDRING_PASSWORD_ENV")`,
		"pass" + `word := os.Getenv("CLOUDRING_PASSWORD_ENV")`,
		"secret" + "Ref: secretref.synthetic.access",
		"csi.storage.k8s.io/provisioner-" + "secret-name" + ": rook-csi-rbd-provisioner",
		"csi.storage.k8s.io/provisioner-" + "secret-namespace" + ": rook-ceph",
		"token" + "Env: CLOUDRING_SYNTHETIC_TOKEN_ENV",
		"pass" + "word: <redacted>",
		"secret" + "Name: {{ .Values.ingress.tlsSecret }}",
	} {
		if credentialAssignment(line) {
			t.Fatalf("legitimate exact reference was rejected: %q", line)
		}
	}
}

func TestScanContent_allows_structural_credential_containers(t *testing.T) {
	content := "{\n  \"se" + "crets\": {\n    \"se" + "cretRefs\": []\n  }\n}"
	if findings := scanContent("synthetic-config.json", content); len(findings) != 0 {
		t.Fatalf("structural credential containers were rejected: %+v", findings)
	}
}

func TestScanContent_does_not_treat_Go_switch_case_as_multiline_credential(t *testing.T) {
	content := "switch value {\ncase \"auth\", \"to" + "ken\":\n\treturn true\n}"
	if findings := scanContent("validate.go", content); len(findings) != 0 {
		t.Fatalf("Go switch case was treated as a credential mapping: %+v", findings)
	}
}

func TestScanContent_rejects_password_shaped_config_credentials(t *testing.T) {
	tests := []struct {
		name string
		text string
		rule string
		line int
	}{
		{
			name: "database password key",
			text: "db_" + "password" + ": \"Synthetic$Value#123\"",
			rule: "credential_assignment",
			line: 1,
		},
		{
			name: "dotted property key",
			text: "spring.datasource." + "password" + "=Synthetic$Value#123",
			rule: "credential_assignment",
			line: 1,
		},
		{
			name: "secret access key",
			text: "aws_" + "secret_access_key" + ": Synthetic$Value#123",
			rule: "credential_assignment",
			line: 1,
		},
		{
			name: "xml password element",
			text: "<" + "password>Synthetic$Value#123</" + "password>",
			rule: "credential_xml",
			line: 1,
		},
		{
			name: "URL userinfo",
			text: "postgres" + "://synthetic-user:Synthetic$Value#123@service.example:5432/database",
			rule: "credential_url",
			line: 1,
		},
		{
			name: "multiline JSON password",
			text: "{\n  \"" + "password" + "\":\n  \"Synthetic$Value#123\"\n}",
			rule: "credential_assignment",
			line: 2,
		},
		{
			name: "multiline YAML unquoted password",
			text: "database_" + "password" + ":\n  Synthetic$Value#123",
			rule: "credential_assignment",
			line: 1,
		},
		{
			name: "password marker embedded in key",
			text: "database_" + "password_hash" + ": Synthetic$Value#123",
			rule: "credential_assignment",
			line: 1,
		},
		{
			name: "secret marker embedded in key with dollar-prefixed literal",
			text: "service_" + "secret_hash" + ": \"$Synthetic#Value123456789\"",
			rule: "credential_assignment",
			line: 1,
		},
		{
			name: "token marker embedded in key with dollar-prefixed literal",
			text: "service_" + "token_hint" + ": \"$Synthetic#Value123456789\"",
			rule: "credential_assignment",
			line: 1,
		},
		{
			name: "credential marker embedded in key with dollar-prefixed literal",
			text: "service_" + "credential_kind" + ": \"$Synthetic#Value123456789\"",
			rule: "credential_assignment",
			line: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := scanContent("synthetic-config.yaml", test.text)
			if !containsRule(findings, test.rule) {
				t.Fatalf("expected %q, got %+v", test.rule, findings)
			}
			for _, finding := range findings {
				if finding.Rule == test.rule && finding.Line != test.line {
					t.Fatalf("finding line = %d, want %d", finding.Line, test.line)
				}
			}
		})
	}
}

func TestScanContent_allows_structural_secret_references_in_extended_syntax(t *testing.T) {
	safe := []string{
		"spring.datasource." + "password" + "=${CLOUDRING_SYNTHETIC_PASSWORD}",
		"service_" + "secret_hash" + ": \"${UPPER_ENV}\"",
		"<" + "password>${CLOUDRING_SYNTHETIC_PASSWORD}</" + "password>",
		"postgres" + "://synthetic-user:${CLOUDRING_SYNTHETIC_PASSWORD}@service.example/database",
		"{\n  \"" + "password" + "\":\n  \"${CLOUDRING_SYNTHETIC_PASSWORD}\"\n}",
	}
	for _, content := range safe {
		if findings := scanContent("synthetic-config.yaml", content); len(findings) != 0 {
			t.Fatalf("structural credential reference was rejected: %+v", findings)
		}
	}
}

func TestReadiness_each_occurrence_requires_direct_negation(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		findings int
		line     int
	}{
		{name: "conjunction bypass", text: "The module is not production " + "ready and GA.", findings: 1, line: 1},
		{name: "both negated", text: "The module is not production " + "ready and not GA.", findings: 0},
		{name: "but bypass", text: "This does not claim production readiness, but the module is production " + "ready.", findings: 1, line: 1},
		{name: "list boundary", text: "- Not production " + "ready.\n- GA.", findings: 1, line: 2},
		{name: "soft wrapped denial", text: "This document does not claim\nproduction readiness.", findings: 0},
		{name: "soft wrapped negation", text: "They do\nnot claim live production readiness.", findings: 0},
		{name: "blockquote soft claim", text: "> The module is production\n> ready.", findings: 1, line: 1},
		{name: "blockquote soft denial", text: "> This does not claim production\n> readiness.", findings: 0},
		{name: "token boundary", text: "The gateway contract remains blocked.", findings: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := readinessFindings("README.md", test.text)
			if len(findings) != test.findings {
				t.Fatalf("findings = %+v, want %d", findings, test.findings)
			}
			if test.findings != 0 && findings[0].Line != test.line {
				t.Fatalf("finding line = %d, want %d", findings[0].Line, test.line)
			}
		})
	}
}

func TestSymlinkTargetEscapes_is_platform_neutral(t *testing.T) {
	unsafe := []string{
		"/outside", `\outside`, `inside\file`, `..\outside`, "../outside", "inside/../../outside",
		`C:relative`, `C:\absolute`, `\\server\share`, `\\?\C:\outside`, `\\.\device`,
	}
	for _, target := range unsafe {
		if !symlinkTargetEscapes(target) {
			t.Fatalf("unsafe symlink target was accepted: %q", target)
		}
	}
	for _, target := range []string{"inside/file", "./inside/file", "file"} {
		if symlinkTargetEscapes(target) {
			t.Fatalf("repository-relative symlink target was rejected: %q", target)
		}
	}
}

func TestPrivateEndpoint_rejects_private_and_allows_documentation_ranges(t *testing.T) {
	for _, value := range []string{
		"127." + "0.0.1",
		"169.254." + "10.20",
		"172.20." + "1.2",
		"192.168." + "1.2",
		"100." + "64.10.20",
		"https://database." + "corp:5432",
		"https://database." + "lan:5432",
		"https://database." + "intranet:5432",
		"https://database." + "home:5432",
		"https://database." + "localdomain:5432",
		"fd00" + ":" + ":1",
		":" + ":1",
	} {
		if !privateEndpoint(value) {
			t.Fatalf("expected private endpoint %q to be rejected", value)
		}
	}
	for _, value := range []string{"192.0.2.10", "198.51.100.20", "203.0.113.30", "https://service.example"} {
		if privateEndpoint(value) {
			t.Fatalf("expected synthetic endpoint %q to be allowed", value)
		}
	}
}

func TestScanPath_rejects_credential_bearing_filenames(t *testing.T) {
	for _, path := range []string{"kubeconfig", "cluster.kubeconfig", "id_ed25519", "tls.key", ".env", ".env.production", ".env.staging", "terraform.tfstate"} {
		input := classifyInput(scanInput{path: path, variant: "worktree", data: []byte("synthetic")})
		if findings := scanPath(input); !containsRule(findings, "unsafe_credential_filename") {
			t.Fatalf("expected unsafe filename %q to fail: %+v", path, findings)
		}
	}
}

func containsRule(findings []Finding, rule string) bool {
	for _, finding := range findings {
		if finding.Rule == rule {
			return true
		}
	}
	return false
}
