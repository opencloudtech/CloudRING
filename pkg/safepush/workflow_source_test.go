// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package safepush

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkflowSourceRequiresLiteralStopOnError(t *testing.T) {
	for _, scope := range []string{"job", "step"} {
		for _, value := range []string{
			"true", "TRUE", "False", "FALSE", "0", "no", "off", "null", "~", "",
			"'false'", `"false"`, "${{ false }}", "${{ matrix.experimental }}",
			"!!str false", "!!bool false", "!custom false", "&disabled false", "[false]", "{value: false}",
		} {
			t.Run(scope+"_"+value, func(t *testing.T) {
				contents := "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
				if scope == "job" {
					contents += "    continue-on-error: " + value + "\n"
				}
				contents += "    steps:\n      - run: go test ./...\n"
				if scope == "step" {
					contents += "        continue-on-error: " + value + "\n"
				}
				if err := verifyWorkflowSource([]byte(contents)); !errors.Is(err, ErrGitHubSource) {
					t.Fatalf("unsafe control was accepted: %v", err)
				}
			})
		}
	}
	for _, contents := range []string{
		ghTestWorkflow,
		"jobs: {test: {continue-on-error: false, steps: [{run: 'exit 0', continue-on-error: false}]}}",
		"---\n'jobs': {'test': {'steps': [{'run': 'exit 0', 'continue-on-error': false}]}}\n...\n# end\n",
	} {
		if err := verifyWorkflowSource([]byte(contents)); err != nil {
			t.Fatalf("literal stop-on-error workflow rejected: %v", err)
		}
	}
}

func TestWorkflowSourceRejectsAmbiguousYAML(t *testing.T) {
	safe := "jobs: {test: {steps: [{run: 'exit 0'}]}}\n"
	cases := map[string]string{
		"empty":             "",
		"comments_only":     "# empty\n",
		"root_sequence":     "[{jobs: {}}]",
		"jobs_sequence":     "jobs: []",
		"jobs_expression":   "jobs: ${{ matrix.jobs }}",
		"empty_jobs":        "jobs: {}",
		"null_job":          "jobs: {test: null}",
		"no_steps":          "jobs: {test: {runs-on: ubuntu-latest}}",
		"empty_steps":       "jobs: {test: {steps: []}}",
		"step_scalar":       "jobs: {test: {steps: ['exit 0']}}",
		"step_mapping":      "jobs: {test: {steps: {run: 'exit 0'}}}",
		"steps_expression":  "jobs: {test: {steps: '${{ matrix.steps }}'}}",
		"second_document":   safe + "---\n" + safe,
		"empty_second_doc":  safe + "---\n",
		"malformed_trailer": safe + "[not valid",
		"duplicate_root":    safe + "jobs: {test: {steps: [{run: 'exit 1', continue-on-error: true}]}}\n",
		"duplicate_job":     "jobs: {test: {continue-on-error: true, continue-on-error: false, steps: [{run: 'exit 1'}]}}",
		"duplicate_step":    "jobs: {test: {steps: [{continue-on-error: true, continue-on-error: false, run: 'exit 1'}]}}",
		"case_duplicate":    "jobs: {test: {steps: [{continue-on-error: false, CONTINUE-ON-ERROR: true, run: 'exit 1'}]}}",
		"case_control":      "jobs: {test: {steps: [{CONTINUE-ON-ERROR: true, run: 'exit 1'}]}}",
		"escaped_key":       `jobs: {test: {steps: [{"continue\u002don-error": true, run: 'exit 1'}]}}`,
		"merge_job":         "jobs: {test: {<<: {continue-on-error: true}, steps: [{run: 'exit 1'}]}}",
		"quoted_merge":      "jobs: {test: {'<<': {continue-on-error: true}, steps: [{run: 'exit 1'}]}}",
		"merge_step":        "jobs: {test: {steps: [{<<: {continue-on-error: true}, run: 'exit 1'}]}}",
		"anchor_only":       "defaults: &settings {continue-on-error: true}\n" + safe,
		"alias_false":       "setting: &disabled false\njobs: {test: {steps: [{run: 'exit 0', continue-on-error: *disabled}]}}",
		"alias_steps":       "setting: &steps [{run: 'exit 1', continue-on-error: true}]\njobs: {test: {steps: *steps}}",
		"alias_cycle":       "setting: &cycle [*cycle]\n" + safe,
		"alias_expansion":   "a: &a [false,false,false]\nb: &b [*a,*a,*a]\nc: [*b,*b,*b]\n" + safe,
		"nonstring_key":     "true: ignored\n" + safe,
		"complex_key":       "? [jobs, steps]\n: ignored\n" + safe,
		"custom_mapping":    "jobs: !custom {test: {steps: [{run: 'exit 0'}]}}",
		"block_string":      "jobs:\n  test:\n    continue-on-error: |\n      false\n    steps:\n      - run: exit 0\n",
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			if err := verifyWorkflowSource([]byte(contents)); !errors.Is(err, ErrGitHubSource) {
				t.Fatalf("ambiguous YAML accepted: %v", err)
			}
		})
	}
}

func TestWorkflowSourceParsingIsBounded(t *testing.T) {
	if err := verifyWorkflowSource([]byte(strings.Repeat(" ", maxWorkflowSourceBytes+1))); !errors.Is(err, ErrGitHubSource) {
		t.Fatal("oversized workflow accepted")
	}
	deep := "env: {nested: " + strings.Repeat("[", maxWorkflowYAMLDepth+1) + "false" + strings.Repeat("]", maxWorkflowYAMLDepth+1) + "}\n" + ghTestWorkflow
	if err := verifyWorkflowSource([]byte(deep)); !errors.Is(err, ErrGitHubSource) {
		t.Fatal("overly deep workflow accepted")
	}
	var many strings.Builder
	many.WriteString("env: {")
	for index := 0; index <= maxWorkflowYAMLNodes/2; index++ {
		_, _ = fmt.Fprintf(&many, "k%d: 0,", index)
	}
	many.WriteString("}\n")
	many.WriteString(ghTestWorkflow)
	if many.Len() > maxWorkflowSourceBytes {
		t.Fatal("node-limit fixture must exercise nodes rather than byte size")
	}
	if err := verifyWorkflowSource([]byte(many.String())); !errors.Is(err, ErrGitHubSource) {
		t.Fatal("too many workflow nodes accepted")
	}
}

func TestWorkflowSourceAcceptsCurrentRequiredWorkflows(t *testing.T) {
	root := openRepositoryRoot(t)
	for _, name := range []string{"ci.yml", "cla-dco.yml", "license.yml", "security.yml", "supply-chain.yml"} {
		t.Run(name, func(t *testing.T) {
			contents, err := root.ReadFile(filepath.Join(".github", "workflows", name))
			if err != nil {
				t.Fatal(err)
			}
			if err = verifyWorkflowSource(contents); err != nil {
				t.Fatalf("current required workflow rejected: %v", err)
			}
		})
	}
}
