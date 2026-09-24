// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package safepush

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func policyFixture() GitHubPolicy {
	return GitHubPolicy{
		SchemaVersion: GitHubPolicySchema,
		Repository:    "synthetic/project", RepositoryID: 42,
		Workflows:         []GitHubWorkflow{{Path: ".github/workflows/ci.yml", Jobs: []string{"test", "race"}}},
		ExcludedWorkflows: []string{".github/workflows/release.yml"},
	}
}

func TestPolicyRejectsAmbiguousOrWeakenedRequirements(t *testing.T) {
	mutations := map[string]func(*GitHubPolicy){
		"wrong schema":           func(p *GitHubPolicy) { p.SchemaVersion = "unknown" },
		"no repository identity": func(p *GitHubPolicy) { p.RepositoryID = 0 },
		"path traversal":         func(p *GitHubPolicy) { p.Repository = "synthetic/../project" },
		"no tests":               func(p *GitHubPolicy) { p.Workflows = nil },
		"empty jobs":             func(p *GitHubPolicy) { p.Workflows[0].Jobs = nil },
		"duplicate workflow":     func(p *GitHubPolicy) { p.Workflows = append(p.Workflows, p.Workflows[0]) },
		"duplicate job":          func(p *GitHubPolicy) { p.Workflows[0].Jobs = []string{"test", "test"} },
		"excluded test workflow": func(p *GitHubPolicy) { p.ExcludedWorkflows = []string{p.Workflows[0].Path} },
		"duplicate exclusion":    func(p *GitHubPolicy) { p.ExcludedWorkflows = append(p.ExcludedWorkflows, p.ExcludedWorkflows[0]) },
		"nested workflow path":   func(p *GitHubPolicy) { p.Workflows[0].Path = ".github/workflows/nested/ci.yml" },
		"noncanonical workflow":  func(p *GitHubPolicy) { p.Workflows[0].Path = ".github/workflows/../ci.yml" },
		"control in identity":    func(p *GitHubPolicy) { p.Workflows[0].Jobs[0] = "test\npass" },
		"invisible job suffix":   func(p *GitHubPolicy) { p.Workflows[0].Jobs[0] = "test " },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			policy := policyFixture()
			mutate(&policy)
			data, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeGitHubPolicy(data); !errors.Is(err, ErrPolicy) {
				t.Fatalf("unsafe policy was accepted: %v", err)
			}
		})
	}
}

func TestPolicyJSONHasOneClosedUnambiguousDocument(t *testing.T) {
	data, err := json.Marshal(policyFixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeGitHubPolicy(data); err != nil {
		t.Fatal(err)
	}
	for name, malformed := range map[string]string{
		"unknown field":                   strings.Replace(string(data), `"repositoryId":42`, `"repositoryId":42,"trusted":true`, 1),
		"duplicate field":                 strings.Replace(string(data), `"repositoryId":42`, `"repositoryId":42,"repositoryId":42`, 1),
		"case variant duplicate":          strings.Replace(string(data), `"repositoryId":42`, `"repositoryId":42,"RepositoryId":43`, 1),
		"weakened case variant workflows": strings.Replace(string(data), `"excludedWorkflows":`, `"Workflows":[{"path":".github/workflows/ci.yml","jobs":["test"]}],"excludedWorkflows":`, 1),
		"weakened case variant jobs":      strings.Replace(string(data), `"jobs":["test","race"]`, `"jobs":["test","race"],"Jobs":["test"]`, 1),
		"unknown case variant schema":     strings.Replace(string(data), `"schemaVersion":`, `"SchemaVersion":`, 1),
		"unknown case variant path":       strings.Replace(string(data), `"path":`, `"Path":`, 1),
		"escaped duplicate field":         strings.Replace(string(data), `"repositoryId":42`, `"repositoryId":42,"\u0072epositoryId":42`, 1),
		"trailing object":                 string(data) + `{}`,
		"wrong integer":                   strings.Replace(string(data), `"repositoryId":42`, `"repositoryId":42.5`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeGitHubPolicy([]byte(malformed)); !errors.Is(err, ErrPolicy) {
				t.Fatalf("ambiguous policy was accepted: %v", err)
			}
		})
	}
}
