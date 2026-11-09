// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package safepush

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValidateGitHubCandidateBounds(t *testing.T) {
	valid := GitHubCandidate{PullRequest: 1, HeadSHA: ghTestHead, BaseSHA: ghTestBase, TargetBranch: "main"}
	for repository, want := range map[string]bool{
		"owner/repo": true, "noslash": false, "owner/.": false, "owner/..": false, "owner/.x": true,
	} {
		if err := ValidateGitHubCandidate(repository, valid); (err == nil) != want {
			t.Errorf("repository %q: %v", repository, err)
		}
	}
	for name, c := range map[string]struct {
		edit func(*GitHubCandidate)
		ok   bool
	}{
		"pull request zero":  {func(c *GitHubCandidate) { c.PullRequest = 0 }, false},
		"pull request one":   {func(c *GitHubCandidate) {}, true},
		"master target":      {func(c *GitHubCandidate) { c.TargetBranch = "master" }, true},
		"other target":       {func(c *GitHubCandidate) { c.TargetBranch = "dev" }, false},
		"same head and base": {func(c *GitHubCandidate) { c.BaseSHA = c.HeadSHA }, false},
	} {
		candidate := valid
		c.edit(&candidate)
		if err := ValidateGitHubCandidate("owner/repo", candidate); (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrRequest)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidateGitHubPolicySizeLimits(t *testing.T) {
	workflowPath := func(i int) string { return fmt.Sprintf(".github/workflows/w%03d.yml", i) }
	names := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("job-%d", i)
		}
		return out
	}
	cases := map[string]struct {
		edit func(*GitHubPolicy)
		ok   bool
	}{
		"99 workflows and one exclusion": {func(p *GitHubPolicy) {
			p.Workflows = nil
			for i := range 99 {
				p.Workflows = append(p.Workflows, GitHubWorkflow{Path: workflowPath(i), Jobs: []string{"test"}})
			}
		}, true},
		"one workflow and 100 exclusions": {func(p *GitHubPolicy) {
			p.ExcludedWorkflows = nil
			for i := range 100 {
				p.ExcludedWorkflows = append(p.ExcludedWorkflows, workflowPath(i))
			}
		}, false},
		"1000 jobs": {func(p *GitHubPolicy) { p.Workflows[0].Jobs = names(1000) }, true},
		"1001 jobs": {func(p *GitHubPolicy) { p.Workflows[0].Jobs = names(1001) }, false},
		"255-byte workflow path": {func(p *GitHubPolicy) {
			p.Workflows[0].Path = ".github/workflows/" + strings.Repeat("w", 255-len(".github/workflows/")-len(".yml")) + ".yml"
		}, true},
		"256-byte workflow path": {func(p *GitHubPolicy) {
			p.Workflows[0].Path = ".github/workflows/" + strings.Repeat("w", 256-len(".github/workflows/")-len(".yml")) + ".yml"
		}, false},
		"workflow outside the directory": {func(p *GitHubPolicy) { p.Workflows[0].Path = "ci.yml" }, false},
		"empty job name":                 {func(p *GitHubPolicy) { p.Workflows[0].Jobs = []string{""} }, false},
		"512-byte job name":              {func(p *GitHubPolicy) { p.Workflows[0].Jobs = []string{strings.Repeat("j", 512)} }, true},
		"513-byte job name":              {func(p *GitHubPolicy) { p.Workflows[0].Jobs = []string{strings.Repeat("j", 513)} }, false},
	}
	for name, c := range cases {
		policy := policyFixture()
		c.edit(&policy)
		if err := ValidateGitHubPolicy(policy); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// ghYAMLShape counts nodes and the deepest level of a parsed document the way
// a reader of the YAML tree sees it: the document is level 0 and every child
// is one level below its parent.
func ghYAMLShape(node *yaml.Node, depth int) (nodes, deepest int) {
	nodes, deepest = 1, depth
	for _, child := range node.Content {
		n, d := ghYAMLShape(child, depth+1)
		nodes += n
		deepest = max(deepest, d)
	}
	return nodes, deepest
}

func ghParse(t *testing.T, source string) *yaml.Node {
	t.Helper()
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(source), &document); err != nil {
		t.Fatal(err)
	}
	return &document
}

func TestWorkflowSourceLimitsAreInclusive(t *testing.T) {
	// Depth: env: {nested: [[...false...]]} with k sequences.
	nested := func(k int) string {
		return "env: {nested: " + strings.Repeat("[", k) + "false" + strings.Repeat("]", k) + "}\n" + ghTestWorkflow
	}
	k := 1
	for _, deepest := ghYAMLShape(ghParse(t, nested(k)), 0); deepest < maxWorkflowYAMLDepth; _, deepest = ghYAMLShape(ghParse(t, nested(k)), 0) {
		k++
	}
	if _, deepest := ghYAMLShape(ghParse(t, nested(k)), 0); deepest != maxWorkflowYAMLDepth {
		t.Fatalf("could not build a document %d levels deep", maxWorkflowYAMLDepth)
	}
	if err := verifyWorkflowSource([]byte(nested(k))); err != nil {
		t.Fatalf("document exactly %d levels deep: %v", maxWorkflowYAMLDepth, err)
	}
	if err := verifyWorkflowSource([]byte(nested(k + 1))); !errors.Is(err, ErrGitHubSource) {
		t.Fatalf("document %d levels deep accepted", maxWorkflowYAMLDepth+1)
	}

	// Nodes: env: {k0: 0, ...} plus, for odd remainders, one x: [0] entry.
	wide := func(pairs int, extra bool) string {
		var b strings.Builder
		b.WriteString("env: {")
		if extra {
			b.WriteString("x: [0], ")
		}
		for i := range pairs {
			fmt.Fprintf(&b, "k%d: 0, ", i)
		}
		b.WriteString("}\n")
		return b.String() + ghTestWorkflow
	}
	base, _ := ghYAMLShape(ghParse(t, wide(0, false)), 0)
	extra := (maxWorkflowYAMLNodes-base)%2 == 1
	pairs := (maxWorkflowYAMLNodes - base) / 2
	if extra {
		pairs = (maxWorkflowYAMLNodes - base - 3) / 2
	}
	exact := wide(pairs, extra)
	if nodes, _ := ghYAMLShape(ghParse(t, exact), 0); nodes != maxWorkflowYAMLNodes {
		t.Fatalf("built %d nodes, want %d", nodes, maxWorkflowYAMLNodes)
	}
	if err := verifyWorkflowSource([]byte(exact)); err != nil {
		t.Fatalf("document of exactly %d nodes: %v", maxWorkflowYAMLNodes, err)
	}
	if err := verifyWorkflowSource([]byte(wide(pairs+1, extra))); !errors.Is(err, ErrGitHubSource) {
		t.Fatalf("document of %d nodes accepted", maxWorkflowYAMLNodes+2)
	}
}

func TestWorkflowSourceSizeAndJobs(t *testing.T) {
	over := ghTestWorkflow + "#"
	over += strings.Repeat("#", maxWorkflowSourceBytes-len(over)) + "\n"
	if err := verifyWorkflowSource([]byte(over)); !errors.Is(err, ErrGitHubSource) {
		t.Fatalf("workflow of %d bytes accepted", len(over))
	}
	if err := verifyWorkflowSource([]byte("name: CI\non: pull_request\n")); !errors.Is(err, ErrGitHubSource) {
		t.Fatal("workflow without jobs accepted")
	}
}
