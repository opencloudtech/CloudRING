// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package safepush

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// This catches an added, removed, or renamed repository CI job being silently
// omitted from the admission policy. API provenance is tested separately.
func TestRepositoryPolicyCoversEveryPreMergeJob(t *testing.T) {
	root := openRepositoryRoot(t)
	data, err := root.ReadFile(".github/safepush.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := DecodeGitHubPolicy(data)
	if err != nil {
		t.Fatal(err)
	}
	expectedPaths := make(map[string]bool)
	for _, workflow := range policy.Workflows {
		expectedPaths[workflow.Path] = true
		data, err := root.ReadFile(filepath.FromSlash(workflow.Path))
		if err != nil {
			t.Fatal(err)
		}
		var actual struct {
			On   map[string]any `yaml:"on"`
			Jobs map[string]struct {
				Name string `yaml:"name"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(data, &actual); err != nil {
			t.Fatal(err)
		}
		if _, exists := actual.On["pull_request"]; !exists {
			t.Fatal("required test workflow no longer runs for pull requests")
		}
		var names []string
		for id, job := range actual.Jobs {
			name := job.Name
			if name == "" {
				name = id
			}
			if strings.Contains(name, "${{") {
				t.Fatal("dynamic job name needs an explicit matrix policy")
			}
			names = append(names, name)
		}
		sort.Strings(names)
		expected := append([]string(nil), workflow.Jobs...)
		sort.Strings(expected)
		if !reflect.DeepEqual(names, expected) {
			t.Fatalf("workflow %s jobs differ from admission policy: actual=%v expected=%v", workflow.Path, names, expected)
		}
	}
	for _, excluded := range policy.ExcludedWorkflows {
		expectedPaths[excluded] = true
		data, err := root.ReadFile(filepath.FromSlash(excluded))
		if err != nil {
			t.Fatal(err)
		}
		var actual struct {
			On map[string]any `yaml:"on"`
		}
		if err := yaml.Unmarshal(data, &actual); err != nil {
			t.Fatal(err)
		}
		if len(actual.On) != 1 {
			t.Fatal("excluded release workflow has unexpected triggers")
		}
		if _, exists := actual.On["push"]; !exists {
			t.Fatal("excluded workflow is not a post-acceptance release workflow")
		}
	}
	directory, err := root.Open(".github/workflows")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := directory.ReadDir(-1)
	if closeErr := directory.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := ".github/workflows/" + entry.Name()
		if (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) && !expectedPaths[name] {
			t.Fatalf("workflow is absent from admission policy: %s", name)
		}
	}
}

// Confine fixture reads to the checkout, including symlink resolution.
func openRepositoryRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot("../..")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return root
}
