// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package safepush

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	maxWorkflowSourceBytes = 1 << 20
	maxWorkflowYAMLDepth   = 64
	maxWorkflowYAMLNodes   = 100000
)

// verifyWorkflowSource checks accepted, hash-verified workflow bytes. GitHub's
// REST step conclusion can be success after a failed outcome when the workflow
// permits continue-on-error, so successful API statuses alone are insufficient.
// This verifies that specific control; it does not prove test adequacy or the
// behavior of scripts/actions invoked by the workflow.
func verifyWorkflowSource(contents []byte) error {
	if len(contents) == 0 || len(contents) > maxWorkflowSourceBytes {
		return ErrGitHubSource
	}
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	var document yaml.Node
	if decoder.Decode(&document) != nil {
		return ErrGitHubSource
	}
	nodes := 0
	if !validWorkflowYAML(&document, 0, &nodes) || document.Kind != yaml.DocumentNode ||
		len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return ErrGitHubSource
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrGitHubSource
	}
	jobs := workflowMappingValue(document.Content[0], "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode || len(jobs.Content) == 0 {
		return ErrGitHubSource
	}
	for index := 1; index < len(jobs.Content); index += 2 {
		job := jobs.Content[index]
		if job.Kind != yaml.MappingNode || !workflowStopsOnError(job) {
			return ErrGitHubSource
		}
		steps := workflowMappingValue(job, "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode || len(steps.Content) == 0 {
			return ErrGitHubSource
		}
		for _, step := range steps.Content {
			if step.Kind != yaml.MappingNode || !workflowStopsOnError(step) {
				return ErrGitHubSource
			}
		}
	}
	return nil
}

func workflowStopsOnError(mapping *yaml.Node) bool {
	value := workflowMappingValue(mapping, "continue-on-error")
	return value == nil || (value.Kind == yaml.ScalarNode && value.Tag == "!!bool" &&
		value.Style == 0 && value.Value == "false")
}

func workflowMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	for index := 0; index < len(mapping.Content); index += 2 {
		if strings.EqualFold(mapping.Content[index].Value, key) {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func validWorkflowYAML(node *yaml.Node, depth int, nodes *int) bool {
	*nodes = *nodes + 1
	if depth > maxWorkflowYAMLDepth || *nodes > maxWorkflowYAMLNodes || node == nil ||
		node.Anchor != "" || node.Alias != nil {
		return false
	}
	switch node.Kind {
	case yaml.DocumentNode:
		if depth != 0 || len(node.Content) != 1 {
			return false
		}
	case yaml.MappingNode:
		if node.Tag != "!!map" || len(node.Content)%2 != 0 {
			return false
		}
		seen := make(map[string]bool, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || !validJobName(key.Value) || key.Value == "<<" {
				return false
			}
			identity := strings.ToLower(key.Value)
			if seen[identity] {
				return false
			}
			seen[identity] = true
		}
	case yaml.SequenceNode:
		if node.Tag != "!!seq" {
			return false
		}
	case yaml.ScalarNode:
		if len(node.Content) != 0 {
			return false
		}
		switch node.Tag {
		case "!!str", "!!bool", "!!int", "!!float", "!!null":
		default:
			return false
		}
	default:
		return false // Includes aliases, without traversing their targets.
	}
	for _, child := range node.Content {
		if !validWorkflowYAML(child, depth+1, nodes) {
			return false
		}
	}
	return true
}
