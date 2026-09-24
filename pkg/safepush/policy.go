// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package safepush

import (
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const GitHubPolicySchema = "cloudring.safepush.github/v1"

var (
	ErrPolicy  = errors.New("SafePush policy is invalid")
	ErrRequest = errors.New("SafePush request is invalid")
)

// GitHubPolicy is read from the accepted target commit by the trusted CI
// workflow. Loading a candidate's policy would let that candidate remove its
// own requirements. RepositoryID also prevents name reuse from changing scope.
type GitHubPolicy struct {
	SchemaVersion     string           `json:"schemaVersion"`
	Repository        string           `json:"repository"`
	RepositoryID      int64            `json:"repositoryId"`
	Workflows         []GitHubWorkflow `json:"workflows"`
	ExcludedWorkflows []string         `json:"excludedWorkflows"`
}

// GitHubWorkflow identifies the complete expected job set of one test workflow.
// Path and job name together are the identity; a same-named job in another
// workflow cannot satisfy a requirement.
type GitHubWorkflow struct {
	Path string   `json:"path"`
	Jobs []string `json:"jobs"`
}

// GitHubCandidate binds one admission attempt to the PR and target snapshot.
// The adapter re-reads GitHub state; these values do not assert approval or
// successful execution and cannot replace native server protection.
type GitHubCandidate struct {
	PullRequest  int
	HeadSHA      string
	BaseSHA      string
	TargetBranch string
}

var repositoryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}$`)

// ValidateGitHubCandidate validates event arguments before any network access.
// Ref names are never accepted in place of immutable Git object identifiers.
func ValidateGitHubCandidate(repository string, candidate GitHubCandidate) error {
	if !repositoryName.MatchString(repository) || strings.HasSuffix(repository, "/.") ||
		strings.HasSuffix(repository, "/..") || candidate.PullRequest <= 0 ||
		!validHeadSHA(candidate.HeadSHA) || !validHeadSHA(candidate.BaseSHA) ||
		candidate.HeadSHA == candidate.BaseSHA ||
		(candidate.TargetBranch != "main" && candidate.TargetBranch != "master") {
		return ErrRequest
	}
	return nil
}

// DecodeGitHubPolicy rejects unknown and duplicate fields, trailing documents,
// empty test sets, overlapping exclusions and ambiguous workflow identities.
func DecodeGitHubPolicy(data []byte) (GitHubPolicy, error) {
	// encoding/json matches struct fields case-insensitively, including when
	// DisallowUnknownFields is set. Inspect exact spellings before decoding so
	// a second "Workflows" or "Jobs" cannot replace an earlier requirement.
	var fields map[string]json.RawMessage
	if strictjson.Decode(data, &fields) != nil || fields == nil {
		return GitHubPolicy{}, ErrPolicy
	}
	for name := range fields {
		switch name {
		case "schemaVersion", "repository", "repositoryId", "workflows", "excludedWorkflows":
		default:
			return GitHubPolicy{}, ErrPolicy
		}
	}
	var workflows []map[string]json.RawMessage
	if json.Unmarshal(fields["workflows"], &workflows) != nil {
		return GitHubPolicy{}, ErrPolicy
	}
	for _, workflow := range workflows {
		for name := range workflow {
			if name != "path" && name != "jobs" {
				return GitHubPolicy{}, ErrPolicy
			}
		}
	}
	var policy GitHubPolicy
	if json.Unmarshal(data, &policy) != nil || ValidateGitHubPolicy(policy) != nil {
		return GitHubPolicy{}, ErrPolicy
	}
	return policy, nil
}

func ValidateGitHubPolicy(policy GitHubPolicy) error {
	if policy.SchemaVersion != GitHubPolicySchema || policy.RepositoryID <= 0 ||
		!repositoryName.MatchString(policy.Repository) ||
		strings.HasSuffix(policy.Repository, "/.") || strings.HasSuffix(policy.Repository, "/..") ||
		len(policy.Workflows) == 0 || len(policy.Workflows)+len(policy.ExcludedWorkflows) > 100 {
		return ErrPolicy
	}
	seen := make(map[string]bool)
	for _, workflow := range policy.Workflows {
		if !validWorkflowPath(workflow.Path) || seen[workflow.Path] || len(workflow.Jobs) == 0 || len(workflow.Jobs) > 1000 {
			return ErrPolicy
		}
		seen[workflow.Path] = true
		jobs := make(map[string]bool)
		for _, job := range workflow.Jobs {
			if !validJobName(job) || jobs[job] {
				return ErrPolicy
			}
			jobs[job] = true
		}
	}
	for _, excluded := range policy.ExcludedWorkflows {
		if !validWorkflowPath(excluded) || seen[excluded] {
			return ErrPolicy
		}
		seen[excluded] = true
	}
	return nil
}

func validWorkflowPath(value string) bool {
	if len(value) > 255 || !strings.HasPrefix(value, ".github/workflows/") || path.Clean(value) != value {
		return false
	}
	name := strings.TrimPrefix(value, ".github/workflows/")
	if strings.ContainsAny(name, "/\\") || !(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
		return false
	}
	return validJobName(name)
}

func validJobName(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
