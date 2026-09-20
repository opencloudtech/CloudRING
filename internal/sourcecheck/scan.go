// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package sourcecheck

import (
	"errors"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type preparedAllowance struct {
	path     string
	digest   string
	consumed bool
}

type findingBudget struct {
	limit       int
	count       int
	clauseLimit int
	clauseCount int
	lineLimit   int
	lineCount   int
}

func newFindingBudget(requested *resourceLimits) *findingBudget {
	limit := maxSourceFindings
	if requested != nil && requested.findingCount > 0 && requested.findingCount < limit {
		limit = requested.findingCount
	}
	clauseLimit := maxReadinessClauses
	lineLimit := maxSourceLines
	if requested != nil {
		if requested.clauseCount > 0 && requested.clauseCount < clauseLimit {
			clauseLimit = requested.clauseCount
		}
		if requested.lineCount > 0 && requested.lineCount < lineLimit {
			lineLimit = requested.lineCount
		}
	}
	return &findingBudget{limit: limit, clauseLimit: clauseLimit, lineLimit: lineLimit}
}

func (budget *findingBudget) add(target *[]Finding, findings ...Finding) error {
	if len(findings) > budget.limit-budget.count {
		return errors.New("source-safety findings exceed the bounded report budget")
	}
	budget.count += len(findings)
	*target = append(*target, findings...)
	return nil
}

func (budget *findingBudget) consumeClause() error {
	if budget.clauseCount >= budget.clauseLimit {
		return errors.New("readiness structure exceeds the source-safety clause budget")
	}
	budget.clauseCount++
	return nil
}

func (budget *findingBudget) consumeLine() error {
	if budget.lineCount >= budget.lineLimit {
		return errors.New("source text exceeds the source-safety line budget")
	}
	budget.lineCount++
	return nil
}

func Scan(options Options) (Report, error) {
	if options.Scope == "" {
		options.Scope = ScopeFull
	}
	allowances, err := prepareAllowances(options.NonTextAllowances)
	if err != nil {
		return Report{}, err
	}
	_, inputs, err := collectInputs(options)
	if err != nil {
		return Report{}, err
	}

	report := newReport(options.Scope)
	findingLimit := newFindingBudget(options.limits)
	fileSet := map[string]PathIdentity{}
	cleanGitlinks := map[string]bool{}
	recursivelyScannedGitlinks := map[string]bool{}
	for _, input := range inputs {
		if input.kind == "gitlink" && input.gitlinkState == "clean" && input.gitlinkRoot != "" {
			cleanGitlinks[input.path] = true
			if options.RecurseGitlinks {
				recursivelyScannedGitlinks[input.path] = true
			}
		}
	}

	for _, input := range inputs {
		identity := identifyPath(input.path)
		fileSet[input.path] = identity
		report.ScannedInputs = append(report.ScannedInputs, ScannedInput{
			Path:          identity.Display,
			PathSHA256:    identity.SHA256,
			PathBase64URL: identity.Base64URL,
			SourceVariant: input.variant,
			Kind:          input.kind,
			GitlinkState:  input.gitlinkState,
			SHA256:        input.digest,
		})
		for _, finding := range scanPath(input) {
			if findingErr := findingLimit.add(&report.Findings, bindFinding(finding, input)); findingErr != nil {
				return Report{}, findingErr
			}
		}

		switch input.kind {
		case "absent":
			continue
		case "unavailable":
			if findingErr := findingLimit.add(&report.Findings, bindFinding(Finding{
				Rule: "source_input_unavailable", Class: "source_integrity", Message: "source input cannot be resolved safely",
			}, input)); findingErr != nil {
				return Report{}, findingErr
			}
			continue
		case "gitlink":
			if gitlinkStateUnsafe(input.gitlinkState) {
				if findingErr := findingLimit.add(&report.Findings, bindFinding(Finding{
					Rule: "gitlink_state_unsafe", Class: "source_integrity", Message: "gitlink worktree state is dirty, mismatched, or invalid",
				}, input)); findingErr != nil {
					return Report{}, findingErr
				}
				continue
			}
			commitHistoryGitlink := input.variant == "commit" && input.gitlinkState == "commit"
			if !commitHistoryGitlink && !cleanGitlinks[input.path] {
				if findingErr := findingLimit.add(&report.Findings, bindFinding(Finding{
					Rule: "gitlink_policy_required", Class: "non_text", Message: "gitlink requires a clean initialized worktree at the exact indexed commit",
				}, input)); findingErr != nil {
					return Report{}, findingErr
				}
				continue
			}
			if !commitHistoryGitlink && recursivelyScannedGitlinks[input.path] {
				continue
			}
			if consumeAllowance(allowances, input.path, input.digest) {
				continue
			}
			message := "gitlink requires an exact digest allowance or a clean recursive scan"
			if commitHistoryGitlink {
				message = "gitlink commit history requires an exact reviewed digest allowance"
			}
			if findingErr := findingLimit.add(&report.Findings, bindFinding(Finding{
				Rule: "gitlink_policy_required", Class: "non_text", Message: message,
			}, input)); findingErr != nil {
				return Report{}, findingErr
			}
			continue
		}

		if input.nonTextReason != "" {
			if !consumeAllowance(allowances, input.path, input.digest) {
				if findingErr := findingLimit.add(&report.Findings, bindFinding(Finding{
					Rule: "non_text_review_required", Class: "non_text", Message: "non-text artifact requires an exact canonical path and SHA-256 allowance (" + input.nonTextReason + ")",
				}, input)); findingErr != nil {
					return Report{}, findingErr
				}
			}
			continue
		}
		contentFindings, contentErr := scanContentWithBudget(input.path, input.variant, input.kind, string(input.data), findingLimit)
		if contentErr != nil {
			return Report{}, contentErr
		}
		for _, finding := range contentFindings {
			report.Findings = append(report.Findings, bindFinding(finding, input))
		}
	}

	for _, identity := range fileSet {
		report.ScannedFiles = append(report.ScannedFiles, identity)
	}
	sort.Slice(report.ScannedFiles, func(left, right int) bool {
		if report.ScannedFiles[left].Display != report.ScannedFiles[right].Display {
			return report.ScannedFiles[left].Display < report.ScannedFiles[right].Display
		}
		return report.ScannedFiles[left].SHA256 < report.ScannedFiles[right].SHA256
	})
	for _, allowance := range allowances {
		identity := identifyPath(allowance.path)
		report.NonTextAllowances = append(report.NonTextAllowances, AllowanceReport{
			Path: identity.Display, PathSHA256: identity.SHA256, PathBase64URL: identity.Base64URL,
			SHA256: allowance.digest, Consumed: allowance.consumed,
		})
		if !allowance.consumed {
			if findingErr := findingLimit.add(&report.Findings, Finding{
				Rule: "unused_non_text_allowance", Class: "policy", Path: identity.Display,
				PathSHA256: identity.SHA256, PathBase64URL: identity.Base64URL,
				SourceVariant: "allowance", ContentSHA256: allowance.digest,
				Message: "non-text allowance did not match an input with the exact canonical path and digest",
			}); findingErr != nil {
				return Report{}, findingErr
			}
		}
	}
	report.Findings = deduplicateFindings(report.Findings)
	if len(report.Findings) != 0 {
		report.Status = StatusBlocked
		report.Passed = false
	}
	return report, nil
}

func prepareAllowances(requested []NonTextAllowance) ([]*preparedAllowance, error) {
	if len(requested) > maxSourceFindings {
		return nil, errors.New("non-text allowances exceed the source-safety policy budget")
	}
	seen := map[string]bool{}
	result := make([]*preparedAllowance, 0, len(requested))
	for _, item := range requested {
		path, err := canonicalPolicyPath(item.Path)
		if err != nil {
			return nil, errors.New("non-text allowance has an invalid canonical path")
		}
		digest := strings.ToLower(strings.TrimSpace(item.SHA256))
		if len(digest) != 64 || !isHex(digest) {
			return nil, errors.New("non-text allowance requires a 64-hex SHA-256 digest")
		}
		allowanceIdentity := path + "\x00" + digest
		if seen[allowanceIdentity] {
			return nil, errors.New("duplicate canonical non-text allowance path and digest rejected")
		}
		seen[allowanceIdentity] = true
		result = append(result, &preparedAllowance{path: path, digest: digest})
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].path != result[right].path {
			return result[left].path < result[right].path
		}
		return result[left].digest < result[right].digest
	})
	return result, nil
}

func consumeAllowance(allowances []*preparedAllowance, rawPath string, digest string) bool {
	canonical, err := canonicalPolicyPath(rawPath)
	if err != nil || canonical != rawPath {
		return false
	}
	for _, allowance := range allowances {
		if allowance.path == canonical && strings.EqualFold(allowance.digest, digest) {
			allowance.consumed = true
			return true
		}
	}
	return false
}

func isHex(value string) bool {
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", character) {
			return false
		}
	}
	return value != ""
}

func gitlinkStateUnsafe(state string) bool {
	switch state {
	case "uninitialized", "dirty", "commit_mismatch", "dirty_commit_mismatch", "invalid":
		return true
	default:
		return false
	}
}

func scanPath(input scanInput) []Finding {
	lower := strings.ToLower(strings.ReplaceAll(input.path, `\`, "/"))
	base := strings.ToLower(filepath.Base(lower))
	var findings []Finding
	unsafeName := base == "kubeconfig" || strings.HasPrefix(base, "kubeconfig.") || strings.HasSuffix(base, ".kubeconfig") ||
		base == "id_rsa" || base == "id_ed25519" || base == "id_ecdsa" || strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") ||
		strings.HasSuffix(base, ".p12") || strings.HasSuffix(base, ".pfx") || base == ".env" || strings.HasPrefix(base, ".env.") ||
		base == "terraform.tfstate" || strings.HasPrefix(base, "terraform.tfstate.") ||
		base == "credentials.json" || base == "credentials.yaml" || base == "credentials.yml" ||
		base == "secrets.json" || base == "secrets.yaml" || base == "secrets.yml"
	if unsafeName {
		findings = append(findings, Finding{Rule: "unsafe_credential_filename", Class: "credentials", Message: "credential-bearing filename is forbidden"})
	}
	if strings.HasPrefix(lower, ".git/") || strings.Contains(lower, "/.git/") {
		findings = append(findings, Finding{Rule: "git_metadata_path", Class: "private_metadata", Message: "Git metadata must not be scanned or published as source"})
	}
	if input.kind == "symlink" && symlinkTargetEscapes(string(input.data)) {
		findings = append(findings, Finding{Rule: "symlink_escape", Class: "local_path", Message: "symbolic link target is not a portable repository-relative path"})
	}
	return findings
}

func symlinkTargetEscapes(target string) bool {
	if target == "" || strings.IndexByte(target, 0) >= 0 || strings.Contains(target, `\`) || strings.HasPrefix(target, "/") || drivePrefixedPath(target) {
		return true
	}
	normalized := strings.ReplaceAll(target, `\`, "/")
	if strings.HasPrefix(normalized, "/") || strings.HasPrefix(normalized, "//") || drivePrefixedPath(normalized) {
		return true
	}
	for _, part := range strings.Split(normalized, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func bindFinding(finding Finding, input scanInput) Finding {
	identity := identifyPath(input.path)
	finding.Path = identity.Display
	finding.PathSHA256 = identity.SHA256
	finding.PathBase64URL = identity.Base64URL
	finding.SourceVariant = input.variant
	finding.ContentSHA256 = input.digest
	return finding
}

func deduplicateFindings(findings []Finding) []Finding {
	sort.Slice(findings, func(left int, right int) bool {
		if findings[left].PathSHA256 != findings[right].PathSHA256 {
			return findings[left].PathSHA256 < findings[right].PathSHA256
		}
		if findings[left].Line != findings[right].Line {
			return findings[left].Line < findings[right].Line
		}
		if findings[left].Column != findings[right].Column {
			return findings[left].Column < findings[right].Column
		}
		if findings[left].Rule != findings[right].Rule {
			return findings[left].Rule < findings[right].Rule
		}
		if findings[left].SourceVariant != findings[right].SourceVariant {
			return findings[left].SourceVariant < findings[right].SourceVariant
		}
		return findings[left].ContentSHA256 < findings[right].ContentSHA256
	})
	result := findings[:0]
	last := ""
	for _, finding := range findings {
		key := finding.PathSHA256 + "\x00" + strconv.Itoa(finding.Line) + "\x00" + strconv.Itoa(finding.Column) + "\x00" + finding.Rule + "\x00" + finding.SourceVariant + "\x00" + finding.ContentSHA256
		if key != last {
			result = append(result, finding)
			last = key
		}
	}
	return result
}
