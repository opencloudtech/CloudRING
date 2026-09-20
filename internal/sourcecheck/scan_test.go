// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package sourcecheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestScan_full_includes_untracked_while_tracked_does_not(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "README.md", "Synthetic repository.\n")
	commitAll(t, root, "initial")
	writeRepositoryFile(t, root, "untracked.txt", "g"+"hp_"+strings.Repeat("a", 24))

	tracked, err := Scan(Options{Root: root, Scope: ScopeTracked})
	if err != nil {
		t.Fatalf("tracked scan: %v", err)
	}
	if !tracked.Passed {
		t.Fatalf("tracked scan unexpectedly included untracked input: %+v", tracked.Findings)
	}
	full, err := Scan(Options{Root: root, Scope: ScopeFull})
	if err != nil {
		t.Fatalf("full scan: %v", err)
	}
	if full.Passed || !containsRule(full.Findings, "github_classic_token") {
		t.Fatalf("full scan missed untracked secret finding %+v", full.Findings)
	}
}

func TestScan_tracked_reads_canonical_index_and_existing_worktree(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "config.txt", "safe\n")
	commitAll(t, root, "initial")
	writeRepositoryFile(t, root, "config.txt", "g"+"hp_"+strings.Repeat("i", 24)+"\n")
	runGit(t, root, "add", "config.txt")
	writeRepositoryFile(t, root, "config.txt", "safe worktree replacement\n")

	report, err := Scan(Options{Root: root, Scope: ScopeTracked})
	if err != nil {
		t.Fatalf("tracked scan: %v", err)
	}
	if report.Passed || !containsFinding(report.Findings, "github_classic_token", "index") {
		t.Fatalf("tracked scan missed canonical index secret finding %+v", report.Findings)
	}
	if !containsInputVariant(report.ScannedInputs, "config.txt", "worktree") {
		t.Fatalf("tracked scan omitted existing worktree variant: %+v", report.ScannedInputs)
	}
}

func TestScan_tracked_records_absent_worktree_path(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "sparse-or-deleted.txt", "safe\n")
	commitAll(t, root, "initial")
	if err := os.Remove(filepath.Join(root, "sparse-or-deleted.txt")); err != nil {
		t.Fatalf("remove tracked worktree fixture: %v", err)
	}
	report, err := Scan(Options{Root: root, Scope: ScopeTracked})
	if err != nil {
		t.Fatalf("tracked scan: %v", err)
	}
	if !containsInputKind(report.ScannedInputs, "sparse-or-deleted.txt", "worktree", "absent") {
		t.Fatalf("absent/sparse worktree state was silently skipped: %+v", report.ScannedInputs)
	}
}

func TestScan_changed_reads_staged_index_and_worktree_variants(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "config.txt", "safe\n")
	commitAll(t, root, "initial")
	writeRepositoryFile(t, root, "config.txt", "g"+"hp_"+strings.Repeat("b", 24)+"\n")
	runGit(t, root, "add", "config.txt")
	writeRepositoryFile(t, root, "config.txt", "safe worktree replacement\n")

	report, err := Scan(Options{Root: root, Scope: ScopeChanged})
	if err != nil {
		t.Fatalf("changed scan: %v", err)
	}
	if report.Passed || !containsFinding(report.Findings, "github_classic_token", "index") {
		t.Fatalf("changed scan missed staged secret finding %+v", report.Findings)
	}
	if !containsInputVariant(report.ScannedInputs, "config.txt", "worktree") {
		t.Fatalf("expected worktree variant to be scanned: %+v", report.ScannedInputs)
	}
}

func TestScan_pre_push_checks_intermediate_commits(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "config.txt", "safe\n")
	commitAll(t, root, "base")
	base := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	writeRepositoryFile(t, root, "config.txt", "A"+"KIA"+strings.Repeat("D", 16)+"\n")
	commitAll(t, root, "unsafe intermediate")
	unsafeCommit := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	writeRepositoryFile(t, root, "config.txt", "safe again\n")
	commitAll(t, root, "clean head")
	head := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	runGit(t, root, "replace", unsafeCommit, base)

	report, err := Scan(Options{Root: root, Scope: ScopePrePush, Base: base, Head: head})
	if err != nil {
		t.Fatalf("pre-push scan: %v", err)
	}
	if report.Passed || !containsFinding(report.Findings, "cloud_access_key", "commit") {
		t.Fatalf("pre-push scan missed unsafe intermediate commit: %+v", report.Findings)
	}
}

func TestScan_pre_push_checks_commit_message_metadata(t *testing.T) {
	tests := []struct {
		name    string
		message string
		rule    string
	}{
		{
			name:    "subject local path",
			message: "Document " + "/Us" + "ers/synthetic/private/config",
			rule:    "local_user_path",
		},
		{
			name:    "body private endpoint",
			message: "Document endpoint\n\nUse https://control." + "internal/api.",
			rule:    "private_endpoint",
		},
		{
			name:    "trailer proprietary attribution",
			message: "Document origin\n\nOrigin: copied " + "from proprietary " + "source",
			rule:    "private_source_attribution",
		},
		{
			name:    "body credential",
			message: "Document rotation\n\nPrevious value g" + "hp_" + strings.Repeat("q", 24),
			rule:    "github_classic_token",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := newRepository(t)
			writeRepositoryFile(t, root, "safe.txt", "safe base\n")
			commitAll(t, root, "base")
			base := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
			runGit(t, root, "commit", "--quiet", "--allow-empty", "-m", test.message)
			head := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))

			report, err := Scan(Options{Root: root, Scope: ScopePrePush, Base: base, Head: head})
			if err != nil {
				t.Fatalf("pre-push metadata scan: %v", err)
			}
			if report.Passed || !containsFinding(report.Findings, test.rule, "commit-metadata") {
				t.Fatalf("pre-push scan missed unsafe commit metadata rule %q: %+v", test.rule, report.Findings)
			}
		})
	}
}

func TestScan_pre_push_checks_commit_author_and_committer(t *testing.T) {
	t.Run("author", func(t *testing.T) {
		root := newRepository(t)
		writeRepositoryFile(t, root, "safe.txt", "safe base\n")
		commitAll(t, root, "base")
		base := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
		author := "/Us" + "ers/synthetic/Contributor <contributor@example.test>"
		runGit(t, root, "commit", "--quiet", "--allow-empty", "--author", author, "-m", "Document author metadata")
		head := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))

		report, err := Scan(Options{Root: root, Scope: ScopePrePush, Base: base, Head: head})
		if err != nil {
			t.Fatalf("pre-push author scan: %v", err)
		}
		if report.Passed || !containsFinding(report.Findings, "local_user_path", "commit-metadata") {
			t.Fatalf("pre-push scan missed unsafe author metadata: %+v", report.Findings)
		}
	})

	t.Run("committer", func(t *testing.T) {
		root := newRepository(t)
		writeRepositoryFile(t, root, "safe.txt", "safe base\n")
		commitAll(t, root, "base")
		base := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
		runGit(t, root, "config", "user.name", "copied "+"from proprietary "+"source")
		runGit(t, root, "commit", "--quiet", "--allow-empty", "--author", "Synthetic Author <author@example.test>", "-m", "Document committer metadata")
		head := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))

		report, err := Scan(Options{Root: root, Scope: ScopePrePush, Base: base, Head: head})
		if err != nil {
			t.Fatalf("pre-push committer scan: %v", err)
		}
		if report.Passed || !containsFinding(report.Findings, "private_source_attribution", "commit-metadata") {
			t.Fatalf("pre-push scan missed unsafe committer metadata: %+v", report.Findings)
		}
	})
}

func TestScan_pre_push_accepts_safe_commit_metadata_without_file_changes(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "safe.txt", "safe base\n")
	commitAll(t, root, "base")
	base := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	message := "Document bounded metadata scan\n\nCovers commit identity and message surfaces.\n\nReviewed-by: Synthetic Reviewer <reviewer@example.test>"
	runGit(t, root, "commit", "--quiet", "--allow-empty", "-m", message)
	head := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))

	report, err := Scan(Options{Root: root, Scope: ScopePrePush, Base: base, Head: head})
	if err != nil {
		t.Fatalf("pre-push safe metadata scan: %v", err)
	}
	expectedPath := identifyPath("commit-metadata/" + sha256Hex([]byte(head))).Display
	if !report.Passed || !containsInputVariant(report.ScannedInputs, expectedPath, "commit-metadata") {
		t.Fatalf("safe empty-commit metadata was not scanned and accepted: %+v", report)
	}
}

func TestCommitMetadataInput_resource_budgets_fail_closed(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "safe.txt", "safe base\n")
	commitAll(t, root, "base")
	base := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	sensitiveValue := "g" + "hp_" + strings.Repeat("r", 24)
	runGit(t, root, "commit", "--quiet", "--allow-empty", "-m", "Rotate "+sensitiveValue)
	head := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))

	_, err := commitMetadataInput(root, head, newScanBudget(&resourceLimits{metadataBytes: 1}))
	if err == nil {
		t.Fatal("commit metadata escaped the aggregate metadata budget")
	}
	if strings.Contains(err.Error(), sensitiveValue) {
		t.Fatal("metadata budget error exposed raw commit metadata")
	}
	_, err = Scan(Options{
		Root: root, Scope: ScopePrePush, Base: base, Head: head,
		limits: &resourceLimits{capturedBytes: 1, commitCount: 10, metadataBytes: 1 << 20},
	})
	if err == nil {
		t.Fatal("commit metadata escaped the aggregate captured-input budget")
	}
	if strings.Contains(err.Error(), sensitiveValue) {
		t.Fatal("captured-input budget error exposed raw commit metadata")
	}
}

func TestScan_pre_push_commit_metadata_report_never_contains_matched_secret(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "safe.txt", "safe base\n")
	commitAll(t, root, "base")
	base := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	sensitiveValue := "g" + "hp_" + strings.Repeat("s", 24)
	runGit(t, root, "commit", "--quiet", "--allow-empty", "-m", "Rotate "+sensitiveValue)
	head := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))

	report, err := Scan(Options{Root: root, Scope: ScopePrePush, Base: base, Head: head})
	if err != nil {
		t.Fatalf("pre-push metadata scan: %v", err)
	}
	if report.Passed || !containsFinding(report.Findings, "github_classic_token", "commit-metadata") {
		t.Fatalf("pre-push scan missed sensitive commit metadata: %+v", report.Findings)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encode metadata report: %v", err)
	}
	if bytes.Contains(encoded, []byte(sensitiveValue)) {
		t.Fatal("source-safety report exposed matched commit metadata")
	}
}

func TestScan_pre_push_checks_annotated_tag_metadata_on_published_commit(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "safe.txt", "safe published content\n")
	commitAll(t, root, "published base")
	published := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	bare := filepath.Join(t.TempDir(), "published.git")
	runGit(t, filepath.Dir(bare), "init", "--quiet", "--bare", bare)
	runGit(t, root, "remote", "add", "published-remote", bare)
	runGit(t, root, "push", "--quiet", "published-remote", published+":refs/heads/main")
	sensitiveValue := "g" + "hp_" + strings.Repeat("t", 24)
	annotation := "Document tag metadata " + sensitiveValue
	runGit(t, root, "tag", "-a", "unsafe-metadata", "-m", annotation, published)
	tagOID := strings.TrimSpace(runGit(t, root, "rev-parse", "refs/tags/unsafe-metadata"))

	report, err := Scan(Options{
		Root: root, Scope: ScopePrePush, RemoteName: "published-remote", RemoteURLSHA256: sha256Hex([]byte(bare)),
		RemoteRefs: []string{"refs/heads/main"},
		PushUpdates: []PushUpdate{{
			LocalRef: "refs/tags/unsafe-metadata", LocalOID: tagOID,
			RemoteRef: "refs/tags/unsafe-metadata", RemoteOID: strings.Repeat("0", 40),
		}},
	})
	if err != nil {
		t.Fatalf("pre-push annotated tag scan: %v", err)
	}
	if report.Passed || !containsFinding(report.Findings, "github_classic_token", "tag-metadata") {
		t.Fatalf("annotated tag metadata on a published commit was not blocked: %+v", report.Findings)
	}
	if countInputVariant(report.ScannedInputs, "tag-metadata") != 1 || countInputVariant(report.ScannedInputs, "commit-metadata") != 0 {
		t.Fatalf("annotated tag scan did not preserve the published-commit boundary: %+v", report.ScannedInputs)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encode annotated tag report: %v", err)
	}
	if bytes.Contains(encoded, []byte(annotation)) || bytes.Contains(encoded, []byte(sensitiveValue)) {
		t.Fatal("source-safety report exposed raw annotated tag metadata")
	}
}

func TestScan_pre_push_walks_every_annotated_tag_in_a_chain(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "safe.txt", "safe published content\n")
	commitAll(t, root, "published base")
	published := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	sensitiveValue := "g" + "hp_" + strings.Repeat("u", 24)
	runGit(t, root, "tag", "-a", "inner-metadata", "-m", "Inner annotation "+sensitiveValue, published)
	runGit(t, root, "tag", "-a", "outer-metadata", "-m", "Safe outer annotation", "refs/tags/inner-metadata")
	outerOID := strings.TrimSpace(runGit(t, root, "rev-parse", "refs/tags/outer-metadata"))
	outerRaw := []byte(runGit(t, root, "cat-file", "tag", outerOID))
	_, outerTargetType, err := annotatedTagTarget(outerRaw)
	if err != nil || outerTargetType != "tag" {
		t.Fatalf("nested annotated-tag fixture does not target a tag: type=%q err=%v", outerTargetType, err)
	}

	report, err := Scan(Options{Root: root, Scope: ScopePrePush, Base: published, Head: outerOID})
	if err != nil {
		t.Fatalf("pre-push annotated tag-chain scan: %v", err)
	}
	if report.Passed || !containsFinding(report.Findings, "github_classic_token", "tag-metadata") || countInputVariant(report.ScannedInputs, "tag-metadata") != 2 {
		t.Fatalf("nested annotated tag metadata was not fully scanned: %+v", report)
	}
}

func TestScan_pre_push_accepts_safe_annotated_tag_metadata(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "safe.txt", "safe published content\n")
	commitAll(t, root, "published base")
	published := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	annotation := "Document annotated tag validation\n\nReviewed-by: Synthetic Reviewer <reviewer@example.test>"
	runGit(t, root, "tag", "-a", "safe-metadata", "-m", annotation, published)
	tagOID := strings.TrimSpace(runGit(t, root, "rev-parse", "refs/tags/safe-metadata"))

	report, err := Scan(Options{Root: root, Scope: ScopePrePush, Base: published, Head: tagOID})
	if err != nil {
		t.Fatalf("pre-push safe annotated tag scan: %v", err)
	}
	if !report.Passed || countInputVariant(report.ScannedInputs, "tag-metadata") != 1 {
		t.Fatalf("safe annotated tag metadata was not scanned and accepted: %+v", report)
	}
}

func TestAnnotatedTagMetadata_resource_budgets_fail_closed(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "safe.txt", "safe published content\n")
	commitAll(t, root, "published base")
	published := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	sensitiveValue := "g" + "hp_" + strings.Repeat("v", 24)
	annotation := "Document tag metadata " + sensitiveValue
	runGit(t, root, "tag", "-a", "bounded-metadata", "-m", annotation, published)
	tagOID := strings.TrimSpace(runGit(t, root, "rev-parse", "refs/tags/bounded-metadata"))

	_, err := inspectPublishedObject(root, tagOID, newScanBudget(&resourceLimits{metadataBytes: 4}), map[string]publishedObject{})
	if err == nil {
		t.Fatal("annotated tag escaped the aggregate Git metadata budget")
	}
	if strings.Contains(err.Error(), annotation) || strings.Contains(err.Error(), sensitiveValue) {
		t.Fatal("Git metadata budget error exposed an annotated tag message")
	}
	_, err = Scan(Options{
		Root: root, Scope: ScopePrePush, Base: published, Head: tagOID,
		limits: &resourceLimits{capturedBytes: 1, inputCount: 10, commitCount: 10, metadataBytes: 1 << 20},
	})
	if err == nil {
		t.Fatal("annotated tag escaped the aggregate captured-input budget")
	}
	if strings.Contains(err.Error(), annotation) || strings.Contains(err.Error(), sensitiveValue) {
		t.Fatal("captured-input budget error exposed an annotated tag message")
	}
}

func TestAnnotatedTagTarget_rejects_oversized_header_lines(t *testing.T) {
	target := strings.Repeat("a", 40)
	metadata := []byte("object " + target + "\ntype commit\ntag " + strings.Repeat("x", maxAnnotatedTagHeaderLineBytes+1) + "\n\nsafe annotation\n")
	if _, _, err := annotatedTagTarget(metadata); err == nil {
		t.Fatal("annotated tag parser accepted an oversized header line")
	}
}

func TestScan_pre_push_rejects_unsupported_published_object_types(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "safe.txt", "safe content\n")
	commitAll(t, root, "base")
	objects := map[string]string{
		"blob": strings.TrimSpace(runGit(t, root, "hash-object", "-w", "safe.txt")),
		"tree": strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD^{tree}")),
	}
	for objectType, oid := range objects {
		t.Run(objectType, func(t *testing.T) {
			_, err := Scan(Options{Root: root, Scope: ScopePrePush, Base: strings.Repeat("0", 40), Head: oid})
			if err == nil {
				t.Fatalf("pre-push scan accepted a published %s object", objectType)
			}
		})
	}
}

func TestWalkPublishedObject_rejects_cycles_and_type_mismatch(t *testing.T) {
	oidA := strings.Repeat("a", 40)
	oidB := strings.Repeat("b", 40)
	sensitiveAnnotation := "g" + "hp_" + strings.Repeat("w", 24)
	cycle := map[string]publishedObject{
		oidA: {objectType: "tag", data: syntheticAnnotatedTag(oidB, "tag", sensitiveAnnotation)},
		oidB: {objectType: "tag", data: syntheticAnnotatedTag(oidA, "tag", "safe annotation")},
	}
	inspectCycle := func(oid string) (publishedObject, error) { return cycle[oid], nil }
	_, err := walkPublishedObject(oidA, inspectCycle, func(string, []byte) error { return nil })
	if err == nil {
		t.Fatal("annotated tag cycle was accepted")
	}
	if strings.Contains(err.Error(), sensitiveAnnotation) {
		t.Fatal("annotated tag cycle error exposed raw metadata")
	}

	mismatch := map[string]publishedObject{
		oidA: {objectType: "tag", data: syntheticAnnotatedTag(oidB, "commit", "safe annotation")},
		oidB: {objectType: "tag", data: syntheticAnnotatedTag(oidA, "tag", "safe annotation")},
	}
	inspectMismatch := func(oid string) (publishedObject, error) { return mismatch[oid], nil }
	if _, err := walkPublishedObject(oidA, inspectMismatch, nil); err == nil {
		t.Fatal("annotated tag target-type mismatch was accepted")
	}
}

func TestWalkPublishedObject_enforces_tag_depth_limit(t *testing.T) {
	makeChain := func(tagCount int) (string, map[string]publishedObject) {
		objects := make(map[string]publishedObject, tagCount+1)
		tags := make([]string, tagCount)
		for index := range tags {
			tags[index] = fmt.Sprintf("%040x", index+1)
		}
		commit := fmt.Sprintf("%040x", tagCount+1)
		objects[commit] = publishedObject{objectType: "commit"}
		for index, tag := range tags {
			target := commit
			targetType := "commit"
			if index+1 < len(tags) {
				target = tags[index+1]
				targetType = "tag"
			}
			objects[tag] = publishedObject{objectType: "tag", data: syntheticAnnotatedTag(target, targetType, "safe annotation")}
		}
		return tags[0], objects
	}

	for _, test := range []struct {
		name      string
		tagCount  int
		wantError bool
	}{
		{name: "at limit", tagCount: maxAnnotatedTagDepth},
		{name: "above limit", tagCount: maxAnnotatedTagDepth + 1, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			start, objects := makeChain(test.tagCount)
			inspectedTags := 0
			inspect := func(oid string) (publishedObject, error) { return objects[oid], nil }
			_, err := walkPublishedObject(start, inspect, func(string, []byte) error {
				inspectedTags++
				return nil
			})
			if test.wantError && err == nil {
				t.Fatal("annotated tag chain above the depth limit was accepted")
			}
			if !test.wantError && (err != nil || inspectedTags != test.tagCount) {
				t.Fatalf("annotated tag chain at the depth limit was rejected: tags=%d err=%v", inspectedTags, err)
			}
		})
	}
}

func TestScan_pre_push_checks_two_parent_and_octopus_merge_resolutions(t *testing.T) {
	for _, parentCount := range []int{2, 3} {
		t.Run(fmt.Sprintf("%d-parents", parentCount), func(t *testing.T) {
			root, base, head := repositoryWithUnsafeMergeResolution(t, parentCount)
			report, err := Scan(Options{Root: root, Scope: ScopePrePush, Base: base, Head: head})
			if err != nil {
				t.Fatalf("pre-push merge scan: %v", err)
			}
			if report.Passed || !containsFinding(report.Findings, "github_classic_token", "commit") {
				t.Fatalf("merge-resolution secret was missed for %d parents: %+v", parentCount, report.Findings)
			}
		})
	}
}

func TestScan_zero_base_scans_all_history_unless_exact_remote_ref_is_supplied(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "config.txt", "g"+"hp_"+strings.Repeat("z", 24)+"\n")
	commitAll(t, root, "unsafe root")
	writeRepositoryFile(t, root, "config.txt", "safe at remote boundary\n")
	commitAll(t, root, "clean remote boundary")
	remoteBoundary := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	runGit(t, root, "update-ref", "refs/remotes/target/main", remoteBoundary)
	writeRepositoryFile(t, root, "later.txt", "safe later content\n")
	commitAll(t, root, "safe head")
	head := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))

	for _, zero := range []string{strings.Repeat("0", 40), strings.Repeat("0", 64)} {
		report, err := Scan(Options{Root: root, Scope: ScopePrePush, Base: zero, Head: head})
		if err != nil {
			t.Fatalf("zero-base scan: %v", err)
		}
		if report.Passed || !containsRule(report.Findings, "github_classic_token") {
			t.Fatalf("zero-base scan did not inspect all reachable history: %+v", report.Findings)
		}
	}
	_, err := Scan(Options{
		Root: root, Scope: ScopePrePush, Base: strings.Repeat("0", 40), Head: head,
		RemoteRefs: []string{"refs/remotes/target/main"},
	})
	if err == nil {
		t.Fatal("unverified local remote ref was accepted as a target-remote exclusion")
	}
	bare := filepath.Join(t.TempDir(), "target.git")
	runGit(t, filepath.Dir(bare), "init", "--quiet", "--bare", bare)
	runGit(t, root, "remote", "add", "target-remote", bare)
	runGit(t, root, "push", "--quiet", "target-remote", remoteBoundary+":refs/heads/main")
	remoteExact, err := Scan(Options{
		Root: root, Scope: ScopePrePush, Base: strings.Repeat("0", 40), Head: head,
		RemoteName: "target-remote", RemoteURLSHA256: sha256Hex([]byte(bare)), RemoteRefs: []string{"refs/heads/main"},
	})
	if err != nil {
		t.Fatalf("target remote discovery scan: %v", err)
	}
	if !remoteExact.Passed {
		t.Fatalf("actual target remote OIDs did not safely narrow published ancestors: %+v", remoteExact.Findings)
	}
	if _, err := Scan(Options{
		Root: root, Scope: ScopePrePush, Base: strings.Repeat("0", 40), Head: head,
		RemoteName: "target-remote", RemoteURLSHA256: sha256Hex([]byte(bare)), RemoteRefs: []string{"refs/heads/missing"},
	}); err == nil {
		t.Fatal("unadvertised exact target-remote ref was accepted")
	}
	pushTarget := filepath.Join(t.TempDir(), "push-target.git")
	runGit(t, filepath.Dir(pushTarget), "init", "--quiet", "--bare", pushTarget)
	runGit(t, root, "remote", "set-url", "--push", "target-remote", pushTarget)
	mismatched, err := Scan(Options{
		Root: root, Scope: ScopePrePush, Base: strings.Repeat("0", 40), Head: head,
		RemoteName: "target-remote", RemoteURLSHA256: sha256Hex([]byte(pushTarget)),
	})
	if err != nil {
		t.Fatalf("pushurl mismatch scan: %v", err)
	}
	if mismatched.Passed || !containsRule(mismatched.Findings, "github_classic_token") {
		t.Fatalf("fetch URL exclusions weakened a different pushurl target: %+v", mismatched.Findings)
	}
}

func TestScan_pre_push_rejects_shallow_history(t *testing.T) {
	source := newRepository(t)
	writeRepositoryFile(t, source, "one.txt", "safe one\n")
	commitAll(t, source, "one")
	writeRepositoryFile(t, source, "two.txt", "safe two\n")
	commitAll(t, source, "two")
	clone := filepath.Join(t.TempDir(), "shallow")
	runGit(t, filepath.Dir(clone), "clone", "--quiet", "--depth=1", "file://"+source, clone)
	if strings.TrimSpace(runGit(t, clone, "rev-parse", "--is-shallow-repository")) != "true" {
		t.Fatal("test fixture is not shallow")
	}
	if _, err := Scan(Options{Root: clone, Scope: ScopePrePush, Base: strings.Repeat("0", 40), Head: "HEAD"}); err == nil {
		t.Fatal("pre-push scan accepted incomplete shallow history")
	}
}

func TestRemoteURLSafeForHelper_suppresses_credential_bearing_targets(t *testing.T) {
	for _, value := range []string{
		strings.Join([]string{"https", "://user:", "literal@example.test/repository"}, ""),
		"https://example.test/repository?signature=literal",
		"git@example.test:repository",
		"ext::synthetic-command",
	} {
		if remoteURLSafeForHelper([]byte(value)) {
			t.Fatalf("credential/private remote URL would be expanded into helper argv: %q", value)
		}
	}
	for _, value := range []string{"https://example.test/repository", "/synthetic/local/repository"} {
		if !remoteURLSafeForHelper([]byte(value)) {
			t.Fatalf("credential-free remote URL was rejected: %q", value)
		}
	}
}

func TestScan_pre_push_rejects_option_like_revision(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "safe.txt", "safe\n")
	commitAll(t, root, "initial")
	_, err := Scan(Options{Root: root, Scope: ScopePrePush, Base: "--all", Head: "HEAD"})
	if err == nil {
		t.Fatal("expected option-like pre-push revision to be rejected")
	}
}

func TestScan_non_text_allowance_is_exact_consumed_and_fail_closed(t *testing.T) {
	root := newRepository(t)
	data := []byte{0x00, 0xff, 0x10, 0x11}
	writeRepositoryBytes(t, root, "assets/image.bin", data)
	blocked, err := Scan(Options{Root: root, Scope: ScopeFull})
	if err != nil {
		t.Fatalf("non-text scan: %v", err)
	}
	if blocked.Passed || !containsRule(blocked.Findings, "non_text_review_required") {
		t.Fatalf("unreviewed non-text artifact was not blocked: %+v", blocked.Findings)
	}
	digest := sha256Hex(data)
	approved, err := Scan(Options{Root: root, Scope: ScopeFull, NonTextAllowances: []NonTextAllowance{{Path: "assets/image.bin", SHA256: digest}}})
	if err != nil {
		t.Fatalf("reviewed non-text scan: %v", err)
	}
	if !approved.Passed || len(approved.NonTextAllowances) != 1 || !approved.NonTextAllowances[0].Consumed {
		t.Fatalf("exact reviewed allowance was not consumed: %+v", approved)
	}
	unused, err := Scan(Options{Root: root, Scope: ScopeFull, NonTextAllowances: []NonTextAllowance{{Path: "assets/other.bin", SHA256: digest}}})
	if err != nil {
		t.Fatalf("unused allowance scan: %v", err)
	}
	if unused.Passed || !containsRule(unused.Findings, "unused_non_text_allowance") {
		t.Fatalf("unused allowance was silently accepted: %+v", unused.Findings)
	}
	prepared, err := prepareAllowances([]NonTextAllowance{
		{Path: "assets/./image.bin", SHA256: digest}, {Path: `assets\image.bin`, SHA256: strings.Repeat("1", 64)},
	})
	if err != nil || len(prepared) != 2 {
		t.Fatalf("multiple reviewed revisions for one path were rejected: err=%v allowances=%+v", err, prepared)
	}
	if _, err := Scan(Options{NonTextAllowances: []NonTextAllowance{
		{Path: "assets/./image.bin", SHA256: digest}, {Path: `assets\image.bin`, SHA256: digest},
	}}); err == nil {
		t.Fatal("duplicate canonical path and digest allowance was not rejected")
	}
}

func TestScan_prePush_gitlinkHistory_acceptsEveryExactReviewedRevision(t *testing.T) {
	child := newRepository(t)
	writeRepositoryFile(t, child, "safe.txt", "first safe child revision\n")
	commitAll(t, child, "child first")
	firstChildOID := strings.TrimSpace(runGit(t, child, "rev-parse", "HEAD"))
	writeRepositoryFile(t, child, "safe.txt", "second safe child revision\n")
	commitAll(t, child, "child second")
	secondChildOID := strings.TrimSpace(runGit(t, child, "rev-parse", "HEAD"))

	root := newRepository(t)
	runGit(t, root, "update-index", "--add", "--cacheinfo", "160000", firstChildOID, "module")
	runGit(t, root, "commit", "--quiet", "-m", "pin child first")
	runGit(t, root, "update-index", "--cacheinfo", "160000", secondChildOID, "module")
	runGit(t, root, "commit", "--quiet", "-m", "pin child second")
	head := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))

	report, err := Scan(Options{
		Root: root, Scope: ScopePrePush, Base: strings.Repeat("0", 40), Head: head,
		NonTextAllowances: []NonTextAllowance{
			{Path: "module", SHA256: sha256Hex([]byte(firstChildOID))},
			{Path: "module", SHA256: sha256Hex([]byte(secondChildOID))},
		},
	})
	if err != nil {
		t.Fatalf("scan gitlink revision history: %v", err)
	}
	if !report.Passed || len(report.NonTextAllowances) != 2 || !report.NonTextAllowances[0].Consumed || !report.NonTextAllowances[1].Consumed {
		t.Fatalf("exact reviewed gitlink revision history was not accepted: %+v", report)
	}
	missingRevision, err := Scan(Options{
		Root: root, Scope: ScopePrePush, Base: strings.Repeat("0", 40), Head: head,
		NonTextAllowances: []NonTextAllowance{{Path: "module", SHA256: sha256Hex([]byte(secondChildOID))}},
	})
	if err != nil {
		t.Fatalf("scan incomplete gitlink review set: %v", err)
	}
	if missingRevision.Passed || !containsRule(missingRevision.Findings, "gitlink_policy_required") {
		t.Fatalf("unreviewed historical gitlink revision was accepted: %+v", missingRevision)
	}
}

func TestScan_large_artifacts_are_streamed_and_hard_capped(t *testing.T) {
	root := newRepository(t)
	data := bytes.Repeat([]byte{'x'}, maxTextBytes+1024)
	writeRepositoryBytes(t, root, "large.txt", data)
	blocked, err := Scan(Options{Root: root, Scope: ScopeFull})
	if err != nil {
		t.Fatalf("stream large artifact: %v", err)
	}
	if blocked.Passed || !containsRule(blocked.Findings, "non_text_review_required") {
		t.Fatalf("large artifact did not enter exact non-text review: %+v", blocked.Findings)
	}
	digest := sha256Hex(data)
	approved, err := Scan(Options{Root: root, Scope: ScopeFull, NonTextAllowances: []NonTextAllowance{{Path: "large.txt", SHA256: digest}}})
	if err != nil || !approved.Passed {
		t.Fatalf("streamed exact digest allowance failed: err=%v findings=%+v", err, approved.Findings)
	}
	hardPath := filepath.Join(root, "hard-cap.bin")
	// #nosec G304 -- the test path is constructed beneath a fresh t.TempDir repository.
	file, err := os.OpenFile(hardPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create hard-cap fixture: %v", err)
	}
	if err := file.Truncate(maxReviewBytes + 1); err != nil {
		_ = file.Close()
		t.Fatalf("truncate hard-cap fixture: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close hard-cap fixture: %v", err)
	}
	hardCapped, err := Scan(Options{Root: root, Scope: ScopeFiles, Files: []string{"hard-cap.bin"}})
	if err != nil {
		t.Fatalf("hard-cap scan: %v", err)
	}
	if hardCapped.Passed || !containsRule(hardCapped.Findings, "source_input_unavailable") {
		t.Fatalf("artifact above hard cap was not fail-closed: %+v", hardCapped)
	}
}

func TestScan_resource_budgets_fail_closed_for_aggregate_growth(t *testing.T) {
	root := newRepository(t)
	writeRepositoryFile(t, root, "one.txt", "safe one\n")
	writeRepositoryFile(t, root, "two.txt", "safe two\n")
	commitAll(t, root, "base")
	for name, limits := range map[string]*resourceLimits{
		"captured bytes": {capturedBytes: 1},
		"input count":    {inputCount: 1},
		"metadata bytes": {metadataBytes: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Scan(Options{Root: root, Scope: ScopeTracked, limits: limits}); err == nil {
				t.Fatal("aggregate resource budget was not enforced")
			}
		})
	}
	base := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	writeRepositoryFile(t, root, "versioned.txt", "safe version one\n")
	commitAll(t, root, "version one")
	writeRepositoryFile(t, root, "versioned.txt", "safe version two with more bytes\n")
	commitAll(t, root, "version two")
	head := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	if _, err := Scan(Options{
		Root: root, Scope: ScopePrePush, Base: base, Head: head, limits: &resourceLimits{commitCount: 1},
	}); err == nil {
		t.Fatal("pre-push commit-count budget was not enforced")
	}
	if _, err := Scan(Options{
		Root: root, Scope: ScopePrePush, Base: base, Head: head,
		limits: &resourceLimits{capturedBytes: 60, commitCount: 10, metadataBytes: 1 << 20},
	}); err == nil {
		t.Fatal("many-version pre-push capture budget was not enforced")
	}
	writeRepositoryFile(t, root, "claims.md", strings.Repeat("GA ", 20))
	if _, err := Scan(Options{
		Root: root, Scope: ScopeFiles, Files: []string{"claims.md"}, limits: &resourceLimits{findingCount: 5},
	}); err == nil {
		t.Fatal("repeated readiness occurrences escaped the global finding budget")
	}
	writeRepositoryFile(t, root, "clauses.md", strings.Repeat("safe sentence.\n", 10))
	if _, err := Scan(Options{
		Root: root, Scope: ScopeFiles, Files: []string{"clauses.md"}, limits: &resourceLimits{clauseCount: 3},
	}); err == nil {
		t.Fatal("readiness structure escaped the bounded clause budget")
	}
}

func TestScan_gitlinks_require_exact_allowance_or_clean_recursion(t *testing.T) {
	child := newRepository(t)
	writeRepositoryFile(t, child, "safe.txt", "safe child content\n")
	commitAll(t, child, "child initial")
	childOID := strings.TrimSpace(runGit(t, child, "rev-parse", "HEAD"))
	root := newRepository(t)
	runGit(t, root, "update-index", "--add", "--cacheinfo", "160000", childOID, "module")

	uninitialized, err := Scan(Options{Root: root, Scope: ScopeTracked})
	if err != nil {
		t.Fatalf("uninitialized gitlink scan: %v", err)
	}
	if uninitialized.Passed || !containsGitlinkState(uninitialized.ScannedInputs, "uninitialized") || !containsRule(uninitialized.Findings, "gitlink_policy_required") {
		t.Fatalf("uninitialized gitlink was not explicit and fail-closed: %+v", uninitialized)
	}
	allowance := NonTextAllowance{Path: "module", SHA256: sha256Hex([]byte(childOID))}
	allowed, err := Scan(Options{Root: root, Scope: ScopeTracked, NonTextAllowances: []NonTextAllowance{allowance}})
	if err != nil {
		t.Fatalf("allowlisted gitlink scan: %v", err)
	}
	if allowed.Passed || allowed.NonTextAllowances[0].Consumed || !containsRule(allowed.Findings, "gitlink_state_unsafe") {
		t.Fatalf("allowance bypassed an uninitialized gitlink: %+v", allowed)
	}
	modulePath := filepath.Join(root, "module")
	if err := os.Mkdir(modulePath, 0o700); err != nil {
		t.Fatalf("create empty uninitialized gitlink directory: %v", err)
	}
	emptyDirectory, err := Scan(Options{Root: root, Scope: ScopeTracked})
	if err != nil || !containsGitlinkState(emptyDirectory.ScannedInputs, "uninitialized") {
		t.Fatalf("empty uninitialized gitlink directory was not classified explicitly: err=%v report=%+v", err, emptyDirectory)
	}
	writeRepositoryFile(t, modulePath, "stray.txt", "safe but untracked\n")
	oneEntryDirectory, err := Scan(Options{Root: root, Scope: ScopeTracked})
	if err != nil || !containsGitlinkState(oneEntryDirectory.ScannedInputs, "dirty") {
		t.Fatalf("one-entry uninitialized gitlink directory was not dirty: err=%v report=%+v", err, oneEntryDirectory)
	}
	// #nosec G703 -- the synthetic path is fixed beneath a fresh t.TempDir repository.
	if err := os.RemoveAll(modulePath); err != nil {
		t.Fatalf("remove uninitialized gitlink fixture: %v", err)
	}

	runGit(t, root, "clone", "--quiet", child, "module")
	cleanAllowed, err := Scan(Options{Root: root, Scope: ScopeTracked, NonTextAllowances: []NonTextAllowance{allowance}})
	if err != nil {
		t.Fatalf("clean allowlisted gitlink scan: %v", err)
	}
	if !cleanAllowed.Passed || !cleanAllowed.NonTextAllowances[0].Consumed {
		t.Fatalf("exact allowance did not approve a clean exact-HEAD gitlink: %+v", cleanAllowed)
	}
	recursive, err := Scan(Options{Root: root, Scope: ScopeTracked, RecurseGitlinks: true})
	if err != nil {
		t.Fatalf("recursive gitlink scan: %v", err)
	}
	if !recursive.Passed || !containsGitlinkState(recursive.ScannedInputs, "clean") || !containsNestedVariant(recursive.ScannedInputs) {
		t.Fatalf("clean initialized gitlink was not recursively scanned: %+v", recursive)
	}
	if _, err := Scan(Options{
		Root: root, Scope: ScopeTracked, RecurseGitlinks: true, limits: &resourceLimits{capturedBytes: 180},
	}); err == nil {
		t.Fatal("recursive gitlink path-prefix expansion escaped the shared capture budget")
	}

	writeRepositoryFile(t, filepath.Join(root, "module"), "dirty.txt", "dirty but otherwise safe\n")
	dirty, err := Scan(Options{Root: root, Scope: ScopeTracked, RecurseGitlinks: true})
	if err != nil {
		t.Fatalf("dirty gitlink scan: %v", err)
	}
	if dirty.Passed || !containsRule(dirty.Findings, "gitlink_state_unsafe") || !containsGitlinkState(dirty.ScannedInputs, "dirty") {
		t.Fatalf("dirty gitlink was not blocked: %+v", dirty)
	}
	if err := os.Remove(filepath.Join(root, "module", "dirty.txt")); err != nil {
		t.Fatalf("remove dirty fixture: %v", err)
	}
	writeRepositoryFile(t, filepath.Join(root, "module"), "new.txt", "safe new commit\n")
	runGit(t, filepath.Join(root, "module"), "config", "user.name", "Synthetic Contributor")
	runGit(t, filepath.Join(root, "module"), "config", "user.email", "synthetic-contributor@example.test")
	commitAll(t, filepath.Join(root, "module"), "new child commit")
	mismatch, err := Scan(Options{Root: root, Scope: ScopeTracked, RecurseGitlinks: true})
	if err != nil {
		t.Fatalf("mismatched gitlink scan: %v", err)
	}
	if mismatch.Passed || !containsGitlinkState(mismatch.ScannedInputs, "commit_mismatch") || !containsRule(mismatch.Findings, "gitlink_state_unsafe") {
		t.Fatalf("gitlink commit mismatch was not blocked: %+v", mismatch)
	}
}

func TestScan_recursiveGitlink_preservesExactReviewedVendoredDocumentationException(t *testing.T) {
	repositoryPath := filepath.Join("..", "..", filepath.FromSlash(reviewedVendoredPrivateKeyDocumentationPath))
	// #nosec G304 -- this test reads one fixed repository fixture path assembled for platform portability.
	data, err := os.ReadFile(repositoryPath)
	if err != nil {
		t.Fatal(err)
	}

	child := newRepository(t)
	writeRepositoryFile(t, child, ".gitattributes", reviewedVendoredPrivateKeyDocumentationPath+" text eol=lf\n")
	writeRepositoryFile(t, child, reviewedVendoredPrivateKeyDocumentationPath, string(data))
	commitAll(t, child, "reviewed vendored documentation")

	direct, err := Scan(Options{Root: child, Scope: ScopeTracked})
	if err != nil {
		t.Fatalf("scan direct child: %v", err)
	}
	if !direct.Passed {
		t.Fatalf("direct child scan rejected reviewed documentation: %+v", direct.Findings)
	}

	parent := newRepository(t)
	runGit(t, parent, "clone", "--quiet", child, "cloudring_core")
	runGit(t, parent, "add", "cloudring_core")
	recursive, err := Scan(Options{Root: parent, Scope: ScopeTracked, RecurseGitlinks: true})
	if err != nil {
		t.Fatalf("scan parent recursively: %v", err)
	}
	if !recursive.Passed {
		t.Fatalf("recursive scan rejected reviewed documentation: %+v", recursive.Findings)
	}

	prefixedPath := "cloudring_core/" + reviewedVendoredPrivateKeyDocumentationPath
	variants := map[string]int{}
	for _, input := range recursive.ScannedInputs {
		if input.Path == prefixedPath {
			variants[input.SourceVariant]++
		}
	}
	if variants["gitlink/index"] != 1 || variants["gitlink/worktree"] != 1 || len(variants) != 2 {
		t.Fatalf("recursive scan did not preserve exact index/worktree duplication semantics: %+v", variants)
	}
}

func TestScan_files_rejects_repository_escape(t *testing.T) {
	root := newRepository(t)
	outside := filepath.Join(filepath.Dir(root), "outside.txt")
	if err := os.WriteFile(outside, []byte("safe"), 0o600); err != nil {
		t.Fatalf("write outside fixture: %v", err)
	}
	if _, err := Scan(Options{Root: root, Scope: ScopeFiles, Files: []string{outside}}); err == nil {
		t.Fatal("expected repository escape rejection")
	}
}

func TestScan_report_redacts_sensitive_path_and_exposes_digest_identity(t *testing.T) {
	root := newRepository(t)
	secretPath := "g" + "hp_" + strings.Repeat("p", 24) + ".txt"
	writeRepositoryFile(t, root, secretPath, "safe content\n")
	report, err := Scan(Options{Root: root, Scope: ScopeFull})
	if err != nil {
		t.Fatalf("full scan: %v", err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encode report: %v", err)
	}
	if bytes.Contains(encoded, []byte(secretPath)) {
		t.Fatal("report exposed a credential-like raw path")
	}
	if len(report.ScannedFiles) != 1 || report.ScannedFiles[0].SHA256 == "" || report.ScannedFiles[0].Base64URL == "" || !strings.HasPrefix(report.ScannedFiles[0].Display, "<redacted-path:") {
		t.Fatalf("path digest identity is incomplete: %+v", report.ScannedFiles)
	}
}

func TestPathIdentity_redacts_credential_like_printable_filename(t *testing.T) {
	raw := "siriusC3scs0504B.txt"
	identity := identifyPath(raw)
	if identity.Display == raw || !strings.HasPrefix(identity.Display, "<redacted-path:") || identity.SHA256 == "" || identity.Base64URL == "" {
		t.Fatalf("credential-like printable filename was not redacted: %+v", identity)
	}
}

func TestScan_report_never_contains_matched_secret_value(t *testing.T) {
	root := newRepository(t)
	sensitiveValue := "g" + "hp_" + strings.Repeat("e", 24)
	writeRepositoryFile(t, root, "config.txt", sensitiveValue)
	report, err := Scan(Options{Root: root, Scope: ScopeFull})
	if err != nil {
		t.Fatalf("full scan: %v", err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encode report: %v", err)
	}
	if bytes.Contains(encoded, []byte(sensitiveValue)) {
		t.Fatal("report exposed matched credential content")
	}
}

func repositoryWithUnsafeMergeResolution(t *testing.T, parentCount int) (string, string, string) {
	t.Helper()
	root := newRepository(t)
	writeRepositoryFile(t, root, "base.txt", "safe base\n")
	commitAll(t, root, "base")
	base := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	mainBranch := strings.TrimSpace(runGit(t, root, "symbolic-ref", "--short", "HEAD"))
	var branches []string
	for index := 1; index < parentCount; index++ {
		branch := "side-" + string(rune('0'+index))
		runGit(t, root, "checkout", "--quiet", "-b", branch, base)
		writeRepositoryFile(t, root, branch+".txt", "safe side content\n")
		commitAll(t, root, branch)
		branches = append(branches, branch)
	}
	runGit(t, root, "checkout", "--quiet", mainBranch)
	writeRepositoryFile(t, root, "main.txt", "safe main content\n")
	commitAll(t, root, "main parent")
	mergeArgs := []string{"merge", "--no-ff", "--no-commit"}
	mergeArgs = append(mergeArgs, branches...)
	runGit(t, root, mergeArgs...)
	writeRepositoryFile(t, root, "merge-resolution.txt", "g"+"hp_"+strings.Repeat("m", 24)+"\n")
	commitAll(t, root, "merge resolution")
	head := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	parents := strings.Fields(strings.TrimSpace(runGit(t, root, "rev-list", "--parents", "-n", "1", head)))
	if len(parents)-1 != parentCount {
		t.Fatalf("merge has %d parents, want %d", len(parents)-1, parentCount)
	}
	return root, base, head
}

func newRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "--quiet")
	runGit(t, root, "config", "user.name", "Synthetic Contributor")
	runGit(t, root, "config", "user.email", "synthetic-contributor@example.test")
	return root
}

func writeRepositoryFile(t *testing.T, root string, path string, content string) {
	t.Helper()
	writeRepositoryBytes(t, root, path, []byte(content))
}

func writeRepositoryBytes(t *testing.T, root string, path string, content []byte) {
	t.Helper()
	rootAbsolute, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("resolve fixture root: %v", err)
	}
	absolute, err := filepath.Abs(filepath.Join(rootAbsolute, filepath.FromSlash(path)))
	if err != nil {
		t.Fatalf("resolve fixture path: %v", err)
	}
	relative, err := filepath.Rel(rootAbsolute, absolute)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		t.Fatalf("fixture path escapes repository root: %q", path)
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	// #nosec G703 -- the test-only destination is proven to remain beneath the t.TempDir repository root above.
	if err := os.WriteFile(absolute, content, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func commitAll(t *testing.T, root string, message string) {
	t.Helper()
	runGit(t, root, "add", "--all")
	runGit(t, root, "commit", "--quiet", "-m", message)
}

func runGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	// #nosec G204 -- tests execute Git directly with controlled synthetic arguments.
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, stderr.String())
	}
	return stdout.String()
}

func containsFinding(findings []Finding, rule string, variant string) bool {
	for _, finding := range findings {
		if finding.Rule == rule && finding.SourceVariant == variant {
			return true
		}
	}
	return false
}

func containsInputVariant(inputs []ScannedInput, path string, variant string) bool {
	for _, input := range inputs {
		if input.Path == path && input.SourceVariant == variant {
			return true
		}
	}
	return false
}

func containsInputKind(inputs []ScannedInput, path string, variant string, kind string) bool {
	for _, input := range inputs {
		if input.Path == path && input.SourceVariant == variant && input.Kind == kind {
			return true
		}
	}
	return false
}

func containsGitlinkState(inputs []ScannedInput, state string) bool {
	for _, input := range inputs {
		if input.Kind == "gitlink" && input.GitlinkState == state {
			return true
		}
	}
	return false
}

func containsNestedVariant(inputs []ScannedInput) bool {
	for _, input := range inputs {
		if strings.HasPrefix(input.SourceVariant, "gitlink/") {
			return true
		}
	}
	return false
}

func countInputVariant(inputs []ScannedInput, variant string) int {
	count := 0
	for _, input := range inputs {
		if input.SourceVariant == variant {
			count++
		}
	}
	return count
}

func syntheticAnnotatedTag(target string, targetType string, annotation string) []byte {
	return []byte("object " + target + "\ntype " + targetType + "\ntag synthetic\ntagger Synthetic Contributor <contributor@example.test> 1700000000 +0000\n\n" + annotation + "\n")
}
