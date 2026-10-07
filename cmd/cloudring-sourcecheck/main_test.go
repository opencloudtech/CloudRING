// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencloudtech/CloudRING/internal/sourcecheck"
)

func TestRun_returns_blocked_exit_and_sanitized_report(t *testing.T) {
	root := cliRepository(t)
	sensitiveValue := "g" + "hp_" + strings.Repeat("f", 24)
	if err := os.WriteFile(filepath.Join(root, "unsafe.txt"), []byte(sensitiveValue), 0o600); err != nil {
		t.Fatalf("write unsafe fixture: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"scan", "--root", root, "--scope", "full", "--format", "json"}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("exit code = %d, stderr=%s", exitCode, stderr.String())
	}
	var report sourcecheck.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, stdout.String())
	}
	if report.Passed || len(report.Findings) == 0 {
		t.Fatalf("expected blocked report: %+v", report)
	}
	if strings.Contains(stdout.String(), sensitiveValue) || strings.Contains(stderr.String(), sensitiveValue) {
		t.Fatal("CLI output exposed matched credential")
	}
}

func TestRun_approves_safe_repository(t *testing.T) {
	root := cliRepository(t)
	if err := os.WriteFile(filepath.Join(root, "safe.txt"), []byte("synthetic public content\n"), 0o600); err != nil {
		t.Fatalf("write safe fixture: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"scan", "--root", root, "--scope", "full"}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr=%s, stdout=%s", exitCode, stderr.String(), stdout.String())
	}
}

func TestRun_summary_is_compact_and_detailed_report_is_opt_in(t *testing.T) {
	root := cliRepository(t)
	if err := os.WriteFile(filepath.Join(root, "safe.txt"), []byte("synthetic public content\n"), 0o600); err != nil {
		t.Fatalf("write safe fixture: %v", err)
	}
	reportPath := filepath.Join(t.TempDir(), "sourcecheck-report.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"scan", "--root", root, "--scope", "full", "--report", reportPath}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "sourceVariant") || strings.Contains(stdout.String(), `"findings":[`) || len(stdout.Bytes()) > 256 {
		t.Fatalf("default summary is not compact: %s", stdout.String())
	}
	// #nosec G304 -- the report path is constructed beneath a fresh t.TempDir.
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read detailed report: %v", err)
	}
	var report sourcecheck.Report
	if err := json.Unmarshal(data, &report); err != nil || len(report.ScannedInputs) == 0 {
		t.Fatalf("opt-in detailed report is invalid: err=%v report=%+v", err, report)
	}
	stdout.Reset()
	stderr.Reset()
	if exitCode := run([]string{"scan", "--root", root, "--report", reportPath}, strings.NewReader(""), &stdout, &stderr); exitCode != 2 {
		t.Fatalf("existing report path was overwritten or accepted: exit=%d", exitCode)
	}
}

func TestRun_pre_push_hook_reads_every_update_and_does_not_emit_remote_secret(t *testing.T) {
	root := cliRepository(t)
	cliGit(t, root, "config", "user.name", "Synthetic Contributor")
	cliGit(t, root, "config", "user.email", "synthetic-contributor@example.test")
	if err := os.WriteFile(filepath.Join(root, "config.txt"), []byte("safe\n"), 0o600); err != nil {
		t.Fatalf("write base: %v", err)
	}
	cliGit(t, root, "add", "--all")
	cliGit(t, root, "commit", "--quiet", "-m", "base")
	base := strings.TrimSpace(cliGit(t, root, "rev-parse", "HEAD"))
	sensitiveValue := "g" + "hp_" + strings.Repeat("u", 24)
	if err := os.WriteFile(filepath.Join(root, "config.txt"), []byte(sensitiveValue), 0o600); err != nil {
		t.Fatalf("write unsafe head: %v", err)
	}
	cliGit(t, root, "add", "--all")
	cliGit(t, root, "commit", "--quiet", "-m", "unsafe")
	head := strings.TrimSpace(cliGit(t, root, "rev-parse", "HEAD"))
	zero := strings.Repeat("0", 40)
	bare := filepath.Join(t.TempDir(), "origin.git")
	cliGit(t, filepath.Dir(bare), "init", "--quiet", "--bare", bare)
	cliGit(t, root, "remote", "add", "origin", bare)
	cliGit(t, root, "push", "--quiet", "origin", base+":refs/heads/main")
	updates := strings.Join([]string{
		"(delete) " + zero + " refs/heads/old " + base,
		"refs/heads/feature " + head + " refs/heads/feature " + zero,
	}, "\n") + "\n"

	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("enter hook repository: %v", err)
	}
	defer func() {
		if err := os.Chdir(previous); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	}()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"pre-push-hook", "origin"}, strings.NewReader(bare+"\x00"+updates), &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("hook exit code = %d, stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), sensitiveValue) || strings.Contains(stderr.String(), sensitiveValue) {
		t.Fatal("hook output exposed secret input")
	}
}

func TestParsePrePushHook_preserves_all_updates_and_rejects_args(t *testing.T) {
	oidA := strings.Repeat("a", 40)
	oidB := strings.Repeat("b", 64)
	input := "HEAD " + oidA + " refs/heads/a " + strings.Repeat("0", 40) + "\n" +
		"refs/heads/b " + oidB + " refs/heads/b " + strings.Repeat("0", 64) + "\n"
	options, err := parsePrePushHook([]string{"pre-push-hook", "origin"}, strings.NewReader("https://example.test/repository\x00"+input))
	if err != nil {
		t.Fatalf("parse hook updates: %v", err)
	}
	if options.RemoteName != "origin" || len(options.RemoteURLSHA256) != 64 || options.PushUpdates == nil || len(options.PushUpdates) != 2 {
		t.Fatalf("hook did not preserve every update: %+v", options.PushUpdates)
	}
	if options.PushUpdates[0].LocalRef != "HEAD" {
		t.Fatalf("hook did not accept Git's symbolic HEAD source: %+v", options.PushUpdates[0])
	}
	for _, invalidLocalRef := range []string{"head", "FETCH_HEAD", "HEAD~1", "-HEAD"} {
		invalidInput := invalidLocalRef + " " + oidA + " refs/heads/a " + strings.Repeat("0", 40) + "\n"
		if _, err := parsePrePushHook([]string{"pre-push-hook", "origin"}, strings.NewReader("https://example.test/repository\x00"+invalidInput)); err == nil {
			t.Fatalf("hook accepted unsupported local ref %q", invalidLocalRef)
		}
	}
	remoteSecret := "https://user:" + "pass" + "word@example.test/repository"
	if _, err := parsePrePushHook([]string{"pre-push-hook", "origin", remoteSecret}, strings.NewReader("")); err == nil || strings.Contains(err.Error(), remoteSecret) {
		t.Fatalf("hook args were accepted or leaked: %v", err)
	}
	if _, err := parsePrePushHook([]string{"pre-push-hook", "--upload-pack=unsafe"}, strings.NewReader("")); err == nil {
		t.Fatal("option-like remote name was accepted")
	}
}

func TestParseArgs_validates_scope_and_canonical_allowances(t *testing.T) {
	if _, err := parseArgs([]string{"scan", "--scope", "unknown"}); err == nil {
		t.Fatal("expected unknown scope to fail")
	}
	if _, err := parseArgs([]string{"scan", "--allow-non-text", "asset.bin=short"}); err == nil {
		t.Fatal("expected malformed non-text allowance to fail")
	}
	options, err := parseArgs([]string{
		"scan", "--scope", "files", "--file", "asset.bin",
		"--allow-non-text", "asset.bin=" + strings.Repeat("a", 64), "--recurse-gitlinks",
	})
	if err != nil {
		t.Fatalf("parse valid arguments: %v", err)
	}
	if options.Scope != sourcecheck.ScopeFiles || len(options.NonTextAllowances) != 1 || options.NonTextAllowances[0].Path != "asset.bin" || !options.RecurseGitlinks {
		t.Fatalf("unexpected options: %+v", options)
	}
	multipleRevisions, err := parseArgs([]string{
		"scan", "--allow-non-text", "assets/./x.bin=" + strings.Repeat("a", 64),
		"--allow-non-text", `assets\x.bin=` + strings.Repeat("b", 64),
	})
	if err != nil || len(multipleRevisions.NonTextAllowances) != 2 {
		t.Fatalf("multiple reviewed revisions for one canonical path were rejected: err=%v options=%+v", err, multipleRevisions)
	}
	if _, err := parseArgs([]string{
		"scan", "--allow-non-text", "assets/./x.bin=" + strings.Repeat("a", 64),
		"--allow-non-text", `assets\x.bin=` + strings.Repeat("a", 64),
	}); err == nil {
		t.Fatal("duplicate canonical path and digest allowance was not rejected by CLI")
	}
	remoteOptions, err := parseArgs([]string{
		"scan", "--scope", "pre-push", "--base", strings.Repeat("0", 40),
		"--remote-name", "origin", "--remote-url-sha256", strings.Repeat("c", 64), "--remote-ref", "refs/heads/main",
	})
	if err != nil || remoteOptions.RemoteName != "origin" || len(remoteOptions.RemoteRefs) != 1 {
		t.Fatalf("verified target-remote options were not preserved: err=%v options=%+v", err, remoteOptions)
	}
	if _, err := parseArgs([]string{"scan", "--scope", "pre-push", "--remote-ref", "refs/heads/main"}); err == nil {
		t.Fatal("unverified target-remote ref option was accepted")
	}
}

func cliRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	cliGit(t, root, "init", "--quiet")
	return root
}

func cliGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	// #nosec G204 -- tests execute Git directly with controlled temporary arguments.
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
	return string(output)
}
