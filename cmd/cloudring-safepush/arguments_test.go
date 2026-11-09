// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/safepush"
)

// validInvocation is a complete, well-formed request; extra flags override it.
func validInvocation(extra ...string) []string {
	return append([]string{"github", "--repository", "synthetic/project", "--pr", "1",
		"--head", strings.Repeat("a", 40), "--base", strings.Repeat("b", 40), "--branch", "main"}, extra...)
}

func TestEachInvalidArgumentAloneMakesNoProviderCall(t *testing.T) {
	for _, extra := range [][]string{
		{"extra"}, {"--unknown"}, {"--repository="}, {"--pr=0"}, {"--pr=-1"}, {"--head="}, {"--base="},
		{"--branch=develop"}, {"--branch="}, {"--timeout=0s"}, {"--timeout=-1s"}, {"--timeout=30m1ns"}, {"--timeout=31m"},
	} {
		var out, errOut bytes.Buffer
		read := func(context.Context, *http.Client, string, string, string) (safepush.GitHubPolicy, error) {
			t.Errorf("%v: provider called for an invalid request", extra)
			return safepush.GitHubPolicy{}, nil
		}
		code := run(context.Background(), validInvocation(extra...), func(string) string { return "synthetic-test-value" }, &out, &errOut, read, nil)
		if code != 2 || out.Len() != 0 || errOut.String() != "SafePush request is invalid\n" {
			t.Fatalf("%v: exit=%d out=%q err=%q", extra, code, &out, &errOut)
		}
	}
}

func TestCommandAdmitsBothProtectedBranchesAndTheTimeoutBound(t *testing.T) {
	for _, tc := range []struct {
		extra  []string
		branch string
	}{
		{nil, "main"},
		{[]string{"--branch=master"}, "master"},
		{[]string{"--timeout=30m"}, "main"},
	} {
		var out, errOut bytes.Buffer
		var clientTimeout time.Duration
		var verified safepush.GitHubCandidate
		read := func(_ context.Context, client *http.Client, _, repository, base string) (safepush.GitHubPolicy, error) {
			clientTimeout = client.Timeout
			if repository != "synthetic/project" || base != strings.Repeat("b", 40) {
				t.Errorf("policy read for %s at %s", repository, base)
			}
			return safepush.GitHubPolicy{Repository: repository}, nil
		}
		verify := func(_ context.Context, _ *http.Client, _ string, _ safepush.GitHubPolicy, candidate safepush.GitHubCandidate) error {
			verified = candidate
			return nil
		}
		code := run(context.Background(), validInvocation(tc.extra...), func(string) string { return "synthetic-test-value" }, &out, &errOut, read, verify)
		if code != 0 || errOut.Len() != 0 || !strings.HasPrefix(out.String(), "SafePush: the exact required CI checks passed") {
			t.Fatalf("%v: exit=%d out=%q err=%q", tc.extra, code, &out, &errOut)
		}
		want := safepush.GitHubCandidate{PullRequest: 1, HeadSHA: strings.Repeat("a", 40), BaseSHA: strings.Repeat("b", 40), TargetBranch: tc.branch}
		if verified != want || clientTimeout != 30*time.Second {
			t.Fatalf("%v: verified %+v with client timeout %s", tc.extra, verified, clientTimeout)
		}
	}
}

// A pending result is retried no sooner than the 30 s poll interval: within a
// one-second deadline the provider is asked exactly once.
func TestPendingAdmissionIsNotPolledBeforeTheInterval(t *testing.T) {
	var out, errOut bytes.Buffer
	calls := 0
	read := func(_ context.Context, _ *http.Client, _, repository, _ string) (safepush.GitHubPolicy, error) {
		return safepush.GitHubPolicy{Repository: repository}, nil
	}
	verify := func(context.Context, *http.Client, string, safepush.GitHubPolicy, safepush.GitHubCandidate) error {
		calls++
		return safepush.ErrGitHubPending
	}
	code := run(context.Background(), validInvocation("--timeout=1s"), func(string) string { return "synthetic-test-value" }, &out, &errOut, read, verify)
	if code != 1 || calls != 1 || errOut.String() != "SafePush blocked: verification deadline exceeded\n" {
		t.Fatalf("exit=%d calls=%d err=%q", code, calls, &errOut)
	}
}
