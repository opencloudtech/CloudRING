// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/safepush"
)

func TestPendingIsTheOnlyRetriableAdmissionResult(t *testing.T) {
	for _, terminal := range []error{nil, safepush.ErrCheckNotSuccessful, safepush.ErrPolicy, errors.New("unavailable")} {
		calls := 0
		err := waitForChecks(context.Background(), time.Nanosecond, func() error {
			calls++
			if calls == 1 {
				return safepush.ErrGitHubPending
			}
			return terminal
		})
		if calls != 2 || !errors.Is(err, terminal) {
			t.Fatalf("calls=%d error=%v", calls, err)
		}
	}
}

func TestCancellationStopsPendingAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := waitForChecks(ctx, time.Hour, func() error { calls++; cancel(); return safepush.ErrGitHubPending })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("calls=%d error=%v", calls, err)
	}
}

func TestSuccessAfterCancellationIsNotAccepted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	err := waitForChecks(ctx, time.Nanosecond, func() error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("late success was accepted: %v", err)
	}
}

func TestCommandDoesNotEchoSensitiveProviderErrors(t *testing.T) {
	args := []string{"github", "--repository", "synthetic/project", "--pr", "1", "--head", strings.Repeat("a", 40), "--base", strings.Repeat("b", 40), "--branch", "main"}
	marker := "synthetic-confidential-marker"
	read := func(context.Context, *http.Client, string, string, string) (safepush.GitHubPolicy, error) {
		return safepush.GitHubPolicy{Repository: "synthetic/project"}, nil
	}
	for _, failure := range []error{nil, errors.New(marker)} {
		var out, errout bytes.Buffer
		code := run(context.Background(), args, func(string) string { return marker }, &out, &errout, read,
			func(context.Context, *http.Client, string, safepush.GitHubPolicy, safepush.GitHubCandidate) error {
				return failure
			})
		if (code == 0) != (failure == nil) {
			t.Fatalf("unexpected exit %d", code)
		}
		if strings.Contains(out.String()+errout.String(), marker) {
			t.Fatal("provider error leaked sensitive input")
		}
	}
}

func TestInvalidInvocationMakesNoProviderCall(t *testing.T) {
	for _, args := range [][]string{
		{}, {"github", "--trusted=true"},
		{"github", "--repository", "synthetic/project", "--pr", "1", "--head", "a", "--base", "b", "--branch", "feature"},
		{"github", "--repository", "synthetic/project", "--pr", "1", "--head", "a", "--base", "b", "--branch", "main", "--timeout", "31m"},
		{"github", "--repository", "synthetic/project", "--pr", "1", "--head", "a", "--base", "main", "--branch", "main"},
		{"github", "--repository", "synthetic/../project", "--pr", "1", "--head", strings.Repeat("a", 40), "--base", strings.Repeat("b", 40), "--branch", "main"},
		{"github", "--repository", "synthetic/project", "--pr", "1", "--head", strings.Repeat("0", 40), "--base", strings.Repeat("b", 40), "--branch", "main"},
	} {
		var out bytes.Buffer
		read := func(context.Context, *http.Client, string, string, string) (safepush.GitHubPolicy, error) {
			t.Fatal("provider called for invalid request")
			return safepush.GitHubPolicy{}, nil
		}
		if code := run(context.Background(), args, func(string) string { return "synthetic-test-value" }, &out, &out, read, nil); code != 2 {
			t.Fatalf("exit=%d", code)
		}
	}
}
