// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/safepush"
)

type githubVerifier func(context.Context, *http.Client, string, safepush.GitHubPolicy, safepush.GitHubCandidate) error
type githubPolicyReader func(context.Context, *http.Client, string, string, string) (safepush.GitHubPolicy, error)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr, safepush.ReadGitHubPolicy, safepush.VerifyGitHub))
}

// The native required workflow owns these arguments. There is deliberately no
// caller-supplied check-results file, success flag, API host, or policy override.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer, read githubPolicyReader, verify githubVerifier) int {
	if len(args) == 0 || args[0] != "github" {
		fmt.Fprintln(stderr, "usage: cloudring-safepush github --repository OWNER/REPO --pr NUMBER --head SHA --base SHA --branch main|master")
		return 2
	}
	flags := flag.NewFlagSet("github", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	repository := flags.String("repository", "", "target GitHub repository")
	pr := flags.Int("pr", 0, "pull request number")
	head := flags.String("head", "", "exact proposed commit")
	base := flags.String("base", "", "exact accepted target commit")
	branch := flags.String("branch", "", "protected target branch")
	timeout := flags.Duration("timeout", 20*time.Minute, "bounded wait for native CI, at most 30 minutes")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *repository == "" || *pr <= 0 ||
		*head == "" || *base == "" || (*branch != "main" && *branch != "master") ||
		*timeout <= 0 || *timeout > 30*time.Minute {
		fmt.Fprintln(stderr, "SafePush request is invalid")
		return 2
	}
	candidate := safepush.GitHubCandidate{PullRequest: *pr, HeadSHA: *head, BaseSHA: *base, TargetBranch: *branch}
	if safepush.ValidateGitHubCandidate(*repository, candidate) != nil {
		fmt.Fprintln(stderr, "SafePush request is invalid")
		return 2
	}
	bearer := getenv("GITHUB_TOKEN")
	if bearer == "" {
		fmt.Fprintln(stderr, "SafePush requires the workflow's read-only GITHUB_TOKEN")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second}
	policy, err := read(ctx, client, bearer, *repository, *base)
	if err != nil {
		fmt.Fprintln(stderr, "SafePush blocked:", safeDiagnostic(err))
		return 1
	}
	if policy.Repository != *repository {
		fmt.Fprintln(stderr, "SafePush blocked: accepted policy belongs to another repository")
		return 1
	}
	err = waitForChecks(ctx, 30*time.Second, func() error { return verify(ctx, client, bearer, policy, candidate) })
	if err != nil {
		fmt.Fprintln(stderr, "SafePush blocked:", safeDiagnostic(err))
		return 1
	}
	if _, err := fmt.Fprintln(stdout, "SafePush: the exact required CI checks passed for the current candidate and base"); err != nil {
		return 1
	}
	return 0
}

func safeDiagnostic(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "request canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "verification deadline exceeded"
	case errors.Is(err, safepush.ErrPolicy):
		return "accepted repository policy is invalid"
	case errors.Is(err, safepush.ErrGitHubAPI):
		return "GitHub API is unavailable or returned an invalid response"
	case errors.Is(err, safepush.ErrGitHubSource):
		return "workflow or policy source does not match the accepted revision"
	case errors.Is(err, safepush.ErrGitHubState):
		return "pull request or protected target is stale or changed during verification"
	case errors.Is(err, safepush.ErrGitHubRun):
		return "CI run, job, or step provenance is invalid"
	case errors.Is(err, safepush.ErrMissingCheck):
		return "a required CI job is missing"
	case errors.Is(err, safepush.ErrUnexpectedCheck), errors.Is(err, safepush.ErrDuplicateObservation):
		return "the CI job set is unexpected or ambiguous"
	case errors.Is(err, safepush.ErrCheckNotSuccessful):
		return "a required CI job did not complete successfully"
	default:
		return "verification failed"
	}
}

func waitForChecks(ctx context.Context, interval time.Duration, verify func() error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := verify()
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		if !errors.Is(err, safepush.ErrGitHubPending) {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
