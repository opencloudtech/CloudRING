// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/opencloudtech/CloudRING/internal/openbaoapply"
	"github.com/opencloudtech/CloudRING/pkg/openbaoauth"
	"github.com/opencloudtech/CloudRING/pkg/openbaoexecutor"
)

const (
	exitPlanned            = 0
	exitUsage              = 1
	exitBlocked            = 2
	exitRolledBack         = 3
	exitManualIntervention = 4
)

func main() {
	if len(os.Args) == 3 && (os.Args[1] == "apply" || os.Args[1] == "supervise") && os.Args[2] == "kubernetes-auth" {
		if !applyStdinAllowed(os.Stdin) {
			fmt.Fprintln(os.Stderr, "OpenBao stateful operation requires an anonymous or named pipe on stdin")
			os.Exit(exitUsage)
		}
	}
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 2 && args[0] == "apply" && args[1] == "kubernetes-auth" {
		return runApply(context.Background(), stdin, stdout, stderr)
	}
	if len(args) == 2 && args[0] == "supervise" && args[1] == "kubernetes-auth" {
		return runSupervise(context.Background(), stdin, stdout, stderr)
	}
	if len(args) == 2 && args[0] == "render" && args[1] == "kubernetes-auth-executor" {
		return runRenderExecutor(stdin, stdout, stderr)
	}
	if len(args) != 2 || args[0] != "plan" || args[1] != "kubernetes-auth" {
		fmt.Fprintln(stderr, "usage: cloudring-openbao plan kubernetes-auth < contract.json | cloudring-openbao render kubernetes-auth-executor < profile.json | cloudring-openbao apply kubernetes-auth < protected-pipe | cloudring-openbao supervise kubernetes-auth < protected-pipe")
		return exitUsage
	}
	report, err := openbaoauth.Evaluate(stdin)
	if err != nil {
		fmt.Fprintln(stderr, "OpenBao plan input unavailable")
		return exitUsage
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(stderr, "encode OpenBao plan report")
		return exitUsage
	}
	if report.Status != "planned" {
		fmt.Fprintln(stderr, "OpenBao Kubernetes auth plan blocked")
		return exitBlocked
	}
	return exitPlanned
}

func runRenderExecutor(stdin io.Reader, stdout, stderr io.Writer) int {
	profile, problems, err := openbaoexecutor.Decode(stdin)
	if err != nil {
		fmt.Fprintln(stderr, "OpenBao executor profile input unavailable")
		return exitUsage
	}
	if len(problems) != 0 {
		fmt.Fprintln(stderr, "OpenBao Kubernetes auth executor profile blocked")
		return exitBlocked
	}
	manifest, err := openbaoexecutor.Render(profile)
	if err != nil {
		fmt.Fprintln(stderr, "OpenBao Kubernetes auth executor profile blocked")
		return exitBlocked
	}
	written, err := stdout.Write(manifest)
	if err != nil || written != len(manifest) {
		fmt.Fprintln(stderr, "encode OpenBao executor manifest")
		return exitUsage
	}
	return exitPlanned
}

func runSupervise(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) int {
	report, err := openbaoapply.Supervise(ctx, stdin)
	if err != nil {
		fmt.Fprintln(stderr, "OpenBao supervisor input unavailable")
		return exitUsage
	}
	return encodeApplyReport(report, stdout, stderr)
}

func runApply(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) int {
	report, err := openbaoapply.Apply(ctx, stdin)
	if err != nil {
		fmt.Fprintln(stderr, "OpenBao apply input unavailable")
		return exitUsage
	}
	return encodeApplyReport(report, stdout, stderr)
}

func encodeApplyReport(report openbaoapply.Report, stdout, stderr io.Writer) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		if report.MutationPerformed || report.Status != openbaoapply.StatusBlockedPreflight {
			fmt.Fprintln(stderr, "OpenBao apply result unavailable after a stateful operation")
			return exitManualIntervention
		}
		fmt.Fprintln(stderr, "encode blocked OpenBao apply report")
		return exitUsage
	}
	switch report.Status {
	case openbaoapply.StatusApplied:
		return exitPlanned
	case openbaoapply.StatusBlockedPreflight:
		fmt.Fprintln(stderr, "OpenBao Kubernetes auth apply blocked")
		return exitBlocked
	case openbaoapply.StatusRolledBack:
		fmt.Fprintln(stderr, "OpenBao Kubernetes auth apply rolled back")
		return exitRolledBack
	default:
		fmt.Fprintln(stderr, "OpenBao Kubernetes auth apply requires manual intervention")
		return exitManualIntervention
	}
}

func applyStdinAllowed(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}
	mode := info.Mode()
	return mode&os.ModeNamedPipe != 0 || mode&os.ModeSocket != 0
}
