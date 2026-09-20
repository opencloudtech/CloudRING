// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"time"
)

// RunCLI is the public `cloudring dev` entry point. All diagnostic messages
// are constructed by the installer; credential inputs and API bodies stay out.
func RunCLI(ctx context.Context, args []string, input io.Reader, output, diagnostics io.Writer) int {
	if len(args) == 0 || args[0] != "dev" {
		_, _ = fmt.Fprintln(diagnostics, "usage: cloudring dev validate|create|status|diagnose|reset|destroy --profile FILE [--state DIRECTORY]")
		return 2
	}
	args = args[1:]
	if len(args) == 1 && args[0] == "guest-bootstrap" {
		if err := BootstrapGuest(ctx, input, output); err != nil {
			_, _ = fmt.Fprintln(diagnostics, "cloudring_guest_bootstrap status=BLOCKED")
			return 1
		}
		return 0
	}
	if len(args) == 0 || !slices.Contains([]string{"validate", "create", "status", "diagnose", "reset", "destroy"}, args[0]) {
		_, _ = fmt.Fprintln(diagnostics, "cloudring_dev status=BLOCKED reason=unsupported_command")
		return 2
	}
	command := args[0]
	flags := flag.NewFlagSet("cloudring dev "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profilePath := flags.String("profile", "", "explicit immutable development profile")
	statePath := flags.String("state", "", "one private installation state directory")
	timeout := flags.Duration("timeout", 45*time.Minute, "bounded operation timeout")
	connect := flags.Bool("connect", false, "keep the owned HTTPS loopback connection in the foreground")
	offline := flags.Bool("offline", false, "validate only the public profile and deterministic plan")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *profilePath == "" || command != "validate" && *statePath == "" ||
		*timeout < time.Second || *timeout > 2*time.Hour || *offline && command != "validate" || *connect && command != "create" && command != "status" && command != "reset" {
		_, _ = fmt.Fprintln(diagnostics, "cloudring_dev status=BLOCKED reason=invalid_arguments")
		return 2
	}
	file, err := os.Open(*profilePath)
	if err != nil {
		_, _ = fmt.Fprintln(diagnostics, "cloudring_dev status=BLOCKED reason=profile_unavailable")
		return 2
	}
	profile, err := Parse(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		_, _ = fmt.Fprintln(diagnostics, "cloudring_dev status=BLOCKED reason=invalid_development_profile")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	plan, _ := BuildPlan(profile)
	if command == "validate" && *offline {
		if json.NewEncoder(output).Encode(plan) != nil {
			return 1
		}
		return 0
	}
	if standard, ok := input.(*os.File); ok {
		if info, err := standard.Stat(); err != nil || info.Mode()&os.ModeCharDevice != 0 {
			_, _ = fmt.Fprintln(diagnostics, "cloudring_dev status=BLOCKED reason=inline_kubeconfig_stdin_required")
			return 2
		}
	}
	client, err := NewClient(input, profile)
	if err != nil {
		_, _ = fmt.Fprintln(diagnostics, "cloudring_dev status=BLOCKED reason=invalid_inline_kubeconfig")
		return 2
	}
	defer client.Close()
	if command == "validate" {
		prerequisites, err := client.CheckPrerequisites(ctx)
		if err != nil {
			return cliFailure(err, diagnostics)
		}
		if json.NewEncoder(output).Encode(struct {
			Plan          Plan          `json:"plan"`
			Prerequisites Prerequisites `json:"prerequisites"`
		}{plan, prerequisites}) != nil {
			return 1
		}
		return 0
	}
	store, err := OpenState(*statePath, profile, command == "create")
	if errors.Is(err, ErrNotFound) && command == "destroy" {
		// No journal means no ownership evidence. A retry makes no change,
		// and deliberately does not invent a second zero-residue receipt.
		if json.NewEncoder(output).Encode(Report{APIVersion: "cloudring.development-report/v1", InstallationID: profile.InstallationID, Profile: Development,
			ObservedAt: time.Now().UTC(), Phase: "absent", TargetClusterUID: profile.Target.KubeSystemUID, PublicOrigin: profile.Network.PublicOrigin,
			Objects: []Object{}, Checks: []Check{{Name: "local-state-absent-no-action", Passed: true}}}) != nil {
			return 1
		}
		return 0
	}
	if err != nil {
		return cliFailure(err, diagnostics)
	}
	engine := &Engine{Client: client, Store: store, Progress: diagnostics}
	defer func() { _ = engine.Store.Close() }()
	var report Report
	switch command {
	case "create":
		report, err = engine.Create(ctx)
	case "status":
		report, err = engine.Status(ctx)
	case "diagnose":
		report, err = engine.Diagnose(ctx)
	case "reset":
		report, err = engine.Reset(ctx)
	case "destroy":
		report, err = engine.Destroy(ctx)
	}
	if report.InstallationID != "" {
		if encodeErr := json.NewEncoder(output).Encode(report); encodeErr != nil {
			return 1
		}
	}
	if err != nil {
		return cliFailure(err, diagnostics)
	}
	if *connect {
		if err := engine.Connect(ctx); err != nil {
			return cliFailure(err, diagnostics)
		}
	}
	return 0
}

func cliFailure(err error, output io.Writer) int {
	code := "operation_failed"
	switch {
	case errors.Is(err, context.Canceled):
		code = "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		code = "timeout"
	case errors.Is(err, ErrConflict):
		code = "ownership_conflict"
	case errors.Is(err, ErrNotFound):
		code = "installation_absent"
	case errors.Is(err, ErrCredentials):
		code = "invalid_credentials"
	}
	// Errors reaching this boundary contain installer-authored explanations;
	// transport code discards API bodies and remote command output first.
	message := err.Error()
	if len(message) > 512 {
		message = "development operation failed"
	}
	_ = json.NewEncoder(output).Encode(map[string]string{"event": "cloudring_dev", "status": "BLOCKED", "reason": code, "message": message})
	if code == "cancelled" {
		return 130
	}
	return 1
}
