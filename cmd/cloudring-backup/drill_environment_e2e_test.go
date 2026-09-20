//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/backup/drill"
)

func TestDrillCLIExplicitEnvironmentTransport(t *testing.T) {
	directory := t.TempDir()
	cli := buildDrillExecutable(t, directory, "cloudring-backup", ".")
	adapter := buildDrillExecutable(t, directory, "adapter", "../../pkg/backup/drill/testdata/fakeadapter")
	selected := []string{
		"CLOUDRING_TEST_APPLICATION_KEY=synthetic-application-value-271828",
		"CLOUDRING_TEST_APPLICATION_SECRET=synthetic-application-secret-314159", // gitleaks:allow -- synthetic test-only value shared by the CLI and fake adapter.
		"CLOUDRING_TEST_CONSUMER_KEY=synthetic-consumer-value-161803",
	}
	for _, entry := range append(append([]string(nil), selected...), "CLOUDRING_TEST_UNSELECTED=unselected-must-not-leak", "AWS_SECRET_ACCESS_KEY=ambient-must-not-leak") {
		name, value, _ := strings.Cut(entry, "=")
		t.Setenv(name, value)
	}
	var optIn []string
	for _, entry := range selected {
		name, _, _ := strings.Cut(entry, "=")
		optIn = append(optIn, "--adapter-env", name)
	}

	t.Run("default-environment-is-still-scrubbed", func(t *testing.T) {
		plan, _ := drillCLIPlan(t, cli, adapter, "default-operation")
		approval := filepath.Join(t.TempDir(), "approval.json")
		if output, err := invokeDrillCLI(t, cli, "preflight", plan, adapter, "--approval", approval); err != nil {
			t.Fatalf("default preflight failed: %v: %s", err, output)
		}
	})
	t.Run("ambient-values-need-explicit-names", func(t *testing.T) {
		plan, _ := drillCLIPlan(t, cli, adapter, "environment-missing")
		approval := filepath.Join(t.TempDir(), "approval.json")
		output, err := invokeDrillCLI(t, cli, "preflight", plan, adapter, "--approval", approval)
		if err == nil {
			t.Fatal("unselected ambient values reached the adapter")
		}
		assertDrillCredentialsAbsent(t, output, selected)
		if _, err := os.Stat(approval); !os.IsNotExist(err) {
			t.Fatal("failed preflight created an approval")
		}
	})
	for _, mode := range []string{"complete", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			operation := "environment-complete"
			if mode == "rollback" {
				operation = "partial-environment-rollback"
			}
			planPath, _ := drillCLIPlan(t, cli, adapter, operation)
			artifacts := t.TempDir()
			approval := filepath.Join(artifacts, "approval.json")
			journal := filepath.Join(artifacts, "journal.jsonl")
			receipt := filepath.Join(artifacts, "receipt.json")
			output, err := invokeDrillCLI(t, cli, "preflight", planPath, adapter, append([]string{"--approval", approval}, optIn...)...)
			if err != nil {
				t.Fatalf("explicit preflight: %v: %s", err, output)
			}
			var report drill.ApprovalReport
			if err := readStrictJSON(approval, &report); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"--approval", approval, "--journal", journal, "--confirm", report.ApprovalTuple}, optIn...)
			output, err = invokeDrillCLI(t, cli, "apply", planPath, adapter, append(append([]string(nil), args...), "--receipt", receipt)...)
			assertDrillCredentialsAbsent(t, output, selected)
			if mode == "complete" {
				if err != nil {
					t.Fatalf("explicit apply: %v: %s", err, output)
				}
				// Reuse a valid journal prefix to model interruption before restore
				// validation, so recover must execute credential-consuming children.
				// #nosec G304 -- journal is a fixed filename beneath this test's private t.TempDir().
				payload, readErr := os.ReadFile(journal)
				if readErr != nil {
					t.Fatal(readErr)
				}
				lines := bytes.Split(bytes.TrimSpace(payload), []byte("\n"))
				if len(lines) < 7 {
					t.Fatal("completed drill journal is too short")
				}
				// #nosec G703 -- journal is a fixed test-owned t.TempDir path; the payload is a synthetic journal prefix.
				if writeErr := os.WriteFile(journal, append(bytes.Join(lines[:6], []byte("\n")), '\n'), 0o600); writeErr != nil {
					t.Fatal(writeErr)
				}
				output, err = invokeDrillCLI(t, cli, "recover", planPath, adapter, append(append([]string(nil), args...), "--receipt", filepath.Join(artifacts, "recovered.json"))...)
			} else {
				if err == nil {
					t.Fatal("partial fixture unexpectedly completed")
				}
				output, err = invokeDrillCLI(t, cli, "rollback", planPath, adapter, args...)
			}
			if err != nil {
				t.Fatalf("explicit %s: %v: %s", mode, err, output)
			}
			assertDrillCredentialsAbsent(t, output, selected)
			entries, err := os.ReadDir(artifacts)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				// #nosec G304 -- entry comes from the test-owned private artifact directory, containing only synthetic CLI outputs.
				payload, err := os.ReadFile(filepath.Join(artifacts, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				assertDrillCredentialsAbsent(t, payload, selected)
			}
		})
	}
	for _, operation := range []string{"environment-echo", "environment-echo-escaped"} {
		t.Run(operation, func(t *testing.T) {
			plan, _ := drillCLIPlan(t, cli, adapter, operation)
			approval := filepath.Join(t.TempDir(), "approval.json")
			output, err := invokeDrillCLI(t, cli, "preflight", plan, adapter, append([]string{"--approval", approval}, optIn...)...)
			if err == nil {
				t.Fatal("adapter response leaked selected value")
			}
			assertDrillCredentialsAbsent(t, output, selected)
			if _, err := os.Stat(approval); !os.IsNotExist(err) {
				t.Fatal("credential-bearing response produced an artifact")
			}
		})
	}
	for _, names := range [][]string{{"NAME=value"}, {"KUBECONFIG"}, {"LD_PRELOAD"}, {""}, {"CLOUDRING_TEST_APPLICATION_KEY", "CLOUDRING_TEST_APPLICATION_KEY"}, {"CLOUDRING_TEST_ABSENT"}} {
		t.Run("reject-"+strings.Join(names, "-"), func(t *testing.T) {
			plan, _ := drillCLIPlan(t, cli, adapter, "default-operation")
			approval := filepath.Join(t.TempDir(), "approval.json")
			args := []string{"--approval", approval}
			for _, name := range names {
				args = append(args, "--adapter-env", name)
			}
			output, err := invokeDrillCLI(t, cli, "preflight", plan, adapter, args...)
			if err == nil {
				t.Fatal("invalid environment selection accepted")
			}
			assertDrillCredentialsAbsent(t, output, selected)
		})
	}
}

func buildDrillExecutable(t *testing.T, directory, name, target string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	command := exec.Command("go", "build", "-o", path, target) // #nosec G204 -- test-only fixed Go packages and test-owned output path.
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v: %s", name, err, output)
	}
	return path
}

func drillCLIPlan(t *testing.T, cli, adapter, operation string) (string, drill.Plan) {
	t.Helper()
	var plan drill.Plan
	if err := readStrictJSON("../../contracts/backup-drill/fixtures/synthetic-plan.json", &plan); err != nil {
		t.Fatal(err)
	}
	plan.OperationID = operation
	now := time.Now().UTC()
	plan.IssuedAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
	plan.ExpiresAt = now.Add(9 * time.Minute).Format(time.RFC3339Nano)
	for path, identity := range map[string]*drill.ExecutableIdentity{cli: &plan.Tool, adapter: &plan.Adapter} {
		// #nosec G304 -- path is one of the two test-built executables in t.TempDir().
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(payload)
		identity.ExecutableSHA256 = hex.EncodeToString(sum[:])
	}
	payload, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, plan
}

func invokeDrillCLI(t *testing.T, cli, mode, plan, adapter string, extra ...string) ([]byte, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := writer.WriteString("apiVersion: v1\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"drill", mode, "--plan", plan, "--adapter", adapter, "--kubeconfig-fd", "3"}, extra...)
	command := exec.Command(cli, args...) // #nosec G204 -- test-built CLI and synthetic argv; no shell or real credentials.
	command.ExtraFiles = []*os.File{reader}
	return command.CombinedOutput()
}

func assertDrillCredentialsAbsent(t *testing.T, output []byte, environment []string) {
	t.Helper()
	for _, entry := range environment {
		name, value, _ := strings.Cut(entry, "=")
		if bytes.Contains(output, []byte(value)) || bytes.Contains(output, []byte(name)) {
			t.Fatal("transport environment leaked into output or artifact")
		}
	}
}
