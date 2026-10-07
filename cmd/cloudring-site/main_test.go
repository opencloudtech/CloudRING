// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/kubeadm"
)

func TestCLIProducesReadyPreflightAndDeterministicPlan(t *testing.T) {
	root := filepath.Join("..", "..")
	profile := filepath.Join(root, "examples", "provider-site-profile.yaml")
	for _, command := range []string{"preflight", "plan"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{command, "--profile", profile}, nil, &stdout, &stderr); code != 0 {
			t.Fatalf("%s failed with code %d: %s", command, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"nonClaim": "preflight-and-plan-only"`) {
			t.Fatalf("%s output lacks non-claim: %s", command, stdout.String())
		}
	}
}

func TestCLIBlocksInvalidProfileWithoutEchoingInput(t *testing.T) {
	secretLikeCanary := "value-that-must-not-be-echoed"
	var stdout, stderr bytes.Buffer
	code := run([]string{"preflight", "--profile", "-"}, strings.NewReader("unknown: "+secretLikeCanary), &stdout, &stderr)
	if code != 1 || strings.Contains(stdout.String()+stderr.String(), secretLikeCanary) {
		t.Fatalf("invalid input was accepted or echoed: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestCLIBlocksSemanticInvalidNameWithoutEchoingInput(t *testing.T) {
	secretLikeCanary := "invalid_name"
	profile := strings.Replace(validCLIProfile(t), "name: synthetic-provider-site", "name: "+secretLikeCanary, 1)
	var stdout, stderr bytes.Buffer
	code := run([]string{"preflight", "--profile", "-"}, strings.NewReader(profile), &stdout, &stderr)
	if code != 1 || strings.Contains(stdout.String()+stderr.String(), secretLikeCanary) {
		t.Fatalf("semantic invalid input was accepted or echoed: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestCLIBlocksMissingProfile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	path := filepath.Join(t.TempDir(), "missing.yaml")
	if code := run([]string{"plan", "--profile", path}, nil, &stdout, &stderr); code != 1 {
		t.Fatalf("missing profile returned %d", code)
	}
}

func TestMainExampleExists(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "..", "examples", "provider-site-profile.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestCLIRendersKubeadmBundleDeterministically(t *testing.T) {
	specPath := examplePath("kubeadm-bootstrap-spec.json")
	var firstStdout, firstStderr bytes.Buffer
	if code := run([]string{"render-kubeadm", "--spec", specPath}, nil, &firstStdout, &firstStderr); code != exitSuccess {
		t.Fatalf("render-kubeadm failed with code %d: %s", code, firstStderr.String())
	}
	var secondStdout, secondStderr bytes.Buffer
	if code := run([]string{"render-kubeadm", "--spec", specPath}, nil, &secondStdout, &secondStderr); code != exitSuccess {
		t.Fatalf("second render-kubeadm failed with code %d: %s", code, secondStderr.String())
	}
	if firstStdout.String() != secondStdout.String() {
		t.Fatal("render-kubeadm output is not byte-deterministic")
	}
	var bundle kubeadm.BootstrapBundle
	if err := strictjson.DecodeExact(firstStdout.Bytes(), &bundle); err != nil {
		t.Fatalf("render-kubeadm returned an invalid bundle: %v", err)
	}
	for _, want := range []string{
		"controlPlaneEndpoint: api.synthetic.example:6443",
		"REDACTED_CERTIFICATE_KEY_SECRET_REF",
		"192.0.2.20",
		"2001:db8::20",
	} {
		if !strings.Contains(bundle.InitYAML, want) {
			t.Fatalf("rendered init config missing %q", want)
		}
	}
	if len(bundle.ControlPlaneJoinYAML) != 2 ||
		!strings.Contains(bundle.ControlPlaneJoinYAML[0].YAML, "apiServerEndpoint: api.synthetic.example:6443") ||
		!bundle.Cilium.DualStack {
		t.Fatalf("rendered bundle omitted HA join or Cilium state: %#v", bundle)
	}
}

func TestCLIVerifierRequiresIdentityBoundOneServerLossReceipt(t *testing.T) {
	inventoryPath := examplePath("kubeadm-stand-inventory.json")
	var absentStdout, absentStderr bytes.Buffer
	if code := run(
		[]string{"verify-kubeadm", "--inventory", inventoryPath},
		nil,
		&absentStdout,
		&absentStderr,
	); code != exitBlocked {
		t.Fatalf("missing one-server-loss receipt returned code %d: %s", code, absentStderr.String())
	}
	var absent kubeadm.StandReport
	if err := strictjson.DecodeExact(absentStdout.Bytes(), &absent); err != nil ||
		absent.Status != "blocked" || !hasBlocker(absent.Blockers, "missing_one_server_loss_evidence") {
		t.Fatalf("missing receipt did not fail closed with its blocker: err=%v report=%#v", err, absent)
	}

	receiptPath := semanticInvalidReceiptPath(t)
	var missingStdout, missingStderr bytes.Buffer
	if code := run(
		[]string{"verify-kubeadm", "--inventory", inventoryPath, "--one-server-loss-receipt", receiptPath},
		nil,
		&missingStdout,
		&missingStderr,
	); code != exitBlocked {
		t.Fatalf("unverified one-server-loss evidence returned code %d: %s", code, missingStderr.String())
	}
	var missing kubeadm.StandReport
	if err := strictjson.DecodeExact(missingStdout.Bytes(), &missing); err != nil || missing.Status != "blocked" {
		t.Fatalf("unverified receipt returned an invalid report: err=%v report=%#v", err, missing)
	}
	if !hasBlocker(missing.Blockers, "missing_one_server_loss_evidence") {
		t.Fatalf("unverified receipt omitted the evidence blocker: %#v", missing.Blockers)
	}

	blockedInput := strings.Replace(
		readExample(t, "kubeadm-stand-inventory.json"),
		`"controlPlaneAPIFailoverReady": true`,
		`"controlPlaneAPIFailoverReady": false`,
		1,
	)
	var blockedStdout, blockedStderr bytes.Buffer
	if code := run(
		[]string{"verify-kubeadm", "--inventory", "-", "--one-server-loss-receipt", receiptPath},
		strings.NewReader(blockedInput),
		&blockedStdout,
		&blockedStderr,
	); code != exitBlocked {
		t.Fatalf("blocked inventory returned code %d, want %d: %s", code, exitBlocked, blockedStderr.String())
	}
	var blocked kubeadm.StandReport
	if err := strictjson.DecodeExact(blockedStdout.Bytes(), &blocked); err != nil || blocked.Status != "blocked" {
		t.Fatalf("blocked inventory returned an invalid report: err=%v report=%#v", err, blocked)
	}
	if !hasBlocker(blocked.Blockers, "control_plane_api_failover_unverified") {
		t.Fatalf("blocked report omitted API failover blocker: %#v", blocked.Blockers)
	}
}

func TestCLIVerifierIgnoresCallerDeclaredSurviveCount(t *testing.T) {
	payload := strings.Replace(
		readExample(t, "kubeadm-stand-inventory.json"),
		`"oneServerLossReceipt":`,
		`"surviveUnavailableServers": 1, "oneServerLossReceipt":`,
		1,
	)
	var stdout, stderr bytes.Buffer
	if code := run(
		[]string{"verify-kubeadm", "--inventory", "-"},
		strings.NewReader(payload),
		&stdout,
		&stderr,
	); code != exitBlocked {
		t.Fatalf("caller-declared survive count returned code %d, want %d", code, exitBlocked)
	}
	var report kubeadm.StandReport
	if err := strictjson.DecodeExact(stdout.Bytes(), &report); err != nil ||
		report.VerifiedSurviveUnavailableServers != 0 || report.Observed.SurviveUnavailableServers != 0 ||
		!hasBlocker(report.Blockers, "missing_one_server_loss_evidence") {
		t.Fatalf("caller declaration influenced verified evidence: err=%v report=%#v stderr=%q", err, report, stderr.String())
	}
}

func TestCLIKubeadmInputsFailClosedWithoutEcho(t *testing.T) {
	canary := "must-not-be-echoed"
	tests := []struct {
		name    string
		command string
		flag    string
		payload string
	}{
		{
			name:    "duplicate field",
			command: "render-kubeadm",
			flag:    "--spec",
			payload: `{"clusterName":"` + canary + `","clusterName":"duplicate"}`,
		},
		{
			name:    "unknown field",
			command: "render-kubeadm",
			flag:    "--spec",
			payload: `{"clusterName":"` + canary + `","unknown":true}`,
		},
		{
			name:    "trailing document",
			command: "verify-kubeadm",
			flag:    "--inventory",
			payload: `{"distribution":"` + canary + `"} {}`,
		},
		{
			name:    "oversized document",
			command: "render-kubeadm",
			flag:    "--spec",
			payload: strings.Repeat(canary, strictjson.MaxDocumentBytes/len(canary)+2),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := []string{test.command, test.flag, "-"}
			if test.command == "verify-kubeadm" {
				args = append(args, "--one-server-loss-receipt", semanticInvalidReceiptPath(t))
			}
			code := run(
				args,
				strings.NewReader(test.payload),
				&stdout,
				&stderr,
			)
			if code != exitFailure {
				t.Fatalf("invalid input returned code %d, want %d", code, exitFailure)
			}
			if strings.Contains(stdout.String()+stderr.String(), canary) {
				t.Fatalf("invalid input was echoed: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func semanticInvalidReceiptPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func hasBlocker(blockers []kubeadm.Blocker, id string) bool {
	for _, blocker := range blockers {
		if blocker.ID == id {
			return true
		}
	}
	return false
}

func TestCLIKubeadmSemanticValidationBlocksUnsafeContracts(t *testing.T) {
	valid := strings.ReplaceAll(
		readExample(t, "kubeadm-bootstrap-spec.json"),
		"\r\n",
		"\n",
	)
	tests := []struct {
		name    string
		payload string
	}{
		{
			name: "node-bound endpoint",
			payload: strings.ReplaceAll(
				valid,
				"api.synthetic.example:6443",
				"192.0.2.11:6443",
			),
		},
		{
			name: "missing IPv6 SAN",
			payload: strings.Replace(
				valid,
				"    \"2001:db8::20\"\n  ],",
				"    \"192.0.2.21\"\n  ],",
				1,
			),
		},
		{
			name: "unsafe certificate rollout",
			payload: strings.Replace(
				valid,
				`"rolloutStrategy": "one-node-at-a-time"`,
				`"rolloutStrategy": "parallel"`,
				1,
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(
				[]string{"render-kubeadm", "--spec", "-"},
				strings.NewReader(test.payload),
				&stdout,
				&stderr,
			); code != exitFailure {
				t.Fatalf("unsafe contract returned code %d, want %d", code, exitFailure)
			}
			if stdout.Len() != 0 {
				t.Fatalf("unsafe contract emitted a bundle: %s", stdout.String())
			}
		})
	}
}

func TestCLIUsesDistinctUsageAndBlockedExitCodes(t *testing.T) {
	var usageStdout, usageStderr bytes.Buffer
	if code := run([]string{"unknown"}, nil, &usageStdout, &usageStderr); code != exitUsage {
		t.Fatalf("unknown command returned code %d, want %d", code, exitUsage)
	}
	if exitBlocked == exitUsage || exitBlocked == exitFailure {
		t.Fatal("blocked, usage, and invalid-input exit codes must be distinct")
	}
}

func validCLIProfile(t *testing.T) string {
	t.Helper()
	// #nosec G304 -- the test reads the repository-owned example at a fixed relative path.
	payload, err := os.ReadFile(filepath.Join("..", "..", "examples", "provider-site-profile.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func examplePath(name string) string {
	return filepath.Join("..", "..", "examples", name)
}

func readExample(t *testing.T, name string) string {
	t.Helper()
	// #nosec G304 -- tests select repository-owned examples by fixed names.
	payload, err := os.ReadFile(examplePath(name))
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
