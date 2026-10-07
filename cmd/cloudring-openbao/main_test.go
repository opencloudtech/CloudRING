// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/opencloudtech/CloudRING/internal/openbaoapply"
)

const validInput = `{
  "schemaVersion":"cloudring.openbao-kubernetes-auth-plan/v2",
  "authMount":"kubernetes-consumer-example",
  "authMountOwnership":"dedicated-create-owned",
  "kvV2Mount":"cloudring",
  "dataPrefix":"services/cloudring-consumer-example",
  "policyName":"cloudring-consumer-example-kv-read",
  "roleName":"cloudring-consumer-example",
  "workloadIdentity":{"namespace":"cloudring-consumer-example","serviceAccount":"cloudring-openbao-reader"},
  "audience":"openbao",
  "aliasNameSource":"serviceaccount_uid",
  "tokenTTL":"10m",
  "tokenMaxTTL":"30m",
  "tokenNoDefaultPolicy":true
}`

const validExecutorInput = `{
  "schemaVersion":"cloudring.openbao-kubernetes-auth-executor/v1",
  "contract":` + validInput + `,
  "executorIdentity":{"namespace":"cloudring-consumer-example","serviceAccount":"cloudring-openbao-bootstrap-executor"},
  "lease":{"namespace":"cloudring-consumer-example","name":"cloudring-openbao-exec-6434a933d18dc631c365fc81739ee121c36bd9ac"},
  "negativeIdentities":{
    "wrongServiceAccount":{"namespace":"cloudring-consumer-example","serviceAccount":"cloudring-openbao-reader-denied"},
    "wrongNamespace":{"namespace":"cloudring-consumer-negative-example","serviceAccount":"cloudring-openbao-reader"}
  }
}`

func TestRunPlansValidStdinContract(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"plan", "kubernetes-auth"}, strings.NewReader(validInput), &stdout, &stderr)
	if code != exitPlanned || !strings.Contains(stdout.String(), `"status":"planned"`) || stderr.Len() != 0 {
		t.Fatalf("run() code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "cloudring-consumer-example") {
		t.Fatalf("run() reflected contract identifiers: %q", stdout.String())
	}
}

func TestRunUsesStableExitSemantics(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		stdin  io.Reader
		stdout io.Writer
		want   int
	}{
		{"usage", nil, strings.NewReader(""), io.Discard, exitUsage},
		{"extra arg", []string{"plan", "kubernetes-auth", "file.json"}, strings.NewReader(validInput), io.Discard, exitUsage},
		{"apply invalid", []string{"apply", "kubernetes-auth"}, strings.NewReader(`{"wrappingTokenBase64":"do-not-reflect"}`), io.Discard, exitBlocked},
		{"supervise invalid", []string{"supervise", "kubernetes-auth"}, strings.NewReader(`{"rootCredentialBase64":"do-not-reflect"}`), io.Discard, exitBlocked},
		{"render invalid", []string{"render", "kubernetes-auth-executor"}, strings.NewReader(`{"unexpected":"do-not-reflect"}`), io.Discard, exitBlocked},
		{"blocked", []string{"plan", "kubernetes-auth"}, strings.NewReader(`{"unexpected":"do-not-reflect"}`), io.Discard, exitBlocked},
		{"input unavailable", []string{"plan", "kubernetes-auth"}, cliErrorReader{}, io.Discard, exitUsage},
		{"output unavailable", []string{"plan", "kubernetes-auth"}, strings.NewReader(validInput), cliErrorWriter{}, exitUsage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if got := run(test.args, test.stdin, test.stdout, &stderr); got != test.want {
				t.Fatalf("run() exit = %d, want %d, stderr=%q", got, test.want, stderr.String())
			}
			if strings.Contains(stderr.String(), "do-not-reflect") {
				t.Fatalf("stderr reflected input: %q", stderr.String())
			}
		})
	}
}

func TestRunRendersExactExecutorManifest(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"render", "kubernetes-auth-executor"}, strings.NewReader(validExecutorInput), &stdout, &stderr)
	if code != exitPlanned || stderr.Len() != 0 {
		t.Fatalf("run() code=%d stderr=%q", code, stderr.String())
	}
	want, err := os.ReadFile("../../deploy/kubernetes/secret-manager/consumer-example/bootstrap-executor.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), want) {
		t.Fatalf("render output does not match canonical manifest")
	}
}

func TestRunRenderDoesNotReflectInputAndHandlesOutputFailure(t *testing.T) {
	const rejected = `{"schemaVersion":"do-not-reflect","unexpected":true}`
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"render", "kubernetes-auth-executor"}, strings.NewReader(rejected), &stdout, &stderr); code != exitBlocked {
		t.Fatalf("invalid render exit=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "do-not-reflect") {
		t.Fatalf("render reflected rejected input: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"render", "kubernetes-auth-executor"}, strings.NewReader(validExecutorInput), cliErrorWriter{}, &stderr); code != exitUsage {
		t.Fatalf("failed render output exit=%d stderr=%q", code, stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"render", "kubernetes-auth-executor"}, strings.NewReader(validExecutorInput), shortWriter{}, &stderr); code != exitUsage {
		t.Fatalf("short render output exit=%d stderr=%q", code, stderr.String())
	}
}

func TestRunApplyDoesNotReflectInput(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"apply", "kubernetes-auth"}, strings.NewReader(`{"wrappingTokenBase64":"do-not-reflect"}`), &stdout, &stderr)
	if code != exitBlocked || !strings.Contains(stdout.String(), `"status":"blocked_preflight"`) {
		t.Fatalf("run() code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "do-not-reflect") {
		t.Fatalf("apply reflected input: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestApplyStdinAllowsPipeAndRejectsRegularFile(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if !applyStdinAllowed(reader) {
		t.Fatal("anonymous pipe was rejected")
	}
	regular, err := os.CreateTemp(t.TempDir(), "request")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if applyStdinAllowed(regular) {
		t.Fatal("regular request file was accepted")
	}
}

func TestEncodeApplyReportUsesManualInterventionExitAfterMutation(t *testing.T) {
	var stderr bytes.Buffer
	report := openbaoapply.Report{SchemaVersion: openbaoapply.SchemaVersion, Status: openbaoapply.StatusApplied, MutationPerformed: true}
	if code := encodeApplyReport(report, cliErrorWriter{}, &stderr); code != exitManualIntervention {
		t.Fatalf("encodeApplyReport()=%d stderr=%q", code, stderr.String())
	}
}

type cliErrorReader struct{}

func (cliErrorReader) Read([]byte) (int, error) { return 0, errors.New("sensitive reader detail") }

type cliErrorWriter struct{}

func (cliErrorWriter) Write([]byte) (int, error) { return 0, errors.New("sensitive writer detail") }

type shortWriter struct{}

func (shortWriter) Write(input []byte) (int, error) {
	if len(input) == 0 {
		return 0, nil
	}
	return 1, nil
}
