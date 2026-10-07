// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package main

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestKeyGenerateSignVerifyRoundTrip(t *testing.T) {
	directory := t.TempDir()
	policyPath := filepath.Join(directory, "trust-policy.json")
	keyDocument := generateSecretThroughPipe(t, policyPath)
	defer clear(keyDocument)
	derivedPolicyPath := filepath.Join(directory, "derived-trust-policy.json")
	if err := runWithKeyInput(t, keyDocument, []string{
		"key", "public", "--trust-policy", derivedPolicyPath,
	}); err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	// #nosec G304 -- policyPath is a fixed basename below this test's t.TempDir().
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- derivedPolicyPath is a fixed basename below this test's t.TempDir().
	derivedPolicy, err := os.ReadFile(derivedPolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(policy) != string(derivedPolicy) {
		t.Fatal("derived trust policy differs from generated policy")
	}

	payloadPath := filepath.Join(directory, "proof.json")
	if err := os.WriteFile(payloadPath, []byte("{\n  \"kind\": \"SyntheticProof\",\n  \"status\": \"verified\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signaturePath := filepath.Join(directory, "signature.json")
	if err := runWithKeyInput(t, keyDocument, []string{
		"sign", "--payload", payloadPath, "--signature", signaturePath,
	}); err != nil {
		t.Fatalf("sign payload: %v", err)
	}
	if err := run([]string{
		"verify", "--payload", payloadPath, "--signature", signaturePath, "--trust-policy", policyPath,
	}); err != nil {
		t.Fatalf("verify payload: %v", err)
	}

	if err := runWithKeyInput(t, keyDocument, []string{
		"sign", "--payload", payloadPath, "--signature", signaturePath,
	}); err == nil {
		t.Fatal("signature output was overwritten")
	}
	if err := os.WriteFile(payloadPath, []byte(`{"kind":"SyntheticProof","status":"tampered"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"verify", "--payload", payloadPath, "--signature", signaturePath, "--trust-policy", policyPath,
	}); err == nil {
		t.Fatal("tampered proof payload was accepted")
	}
}

func TestSignRejectsRegularFileKeyDescriptor(t *testing.T) {
	directory := t.TempDir()
	policyPath := filepath.Join(directory, "trust-policy.json")
	keyDocument := generateSecretThroughPipe(t, policyPath)
	defer clear(keyDocument)
	secretPath := filepath.Join(directory, "test-only-key.json")
	if err := os.WriteFile(secretPath, keyDocument, 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- secretPath is a fixed basename below this test's t.TempDir().
	file, err := os.Open(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	payloadPath := filepath.Join(directory, "proof.json")
	if err := os.WriteFile(payloadPath, []byte(`{"status":"verified"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err = run([]string{
		"sign", "--payload", payloadPath, "--signature", filepath.Join(directory, "signature.json"),
		"--key-fd", strconv.Itoa(int(file.Fd())),
	})
	if err == nil {
		t.Fatal("regular file key descriptor was accepted")
	}
}

func generateSecretThroughPipe(t *testing.T, policyPath string) []byte {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	writerFD := int(writer.Fd())
	if err := run([]string{
		"key", "generate", "--key-id", "backup-proof-2026-01",
		"--secret-output-fd", strconv.Itoa(writerFD), "--trust-policy", policyPath,
	}); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		t.Fatalf("generate key: %v", err)
	}
	_ = writer.Close()
	secret, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return secret
}

func runWithKeyInput(t *testing.T, secret []byte, args []string) error {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(secret); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	args = append(args, "--key-fd", strconv.Itoa(int(reader.Fd())))
	runErr := run(args)
	_ = reader.Close()
	return runErr
}
