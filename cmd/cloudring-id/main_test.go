// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/identity"
)

func TestContractCommandEmitsIdentityRuntimeEvidence(t *testing.T) {
	evidencePath := filepath.Join(t.TempDir(), "cloudring-id-contract.json")
	stdout := captureStdout(t, func() {
		err := run([]string{
			"contract",
			"--issuer", "https://id.cloudring.example",
			"--audience", "cloudring-console",
			"--evidence", evidencePath,
		})
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	})
	if !strings.Contains(stdout, "CLOUDRING_ID_CONTRACT_JSON:") {
		t.Fatalf("stdout missing JSON marker: %s", stdout)
	}
	if !strings.Contains(stdout, "cloudring_id_contract_valid") {
		t.Fatalf("stdout missing contract-valid marker: %s", stdout)
	}
	// #nosec G304 -- the test reads an exact path created under t.TempDir.
	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	for _, want := range []string{
		`"status": "contract-valid"`,
		`"readinessClaimed": false`,
		`"syntheticOnly": true`,
		`"managementPanelHiddenUntilIamAllow": true`,
		`"forbiddenAlgorithmsRejected": true`,
		`"csrfRequiredForBrowserWrites": true`,
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("evidence missing %s: %s", want, data)
		}
	}
}

func TestContractCommandRejectsHTTPissuer(t *testing.T) {
	err := run([]string{
		"contract",
		"--issuer", "http://id.cloudring.example",
		"--audience", "cloudring-console",
	})
	if err == nil {
		t.Fatal("HTTP issuer should be rejected")
	}
}

func TestVerifyTokenCommandAcceptsAdminFixture(t *testing.T) {
	evidencePath := filepath.Join(t.TempDir(), "token.json")
	fixture := writeTokenFixture(t, nil, false)
	stdout := captureStdout(t, func() {
		err := run(verifyTokenArgs(fixture, evidencePath))
		if err != nil {
			t.Fatalf("run verify-token returned error: %v", err)
		}
	})
	if !strings.Contains(stdout, "cloudring_id_token_verified") {
		t.Fatalf("stdout missing verified marker: %s", stdout)
	}
	// #nosec G304 -- the test reads an exact path created under t.TempDir.
	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	for _, want := range []string{
		`"status": "allowed"`,
		`"issuerValidated": true`,
		`"audienceValidated": true`,
		`"subjectPresent": true`,
		`"groupCount": 1`,
		`"namespaceCount": 1`,
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("evidence missing %s: %s", want, data)
		}
	}
}

func TestVerifyTokenCommandFailsClosedForInvalidFixtures(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(map[string]any)
		malformed bool
	}{
		{name: "expired", mutate: func(claims map[string]any) { claims["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{name: "wrong-audience", mutate: func(claims map[string]any) { claims["aud"] = "other-audience" }},
		{name: "excessive-lifetime", mutate: func(claims map[string]any) {
			claims["iat"] = time.Now().Add(-48 * time.Hour).Unix()
			claims["exp"] = time.Now().Add(time.Hour).Unix()
		}},
		{name: "malformed", malformed: true},
	}
	for _, test := range cases {
		name := test.name
		t.Run(name, func(t *testing.T) {
			evidencePath := filepath.Join(t.TempDir(), name+".json")
			fixture := writeTokenFixture(t, test.mutate, test.malformed)
			err := run(verifyTokenArgs(fixture, evidencePath))
			if err == nil {
				t.Fatalf("%s should fail closed", name)
			}
			// #nosec G304 -- the test reads an exact path created under t.TempDir.
			data, readErr := os.ReadFile(evidencePath)
			if readErr != nil {
				t.Fatalf("read denial evidence: %v", readErr)
			}
			for _, want := range []string{
				`"status": "denied"`,
				`"code": "iam_token_rejected"`,
				`"owner": "platform-identity"`,
				`"impact": "The request is denied before any tenant, project, or provider surface is evaluated."`,
				`"nextAction": "Refresh the short-lived credential from the trusted OIDC issuer and retry."`,
			} {
				if !strings.Contains(string(data), want) {
					t.Fatalf("denial evidence missing %s: %s", want, data)
				}
			}
		})
	}
}

type tokenFixture struct {
	issuer    string
	audience  string
	jwksPath  string
	tokenPath string
}

func verifyTokenArgs(fixture tokenFixture, evidencePath string) []string {
	return []string{
		"verify-token",
		"--issuer", fixture.issuer,
		"--audience", fixture.audience,
		"--jwks", fixture.jwksPath,
		"--token-file", fixture.tokenPath,
		"--evidence", evidencePath,
	}
}

func writeTokenFixture(t *testing.T, mutate func(map[string]any), malformed bool) tokenFixture {
	t.Helper()
	directory := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	const keyID = "test-rs256"
	issuer := "https://id.cloudring.example"
	audience := "cloudring-console"
	jwks := identity.JWKS{Keys: []identity.JWK{{
		KTY: "RSA", Use: "sig", KID: keyID, Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}}
	jwksData, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	jwksPath := filepath.Join(directory, "jwks.json")
	if err := os.WriteFile(jwksPath, jwksData, 0o600); err != nil {
		t.Fatalf("write JWKS: %v", err)
	}
	now := time.Now().UTC()
	claims := map[string]any{
		"iss": issuer, "aud": audience,
		"azp": audience, "token_use": "id",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"sub": "admin@example.test", "groups": []string{"platform:admins"},
		"platform_namespaces": []string{"platform-system"},
	}
	if mutate != nil {
		mutate(claims)
	}
	compactJWT := "malformed"
	if !malformed {
		compactJWT = signRS256Token(t, key, keyID, claims)
	}
	tokenPath := filepath.Join(directory, "token.jwt")
	if err := os.WriteFile(tokenPath, []byte(compactJWT), 0o600); err != nil {
		t.Fatalf("write compact JWT fixture: %v", err)
	}
	return tokenFixture{issuer: issuer, audience: audience, jwksPath: jwksPath, tokenPath: tokenPath}
}

func signRS256Token(t *testing.T, key *rsa.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": keyID}
	signingInput := encodeJSONSegment(t, header) + "." + encodeJSONSegment(t, claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func encodeJSONSegment(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JWT segment: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func TestCaptureStdoutHandlesLargeOutput(t *testing.T) {
	const outputSize = 1 << 20
	want := strings.Repeat("x", outputSize)

	got := captureStdout(t, func() {
		written, err := os.Stdout.WriteString(want)
		if err != nil {
			t.Fatalf("write large stdout payload: %v", err)
		}
		if written != len(want) {
			t.Fatalf("write large stdout payload: wrote %d bytes, want %d", written, len(want))
		}
	})

	if got != want {
		t.Fatalf("captured stdout mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func TestCaptureStdoutRestoresStdoutAfterPanic(t *testing.T) {
	original := os.Stdout
	var recovered any

	func() {
		defer func() {
			recovered = recover()
		}()
		captureStdout(t, func() {
			panic("capture panic")
		})
	}()

	if recovered != "capture panic" {
		t.Fatalf("unexpected recovered panic: %v", recovered)
	}
	if os.Stdout != original {
		t.Fatal("captureStdout did not restore os.Stdout after panic")
	}
}

func captureStdout(t *testing.T, action func()) string {
	t.Helper()
	original := os.Stdout
	output, err := os.CreateTemp(t.TempDir(), "cloudring-id-stdout-*")
	if err != nil {
		t.Fatalf("create stdout capture file: %v", err)
	}
	os.Stdout = output
	defer func() {
		os.Stdout = original
		if output != nil {
			if err := output.Close(); err != nil {
				t.Errorf("close stdout capture file: %v", err)
			}
		}
	}()

	action()
	os.Stdout = original

	if _, err := output.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("rewind stdout capture file: %v", err)
	}
	data, err := io.ReadAll(output)
	if err != nil {
		t.Fatalf("read stdout capture file: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("close stdout capture file: %v", err)
	}
	output = nil
	return string(data)
}
