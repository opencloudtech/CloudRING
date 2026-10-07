// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package proofsignature

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSigningKeyRoundTripAndSignatureVerification(t *testing.T) {
	key, err := Generate("backup-proof-2026-01")
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	secret, err := MarshalSigningKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	parsed, err := ParseSigningKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	trustKey, err := parsed.TrustKey()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"apiVersion":"cloudring.io/v1alpha1","kind":"SyntheticProof","status":"verified"}`)
	envelope, err := Sign(payload, parsed)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(payload, envelope, []TrustKey{trustKey}); err != nil {
		t.Fatalf("verify signed payload: %v", err)
	}

	tampered := append([]byte(nil), payload...)
	tampered[len(tampered)-2] ^= 1
	if err := Verify(tampered, envelope, []TrustKey{trustKey}); err == nil {
		t.Fatal("tampered payload was accepted")
	}

	parsed.Destroy()
	if _, err := Sign(payload, parsed); err == nil {
		t.Fatal("destroyed key remained usable")
	}
}

func TestParseSigningKeyRejectsAmbiguousOrInvalidDocuments(t *testing.T) {
	key, err := Generate("backup-proof-2026-01")
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	valid, err := MarshalSigningKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(valid)

	cases := map[string][]byte{
		"unknown field": append(bytes.TrimSuffix(valid, []byte("}")), []byte(`,"unexpected":true}`)...),
		"trailing":      append(append([]byte(nil), valid...), []byte(` {}`)...),
		"duplicate":     []byte(`{"apiVersion":"cloudring.io/v1alpha1","apiVersion":"cloudring.io/v1alpha1","kind":"ProofSigningKey","keyId":"backup-proof-2026-01","algorithm":"Ed25519","privateKeySeed":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`),
		"bad key id":    []byte(`{"apiVersion":"cloudring.io/v1alpha1","kind":"ProofSigningKey","keyId":"../key","algorithm":"Ed25519","privateKeySeed":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`),
		"bad base64":    []byte(`{"apiVersion":"cloudring.io/v1alpha1","kind":"ProofSigningKey","keyId":"backup-proof-2026-01","algorithm":"Ed25519","privateKeySeed":"not-base64"}`),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if parsed, parseErr := ParseSigningKey(input); parseErr == nil {
				parsed.Destroy()
				t.Fatal("invalid signing key was accepted")
			}
		})
	}
}

func TestVerifyFailsClosedOnTrustPolicyProblems(t *testing.T) {
	key, err := Generate("backup-proof-2026-01")
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	payload := []byte(`{"status":"verified"}`)
	envelope, err := Sign(payload, key)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := key.TrustKey()
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(payload, envelope, nil); err == nil {
		t.Fatal("missing trust key was accepted")
	}
	if err := Verify(payload, envelope, []TrustKey{trusted, trusted}); err == nil {
		t.Fatal("duplicate trust key was accepted")
	}
	wrong, err := Generate("backup-proof-other")
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Destroy()
	wrongTrust, err := wrong.TrustKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(payload, envelope, []TrustKey{wrongTrust}); err == nil {
		t.Fatal("untrusted signing key was accepted")
	}

	encoded, err := json.Marshal(envelope)
	if err != nil || bytes.Contains(encoded, []byte("private")) {
		t.Fatal("signature envelope exposed private material")
	}
}
