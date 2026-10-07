// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package identity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestVerifierAcceptsRS256WithRequiredClaims(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	key := mustRSAKey(t)
	runtime := mustRuntime(t, now, "main", &key.PublicKey)
	jwtValue := signRS256(t, key, "main", validClaims(runtime, now))

	claims, err := runtime.VerifyJWT(jwtValue, now)
	if err != nil {
		t.Fatalf("VerifyJWT returned error: %v", err)
	}
	if claims.Subject != "admin@example.test" {
		t.Fatalf("unexpected subject: %q", claims.Subject)
	}
}

func TestRejectForbiddenJWTAlgorithms(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	key := mustRSAKey(t)
	runtime := mustRuntime(t, now, "main", &key.PublicKey)
	baseClaims := validClaims(runtime, now)

	for name, jwtValue := range map[string]string{
		"none":  unsignedJWT(t, "none", "main", baseClaims),
		"HS256": signedHS256(t, "main", baseClaims, []byte("not-a-production-secret")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runtime.VerifyJWT(jwtValue, now); err == nil {
				t.Fatalf("%s token should be rejected", name)
			}
		})
	}
}

func TestJWTNegativeSecuritySuite(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	key := mustRSAKey(t)
	otherKey := mustRSAKey(t)
	runtime := mustRuntime(t, now, "main", &key.PublicKey)
	validClaims := validClaims(runtime, now)
	without := func(claim string) map[string]any {
		copy := map[string]any{}
		for key, value := range validClaims {
			copy[key] = value
		}
		delete(copy, claim)
		return copy
	}

	cases := map[string]string{
		"wrong issuer":            signRS256(t, key, "main", withClaim(validClaims, "iss", "https://wrong.example")),
		"wrong audience":          signRS256(t, key, "main", withClaim(validClaims, "aud", "other-audience")),
		"wrong authorized party":  signRS256(t, key, "main", withClaim(validClaims, "azp", "other-client")),
		"wrong jwt class":         signRS256(t, key, "main", withClaim(validClaims, "token_use", "access")),
		"ambiguous audiences":     signRS256(t, key, "main", withClaim(withClaim(validClaims, "aud", []string{"cloudring-console", "other-audience"}), "azp", "other-client")),
		"expired JWT":             signRS256(t, key, "main", withClaim(validClaims, "exp", now.Add(-time.Minute).Unix())),
		"inverted lifetime":       signRS256(t, key, "main", withClaim(withClaim(validClaims, "iat", now.Add(5*time.Minute).Unix()), "exp", now.Add(time.Minute).Unix())),
		"future not-before":       signRS256(t, key, "main", withClaim(validClaims, "nbf", now.Add(5*time.Minute).Unix())),
		"unknown kid":             signRS256(t, key, "missing", validClaims),
		"invalid signature":       signRS256(t, otherKey, "main", validClaims),
		"missing required claims": signRS256(t, key, "main", without("groups")),
	}
	for name, jwtValue := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := runtime.VerifyJWT(jwtValue, now); err == nil {
				t.Fatalf("%s should be rejected", name)
			}
		})
	}
}

func TestJWTRejectsAmbiguousOrOversizedInput(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	key := mustRSAKey(t)
	runtime := mustRuntime(t, now, "main", &key.PublicKey)
	claims, err := json.Marshal(validClaims(runtime, now))
	if err != nil {
		t.Fatalf("Marshal claims: %v", err)
	}
	duplicateClaims := append([]byte{}, claims[:len(claims)-1]...)
	duplicateClaims = append(duplicateClaims, []byte(`,"iss":"https://duplicate.example"}`)...)

	cases := map[string]string{
		"duplicate header": base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","alg":"none","kid":"main","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims) + ".ignored",
		"duplicate claim":  signRS256Raw(t, key, []byte(`{"alg":"RS256","kid":"main","typ":"JWT"}`), duplicateClaims),
		"critical header":  signRS256Raw(t, key, []byte(`{"alg":"RS256","kid":"main","typ":"JWT","crit":["custom"]}`), claims),
		"wrong jose type":  signRS256Raw(t, key, []byte(`{"alg":"RS256","kid":"main","typ":"at+jwt"}`), claims),
		"oversized jwt":    string(make([]byte, maxCompactJWTBytes+1)),
	}
	for name, compactJWT := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := runtime.VerifyJWT(compactJWT, now); err == nil {
				t.Fatalf("%s should be rejected", name)
			}
		})
	}
}

func signRS256Raw(t *testing.T, key *rsa.PrivateKey, header, claims []byte) string {
	t.Helper()
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15 raw JWT: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
