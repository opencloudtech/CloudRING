// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package identity

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func mustRuntime(t *testing.T, now time.Time, kid string, pub *rsa.PublicKey) *Runtime {
	t.Helper()
	return mustRuntimeWithKeys(t, now, []SigningKey{{KeyID: kid, Algorithm: "RS256", PublicKey: pub, ActiveFrom: now.Add(-time.Hour)}})
}

func mustRuntimeWithKeys(t *testing.T, now time.Time, keys []SigningKey) *Runtime {
	t.Helper()
	// #nosec G101 -- all endpoint strings and key IDs are synthetic test
	// metadata; this fixture contains no credential material.
	runtime, err := NewRuntime(RuntimeConfig{
		Issuer:                "https://id.cloudring.example",
		AuthorizationEndpoint: "https://id.cloudring.example/oauth2/authorize",
		TokenEndpoint:         "https://id.cloudring.example/oauth2/token",
		JWKSURI:               "https://id.cloudring.example/oauth2/jwks",
		Audience:              "cloudring-console",
		AuthorizedParty:       "cloudring-console",
		ExpectedJOSEType:      "JWT",
		JWTClassClaim:         "token_use",
		ExpectedJWTClass:      "id",
		AllowedAlgorithms:     []string{"RS256", "ES256"},
		RequiredClaims:        []string{"iss", "aud", "azp", "exp", "iat", "sub", "token_use", "groups", "platform_namespaces"},
		GroupsClaim:           "groups",
		NamespacesClaim:       "platform_namespaces",
		TokenMaxLifetime:      time.Hour,
		ClockSkew:             time.Minute,
		JWKSCacheTTL:          5 * time.Minute,
		RotationOverlap:       24 * time.Hour,
		Keys:                  keys,
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	return runtime
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func validClaims(runtime *Runtime, now time.Time) map[string]any {
	return map[string]any{
		"iss":                 runtime.config.Issuer,
		"aud":                 runtime.config.Audience,
		"azp":                 runtime.config.AuthorizedParty,
		"token_use":           runtime.config.ExpectedJWTClass,
		"exp":                 now.Add(10 * time.Minute).Unix(),
		"iat":                 now.Add(-time.Minute).Unix(),
		"sub":                 "admin@example.test",
		"groups":              []string{"platform:admins"},
		"platform_namespaces": []string{"platform-system"},
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func withClaim(claims map[string]any, key string, value any) map[string]any {
	copy := map[string]any{}
	for k, v := range claims {
		copy[k] = v
	}
	copy[key] = value
	return copy
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": kid}
	signingInput := encodeJSONSegment(t, header) + "." + encodeJSONSegment(t, claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signedHS256(t *testing.T, kid string, claims map[string]any, secret []byte) string {
	t.Helper()
	header := map[string]any{"typ": "JWT", "alg": "HS256", "kid": kid}
	signingInput := encodeJSONSegment(t, header) + "." + encodeJSONSegment(t, claims)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func unsignedJWT(t *testing.T, alg, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"typ": "JWT", "alg": alg, "kid": kid}
	return encodeJSONSegment(t, header) + "." + encodeJSONSegment(t, claims) + "."
}

func encodeJSONSegment(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}
