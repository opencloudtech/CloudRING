// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package iam

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/identity"
)

func TestOIDCAuthenticationVerifierUsesSignedSubjectNotRequestReference(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	runtime, err := identity.NewRuntime(identity.RuntimeConfig{
		Issuer:                "https://id.example.invalid",
		AuthorizationEndpoint: "https://id.example.invalid/authorize",
		TokenEndpoint:         strings.Join([]string{"https://id.example.invalid", "token"}, "/"),
		JWKSURI:               "https://id.example.invalid/jwks",
		Audience:              "cloudring-console",
		AuthorizedParty:       "cloudring-console",
		ExpectedJOSEType:      "JWT",
		JWTClassClaim:         "token_use",
		ExpectedJWTClass:      "id",
		AllowedAlgorithms:     []string{"RS256"},
		RequiredClaims:        []string{"iss", "aud", "azp", "exp", "iat", "sub", "token_use", "groups", "platform_namespaces"},
		GroupsClaim:           "groups",
		NamespacesClaim:       "platform_namespaces",
		TokenMaxLifetime:      time.Hour,
		ClockSkew:             time.Minute,
		JWKSCacheTTL:          time.Minute,
		RotationOverlap:       2 * time.Hour,
		Keys: []identity.SigningKey{{
			KeyID:      "main",
			Algorithm:  "RS256",
			PublicKey:  &privateKey.PublicKey,
			ActiveFrom: now.Add(-time.Hour),
		}},
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	nonce := "browser-nonce"
	compactJWT := signOIDCIDTokenForIAMTest(t, privateKey, now, nonce, "verified-subject")
	verifier, err := NewOIDCAuthenticationVerifier(runtime, OIDCProofFunc(func(context.Context) (OIDCProof, error) {
		return OIDCProof{
			IDToken: compactJWT,
			Nonce:   nonce,
			MFA:     MFAAssurance{Required: true, Satisfied: true, MethodClass: MFAMethodExternalIDP},
			Session: SessionAssurance{State: SessionStateFresh, MaxAgeSeconds: 3600},
		}, nil
	}))
	if err != nil {
		t.Fatalf("NewOIDCAuthenticationVerifier: %v", err)
	}

	policy := testPolicy(now)
	policy.authenticator = verifier
	policy.Principals["verified-subject"] = Principal{
		ID: "verified-subject",
		Memberships: []Membership{{
			OrgID: "org-a", TenantID: "tenant-a", ProjectID: "project-a", Role: RoleTenantAdmin,
		}},
	}
	matching := AuthorizationRequest{
		Subject: PrincipalRef{ID: "verified-subject"},
		Action:  ActionProjectRead,
		Target:  testTarget("org-a", "tenant-a", "project-a"),
		Context: RequestContext{CorrelationID: "oidc-matching-subject", Reason: "verified oidc subject"},
	}
	if decision := policy.Authorize(matching); !decision.Allowed {
		t.Fatalf("matching verified OIDC subject was denied: %#v", decision)
	}

	mismatched := matching
	mismatched.Subject.ID = "user-tenant-admin"
	mismatched.Context.CorrelationID = "oidc-mismatched-subject"
	decision := policy.Authorize(mismatched)
	if decision.Allowed || !errors.Is(decision.Err, ErrAuthentication) {
		t.Fatalf("requested subject replaced signed OIDC subject: %#v", decision)
	}
}

func signOIDCIDTokenForIAMTest(t *testing.T, key *rsa.PrivateKey, now time.Time, nonce, subject string) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": "main", "typ": "JWT"}
	claims := map[string]any{
		"iss":                 "https://id.example.invalid",
		"aud":                 "cloudring-console",
		"azp":                 "cloudring-console",
		"exp":                 now.Add(time.Hour).Unix(),
		"iat":                 now.Unix(),
		"sub":                 subject,
		"token_use":           "id",
		"groups":              []string{"tenant-admin"},
		"platform_namespaces": []string{"tenant-a-system"},
		"nonce":               nonce,
	}
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signingInput := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
