// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
	"time"
)

func TestOIDCDiscoveryAndJWKS(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	activeKey := mustRSAKey(t)
	overlapKey := mustRSAKey(t)
	outsideOverlapKey := mustRSAKey(t)
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
		Keys: []SigningKey{
			{KeyID: "active-rs256", Algorithm: "RS256", PublicKey: &activeKey.PublicKey, ActiveFrom: now.Add(-time.Hour)},
			{KeyID: "overlap-rs256", Algorithm: "RS256", PublicKey: &overlapKey.PublicKey, ActiveFrom: now.Add(-25 * time.Hour), ActiveUntil: now.Add(-time.Hour)},
			{KeyID: "outside-overlap-rs256", Algorithm: "RS256", PublicKey: &outsideOverlapKey.PublicKey, ActiveFrom: now.Add(-72 * time.Hour), ActiveUntil: now.Add(-25 * time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}

	discovery := runtime.Discovery()
	if discovery.Issuer != "https://id.cloudring.example" {
		t.Fatalf("unexpected issuer: %q", discovery.Issuer)
	}
	if discovery.JWKSURI != "https://id.cloudring.example/oauth2/jwks" {
		t.Fatalf("unexpected jwks uri: %q", discovery.JWKSURI)
	}
	if !contains(discovery.IDTokenSigningAlgValuesSupported, "RS256") || contains(discovery.IDTokenSigningAlgValuesSupported, "HS256") {
		t.Fatalf("unexpected signing algorithms: %#v", discovery.IDTokenSigningAlgValuesSupported)
	}

	jwks := runtime.JWKS(now)
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected active plus expired-overlap keys, got %d", len(jwks.Keys))
	}
	if !jwksContainsKID(jwks, "overlap-rs256") {
		t.Fatalf("expired key within rotation overlap must remain published: %#v", jwks.Keys)
	}
	if jwksContainsKID(jwks, "outside-overlap-rs256") {
		t.Fatalf("key outside rotation overlap must be hidden: %#v", jwks.Keys)
	}
	if err := runtime.ValidateDiscovery(discovery); err != nil {
		t.Fatalf("discovery should match runtime: %v", err)
	}
	mismatched := discovery
	mismatched.Issuer = "https://wrong.example"
	if err := runtime.ValidateDiscovery(mismatched); err == nil {
		t.Fatal("discovery mismatch should fail closed")
	}
}

func TestSigningKeyRotationOverlap_publishesAndVerifiesExpiredKeysWithinOverlap(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	activeKey := mustRSAKey(t)
	overlapKey := mustRSAKey(t)
	outsideOverlapKey := mustRSAKey(t)
	runtime := mustRuntimeWithKeys(t, now, []SigningKey{
		{KeyID: "active-rs256", Algorithm: "RS256", PublicKey: &activeKey.PublicKey, ActiveFrom: now.Add(-time.Hour)},
		{KeyID: "overlap-rs256", Algorithm: "RS256", PublicKey: &overlapKey.PublicKey, ActiveFrom: now.Add(-25 * time.Hour), ActiveUntil: now.Add(-5 * time.Minute)},
		{KeyID: "outside-overlap-rs256", Algorithm: "RS256", PublicKey: &outsideOverlapKey.PublicKey, ActiveFrom: now.Add(-72 * time.Hour), ActiveUntil: now.Add(-25 * time.Hour)},
	})
	claims := validClaims(runtime, now)
	claims["iat"] = now.Add(-10 * time.Minute).Unix()

	jwks := runtime.JWKS(now)
	if !jwksContainsKID(jwks, "overlap-rs256") {
		t.Fatalf("expired key inside overlap should remain in JWKS: %#v", jwks.Keys)
	}
	if jwksContainsKID(jwks, "outside-overlap-rs256") {
		t.Fatalf("expired key outside overlap should not remain in JWKS: %#v", jwks.Keys)
	}
	if _, err := runtime.VerifyJWT(signRS256(t, overlapKey, "overlap-rs256", claims), now); err != nil {
		t.Fatalf("token signed by expired key inside overlap should verify: %v", err)
	}
	if _, err := runtime.VerifyJWT(signRS256(t, overlapKey, "overlap-rs256", validClaims(runtime, now)), now); err == nil {
		t.Fatal("token newly issued by an expired overlap key should be rejected")
	}
	if _, err := runtime.VerifyJWT(signRS256(t, outsideOverlapKey, "outside-overlap-rs256", claims), now); err == nil {
		t.Fatal("token signed by expired key outside overlap should be rejected")
	}
}

func TestSigningKeyRejectsJWTIssuedBeforeActivation(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	key := mustRSAKey(t)
	runtime := mustRuntimeWithKeys(t, now, []SigningKey{{
		KeyID: "new-rs256", Algorithm: "RS256", PublicKey: &key.PublicKey, ActiveFrom: now.Add(-5 * time.Minute),
	}})
	claims := validClaims(runtime, now)
	claims["iat"] = now.Add(-10 * time.Minute).Unix()
	if _, err := runtime.VerifyJWT(signRS256(t, key, "new-rs256", claims), now); err == nil {
		t.Fatal("jwt issued before key activation should be rejected")
	}
}

func TestSigningKeyIsPrepublishedForCachedClientBeforeActivation(t *testing.T) {
	activation := time.Unix(1710000000, 0).UTC()
	key := mustRSAKey(t)
	runtime := mustRuntimeWithKeys(t, activation, []SigningKey{{
		KeyID: "successor-rs256", Algorithm: "RS256", PublicKey: &key.PublicKey, ActiveFrom: activation,
	}})

	beforePublication := runtime.JWKS(activation.Add(-runtime.config.JWKSCacheTTL - time.Nanosecond))
	if jwksContainsKID(beforePublication, "successor-rs256") {
		t.Fatal("successor key was published before its cache prepublication window")
	}
	cachedBeforeActivation := runtime.JWKS(activation.Add(-runtime.config.JWKSCacheTTL))
	if !jwksContainsKID(cachedBeforeActivation, "successor-rs256") {
		t.Fatal("successor key was not available for a full JWKS cache TTL before activation")
	}

	claims := validClaims(runtime, activation)
	claims["iat"] = activation.Unix()
	compactJWT := signRS256(t, key, "successor-rs256", claims)
	if !jwksContainsKID(cachedBeforeActivation, "successor-rs256") {
		t.Fatal("cached client cannot resolve the key at activation")
	}
	if _, err := runtime.VerifyJWT(compactJWT, activation); err != nil {
		t.Fatalf("token issued at activation should verify with the prepublished key: %v", err)
	}

	preactivationClaims := validClaims(runtime, activation)
	preactivationClaims["iat"] = activation.Add(-time.Second).Unix()
	if _, err := runtime.VerifyJWT(signRS256(t, key, "successor-rs256", preactivationClaims), activation); err == nil {
		t.Fatal("prepublished key accepted a token issued before activation")
	}
}

func TestSigningWindowAndTokenLifetimeDoNotSpendClockSkewTwice(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	key := mustRSAKey(t)
	runtime := mustRuntimeWithKeys(t, now, []SigningKey{{
		KeyID: "bounded", Algorithm: "RS256", PublicKey: &key.PublicKey,
		ActiveFrom: now.Add(-time.Hour), ActiveUntil: now,
	}})

	issuedAtRetirement := validClaims(runtime, now)
	issuedAtRetirement["iat"] = now.Unix()
	compactRetirement := signRS256(t, key, "bounded", issuedAtRetirement)
	if _, err := runtime.VerifyJWT(compactRetirement, now); err == nil {
		t.Fatal("key accepted a token issued at its exclusive retirement boundary")
	}

	overlong := validClaims(runtime, now.Add(-time.Second))
	overlong["iat"] = now.Add(-time.Second).Unix()
	overlong["exp"] = now.Add(-time.Second).Add(runtime.config.TokenMaxLifetime + time.Second).Unix()
	compactOverlong := signRS256(t, key, "bounded", overlong)
	if _, err := runtime.VerifyJWT(compactOverlong, now); err == nil {
		t.Fatal("token lifetime consumed verification clock skew as extra lifetime")
	}
}

func TestRuntimeRejectsWeakAmbiguousOrInvalidSigningKeys(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	strong := mustRSAKey(t)
	// #nosec G403 -- a deliberately weak key is required to prove rejection.
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey(1024): %v", err)
	}
	base := []SigningKey{{KeyID: "main", Algorithm: "RS256", PublicKey: &strong.PublicKey, ActiveFrom: now.Add(-time.Hour)}}
	tests := []struct {
		name string
		keys []SigningKey
	}{
		{name: "duplicate kid", keys: append(append([]SigningKey{}, base...), SigningKey{KeyID: "main", Algorithm: "RS256", PublicKey: &strong.PublicKey})},
		{name: "weak rsa", keys: []SigningKey{{KeyID: "weak", Algorithm: "RS256", PublicKey: &weak.PublicKey}}},
		{name: "unsafe exponent", keys: []SigningKey{{KeyID: "exponent", Algorithm: "RS256", PublicKey: &rsa.PublicKey{N: new(big.Int).Set(strong.N), E: 3}}}},
		{name: "invalid window", keys: []SigningKey{{KeyID: "window", Algorithm: "RS256", PublicKey: &strong.PublicKey, ActiveFrom: now, ActiveUntil: now}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewRuntime(runtimeConfigForTest(test.keys)); err == nil {
				t.Fatalf("NewRuntime accepted %s", test.name)
			}
		})
	}
}

func TestRuntimeCopiesCallerOwnedPublicKeys(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	key := mustRSAKey(t)
	runtime := mustRuntime(t, now, "main", &key.PublicKey)
	compactJWT := signRS256(t, key, "main", validClaims(runtime, now))
	key.PublicKey.N.SetInt64(3)
	key.PublicKey.E = 3
	if _, err := runtime.VerifyJWT(compactJWT, now); err != nil {
		t.Fatalf("runtime retained caller-owned mutable key: %v", err)
	}
}

func TestRuntimeRejectsUnsafeRotationAndCacheDurations(t *testing.T) {
	key := mustRSAKey(t)
	base := runtimeConfigForTest([]SigningKey{{KeyID: "main", Algorithm: "RS256", PublicKey: &key.PublicKey}})
	tests := []struct {
		name   string
		mutate func(*RuntimeConfig)
	}{
		{name: "overlap shorter than jwt lifetime", mutate: func(config *RuntimeConfig) { config.RotationOverlap = 30 * time.Minute }},
		{name: "overlap missing verification skew", mutate: func(config *RuntimeConfig) { config.RotationOverlap = config.TokenMaxLifetime }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)
			if _, err := NewRuntime(config); err == nil {
				t.Fatalf("NewRuntime accepted %s", test.name)
			}
		})
	}
}

func TestValidateOIDCDiscoveryAcceptsSafeProviderSupersets(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	key := mustRSAKey(t)
	runtime := mustRuntime(t, now, "main", &key.PublicKey)
	discovery := runtime.Discovery()
	discovery.ResponseTypesSupported = append(discovery.ResponseTypesSupported, "code id_token")
	discovery.SubjectTypesSupported = append(discovery.SubjectTypesSupported, "pairwise")
	discovery.IDTokenSigningAlgValuesSupported = append(discovery.IDTokenSigningAlgValuesSupported, "PS256")
	discovery.TokenEndpointAuthMethodsSupported = append(discovery.TokenEndpointAuthMethodsSupported, "none")
	discovery.ClaimsSupported = append(discovery.ClaimsSupported, "email")
	discovery.CodeChallengeMethodsSupported = append(discovery.CodeChallengeMethodsSupported, "plain")
	discovery.CloudRINGManagementPanelIAMGate = "external-provider-does-not-publish-this-policy"

	if err := runtime.ValidateOIDCDiscovery(discovery); err != nil {
		t.Fatalf("ValidateOIDCDiscovery rejected a safe provider superset: %v", err)
	}
	externalMinimal := cloneDiscoveryForTest(discovery)
	externalMinimal.SubjectTypesSupported = []string{"pairwise"}
	externalMinimal.ClaimsSupported = nil
	if err := runtime.ValidateOIDCDiscovery(externalMinimal); err != nil {
		t.Fatalf("ValidateOIDCDiscovery rejected optional claims or pairwise subjects: %v", err)
	}
	if err := runtime.ValidateCloudRINGDiscoveryPolicy(discovery); err == nil {
		t.Fatal("CloudRING policy validator accepted a changed extension")
	}
}

func TestValidateOIDCDiscoveryRequiresConsumedSecuritySubset(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	key := mustRSAKey(t)
	runtime := mustRuntime(t, now, "main", &key.PublicKey)
	discovery := runtime.Discovery()
	tests := []struct {
		name   string
		mutate func(*DiscoveryMetadata)
	}{
		{name: "missing configured algorithm", mutate: func(value *DiscoveryMetadata) { value.IDTokenSigningAlgValuesSupported = []string{"PS256"} }},
		{name: "duplicate algorithm", mutate: func(value *DiscoveryMetadata) { value.IDTokenSigningAlgValuesSupported = []string{"RS256", "RS256"} }},
		{name: "duplicate optional claim", mutate: func(value *DiscoveryMetadata) {
			value.ClaimsSupported = append(value.ClaimsSupported, value.ClaimsSupported[0])
		}},
		{name: "missing code", mutate: func(value *DiscoveryMetadata) { value.ResponseTypesSupported = []string{"id_token"} }},
		{name: "pkce downgrade", mutate: func(value *DiscoveryMetadata) { value.CodeChallengeMethodsSupported = nil }},
		{name: "subject type downgrade", mutate: func(value *DiscoveryMetadata) { value.SubjectTypesSupported = []string{"unsupported"} }},
		{name: "token auth downgrade", mutate: func(value *DiscoveryMetadata) { value.TokenEndpointAuthMethodsSupported = []string{"tls_client_auth"} }},
		{name: "endpoint mismatch", mutate: func(value *DiscoveryMetadata) { value.TokenEndpoint = "https://wrong.example/token" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneDiscoveryForTest(discovery)
			test.mutate(&candidate)
			if err := runtime.ValidateOIDCDiscovery(candidate); err == nil {
				t.Fatalf("ValidateOIDCDiscovery accepted %s", test.name)
			}
		})
	}
}

func TestValidateCloudRINGDiscoveryPolicyIsSeparateAndFailClosed(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	key := mustRSAKey(t)
	runtime := mustRuntime(t, now, "main", &key.PublicKey)
	discovery := runtime.Discovery()
	tests := []struct {
		name   string
		mutate func(*DiscoveryMetadata)
	}{
		{name: "cache ttl", mutate: func(value *DiscoveryMetadata) { value.CloudRINGJWKSCacheTTLSeconds++ }},
		{name: "rotation overlap", mutate: func(value *DiscoveryMetadata) { value.CloudRINGJWKSRotationOverlapSeconds++ }},
		{name: "management gate", mutate: func(value *DiscoveryMetadata) { value.CloudRINGManagementPanelIAMGate = "allow" }},
		{name: "bootstrap policy", mutate: func(value *DiscoveryMetadata) { value.CloudRINGBootstrapAdminSecretPolicy = "plaintext" }},
		{name: "csrf policy", mutate: func(value *DiscoveryMetadata) { value.CloudRINGBrowserWriteCSRFRequirement = "optional" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneDiscoveryForTest(discovery)
			test.mutate(&candidate)
			if err := runtime.ValidateOIDCDiscovery(candidate); err != nil {
				t.Fatalf("standard validator consumed CloudRING extension %s: %v", test.name, err)
			}
			if err := runtime.ValidateCloudRINGDiscoveryPolicy(candidate); err == nil {
				t.Fatalf("CloudRING policy validator accepted %s", test.name)
			}
			if err := runtime.ValidateDiscovery(candidate); err == nil {
				t.Fatalf("compatibility validator accepted %s", test.name)
			}
		})
	}
}

func cloneDiscoveryForTest(value DiscoveryMetadata) DiscoveryMetadata {
	value.ResponseTypesSupported = append([]string{}, value.ResponseTypesSupported...)
	value.SubjectTypesSupported = append([]string{}, value.SubjectTypesSupported...)
	value.IDTokenSigningAlgValuesSupported = append([]string{}, value.IDTokenSigningAlgValuesSupported...)
	value.TokenEndpointAuthMethodsSupported = append([]string{}, value.TokenEndpointAuthMethodsSupported...)
	value.ClaimsSupported = append([]string{}, value.ClaimsSupported...)
	value.CodeChallengeMethodsSupported = append([]string{}, value.CodeChallengeMethodsSupported...)
	return value
}

func runtimeConfigForTest(keys []SigningKey) RuntimeConfig {
	// #nosec G101 -- all endpoint strings and key IDs are synthetic test
	// metadata; this fixture contains no credential material.
	return RuntimeConfig{
		Issuer: "https://id.cloudring.example", AuthorizationEndpoint: "https://id.cloudring.example/oauth2/authorize",
		TokenEndpoint: "https://id.cloudring.example/oauth2/token", JWKSURI: "https://id.cloudring.example/oauth2/jwks",
		Audience: "cloudring-console", AuthorizedParty: "cloudring-console", ExpectedJOSEType: "JWT", JWTClassClaim: "token_use", ExpectedJWTClass: "id",
		AllowedAlgorithms: []string{"RS256", "ES256"},
		RequiredClaims:    []string{"iss", "aud", "azp", "exp", "iat", "sub", "token_use", "groups", "platform_namespaces"},
		GroupsClaim:       "groups", NamespacesClaim: "platform_namespaces", TokenMaxLifetime: time.Hour,
		ClockSkew: time.Minute, JWKSCacheTTL: 5 * time.Minute, RotationOverlap: 24 * time.Hour, Keys: keys,
	}
}

func jwksContainsKID(jwks JWKS, kid string) bool {
	for _, key := range jwks.Keys {
		if key.KID == kid {
			return true
		}
	}
	return false
}
