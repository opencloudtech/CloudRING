// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package identity

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"
)

type DiscoveryMetadata struct {
	Issuer                               string   `json:"issuer"`
	AuthorizationEndpoint                string   `json:"authorization_endpoint"`
	TokenEndpoint                        string   `json:"token_endpoint"`
	JWKSURI                              string   `json:"jwks_uri"`
	ResponseTypesSupported               []string `json:"response_types_supported"`
	SubjectTypesSupported                []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported     []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported    []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                      []string `json:"claims_supported"`
	CodeChallengeMethodsSupported        []string `json:"code_challenge_methods_supported"`
	CloudRINGJWKSCacheTTLSeconds         int64    `json:"cloudring_jwks_cache_ttl_seconds"`
	CloudRINGJWKSRotationOverlapSeconds  int64    `json:"cloudring_jwks_rotation_overlap_seconds"`
	CloudRINGManagementPanelIAMGate      string   `json:"cloudring_management_panel_iam_gate"`
	CloudRINGBootstrapAdminSecretPolicy  string   `json:"cloudring_bootstrap_admin_secret_policy"`
	CloudRINGBrowserWriteCSRFRequirement string   `json:"cloudring_browser_write_csrf_requirement"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KTY string `json:"kty"`
	Use string `json:"use"`
	KID string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

func (runtime *Runtime) Discovery() DiscoveryMetadata {
	claims := append([]string{}, runtime.config.RequiredClaims...)
	return DiscoveryMetadata{
		Issuer:                               runtime.config.Issuer,
		AuthorizationEndpoint:                runtime.config.AuthorizationEndpoint,
		TokenEndpoint:                        runtime.config.TokenEndpoint,
		JWKSURI:                              runtime.config.JWKSURI,
		ResponseTypesSupported:               []string{"code"},
		SubjectTypesSupported:                []string{"public"},
		IDTokenSigningAlgValuesSupported:     append([]string{}, runtime.config.AllowedAlgorithms...),
		TokenEndpointAuthMethodsSupported:    []string{"client_secret_basic", "private_key_jwt"},
		ClaimsSupported:                      claims,
		CodeChallengeMethodsSupported:        []string{"S256"},
		CloudRINGJWKSCacheTTLSeconds:         int64(runtime.config.JWKSCacheTTL / time.Second),
		CloudRINGJWKSRotationOverlapSeconds:  int64(runtime.config.RotationOverlap / time.Second),
		CloudRINGManagementPanelIAMGate:      "deny-until-authenticated-token-valid-and-iam-allow",
		CloudRINGBootstrapAdminSecretPolicy:  "exactly-one-admin-env-or-external-secret-references-only",
		CloudRINGBrowserWriteCSRFRequirement: "required",
	}
}

func (runtime *Runtime) ValidateDiscovery(discovery DiscoveryMetadata) error {
	if err := runtime.ValidateOIDCDiscovery(discovery); err != nil {
		return err
	}
	return runtime.ValidateCloudRINGDiscoveryPolicy(discovery)
}

// ValidateOIDCDiscovery validates the standard provider capabilities that the
// runtime actually consumes. Providers may advertise additional conforming
// capabilities; CloudRING-specific policy extensions are deliberately not
// evaluated here.
func (runtime *Runtime) ValidateOIDCDiscovery(discovery DiscoveryMetadata) error {
	if discovery.Issuer != runtime.config.Issuer {
		return fmt.Errorf("discovery issuer mismatch: %w", errJWTRejected)
	}
	if discovery.JWKSURI != runtime.config.JWKSURI {
		return fmt.Errorf("discovery jwks uri mismatch: %w", errJWTRejected)
	}
	if discovery.AuthorizationEndpoint != runtime.config.AuthorizationEndpoint {
		return fmt.Errorf("discovery authorization endpoint mismatch: %w", errJWTRejected)
	}
	if discovery.TokenEndpoint != runtime.config.TokenEndpoint {
		return fmt.Errorf("discovery token endpoint mismatch: %w", errJWTRejected)
	}
	for label, values := range map[string][]string{
		"response types":     discovery.ResponseTypesSupported,
		"subject types":      discovery.SubjectTypesSupported,
		"signing algorithms": discovery.IDTokenSigningAlgValuesSupported,
		"token auth methods": discovery.TokenEndpointAuthMethodsSupported,
		"pkce methods":       discovery.CodeChallengeMethodsSupported,
	} {
		if !validUniqueStrings(values) {
			return fmt.Errorf("discovery %s contain an empty or duplicate value: %w", label, errJWTRejected)
		}
	}
	if !containsString(discovery.ResponseTypesSupported, "code") {
		return fmt.Errorf("discovery does not support authorization code: %w", errJWTRejected)
	}
	if !containsAnyString(discovery.SubjectTypesSupported, []string{"public", "pairwise"}) {
		return fmt.Errorf("discovery has no standard subject type: %w", errJWTRejected)
	}
	if !containsString(discovery.CodeChallengeMethodsSupported, "S256") {
		return fmt.Errorf("discovery does not support PKCE S256: %w", errJWTRejected)
	}
	if !containsAnyString(discovery.TokenEndpointAuthMethodsSupported, []string{"none", "client_secret_basic", "private_key_jwt"}) {
		return fmt.Errorf("discovery has no supported token endpoint authentication method: %w", errJWTRejected)
	}
	// claims_supported is optional in OIDC discovery and often omits
	// installation-specific claims. When present it must still be unambiguous;
	// Runtime verifies all configured required claims in each signed token.
	if len(discovery.ClaimsSupported) != 0 && !validUniqueStrings(discovery.ClaimsSupported) {
		return fmt.Errorf("discovery claims contain an empty or duplicate value: %w", errJWTRejected)
	}
	for _, configured := range runtime.config.AllowedAlgorithms {
		if containsString(discovery.IDTokenSigningAlgValuesSupported, configured) {
			return nil
		}
	}
	return fmt.Errorf("discovery has no configured asymmetric signing algorithm: %w", errJWTRejected)
}

// ValidateCloudRINGDiscoveryPolicy validates only the CloudRING extension
// fields emitted by a CloudRING-controlled issuer. External OIDC providers are
// not expected to publish these non-standard fields.
func (runtime *Runtime) ValidateCloudRINGDiscoveryPolicy(discovery DiscoveryMetadata) error {
	if discovery.CloudRINGJWKSCacheTTLSeconds != int64(runtime.config.JWKSCacheTTL/time.Second) ||
		discovery.CloudRINGJWKSRotationOverlapSeconds != int64(runtime.config.RotationOverlap/time.Second) ||
		discovery.CloudRINGManagementPanelIAMGate != "deny-until-authenticated-token-valid-and-iam-allow" ||
		discovery.CloudRINGBootstrapAdminSecretPolicy != "exactly-one-admin-env-or-external-secret-references-only" ||
		discovery.CloudRINGBrowserWriteCSRFRequirement != "required" {
		return fmt.Errorf("cloudring discovery policy mismatch: %w", errJWTRejected)
	}
	return nil
}

func (runtime *Runtime) JWKS(now time.Time) JWKS {
	keys := make([]JWK, 0, len(runtime.config.Keys))
	for _, key := range runtime.config.Keys {
		if !keyPublished(key, now, runtime.config.JWKSCacheTTL, runtime.config.RotationOverlap) {
			continue
		}
		jwk, err := publicJWK(key)
		if err == nil {
			keys = append(keys, jwk)
		}
	}
	return JWKS{Keys: keys}
}

func (runtime *Runtime) keyByID(kid, alg string, now time.Time) (SigningKey, bool) {
	for _, key := range runtime.config.Keys {
		if key.KeyID == kid && key.Algorithm == alg && keyPublished(key, now, runtime.config.JWKSCacheTTL, runtime.config.RotationOverlap) {
			return key, true
		}
	}
	return SigningKey{}, false
}

func publicJWK(key SigningKey) (JWK, error) {
	switch pub := key.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub == nil || pub.N == nil || pub.N.BitLen() < 2048 || pub.E < 65537 || pub.E%2 == 0 {
			return JWK{}, fmt.Errorf("rsa key %q must be at least 2048 bits with a safe odd exponent", key.KeyID)
		}
		if key.Algorithm != "RS256" {
			return JWK{}, fmt.Errorf("rsa key %q must use RS256", key.KeyID)
		}
		return JWK{
			KTY: "RSA",
			Use: "sig",
			KID: key.KeyID,
			Alg: key.Algorithm,
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}, nil
	case *ecdsa.PublicKey:
		if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil || key.Algorithm != "ES256" ||
			pub.Curve.Params().Name != "P-256" || !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return JWK{}, fmt.Errorf("ecdsa key %q must use ES256 P-256", key.KeyID)
		}
		return JWK{
			KTY: "EC",
			Use: "sig",
			KID: key.KeyID,
			Alg: key.Algorithm,
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(fixedWidthBytes(pub.X, 32)),
			Y:   base64.RawURLEncoding.EncodeToString(fixedWidthBytes(pub.Y, 32)),
		}, nil
	default:
		return JWK{}, fmt.Errorf("unsupported public key type for %q", key.KeyID)
	}
}

func validUniqueStrings(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func containsAnyString(values, candidates []string) bool {
	for _, candidate := range candidates {
		if containsString(values, candidate) {
			return true
		}
	}
	return false
}

func keyPublished(key SigningKey, now time.Time, cacheTTL, overlap time.Duration) bool {
	// Publish a successor before it may sign so every conforming cache has a
	// refresh opportunity before the activation boundary.
	if !key.ActiveFrom.IsZero() && now.Before(key.ActiveFrom.Add(-cacheTTL)) {
		return false
	}
	if key.ActiveUntil.IsZero() {
		return true
	}
	return now.Before(key.ActiveUntil.Add(overlap))
}

func fixedWidthBytes(value *big.Int, width int) []byte {
	raw := value.Bytes()
	if len(raw) >= width {
		return raw
	}
	out := make([]byte, width)
	copy(out[width-len(raw):], raw)
	return out
}
