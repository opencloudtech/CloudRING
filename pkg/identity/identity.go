// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package identity

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

var errJWTRejected = errors.New("jwt rejected")

type RuntimeConfig struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	Audience              string
	AuthorizedParty       string
	ExpectedJOSEType      string
	JWTClassClaim         string
	ExpectedJWTClass      string
	AllowedAlgorithms     []string
	RequiredClaims        []string
	GroupsClaim           string
	NamespacesClaim       string
	TokenMaxLifetime      time.Duration
	ClockSkew             time.Duration
	JWKSCacheTTL          time.Duration
	RotationOverlap       time.Duration
	Keys                  []SigningKey
}

type SigningKey struct {
	KeyID       string
	Algorithm   string
	PublicKey   any
	ActiveFrom  time.Time
	ActiveUntil time.Time
}

type Runtime struct {
	config RuntimeConfig
}

func NewRuntime(config RuntimeConfig) (*Runtime, error) {
	if err := validateRuntimeConfig(config); err != nil {
		return nil, err
	}
	return &Runtime{config: normalizeConfig(config)}, nil
}

func validateRuntimeConfig(config RuntimeConfig) error {
	for label, value := range map[string]string{
		"issuer":                 config.Issuer,
		"authorization endpoint": config.AuthorizationEndpoint,
		"token endpoint":         config.TokenEndpoint,
		"jwks uri":               config.JWKSURI,
		"audience":               config.Audience,
		"authorized party":       config.AuthorizedParty,
		"expected jose type":     config.ExpectedJOSEType,
		"jwt class claim":        config.JWTClassClaim,
		"expected jwt class":     config.ExpectedJWTClass,
		"groups claim":           config.GroupsClaim,
		"namespaces claim":       config.NamespacesClaim,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", label)
		}
	}
	if (config.ExpectedJWTClass == "id" && config.ExpectedJOSEType != "JWT") ||
		(config.ExpectedJWTClass == "access" && config.ExpectedJOSEType != "at+jwt") ||
		(config.ExpectedJWTClass != "id" && config.ExpectedJWTClass != "access") {
		return errors.New("jwt class and JOSE type must form an explicit id or access profile")
	}
	for _, endpoint := range []string{config.Issuer, config.AuthorizationEndpoint, config.TokenEndpoint, config.JWKSURI} {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("identity endpoint must be an https URL: %q", endpoint)
		}
	}
	if len(config.AllowedAlgorithms) == 0 {
		return errors.New("at least one asymmetric algorithm is required")
	}
	algorithms := map[string]struct{}{}
	for _, alg := range config.AllowedAlgorithms {
		if alg != "RS256" && alg != "ES256" {
			return fmt.Errorf("forbidden or unsupported algorithm %q", alg)
		}
		if _, duplicate := algorithms[alg]; duplicate {
			return fmt.Errorf("duplicate allowed algorithm %q", alg)
		}
		algorithms[alg] = struct{}{}
	}
	required := map[string]bool{}
	for _, claim := range config.RequiredClaims {
		if claim == "" || required[claim] {
			return fmt.Errorf("required claim %q is empty or duplicated", claim)
		}
		required[claim] = true
	}
	for _, claim := range []string{"iss", "aud", "azp", "exp", "iat", "sub", config.JWTClassClaim, config.GroupsClaim, config.NamespacesClaim} {
		if !required[claim] {
			return fmt.Errorf("required claim %q is missing from policy", claim)
		}
	}
	if config.TokenMaxLifetime <= 0 || config.ClockSkew < 0 || config.JWKSCacheTTL <= 0 || config.RotationOverlap <= 0 {
		return errors.New("token, skew, cache, and rotation durations must be configured")
	}
	if config.RotationOverlap < config.TokenMaxLifetime+config.ClockSkew {
		return errors.New("rotation overlap must cover the maximum token lifetime plus verification clock skew")
	}
	if len(config.Keys) == 0 {
		return errors.New("at least one signing key is required")
	}
	keyIDs := map[string]struct{}{}
	for _, key := range config.Keys {
		if key.KeyID == "" {
			return errors.New("signing key id is required")
		}
		if _, duplicate := keyIDs[key.KeyID]; duplicate {
			return fmt.Errorf("duplicate signing key id %q", key.KeyID)
		}
		keyIDs[key.KeyID] = struct{}{}
		if !isAllowedAlgorithm(config.AllowedAlgorithms, key.Algorithm) {
			return fmt.Errorf("signing key %q uses disallowed algorithm %q", key.KeyID, key.Algorithm)
		}
		if !key.ActiveFrom.IsZero() && !key.ActiveUntil.IsZero() && !key.ActiveFrom.Before(key.ActiveUntil) {
			return fmt.Errorf("signing key %q activation window is invalid", key.KeyID)
		}
		if _, err := publicJWK(key); err != nil {
			return err
		}
	}
	return nil
}

func normalizeConfig(config RuntimeConfig) RuntimeConfig {
	config.AllowedAlgorithms = append([]string{}, config.AllowedAlgorithms...)
	config.RequiredClaims = append([]string{}, config.RequiredClaims...)
	keys := config.Keys
	config.Keys = make([]SigningKey, len(keys))
	for index, key := range keys {
		key.PublicKey = clonePublicKey(key.PublicKey)
		config.Keys[index] = key
	}
	return config
}

func clonePublicKey(publicKey any) any {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil {
			return (*rsa.PublicKey)(nil)
		}
		return &rsa.PublicKey{N: new(big.Int).Set(key.N), E: key.E}
	case *ecdsa.PublicKey:
		if key == nil || key.X == nil || key.Y == nil {
			return (*ecdsa.PublicKey)(nil)
		}
		return &ecdsa.PublicKey{Curve: key.Curve, X: new(big.Int).Set(key.X), Y: new(big.Int).Set(key.Y)}
	default:
		return publicKey
	}
}

func isAllowedAlgorithm(allowed []string, alg string) bool {
	for _, value := range allowed {
		if value == alg {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
