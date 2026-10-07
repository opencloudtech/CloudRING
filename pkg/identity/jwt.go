// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const (
	maxCompactJWTBytes        = 64 << 10
	maxEncodedJWTSegmentBytes = 24 << 10
)

type VerifiedClaims struct {
	Issuer     string
	Audience   []string
	ExpiresAt  time.Time
	IssuedAt   time.Time
	Subject    string
	Nonce      string
	Groups     []string
	Namespaces []string
}

// VerifyIDToken verifies the configured JWT profile and binds the ID token to
// the nonce issued for the browser authorization transaction.
func (runtime *Runtime) VerifyIDToken(token string, now time.Time, expectedNonce string) (VerifiedClaims, error) {
	if !validOpaqueAuthorizationValue(expectedNonce) {
		return VerifiedClaims{}, fmt.Errorf("expected nonce is invalid: %w", errJWTRejected)
	}
	claims, err := runtime.VerifyJWT(token, now)
	if err != nil {
		return VerifiedClaims{}, err
	}
	if len(claims.Nonce) != len(expectedNonce) ||
		subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expectedNonce)) != 1 {
		return VerifiedClaims{}, fmt.Errorf("id token nonce mismatch: %w", errJWTRejected)
	}
	return claims, nil
}

func (runtime *Runtime) VerifyJWT(token string, now time.Time) (VerifiedClaims, error) {
	if len(token) == 0 || len(token) > maxCompactJWTBytes {
		return VerifiedClaims{}, fmt.Errorf("compact jwt size is invalid: %w", errJWTRejected)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return VerifiedClaims{}, fmt.Errorf("compact jwt must have three parts: %w", errJWTRejected)
	}
	var header map[string]any
	if err := decodeJSONSegment(parts[0], &header); err != nil {
		return VerifiedClaims{}, fmt.Errorf("invalid jwt header: %w", errJWTRejected)
	}
	alg, _ := header["alg"].(string)
	kid, _ := header["kid"].(string)
	typ, _ := header["typ"].(string)
	if _, critical := header["crit"]; critical {
		return VerifiedClaims{}, fmt.Errorf("critical jwt headers are unsupported: %w", errJWTRejected)
	}
	if alg == "" || alg == "none" || alg == "HS256" || !isAllowedAlgorithm(runtime.config.AllowedAlgorithms, alg) {
		return VerifiedClaims{}, fmt.Errorf("forbidden jwt algorithm %q: %w", alg, errJWTRejected)
	}
	if kid == "" {
		return VerifiedClaims{}, fmt.Errorf("missing jwt kid: %w", errJWTRejected)
	}
	if typ != runtime.config.ExpectedJOSEType {
		return VerifiedClaims{}, fmt.Errorf("wrong jwt JOSE type %q: %w", typ, errJWTRejected)
	}
	key, ok := runtime.keyByID(kid, alg, now)
	if !ok {
		return VerifiedClaims{}, fmt.Errorf("unknown jwt kid %q: %w", kid, errJWTRejected)
	}

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return VerifiedClaims{}, fmt.Errorf("invalid jwt signature encoding: %w", errJWTRejected)
	}
	if err := verifySignature(alg, key.PublicKey, []byte(signingInput), signature); err != nil {
		return VerifiedClaims{}, err
	}

	var rawClaims map[string]any
	if err := decodeJSONSegment(parts[1], &rawClaims); err != nil {
		return VerifiedClaims{}, fmt.Errorf("invalid jwt claims: %w", errJWTRejected)
	}
	claims, err := runtime.validateClaims(rawClaims, now)
	if err != nil {
		return VerifiedClaims{}, err
	}
	if !issuedWithinSigningWindow(key, claims.IssuedAt) {
		return VerifiedClaims{}, fmt.Errorf("jwt issued outside signing-key activation window: %w", errJWTRejected)
	}
	return claims, nil
}

func (runtime *Runtime) validateClaims(raw map[string]any, now time.Time) (VerifiedClaims, error) {
	for _, claim := range runtime.config.RequiredClaims {
		if _, ok := raw[claim]; !ok {
			return VerifiedClaims{}, fmt.Errorf("missing required claim %q: %w", claim, errJWTRejected)
		}
	}
	issuer, _ := raw["iss"].(string)
	if issuer != runtime.config.Issuer {
		return VerifiedClaims{}, fmt.Errorf("wrong issuer: %w", errJWTRejected)
	}
	audiences, err := claimStrings(raw["aud"])
	if err != nil || !containsString(audiences, runtime.config.Audience) {
		return VerifiedClaims{}, fmt.Errorf("wrong audience: %w", errJWTRejected)
	}
	authorizedParty, _ := raw["azp"].(string)
	if authorizedParty != runtime.config.AuthorizedParty {
		return VerifiedClaims{}, fmt.Errorf("wrong authorized party: %w", errJWTRejected)
	}
	jwtClass, _ := raw[runtime.config.JWTClassClaim].(string)
	if jwtClass != runtime.config.ExpectedJWTClass {
		return VerifiedClaims{}, fmt.Errorf("wrong jwt class: %w", errJWTRejected)
	}
	exp, err := numericTime(raw["exp"])
	if err != nil {
		return VerifiedClaims{}, fmt.Errorf("invalid exp claim: %w", errJWTRejected)
	}
	if !now.Before(exp.Add(runtime.config.ClockSkew)) {
		return VerifiedClaims{}, fmt.Errorf("expired JWT: %w", errJWTRejected)
	}
	iat, err := numericTime(raw["iat"])
	if err != nil {
		return VerifiedClaims{}, fmt.Errorf("invalid iat claim: %w", errJWTRejected)
	}
	if iat.After(now.Add(runtime.config.ClockSkew)) {
		return VerifiedClaims{}, fmt.Errorf("iat in future: %w", errJWTRejected)
	}
	if !exp.After(iat) {
		return VerifiedClaims{}, fmt.Errorf("exp must be after iat: %w", errJWTRejected)
	}
	if rawNotBefore, ok := raw["nbf"]; ok {
		notBefore, err := numericTime(rawNotBefore)
		if err != nil || now.Add(runtime.config.ClockSkew).Before(notBefore) {
			return VerifiedClaims{}, fmt.Errorf("invalid or future nbf claim: %w", errJWTRejected)
		}
	}
	if runtime.config.TokenMaxLifetime > 0 && exp.Sub(iat) > runtime.config.TokenMaxLifetime {
		return VerifiedClaims{}, fmt.Errorf("token lifetime exceeds policy: %w", errJWTRejected)
	}
	subject, _ := raw["sub"].(string)
	if subject == "" {
		return VerifiedClaims{}, fmt.Errorf("missing subject: %w", errJWTRejected)
	}
	nonce, _ := raw["nonce"].(string)
	groups, err := claimStrings(raw[runtime.config.GroupsClaim])
	if err != nil || len(groups) == 0 {
		return VerifiedClaims{}, fmt.Errorf("missing groups claim: %w", errJWTRejected)
	}
	namespaces, err := claimStrings(raw[runtime.config.NamespacesClaim])
	if err != nil || len(namespaces) == 0 {
		return VerifiedClaims{}, fmt.Errorf("missing namespace claim: %w", errJWTRejected)
	}
	return VerifiedClaims{
		Issuer:     issuer,
		Audience:   audiences,
		ExpiresAt:  exp,
		IssuedAt:   iat,
		Subject:    subject,
		Nonce:      nonce,
		Groups:     groups,
		Namespaces: namespaces,
	}, nil
}

func issuedWithinSigningWindow(key SigningKey, issuedAt time.Time) bool {
	if !key.ActiveFrom.IsZero() && issuedAt.Before(key.ActiveFrom) {
		return false
	}
	if !key.ActiveUntil.IsZero() && !issuedAt.Before(key.ActiveUntil) {
		return false
	}
	return true
}

func verifySignature(alg string, publicKey any, signingInput, signature []byte) error {
	digest := sha256.Sum256(signingInput)
	switch alg {
	case "RS256":
		pub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("wrong public key type: %w", errJWTRejected)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
			return fmt.Errorf("invalid jwt signature: %w", errJWTRejected)
		}
		return nil
	case "ES256":
		pub, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("wrong public key type: %w", errJWTRejected)
		}
		if len(signature) != 64 {
			return fmt.Errorf("invalid jwt signature: %w", errJWTRejected)
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return fmt.Errorf("invalid jwt signature: %w", errJWTRejected)
		}
		return nil
	default:
		return fmt.Errorf("unsupported jwt algorithm %q: %w", alg, errJWTRejected)
	}
}

func decodeJSONSegment(segment string, target any) error {
	if len(segment) == 0 || len(segment) > maxEncodedJWTSegmentBytes {
		return errors.New("jwt JSON segment size is invalid")
	}
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return strictjson.Decode(data, target)
}

func numericTime(value any) (time.Time, error) {
	switch typed := value.(type) {
	case json.Number:
		integer, err := typed.Int64()
		if err != nil {
			return time.Time{}, err
		}
		return time.Unix(integer, 0).UTC(), nil
	default:
		return time.Time{}, errors.New("claim is not numeric")
	}
}

func claimStrings(value any) ([]string, error) {
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return nil, errors.New("empty string claim")
		}
		return []string{typed}, nil
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok || text == "" {
				return nil, errors.New("non-string claim item")
			}
			values = append(values, text)
		}
		return values, nil
	case []string:
		if len(typed) == 0 {
			return nil, errors.New("empty string claim")
		}
		return append([]string{}, typed...), nil
	default:
		return nil, errors.New("claim is not string or string array")
	}
}
