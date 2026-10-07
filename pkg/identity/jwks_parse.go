// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"math/big"
)

func SigningKeysFromJWKS(jwks JWKS) ([]SigningKey, error) {
	keys := make([]SigningKey, 0, len(jwks.Keys))
	keyIDs := make(map[string]struct{}, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		if _, duplicate := keyIDs[jwk.KID]; duplicate {
			return nil, fmt.Errorf("duplicate jwk kid %q", jwk.KID)
		}
		key, err := signingKeyFromJWK(jwk)
		if err != nil {
			return nil, err
		}
		keyIDs[jwk.KID] = struct{}{}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks must contain at least one signing key")
	}
	return keys, nil
}

func signingKeyFromJWK(jwk JWK) (SigningKey, error) {
	if jwk.KID == "" || jwk.Alg == "" {
		return SigningKey{}, errors.New("jwk kid and alg are required")
	}
	if jwk.Use != "" && jwk.Use != "sig" {
		return SigningKey{}, fmt.Errorf("jwk %q is not a signing key", jwk.KID)
	}
	switch jwk.KTY {
	case "RSA":
		key, err := rsaPublicKeyFromJWK(jwk)
		if err != nil {
			return SigningKey{}, err
		}
		return SigningKey{KeyID: jwk.KID, Algorithm: jwk.Alg, PublicKey: key}, nil
	case "EC":
		key, err := ecdsaPublicKeyFromJWK(jwk)
		if err != nil {
			return SigningKey{}, err
		}
		return SigningKey{KeyID: jwk.KID, Algorithm: jwk.Alg, PublicKey: key}, nil
	default:
		return SigningKey{}, fmt.Errorf("unsupported jwk kty %q", jwk.KTY)
	}
}

func rsaPublicKeyFromJWK(jwk JWK) (*rsa.PublicKey, error) {
	if jwk.Alg != "RS256" || jwk.N == "" || jwk.E == "" {
		return nil, fmt.Errorf("rsa jwk %q must declare RS256 modulus and exponent", jwk.KID)
	}
	modulus, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("decode rsa modulus for %q: %w", jwk.KID, err)
	}
	exponent, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("decode rsa exponent for %q: %w", jwk.KID, err)
	}
	exponentValue := new(big.Int).SetBytes(exponent)
	if !exponentValue.IsInt64() || exponentValue.Int64() > math.MaxInt32 {
		return nil, fmt.Errorf("rsa jwk %q has invalid exponent", jwk.KID)
	}
	e := int(exponentValue.Int64())
	modulusValue := new(big.Int).SetBytes(modulus)
	if modulusValue.BitLen() < 2048 || e < 65537 || e%2 == 0 {
		return nil, fmt.Errorf("rsa jwk %q has a weak modulus or unsafe exponent", jwk.KID)
	}
	return &rsa.PublicKey{N: modulusValue, E: e}, nil
}

func ecdsaPublicKeyFromJWK(jwk JWK) (*ecdsa.PublicKey, error) {
	if jwk.Alg != "ES256" || jwk.Crv != "P-256" || jwk.X == "" || jwk.Y == "" {
		return nil, fmt.Errorf("ecdsa jwk %q must declare ES256 P-256 coordinates", jwk.KID)
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("decode ecdsa x for %q: %w", jwk.KID, err)
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("decode ecdsa y for %q: %w", jwk.KID, err)
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("ecdsa jwk %q coordinates must be 32 bytes", jwk.KID)
	}
	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, fmt.Errorf("ecdsa jwk %q point is not on P-256", jwk.KID)
	}
	return publicKey, nil
}
