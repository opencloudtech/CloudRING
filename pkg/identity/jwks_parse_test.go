// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestSigningKeysFromJWKSRejectsAmbiguousAndWeakKeys(t *testing.T) {
	strong := mustRSAKey(t)
	// #nosec G403 -- a deliberately weak key is required to prove rejection.
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey(1024): %v", err)
	}
	strongJWK := rsaJWKForTest("main", &strong.PublicKey)
	tests := []struct {
		name string
		jwks JWKS
	}{
		{name: "duplicate kid", jwks: JWKS{Keys: []JWK{strongJWK, strongJWK}}},
		{name: "weak rsa", jwks: JWKS{Keys: []JWK{rsaJWKForTest("weak", &weak.PublicKey)}}},
		{name: "unsafe exponent", jwks: JWKS{Keys: []JWK{{
			KTY: "RSA", Use: "sig", KID: "unsafe", Alg: "RS256",
			N: strongJWK.N, E: base64.RawURLEncoding.EncodeToString(big.NewInt(3).Bytes()),
		}}}},
		{name: "off-curve ec", jwks: JWKS{Keys: []JWK{{
			KTY: "EC", Use: "sig", KID: "off-curve", Alg: "ES256", Crv: "P-256",
			X: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			Y: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := SigningKeysFromJWKS(test.jwks); err == nil {
				t.Fatalf("SigningKeysFromJWKS accepted %s", test.name)
			}
		})
	}
}

func rsaJWKForTest(keyID string, key *rsa.PublicKey) JWK {
	return JWK{
		KTY: "RSA", Use: "sig", KID: keyID, Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}
