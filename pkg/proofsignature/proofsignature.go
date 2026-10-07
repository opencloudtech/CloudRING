// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

// Package proofsignature signs and verifies exact CloudRING proof payloads.
// Private signing material is kept behind an opaque type so callers cannot
// accidentally marshal or log it.
package proofsignature

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
)

const (
	APIVersion       = "cloudring.io/v1alpha1"
	SigningKeyKind   = "ProofSigningKey"
	TrustPolicyKind  = "ProofTrustPolicy"
	AlgorithmEd25519 = "Ed25519"
	maxPayloadBytes  = 8 << 20
)

// Envelope binds a proof payload digest to a named signing key.
type Envelope struct {
	KeyID         string `json:"keyId"`
	Algorithm     string `json:"algorithm"`
	PayloadSHA256 string `json:"payloadSha256"`
	Value         string `json:"value"`
}

// TrustKey is the public half of one accepted signing identity.
type TrustKey struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`
}

// TrustPolicy is a versioned rotation-safe set of accepted public keys.
type TrustPolicy struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Keys       []TrustKey `json:"keys"`
}

// SigningKey holds an Ed25519 seed without exposing it through JSON.
// Destroy must be called as soon as signing is complete.
type SigningKey struct {
	keyID string
	seed  []byte
}

type signingKeyDocument struct {
	APIVersion     string `json:"apiVersion"`
	Kind           string `json:"kind"`
	KeyID          string `json:"keyId"`
	Algorithm      string `json:"algorithm"`
	PrivateKeySeed string `json:"privateKeySeed"`
}

// Generate creates a new signing key using the operating-system CSPRNG.
func Generate(keyID string) (*SigningKey, error) {
	if !validKeyID(keyID) {
		return nil, errors.New("proof signing key id is invalid")
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("generate proof signing key")
	}
	defer clear(privateKey)
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, privateKey.Seed())
	return &SigningKey{keyID: keyID, seed: seed}, nil
}

// ParseSigningKey decodes one strict, closed signing-key document.
func ParseSigningKey(data []byte) (*SigningKey, error) {
	var document signingKeyDocument
	if err := strictjson.DecodeExact(data, &document); err != nil {
		return nil, errors.New("decode proof signing key")
	}
	if document.APIVersion != APIVersion || document.Kind != SigningKeyKind ||
		document.Algorithm != AlgorithmEd25519 || !validKeyID(document.KeyID) {
		return nil, errors.New("proof signing key metadata is invalid")
	}
	seed, err := base64.StdEncoding.DecodeString(document.PrivateKeySeed)
	if err != nil || len(seed) != ed25519.SeedSize ||
		base64.StdEncoding.EncodeToString(seed) != document.PrivateKeySeed {
		clear(seed)
		return nil, errors.New("proof signing key material is invalid")
	}
	return &SigningKey{keyID: document.KeyID, seed: seed}, nil
}

// ParseTrustPolicy decodes one strict, closed public trust policy.
func ParseTrustPolicy(data []byte) (TrustPolicy, error) {
	var policy TrustPolicy
	if err := strictjson.DecodeExact(data, &policy); err != nil {
		return TrustPolicy{}, errors.New("decode proof trust policy")
	}
	if policy.APIVersion != APIVersion || policy.Kind != TrustPolicyKind || len(policy.Keys) == 0 {
		return TrustPolicy{}, errors.New("proof trust policy metadata is invalid")
	}
	if err := validateTrustKeys(policy.Keys); err != nil {
		return TrustPolicy{}, err
	}
	return policy, nil
}

// NewTrustPolicy creates a validated public policy for initial provisioning or
// an explicit key-rotation window.
func NewTrustPolicy(keys ...TrustKey) (TrustPolicy, error) {
	if len(keys) == 0 {
		return TrustPolicy{}, errors.New("proof trust policy requires at least one key")
	}
	if err := validateTrustKeys(keys); err != nil {
		return TrustPolicy{}, err
	}
	return TrustPolicy{APIVersion: APIVersion, Kind: TrustPolicyKind, Keys: append([]TrustKey(nil), keys...)}, nil
}

// MarshalSigningKey serializes a key for a protected pipe. The returned bytes
// contain private material and must be cleared by the caller after use.
func MarshalSigningKey(key *SigningKey) ([]byte, error) {
	if err := validateSigningKey(key); err != nil {
		return nil, err
	}
	document := signingKeyDocument{
		APIVersion:     APIVersion,
		Kind:           SigningKeyKind,
		KeyID:          key.keyID,
		Algorithm:      AlgorithmEd25519,
		PrivateKeySeed: base64.StdEncoding.EncodeToString(key.seed),
	}
	data, err := json.Marshal(document)
	if err != nil {
		return nil, errors.New("encode proof signing key")
	}
	return data, nil
}

// KeyID returns the source-safe public identifier of the key.
func (key *SigningKey) KeyID() string {
	if key == nil {
		return ""
	}
	return key.keyID
}

// TrustKey derives the public trust record without exposing the private seed.
func (key *SigningKey) TrustKey() (TrustKey, error) {
	if err := validateSigningKey(key); err != nil {
		return TrustKey{}, err
	}
	signingMaterial := ed25519.NewKeyFromSeed(key.seed)
	defer clear(signingMaterial)
	publicKey := signingMaterial.Public().(ed25519.PublicKey)
	return TrustKey{
		KeyID:     key.keyID,
		Algorithm: AlgorithmEd25519,
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
	}, nil
}

// Sign signs the exact payload bytes. Canonicalization is deliberately owned
// by the proof schema so a generic signer cannot silently change semantics.
func Sign(payload []byte, key *SigningKey) (Envelope, error) {
	if err := validatePayload(payload); err != nil {
		return Envelope{}, err
	}
	if err := validateSigningKey(key); err != nil {
		return Envelope{}, err
	}
	signingMaterial := ed25519.NewKeyFromSeed(key.seed)
	defer clear(signingMaterial)
	signature := ed25519.Sign(signingMaterial, payload)
	digest := sha256.Sum256(payload)
	return Envelope{
		KeyID:         key.keyID,
		Algorithm:     AlgorithmEd25519,
		PayloadSHA256: hex.EncodeToString(digest[:]),
		Value:         base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// Verify checks one envelope against an explicit set of accepted public keys.
func Verify(payload []byte, envelope Envelope, trustedKeys []TrustKey) error {
	if err := validatePayload(payload); err != nil {
		return err
	}
	if !validKeyID(envelope.KeyID) || envelope.Algorithm != AlgorithmEd25519 ||
		!validSHA256(envelope.PayloadSHA256) {
		return errors.New("proof signature metadata is invalid")
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != envelope.PayloadSHA256 {
		return errors.New("proof payload digest does not match")
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Value)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(signature) != envelope.Value {
		return errors.New("proof signature is invalid")
	}
	if err := validateTrustKeys(trustedKeys); err != nil {
		return err
	}
	var selected ed25519.PublicKey
	for _, candidate := range trustedKeys {
		publicKey, decodeErr := base64.StdEncoding.DecodeString(candidate.PublicKey)
		if decodeErr != nil {
			return errors.New("proof trust public key is invalid")
		}
		if candidate.KeyID == envelope.KeyID {
			selected = ed25519.PublicKey(publicKey)
		}
	}
	if selected == nil {
		return errors.New("proof signing key is not trusted")
	}
	if !ed25519.Verify(selected, payload, signature) {
		return errors.New("proof signature is invalid")
	}
	return nil
}

// VerifyPolicy checks one envelope against a versioned public policy.
func VerifyPolicy(payload []byte, envelope Envelope, policy TrustPolicy) error {
	if policy.APIVersion != APIVersion || policy.Kind != TrustPolicyKind || len(policy.Keys) == 0 {
		return errors.New("proof trust policy metadata is invalid")
	}
	return Verify(payload, envelope, policy.Keys)
}

// Destroy clears the in-memory private seed and makes the key unusable.
func (key *SigningKey) Destroy() {
	if key == nil {
		return
	}
	clear(key.seed)
	key.seed = nil
	key.keyID = ""
}

func validateSigningKey(key *SigningKey) error {
	if key == nil || !validKeyID(key.keyID) || len(key.seed) != ed25519.SeedSize {
		return errors.New("proof signing key is invalid")
	}
	return nil
}

func validatePayload(payload []byte) error {
	if len(payload) == 0 || len(payload) > maxPayloadBytes {
		return errors.New("proof payload size is invalid")
	}
	return nil
}

func validateTrustKeys(keys []TrustKey) error {
	seen := make(map[string]struct{}, len(keys))
	for _, candidate := range keys {
		if !validKeyID(candidate.KeyID) || candidate.Algorithm != AlgorithmEd25519 {
			return errors.New("proof trust key metadata is invalid")
		}
		if _, duplicate := seen[candidate.KeyID]; duplicate {
			return errors.New("proof trust keys contain a duplicate key id")
		}
		seen[candidate.KeyID] = struct{}{}
		publicKey, err := base64.StdEncoding.DecodeString(candidate.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize ||
			base64.StdEncoding.EncodeToString(publicKey) != candidate.PublicKey {
			return errors.New("proof trust public key is invalid")
		}
	}
	return nil
}

func validKeyID(value string) bool {
	if value == "" || len(value) > 96 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return strings.Trim(value, "_") == value && !strings.Contains(value, "cloudring_")
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
