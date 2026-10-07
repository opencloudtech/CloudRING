// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package iam

import (
	"context"
	"errors"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/identity"
)

type OIDCProof struct {
	IDToken string
	Nonce   string
	MFA     MFAAssurance
	Session SessionAssurance
}

// OIDCProofSource reads browser/session proof from trusted transport context.
// It must not derive a subject from AuthorizationRequest.
type OIDCProofSource interface {
	OIDCProof(context.Context) (OIDCProof, error)
}

type OIDCProofFunc func(context.Context) (OIDCProof, error)

func (source OIDCProofFunc) OIDCProof(ctx context.Context) (OIDCProof, error) {
	if source == nil {
		return OIDCProof{}, ErrAuthentication
	}
	return source(ctx)
}

// OIDCAuthenticationVerifier is the reference adapter from a verified OIDC ID
// token to Policy authentication evidence. The subject always comes from the
// signed token; Policy separately requires it to match the requested subject
// and the configured role/scope directory.
type OIDCAuthenticationVerifier struct {
	runtime *identity.Runtime
	source  OIDCProofSource
}

func NewOIDCAuthenticationVerifier(runtime *identity.Runtime, source OIDCProofSource) (*OIDCAuthenticationVerifier, error) {
	if runtime == nil || source == nil {
		return nil, errors.New("iam: oidc runtime and proof source are required")
	}
	return &OIDCAuthenticationVerifier{runtime: runtime, source: source}, nil
}

func (verifier *OIDCAuthenticationVerifier) Authenticate(ctx context.Context, _ AuthorizationRequest, at time.Time) (AuthenticationResult, error) {
	if verifier == nil || verifier.runtime == nil || verifier.source == nil || ctx == nil {
		return AuthenticationResult{}, ErrAuthentication
	}
	proof, err := verifier.source.OIDCProof(ctx)
	if err != nil {
		return AuthenticationResult{}, ErrAuthentication
	}
	claims, err := verifier.runtime.VerifyIDToken(proof.IDToken, at, proof.Nonce)
	if err != nil {
		return AuthenticationResult{}, ErrAuthentication
	}
	return AuthenticationResult{
		SubjectID:       claims.Subject,
		CredentialClass: CredentialClassInteractiveSession,
		MFA:             proof.MFA,
		Session:         proof.Session,
		Proof: AuthenticationProof{
			VerifiedAt: at,
			ExpiresAt:  claims.ExpiresAt,
		},
	}, nil
}
