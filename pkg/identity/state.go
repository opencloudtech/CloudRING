// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package identity

import (
	"context"
	"errors"
	"time"
)

var (
	ErrAuthorizationStateInvalid  = errors.New("identity: authorization state is invalid")
	ErrAuthorizationStateConsumed = errors.New("identity: authorization state was already consumed")
	ErrSessionStateUnavailable    = errors.New("identity: session state is unavailable")
)

// StateReadiness reports whether the durable state dependency is usable. A
// successful result must reflect a real read/write-capable backend, not merely
// local configuration presence.
type StateReadiness interface {
	Ready(context.Context) error
}

// AuthorizationStateRecord contains only hashes and sealed transaction
// material. Raw browser state, nonce, authorization code, and PKCE verifier
// values must not be persisted.
type AuthorizationStateRecord struct {
	StateHash          string
	NonceHash          string
	SealedNonce        []byte
	SealedPKCEVerifier []byte
	RedirectURI        string
	CreatedAt          time.Time
	ExpiresAt          time.Time
}

// AuthorizationStateStore must make Consume atomic. A state record can be
// returned at most once, including when multiple replicas race the callback.
type AuthorizationStateStore interface {
	StateReadiness
	Put(context.Context, AuthorizationStateRecord) error
	Consume(context.Context, string, time.Time) (AuthorizationStateRecord, error)
	DeleteExpired(context.Context, time.Time, int) (int, error)
}

// SessionStateRecord uses the hash of an opaque session token as its key.
// Implementations must never persist the raw session token.
type SessionStateRecord struct {
	TokenHash  string
	SubjectID  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time
}

type SessionStateStore interface {
	StateReadiness
	Load(context.Context, string, time.Time) (SessionStateRecord, error)
	Save(context.Context, SessionStateRecord) error
	Revoke(context.Context, string, time.Time) error
	DeleteExpired(context.Context, time.Time, int) (int, error)
}
