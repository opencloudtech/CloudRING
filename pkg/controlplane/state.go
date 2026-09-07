// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/opencloudtech/CloudRING/internal/strictjson"
	"github.com/opencloudtech/CloudRING/pkg/transactionalstate"
)

const stateScope = "controlplane"
const installationKey = "installation"
const sessionKey = "development-operator-session"

var errState = errors.New("control plane durable state is unavailable")
var errBinding = errors.New("control plane installation identity does not match durable state")
var errSessionInvalid = errors.New("session is invalid")

// StateStore is implemented by transactionalstate.Store. Tests can isolate
// protocol failures; the serving command always opens a real PostgreSQL store.
type StateStore interface {
	Ready(context.Context) error
	Load(context.Context, string, string) (transactionalstate.Document, error)
	Save(context.Context, string, string, int64, []byte) (transactionalstate.Document, error)
}

type installationState struct {
	SchemaVersion       int       `json:"schemaVersion"`
	InstallationID      string    `json:"installationID"`
	Profile             string    `json:"profile"`
	OperatorID          string    `json:"operatorID"`
	OperatorTokenSHA256 string    `json:"operatorTokenSHA256"`
	CreatedAt           time.Time `json:"createdAt"`
	Products            []Product `json:"products"`
}

// Product is a registered product's public identity. The development baseline
// starts with an empty durable registry; it never seeds demo products.
type Product struct {
	ID string `json:"id"`
}

type sessionState struct {
	SchemaVersion  int       `json:"schemaVersion"`
	InstallationID string    `json:"installationID"`
	OperatorID     string    `json:"operatorID"`
	TokenSHA256    string    `json:"tokenSHA256"`
	CreatedAt      time.Time `json:"createdAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	Revoked        bool      `json:"revoked,omitempty"`
}

func bootstrap(ctx context.Context, store StateStore, installationID, operatorToken string, now time.Time) (installationState, error) {
	if err := store.Ready(ctx); err != nil {
		return installationState{}, errState
	}
	document, err := store.Load(ctx, stateScope, installationKey)
	if errors.Is(err, transactionalstate.ErrNotFound) {
		initial := installationState{
			SchemaVersion: 1, InstallationID: installationID, Profile: DevelopmentProfile,
			OperatorID: "dev-operator:" + installationID, OperatorTokenSHA256: tokenHash(operatorToken),
			CreatedAt: now.UTC(), Products: []Product{},
		}
		body, marshalErr := json.Marshal(initial)
		if marshalErr != nil {
			return installationState{}, errState
		}
		document, err = store.Save(ctx, stateScope, installationKey, 0, body)
		// A parallel create or an uncertain response is resolved by the same
		// global identity record. It is never replaced or adopted by name.
		if err != nil {
			document, err = store.Load(ctx, stateScope, installationKey)
		}
	}
	if err != nil {
		return installationState{}, errState
	}
	return validateInstallation(document, installationID, operatorToken)
}

func validateInstallation(document transactionalstate.Document, installationID, operatorToken string) (installationState, error) {
	var state installationState
	if strictjson.DecodeExact(document.Value, &state) != nil || state.SchemaVersion != 1 || document.Revision < 1 ||
		state.InstallationID != installationID || state.Profile != DevelopmentProfile || state.OperatorID != "dev-operator:"+installationID ||
		!equalHash(state.OperatorTokenSHA256, tokenHash(operatorToken)) || state.CreatedAt.IsZero() || state.Products == nil || len(state.Products) != 0 {
		return installationState{}, errBinding
	}
	return state, nil
}

func (server *Server) loadInstallation(ctx context.Context) (installationState, error) {
	document, err := server.store.Load(ctx, stateScope, installationKey)
	if err != nil {
		return installationState{}, errState
	}
	return validateInstallation(document, server.config.InstallationID, server.operatorToken)
}

func (server *Server) createSession(ctx context.Context, now time.Time) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", errState
	}
	sessionToken := hex.EncodeToString(tokenBytes)
	state := sessionState{
		SchemaVersion: 1, InstallationID: server.config.InstallationID,
		OperatorID: "dev-operator:" + server.config.InstallationID, TokenSHA256: tokenHash(sessionToken),
		CreatedAt: now.UTC(), ExpiresAt: now.Add(sessionLifetime).UTC(),
	}
	body, err := json.Marshal(state)
	if err != nil {
		return "", errState
	}
	// One bounded development operator has one persisted browser session.
	// Signing in again revokes the previous browser session. Bearer CLI access
	// is unaffected and no unbounded collection of expired sessions is created.
	for range 3 {
		document, loadErr := server.store.Load(ctx, stateScope, sessionKey)
		if loadErr != nil && !errors.Is(loadErr, transactionalstate.ErrNotFound) {
			return "", errState
		}
		revision := document.Revision
		if errors.Is(loadErr, transactionalstate.ErrNotFound) {
			revision = 0
		}
		if _, err = server.store.Save(ctx, stateScope, sessionKey, revision, body); err == nil {
			return sessionToken, nil
		}
		// Read after an uncertain commit before retrying; this exact random
		// token is the idempotency identity and never appears in a diagnostic.
		readback, readErr := server.store.Load(ctx, stateScope, sessionKey)
		if readErr == nil {
			var observed sessionState
			if strictjson.DecodeExact(readback.Value, &observed) == nil && equalHash(observed.TokenSHA256, state.TokenSHA256) {
				return sessionToken, nil
			}
		}
		if !errors.Is(err, transactionalstate.ErrConflict) {
			return "", errState
		}
	}
	return "", errState
}

func (server *Server) loadSession(ctx context.Context, token string, now time.Time) (transactionalstate.Document, error) {
	if !operatorTokenPattern.MatchString(token) {
		return transactionalstate.Document{}, errSessionInvalid
	}
	document, err := server.store.Load(ctx, stateScope, sessionKey)
	if err != nil {
		return transactionalstate.Document{}, err
	}
	var state sessionState
	if strictjson.DecodeExact(document.Value, &state) != nil || state.SchemaVersion != 1 || document.Revision < 1 || state.Revoked ||
		state.InstallationID != server.config.InstallationID || state.OperatorID != "dev-operator:"+server.config.InstallationID ||
		!equalHash(state.TokenSHA256, tokenHash(token)) || state.CreatedAt.After(now) || !state.ExpiresAt.After(now) ||
		state.ExpiresAt.Sub(state.CreatedAt) != sessionLifetime {
		return transactionalstate.Document{}, errSessionInvalid
	}
	return document, nil
}

func (server *Server) revokeSession(ctx context.Context, document transactionalstate.Document, token string) error {
	var state sessionState
	if strictjson.DecodeExact(document.Value, &state) != nil {
		return errState
	}
	state.Revoked = true
	body, err := json.Marshal(state)
	if err != nil {
		return errState
	}
	// Keep this single bounded record so revisions never return to one after
	// logout. A delayed old logout cannot revoke a later login with a reused
	// revision; its compare-and-swap must conflict with the newer session.
	if _, err := server.store.Save(ctx, stateScope, sessionKey, document.Revision, body); err == nil {
		return nil
	}
	// A lost commit response is successful only when a fresh database read
	// proves that this exact old token is no longer accepted. A DB read error
	// cannot be converted into a successful logout, including after conflict.
	_, err = server.loadSession(ctx, token, server.now())
	if errors.Is(err, errSessionInvalid) || errors.Is(err, transactionalstate.ErrNotFound) {
		return nil
	}
	return errState
}

func tokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func equalHash(first, second string) bool {
	return len(first) == 64 && len(second) == 64 && subtle.ConstantTimeCompare([]byte(first), []byte(second)) == 1
}
