// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package controlplane

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/opencloudtech/CloudRING/pkg/transactionalstate"
)

// delayedSessionMutationStore schedules an overlapping logout and login exactly
// after the first logout has read its session, but before its write commits.
// Both mutation methods are intercepted so this regression also exercises the
// former delete/recreate implementation, where revision one could be reused.
type delayedSessionMutationStore struct {
	StateStore
	beforeMutation func()
}

func (store *delayedSessionMutationStore) intercept(scope, key string) {
	if scope == stateScope && key == sessionKey && store.beforeMutation != nil {
		hook := store.beforeMutation
		store.beforeMutation = nil
		hook()
	}
}

func (store *delayedSessionMutationStore) Save(ctx context.Context, scope, key string, revision int64, value []byte) (transactionalstate.Document, error) {
	store.intercept(scope, key)
	return store.StateStore.Save(ctx, scope, key, revision, value)
}

func (store *delayedSessionMutationStore) Delete(ctx context.Context, scope, key string, revision int64) error {
	store.intercept(scope, key)
	return store.StateStore.(interface {
		Delete(context.Context, string, string, int64) error
	}).Delete(ctx, scope, key, revision)
}

func TestDelayedOldLogoutPreservesNewSessionAfterConcurrentLogoutAndLogin(t *testing.T) {
	runDelayedOldLogoutJourney(t, newProtocolStore())
}

func runDelayedOldLogoutJourney(t *testing.T, backing StateStore) {
	t.Helper()
	store := &delayedSessionMutationStore{StateStore: backing}
	server := newTestServer(t, store)
	first := perform(server, http.MethodPost, "/login", loginForm(server.operatorToken), "", nil)
	requireStatus(t, first, http.StatusSeeOther)
	oldCookie := first.Result().Cookies()[0]
	csrf, err := server.csrf.Issue(oldCookie.Value, server.now())
	if err != nil {
		t.Fatal(err)
	}
	logoutForm := url.Values{"csrf": []string{csrf}}.Encode()
	var newCookie *http.Cookie
	var newDocument transactionalstate.Document
	store.beforeMutation = func() {
		concurrentLogout := perform(server, http.MethodPost, "/logout", logoutForm, "", oldCookie)
		requireStatus(t, concurrentLogout, http.StatusSeeOther)
		next := perform(server, http.MethodPost, "/login", loginForm(server.operatorToken), "", nil)
		requireStatus(t, next, http.StatusSeeOther)
		newCookie = next.Result().Cookies()[0]
		newDocument, err = store.Load(context.Background(), stateScope, sessionKey)
		if err != nil {
			t.Fatal(err)
		}
	}

	delayedLogout := perform(server, http.MethodPost, "/logout", logoutForm, "", oldCookie)
	requireStatus(t, delayedLogout, http.StatusSeeOther)
	if newCookie == nil {
		t.Fatal("test did not interleave a newer login before the delayed logout write")
	}
	requireStatus(t, perform(server, http.MethodGet, "/", "", "", oldCookie), http.StatusUnauthorized)
	requireStatus(t, perform(server, http.MethodGet, "/", "", "", newCookie), http.StatusOK)
	after, err := store.Load(context.Background(), stateScope, sessionKey)
	if err != nil || after.Revision != newDocument.Revision || string(after.Value) != string(newDocument.Value) {
		t.Fatal("delayed logout changed or deleted the newer durable session")
	}
	if newDocument.Revision < 3 {
		t.Fatal("logout/login reused a previous durable session revision")
	}
}
