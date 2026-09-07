// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/transactionalstate"
)

// protocolStore isolates transport and crash/identity boundaries. It is only a
// test double. The separate PostgreSQL integration test runs the same journey
// against migrated least-privileged PostgreSQL, and the CLI has no memory mode.
type protocolStore struct {
	mutex              sync.Mutex
	documents          map[string]transactionalstate.Document
	unavailable        bool
	lostSaveResponse   bool
	lostDeleteResponse bool
}

func newProtocolStore() *protocolStore {
	return &protocolStore{documents: make(map[string]transactionalstate.Document)}
}

func (store *protocolStore) Ready(context.Context) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.unavailable {
		return errors.New("injected unavailable transport")
	}
	return nil
}

func (store *protocolStore) Load(_ context.Context, scope, key string) (transactionalstate.Document, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.unavailable {
		return transactionalstate.Document{}, errors.New("injected unavailable transport")
	}
	document, present := store.documents[scope+":"+key]
	if !present {
		return transactionalstate.Document{}, transactionalstate.ErrNotFound
	}
	document.Value = append([]byte{}, document.Value...)
	return document, nil
}

func (store *protocolStore) Save(_ context.Context, scope, key string, revision int64, value []byte) (transactionalstate.Document, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.unavailable {
		return transactionalstate.Document{}, errors.New("injected unavailable transport")
	}
	previous := store.documents[scope+":"+key]
	if previous.Revision != revision {
		return transactionalstate.Document{}, transactionalstate.ErrConflict
	}
	document := transactionalstate.Document{Scope: scope, Key: key, Revision: revision + 1, Value: append([]byte{}, value...), UpdatedAt: time.Now().UTC()}
	store.documents[scope+":"+key] = document
	if store.lostSaveResponse {
		store.lostSaveResponse = false
		return transactionalstate.Document{}, errors.New("injected lost response")
	}
	return document, nil
}

func (store *protocolStore) Delete(_ context.Context, scope, key string, revision int64) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.unavailable {
		return errors.New("injected unavailable transport")
	}
	previous := store.documents[scope+":"+key]
	if previous.Revision != revision || revision < 1 {
		return transactionalstate.ErrConflict
	}
	delete(store.documents, scope+":"+key)
	if store.lostDeleteResponse {
		store.lostDeleteResponse = false
		return errors.New("injected lost response")
	}
	return nil
}

func newTestServer(t *testing.T, store StateStore) *Server {
	t.Helper()
	server, err := New(context.Background(), testConfig(t), store, strings.Repeat("a", 64), BuildInfo{GoVersion: "test-runtime"})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func perform(server *Server, method, path, body, token string, cookie *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, server.config.PublicOrigin+path, strings.NewReader(body))
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", server.config.PublicOrigin)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

func requireStatus(t *testing.T, response *httptest.ResponseRecorder, expected int) {
	t.Helper()
	if response.Code != expected {
		t.Fatalf("HTTP status=%d, expected=%d; response=%s", response.Code, expected, response.Body.String())
	}
}

func TestBootstrapSurvivesRetryAndLostCommitWithoutAdoptingAnotherInstallation(t *testing.T) {
	store := newProtocolStore()
	store.lostSaveResponse = true
	first := newTestServer(t, store)
	before, err := store.Load(context.Background(), stateScope, installationKey)
	if err != nil {
		t.Fatal(err)
	}
	second := newTestServer(t, store)
	after, _ := store.Load(context.Background(), stateScope, installationKey)
	if before.Revision != 1 || after.Revision != before.Revision || string(after.Value) != string(before.Value) {
		t.Fatal("retry rewrote installation identity")
	}
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := New(context.Background(), testConfig(t), store, first.operatorToken, BuildInfo{}); err != nil {
				t.Error(err)
			}
		}()
	}
	wait.Wait()
	foreign := second.config
	foreign.InstallationID = "other-installation"
	if _, err := New(context.Background(), foreign, store, first.operatorToken, BuildInfo{}); !errors.Is(err, errBinding) {
		t.Fatal("different installation adopted existing database")
	}
	if _, err := New(context.Background(), first.config, store, strings.Repeat("b", 64), BuildInfo{}); !errors.Is(err, errBinding) {
		t.Fatal("changed bootstrap token overwrote durable operator")
	}
	final, _ := store.Load(context.Background(), stateScope, installationKey)
	if string(final.Value) != string(before.Value) || final.Revision != before.Revision {
		t.Fatal("rejected bootstrap mutated original state")
	}
}

func TestProviderBrowserJourneyAndRestart(t *testing.T) {
	runProviderJourney(t, newProtocolStore())
}

func runProviderJourney(t *testing.T, store StateStore) {
	t.Helper()
	server := newTestServer(t, store)
	requireStatus(t, perform(server, "GET", "/healthz/live", "", "", nil), http.StatusOK)
	requireStatus(t, perform(server, "GET", "/healthz/ready", "", "", nil), http.StatusOK)
	for _, operatorKey := range []string{"", strings.Repeat("b", 64), server.operatorToken + "extra"} {
		response := perform(server, "GET", "/api/v1/provider", "", operatorKey, nil)
		requireStatus(t, response, http.StatusUnauthorized)
		if strings.Contains(response.Body.String(), server.config.InstallationID) || strings.Contains(response.Body.String(), server.operatorToken) {
			t.Fatal("denial leaked protected data")
		}
	}
	response := perform(server, "GET", "/api/v1/provider", "", server.operatorToken, nil)
	requireStatus(t, response, http.StatusOK)
	var status ProviderStatus
	if json.Unmarshal(response.Body.Bytes(), &status) != nil || status.InstallationID != server.config.InstallationID || status.OperatorID == "" || status.Products == nil || len(status.Products) != 0 || status.Components.Database != "writable" {
		t.Fatal("invalid durable empty-provider status")
	}
	for _, path := range []string{"/api/v1/projects", "/api/v1/products", "/admin"} {
		requireStatus(t, perform(server, "POST", path, "", server.operatorToken, nil), http.StatusNotFound)
	}
	response = perform(server, "GET", "/", "", "", nil)
	requireStatus(t, response, http.StatusOK)
	if !strings.Contains(response.Body.String(), "Development access key") || strings.Contains(response.Body.String(), status.OperatorID) {
		t.Fatal("unauthenticated portal exposed provider state")
	}
	requireStatus(t, perform(server, "POST", "/login", loginForm(strings.Repeat("b", 64)), "", nil), http.StatusUnauthorized)
	response = perform(server, "POST", "/login", loginForm(server.operatorToken), "", nil)
	requireStatus(t, response, http.StatusSeeOther)
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Domain != "" || cookies[0].Name != sessionCookieName {
		t.Fatal("browser session cookie is not host-scoped and secure")
	}
	cookie := cookies[0]
	response = perform(server, "GET", "/", "", "", cookie)
	requireStatus(t, response, http.StatusOK)
	if !strings.Contains(response.Body.String(), "No products installed") || !strings.Contains(response.Body.String(), status.OperatorID) {
		t.Fatal("authenticated portal did not read durable provider")
	}
	server = newTestServer(t, store)
	response = perform(server, "GET", "/", "", "", cookie)
	requireStatus(t, response, http.StatusOK)
	if !strings.Contains(response.Body.String(), status.OperatorID) {
		t.Fatal("session did not survive process restart")
	}
	requireStatus(t, perform(server, "POST", "/logout", "csrf=invalid", "", cookie), http.StatusForbidden)
	csrf, err := server.csrf.Issue(cookie.Value, server.now())
	if err != nil {
		t.Fatal(err)
	}
	response = perform(server, "POST", "/logout", url.Values{"csrf": []string{csrf}}.Encode(), "", cookie)
	requireStatus(t, response, http.StatusSeeOther)
	if response.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout did not expire browser cookie")
	}
	requireStatus(t, perform(server, "GET", "/", "", "", cookie), http.StatusUnauthorized)
	revokedDocument, err := store.Load(context.Background(), stateScope, sessionKey)
	var revokedSession sessionState
	if err != nil || json.Unmarshal(revokedDocument.Value, &revokedSession) != nil || !revokedSession.Revoked || revokedDocument.Revision < 2 {
		t.Fatal("logout did not persist revocation with an increasing session revision")
	}
	response = perform(server, "GET", "/api/v1/provider", "", server.operatorToken, nil)
	requireStatus(t, response, http.StatusOK)
	var after ProviderStatus
	if json.Unmarshal(response.Body.Bytes(), &after) != nil || !after.CreatedAt.Equal(status.CreatedAt) || after.OperatorID != status.OperatorID {
		t.Fatal("restart changed installation/operator identity")
	}
}

func TestDatabaseFailureAndIdentityDriftNeverAppearReady(t *testing.T) {
	store := newProtocolStore()
	server := newTestServer(t, store)
	store.unavailable = true
	for _, path := range []string{"/healthz/ready", "/api/v1/provider", "/"} {
		requireStatus(t, perform(server, "GET", path, "", server.operatorToken, nil), http.StatusServiceUnavailable)
	}
	requireStatus(t, perform(server, "GET", "/healthz/live", "", "", nil), http.StatusOK)
	store.unavailable = false
	requireStatus(t, perform(server, "GET", "/healthz/ready", "", "", nil), http.StatusOK)
	document, _ := store.Load(context.Background(), stateScope, installationKey)
	var state installationState
	_ = json.Unmarshal(document.Value, &state)
	state.InstallationID = "foreign-installation"
	body, _ := json.Marshal(state)
	_, _ = store.Save(context.Background(), stateScope, installationKey, document.Revision, body)
	requireStatus(t, perform(server, "GET", "/healthz/ready", "", "", nil), http.StatusServiceUnavailable)
	requireStatus(t, perform(server, "GET", "/api/v1/provider", "", server.operatorToken, nil), http.StatusServiceUnavailable)
}

func TestCrossOriginDuplicateCredentialAndOversizeRequestsAreDenied(t *testing.T) {
	server := newTestServer(t, newProtocolStore())
	for _, mutate := range []func(*http.Request){
		func(request *http.Request) { request.Host = "attacker.test:8443" },
		func(request *http.Request) { request.Header.Set("Origin", "https://attacker.test") },
		func(request *http.Request) { request.Header.Del("Origin") },
		func(request *http.Request) { request.Header.Set("Content-Type", "text/plain") },
	} {
		request := httptest.NewRequest("POST", server.config.PublicOrigin+"/login", strings.NewReader(loginForm(server.operatorToken)))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", server.config.PublicOrigin)
		mutate(request)
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		requireStatus(t, response, http.StatusForbidden)
	}
	requireStatus(t, perform(server, "POST", "/login", loginForm(strings.Repeat("a", maximumFormBytes+1)), "", nil), http.StatusBadRequest)
	requireStatus(t, perform(server, "POST", "/login", duplicateLoginForm(server.operatorToken), "", nil), http.StatusUnauthorized)
	requireStatus(t, perform(server, "GET", "/api/v1/provider?token="+server.operatorToken, "", "", nil), http.StatusBadRequest)
	request := httptest.NewRequest("GET", server.config.PublicOrigin+"/api/v1/provider", nil)
	request.Header.Add("Authorization", "Bearer "+server.operatorToken)
	request.Header.Add("Authorization", "Bearer "+strings.Repeat("b", 64))
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	requireStatus(t, response, http.StatusUnauthorized)
}

func TestBrowserSessionRotationExpiryAndUncertainWrites(t *testing.T) {
	store := newProtocolStore()
	server := newTestServer(t, store)
	store.lostSaveResponse = true
	first := perform(server, "POST", "/login", loginForm(server.operatorToken), "", nil)
	requireStatus(t, first, http.StatusSeeOther)
	firstCookie := first.Result().Cookies()[0]
	second := perform(server, "POST", "/login", loginForm(server.operatorToken), "", nil)
	requireStatus(t, second, http.StatusSeeOther)
	secondCookie := second.Result().Cookies()[0]
	requireStatus(t, perform(server, "GET", "/", "", "", firstCookie), http.StatusUnauthorized)
	requireStatus(t, perform(server, "GET", "/", "", "", secondCookie), http.StatusOK)
	csrf, _ := server.csrf.Issue(secondCookie.Value, server.now())
	store.lostSaveResponse = true
	requireStatus(t, perform(server, "POST", "/logout", url.Values{"csrf": []string{csrf}}.Encode(), "", secondCookie), http.StatusSeeOther)
	third := perform(server, "POST", "/login", loginForm(server.operatorToken), "", nil)
	requireStatus(t, third, http.StatusSeeOther)
	thirdCookie := third.Result().Cookies()[0]
	now := server.now()
	server.now = func() time.Time { return now.Add(sessionLifetime + time.Second) }
	requireStatus(t, perform(server, "GET", "/", "", "", thirdCookie), http.StatusUnauthorized)
}

func TestLoginRateLimitIsBounded(t *testing.T) {
	server := newTestServer(t, newProtocolStore())
	now := time.Now()
	server.now = func() time.Time { return now }
	for range 30 {
		requireStatus(t, perform(server, "POST", "/login", loginForm("invalid"), "", nil), http.StatusUnauthorized)
	}
	requireStatus(t, perform(server, "POST", "/login", loginForm(server.operatorToken), "", nil), http.StatusTooManyRequests)
	now = now.Add(time.Minute)
	requireStatus(t, perform(server, "POST", "/login", loginForm(server.operatorToken), "", nil), http.StatusSeeOther)
}

func loginForm(value string) string {
	form := url.Values{}
	form.Set("token", value)
	return form.Encode()
}

func duplicateLoginForm(value string) string {
	form := url.Values{}
	form.Add("token", value)
	form.Add("token", value)
	return form.Encode()
}
