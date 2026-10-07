// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package identity

import (
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizationCodePKCEFlowPrimitives(t *testing.T) {
	secrets, err := GenerateAuthorizationSecrets()
	if err != nil {
		t.Fatalf("GenerateAuthorizationSecrets: %v", err)
	}
	if len(secrets.State) < 43 || len(secrets.Nonce) < 43 {
		t.Fatalf("state or nonce has insufficient entropy encoding: %#v", secrets)
	}
	if secrets.PKCE.Method != "S256" || !validPKCEVerifier(secrets.PKCE.Verifier) {
		t.Fatalf("invalid generated PKCE: %#v", secrets.PKCE)
	}
	challenge, err := PKCEChallenge(secrets.PKCE.Verifier)
	if err != nil || challenge != secrets.PKCE.Challenge {
		t.Fatalf("PKCE challenge mismatch: got %q, err %v", challenge, err)
	}

	authorizationURL, err := BuildAuthorizationURL(AuthorizationURLRequest{
		AuthorizationEndpoint: "https://id.example.invalid/oauth2/authorize",
		ClientID:              "cloudring-console",
		RedirectURI:           "https://hub.example.invalid/auth/oidc/callback",
		Scopes:                []string{"openid", "profile", "groups"},
		State:                 secrets.State,
		Nonce:                 secrets.Nonce,
		PKCE:                  secrets.PKCE,
	})
	if err != nil {
		t.Fatalf("BuildAuthorizationURL: %v", err)
	}
	query := authorizationURL.Query()
	for key, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "cloudring-console",
		"redirect_uri":          "https://hub.example.invalid/auth/oidc/callback",
		"scope":                 "openid profile groups",
		"state":                 secrets.State,
		"nonce":                 secrets.Nonce,
		"code_challenge":        secrets.PKCE.Challenge,
		"code_challenge_method": "S256",
	} {
		if got := query.Get(key); got != want {
			t.Fatalf("authorization query %q = %q, want %q", key, got, want)
		}
	}
	if strings.Contains(authorizationURL.RawQuery, secrets.PKCE.Verifier) {
		t.Fatal("authorization URL disclosed the PKCE verifier")
	}

	form, err := BuildTokenRequest(AuthorizationCodeRequest{
		TokenEndpoint: strings.Join([]string{"https://id.example.invalid/oauth2", "token"}, "/"),
		ClientID:      "cloudring-console",
		RedirectURI:   "https://hub.example.invalid/auth/oidc/callback",
		Code:          "one-time-code",
		PKCEVerifier:  secrets.PKCE.Verifier,
	})
	if err != nil {
		t.Fatalf("BuildTokenRequest: %v", err)
	}
	if form.Get("grant_type") != "authorization_code" || form.Get("code_verifier") != secrets.PKCE.Verifier {
		t.Fatalf("unexpected token form: %#v", form)
	}
	if _, exists := form["client_secret"]; exists {
		t.Fatal("token form contains a client secret field")
	}

	code, err := ValidateAuthorizationCallback(url.Values{
		"state": {secrets.State},
		"code":  {"one-time-code"},
	}, secrets.State)
	if err != nil || code != "one-time-code" {
		t.Fatalf("ValidateAuthorizationCallback = %q, %v", code, err)
	}
}

func TestAuthorizationCodePrimitivesFailClosed(t *testing.T) {
	pkce, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	base := AuthorizationURLRequest{
		AuthorizationEndpoint: "https://id.example.invalid/oauth2/authorize",
		ClientID:              "cloudring-console",
		RedirectURI:           "https://hub.example.invalid/auth/oidc/callback",
		Scopes:                []string{"openid"},
		State:                 "state-value",
		Nonce:                 "nonce-value",
		PKCE:                  pkce,
	}
	tests := []struct {
		name   string
		mutate func(*AuthorizationURLRequest)
	}{
		{name: "insecure endpoint", mutate: func(value *AuthorizationURLRequest) {
			value.AuthorizationEndpoint = "http://id.example.invalid/authorize"
		}},
		{name: "insecure redirect", mutate: func(value *AuthorizationURLRequest) { value.RedirectURI = "http://hub.example.invalid/callback" }},
		{name: "missing state", mutate: func(value *AuthorizationURLRequest) { value.State = "" }},
		{name: "missing nonce", mutate: func(value *AuthorizationURLRequest) { value.Nonce = "" }},
		{name: "plain PKCE", mutate: func(value *AuthorizationURLRequest) { value.PKCE.Method = "plain" }},
		{name: "mismatched challenge", mutate: func(value *AuthorizationURLRequest) { value.PKCE.Challenge = "wrong" }},
		{name: "duplicate scope", mutate: func(value *AuthorizationURLRequest) { value.Scopes = []string{"openid", "openid"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.Scopes = append([]string{}, base.Scopes...)
			test.mutate(&candidate)
			if _, err := BuildAuthorizationURL(candidate); err == nil {
				t.Fatalf("BuildAuthorizationURL accepted %s", test.name)
			}
		})
	}

	for name, values := range map[string]url.Values{
		"provider error":  {"error": {"access_denied"}, "state": {"expected"}},
		"state mismatch":  {"state": {"wrong"}, "code": {"code"}},
		"missing code":    {"state": {"expected"}},
		"duplicate state": {"state": {"expected", "expected"}, "code": {"code"}},
		"duplicate code":  {"state": {"expected"}, "code": {"one", "two"}},
		"newline in code": {"state": {"expected"}, "code": {"bad\ncode"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateAuthorizationCallback(values, "expected"); err == nil {
				t.Fatalf("ValidateAuthorizationCallback accepted %s", name)
			}
		})
	}
}
