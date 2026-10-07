// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	pkceMethodS256          = "S256"
	minPKCEVerifierLength   = 43
	maxPKCEVerifierLength   = 128
	authorizationSecretSize = 32
	maxAuthorizationValue   = 4 << 10
)

type PKCE struct {
	Verifier  string
	Challenge string
	Method    string
}

type AuthorizationSecrets struct {
	State string
	Nonce string
	PKCE  PKCE
}

type AuthorizationURLRequest struct {
	AuthorizationEndpoint string
	ClientID              string
	RedirectURI           string
	Scopes                []string
	State                 string
	Nonce                 string
	PKCE                  PKCE
}

type AuthorizationCodeRequest struct {
	TokenEndpoint string
	ClientID      string
	RedirectURI   string
	Code          string
	PKCEVerifier  string
}

func GenerateAuthorizationSecrets() (AuthorizationSecrets, error) {
	state, err := randomAuthorizationValue(authorizationSecretSize)
	if err != nil {
		return AuthorizationSecrets{}, err
	}
	nonce, err := randomAuthorizationValue(authorizationSecretSize)
	if err != nil {
		return AuthorizationSecrets{}, err
	}
	pkce, err := GeneratePKCE()
	if err != nil {
		return AuthorizationSecrets{}, err
	}
	return AuthorizationSecrets{State: state, Nonce: nonce, PKCE: pkce}, nil
}

func GeneratePKCE() (PKCE, error) {
	verifier, err := randomAuthorizationValue(64)
	if err != nil {
		return PKCE{}, err
	}
	challenge, err := PKCEChallenge(verifier)
	if err != nil {
		return PKCE{}, err
	}
	return PKCE{Verifier: verifier, Challenge: challenge, Method: pkceMethodS256}, nil
}

func PKCEChallenge(verifier string) (string, error) {
	if !validPKCEVerifier(verifier) {
		return "", errors.New("pkce verifier must contain 43 to 128 unreserved characters")
	}
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func BuildAuthorizationURL(request AuthorizationURLRequest) (*url.URL, error) {
	endpoint, err := parseHTTPSURL(request.AuthorizationEndpoint, false)
	if err != nil {
		return nil, fmt.Errorf("authorization endpoint: %w", err)
	}
	if err := validateAuthorizationClient(request.ClientID, request.RedirectURI); err != nil {
		return nil, err
	}
	if !validOpaqueAuthorizationValue(request.State) || !validOpaqueAuthorizationValue(request.Nonce) {
		return nil, errors.New("authorization state and nonce are required and bounded")
	}
	if request.PKCE.Method != pkceMethodS256 || request.PKCE.Challenge == "" {
		return nil, errors.New("authorization request requires PKCE S256")
	}
	if challenge, err := PKCEChallenge(request.PKCE.Verifier); err != nil || challenge != request.PKCE.Challenge {
		return nil, errors.New("authorization PKCE verifier and challenge do not match")
	}
	if len(request.Scopes) == 0 {
		return nil, errors.New("authorization scope is required")
	}
	scopes := make([]string, 0, len(request.Scopes))
	seen := make(map[string]struct{}, len(request.Scopes))
	for _, scope := range request.Scopes {
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			return nil, errors.New("authorization scope contains an invalid value")
		}
		if _, duplicate := seen[scope]; duplicate {
			return nil, errors.New("authorization scope contains a duplicate value")
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	query := endpoint.Query()
	query.Set("response_type", "code")
	query.Set("client_id", request.ClientID)
	query.Set("redirect_uri", request.RedirectURI)
	query.Set("scope", strings.Join(scopes, " "))
	query.Set("state", request.State)
	query.Set("nonce", request.Nonce)
	query.Set("code_challenge", request.PKCE.Challenge)
	query.Set("code_challenge_method", pkceMethodS256)
	endpoint.RawQuery = query.Encode()
	return endpoint, nil
}

// BuildTokenRequest returns only the public authorization-code exchange
// parameters. A confidential client credential, when required by a provider,
// belongs in the transport authentication layer and must not be added here.
func BuildTokenRequest(request AuthorizationCodeRequest) (url.Values, error) {
	if _, err := parseHTTPSURL(request.TokenEndpoint, false); err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	if err := validateAuthorizationClient(request.ClientID, request.RedirectURI); err != nil {
		return nil, err
	}
	if !validOpaqueAuthorizationValue(request.Code) {
		return nil, errors.New("authorization code is required and bounded")
	}
	if _, err := PKCEChallenge(request.PKCEVerifier); err != nil {
		return nil, err
	}
	return url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {request.ClientID},
		"redirect_uri":  {request.RedirectURI},
		"code":          {request.Code},
		"code_verifier": {request.PKCEVerifier},
	}, nil
}

func ValidateAuthorizationCallback(values url.Values, expectedState string) (string, error) {
	if !validOpaqueAuthorizationValue(expectedState) {
		return "", errors.New("expected authorization state is required and bounded")
	}
	if len(values["state"]) != 1 {
		return "", errors.New("authorization callback contains duplicate or missing state")
	}
	state := values.Get("state")
	if len(state) != len(expectedState) || subtle.ConstantTimeCompare([]byte(state), []byte(expectedState)) != 1 {
		return "", errors.New("authorization state mismatch")
	}
	if providerError := values.Get("error"); providerError != "" {
		return "", errors.New("authorization provider returned an error")
	}
	code := values.Get("code")
	if !validOpaqueAuthorizationValue(code) {
		return "", errors.New("authorization code is required and bounded")
	}
	if len(values["code"]) != 1 {
		return "", errors.New("authorization callback contains duplicate code values")
	}
	return code, nil
}

func randomAuthorizationValue(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func validateAuthorizationClient(clientID, redirectURI string) error {
	if !validOpaqueAuthorizationValue(clientID) {
		return errors.New("authorization client id is required and bounded")
	}
	if _, err := parseHTTPSURL(redirectURI, true); err != nil {
		return fmt.Errorf("redirect uri: %w", err)
	}
	return nil
}

func parseHTTPSURL(raw string, allowPath bool) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > maxAuthorizationValue {
		return nil, errors.New("https URL is required and bounded")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("https URL must not contain credentials, query, or fragment")
	}
	if !allowPath && parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed, nil
}

func validOpaqueAuthorizationValue(value string) bool {
	return value != "" && len(value) <= maxAuthorizationValue && !strings.ContainsAny(value, "\x00\r\n")
}

func validPKCEVerifier(verifier string) bool {
	if len(verifier) < minPKCEVerifierLength || len(verifier) > maxPKCEVerifierLength {
		return false
	}
	for _, value := range verifier {
		if (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
			(value >= '0' && value <= '9') || value == '-' || value == '.' || value == '_' || value == '~' {
			continue
		}
		return false
	}
	return true
}
