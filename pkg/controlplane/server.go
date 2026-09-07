// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/opencloudtech/CloudRING/pkg/identity"
)

const sessionLifetime = 30 * time.Minute
const sessionCookieName = "__Host-cloudring-dev-session"
const maximumFormBytes = 1024

// BuildInfo reports the executable's actual Go/VCS metadata. A development
// process built from a dirty source remains visibly different from a release.
type BuildInfo struct {
	GoVersion      string `json:"goVersion"`
	SourceRevision string `json:"sourceRevision"`
	SourceModified bool   `json:"sourceModified"`
}

type ProviderStatus struct {
	APIVersion     string          `json:"apiVersion"`
	InstallationID string          `json:"installationID"`
	Profile        string          `json:"profile"`
	Status         string          `json:"status"`
	OperatorID     string          `json:"operatorID"`
	CreatedAt      time.Time       `json:"createdAt"`
	Products       []Product       `json:"products"`
	Components     ComponentStatus `json:"components"`
	Build          BuildInfo       `json:"build"`
}

type ComponentStatus struct {
	Database string `json:"database"`
}

type Server struct {
	config        Config
	store         StateStore
	operatorToken string
	originHost    string
	build         BuildInfo
	csrf          identity.CSRFManager
	template      *template.Template
	now           func() time.Time
	loginMutex    sync.Mutex
	loginWindow   time.Time
	loginAttempts int
}

// New initializes or verifies the durable installation binding before serving.
// It does not fall back to memory or manufacture readiness after a DB failure.
func New(ctx context.Context, config Config, store StateStore, operatorToken string, build BuildInfo) (*Server, error) {
	if ctx == nil || config.Validate() != nil || store == nil || !operatorTokenPattern.MatchString(operatorToken) {
		return nil, errConfiguration
	}
	if _, err := bootstrap(ctx, store, config.InstallationID, operatorToken, time.Now()); err != nil {
		return nil, err
	}
	origin, err := url.Parse(config.PublicOrigin)
	if err != nil {
		return nil, errConfiguration
	}
	parsedTemplate, err := template.New("portal").Parse(portalHTML)
	if err != nil {
		return nil, errors.New("control plane portal is unavailable")
	}
	csrfKey := sha256.Sum256([]byte("cloudring-development-csrf-v1:" + operatorToken))
	return &Server{
		config: config, store: store, operatorToken: operatorToken, originHost: origin.Host,
		build: build, csrf: identity.NewCSRFManager(csrfKey[:], sessionLifetime),
		template: parsedTemplate, now: time.Now,
	}, nil
}

func (server *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	server.setHeaders(response, strings.HasPrefix(request.URL.Path, "/api/") || strings.HasPrefix(request.URL.Path, "/healthz/"))
	if request.URL.RawQuery != "" || request.URL.Fragment != "" {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	// Health probes use TLS directly to the Pod address; they reveal no
	// installation state and do not use cookies. All user surfaces are bound
	// to the configured HTTPS origin, without trusting forwarded headers.
	if strings.HasPrefix(request.URL.Path, "/healthz/") {
		server.health(response, request)
		return
	}
	if request.Host != server.originHost || (request.Header.Get("Origin") != "" && request.Header.Get("Origin") != server.config.PublicOrigin) {
		writeError(response, http.StatusForbidden, "origin_denied")
		return
	}
	switch request.URL.Path {
	case "/api/v1/provider":
		server.provider(response, request)
	case "/":
		server.portal(response, request)
	case "/login":
		server.login(response, request)
	case "/logout":
		server.logout(response, request)
	case "/assets/portal.css":
		if !allowMethod(response, request, http.MethodGet) {
			return
		}
		response.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = response.Write([]byte(portalCSS))
	default:
		writeError(response, http.StatusNotFound, "not_found")
	}
}

func (server *Server) health(response http.ResponseWriter, request *http.Request) {
	if !allowMethod(response, request, http.MethodGet) {
		return
	}
	switch request.URL.Path {
	case "/healthz/live":
		writeJSON(response, http.StatusOK, map[string]string{"status": "live"})
	case "/healthz/ready":
		if server.ready(request.Context()) != nil {
			writeError(response, http.StatusServiceUnavailable, "not_ready")
			return
		}
		writeJSON(response, http.StatusOK, map[string]string{"status": "ready"})
	default:
		writeError(response, http.StatusNotFound, "not_found")
	}
}

func (server *Server) ready(ctx context.Context) error {
	if server.store.Ready(ctx) != nil {
		return errState
	}
	_, err := server.loadInstallation(ctx)
	return err
}

func (server *Server) provider(response http.ResponseWriter, request *http.Request) {
	if !allowMethod(response, request, http.MethodGet) {
		return
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") ||
		!operatorTokenPattern.MatchString(strings.TrimPrefix(values[0], "Bearer ")) ||
		!equalHash(tokenHash(strings.TrimPrefix(values[0], "Bearer ")), tokenHash(server.operatorToken)) {
		response.Header().Set("WWW-Authenticate", "Bearer")
		writeError(response, http.StatusUnauthorized, "authentication_required")
		return
	}
	status, err := server.providerStatus(request.Context())
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "not_ready")
		return
	}
	writeJSON(response, http.StatusOK, status)
}

func (server *Server) providerStatus(ctx context.Context) (ProviderStatus, error) {
	if server.store.Ready(ctx) != nil {
		return ProviderStatus{}, errState
	}
	state, err := server.loadInstallation(ctx)
	if err != nil {
		return ProviderStatus{}, err
	}
	return ProviderStatus{
		APIVersion: APIVersion, InstallationID: state.InstallationID, Profile: state.Profile,
		Status: "ready", OperatorID: state.OperatorID, CreatedAt: state.CreatedAt,
		Products: state.Products, Components: ComponentStatus{Database: "writable"}, Build: server.build,
	}, nil
}

func (server *Server) portal(response http.ResponseWriter, request *http.Request) {
	if !allowMethod(response, request, http.MethodGet) {
		return
	}
	if server.ready(request.Context()) != nil {
		server.renderPortal(response, http.StatusServiceUnavailable, portalView{Unavailable: true})
		return
	}
	token, present := requestSessionToken(request)
	if !present {
		server.renderPortal(response, http.StatusOK, portalView{})
		return
	}
	if _, err := server.loadSession(request.Context(), token, server.now()); err != nil {
		server.expireCookie(response)
		server.renderPortal(response, http.StatusUnauthorized, portalView{AuthenticationFailed: true})
		return
	}
	status, err := server.providerStatus(request.Context())
	if err != nil {
		server.renderPortal(response, http.StatusServiceUnavailable, portalView{Unavailable: true})
		return
	}
	csrf, err := server.csrf.Issue(token, server.now())
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "not_ready")
		return
	}
	server.renderPortal(response, http.StatusOK, portalView{Provider: &status, CSRF: csrf})
}

func (server *Server) login(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		server.portal(response, request)
		return
	}
	if !allowMethod(response, request, http.MethodPost) {
		return
	}
	if !server.sameOriginForm(response, request) {
		return
	}
	if !server.allowLogin(server.now()) {
		response.Header().Set("Retry-After", "60")
		writeError(response, http.StatusTooManyRequests, "login_rate_limited")
		return
	}
	if len(request.PostForm) != 1 || len(request.PostForm["token"]) != 1 ||
		!operatorTokenPattern.MatchString(request.PostForm.Get("token")) ||
		!equalHash(tokenHash(request.PostForm.Get("token")), tokenHash(server.operatorToken)) {
		server.renderPortal(response, http.StatusUnauthorized, portalView{AuthenticationFailed: true})
		return
	}
	if server.ready(request.Context()) != nil {
		server.renderPortal(response, http.StatusServiceUnavailable, portalView{Unavailable: true})
		return
	}
	token, err := server.createSession(request.Context(), server.now())
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "not_ready")
		return
	}
	cookie, err := identity.NewSessionCookie(identity.CookiePolicy{
		Name: sessionCookieName, Value: token, Path: "/", Lifetime: sessionLifetime, SameSite: identity.SameSiteStrict,
	}, server.now())
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "not_ready")
		return
	}
	http.SetCookie(response, cookie)
	response.Header().Set("Location", "/")
	response.WriteHeader(http.StatusSeeOther)
}

func (server *Server) logout(response http.ResponseWriter, request *http.Request) {
	if !allowMethod(response, request, http.MethodPost) {
		return
	}
	if !server.sameOriginForm(response, request) {
		return
	}
	token, present := requestSessionToken(request)
	if !present || len(request.PostForm) != 1 || len(request.PostForm["csrf"]) != 1 ||
		server.csrf.Check(request.PostForm.Get("csrf"), token, server.now()) != nil {
		writeError(response, http.StatusForbidden, "request_denied")
		return
	}
	if server.ready(request.Context()) != nil {
		writeError(response, http.StatusServiceUnavailable, "not_ready")
		return
	}
	document, err := server.loadSession(request.Context(), token, server.now())
	if err != nil {
		writeError(response, http.StatusUnauthorized, "authentication_required")
		return
	}
	if server.revokeSession(request.Context(), document, token) != nil {
		writeError(response, http.StatusServiceUnavailable, "logout_unverified")
		return
	}
	server.expireCookie(response)
	response.Header().Set("Location", "/")
	response.WriteHeader(http.StatusSeeOther)
}

func (server *Server) sameOriginForm(response http.ResponseWriter, request *http.Request) bool {
	if request.Header.Get("Origin") != server.config.PublicOrigin || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		writeError(response, http.StatusForbidden, "request_denied")
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumFormBytes)
	if request.ParseForm() != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func (server *Server) allowLogin(now time.Time) bool {
	server.loginMutex.Lock()
	defer server.loginMutex.Unlock()
	if server.loginWindow.IsZero() || now.Sub(server.loginWindow) >= time.Minute {
		server.loginWindow, server.loginAttempts = now, 0
	}
	server.loginAttempts++
	return server.loginAttempts <= 30
}

func requestSessionToken(request *http.Request) (string, bool) {
	var sessionToken string
	count := 0
	for _, cookie := range request.Cookies() {
		if cookie.Name == sessionCookieName {
			count++
			sessionToken = cookie.Value
		}
	}
	return sessionToken, count == 1 && operatorTokenPattern.MatchString(sessionToken)
}

func (server *Server) expireCookie(response http.ResponseWriter) {
	cookie, err := identity.ExpireSessionCookie(identity.CookiePolicy{Name: sessionCookieName, Path: "/", SameSite: identity.SameSiteStrict}, server.now())
	if err == nil {
		http.SetCookie(response, cookie)
	}
}

func (server *Server) setHeaders(response http.ResponseWriter, api bool) {
	header := response.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Strict-Transport-Security", "max-age=31536000")
	header.Set("X-Frame-Options", "DENY")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	if api {
		header.Set("Content-Security-Policy", "default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; sandbox")
	} else {
		header.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	}
}

func allowMethod(response http.ResponseWriter, request *http.Request, method string) bool {
	if request.Method == method {
		return true
	}
	response.Header().Set("Allow", method)
	writeError(response, http.StatusMethodNotAllowed, "method_not_allowed")
	return false
}

func writeError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, map[string]string{"error": code})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
